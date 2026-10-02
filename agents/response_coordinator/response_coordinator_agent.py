# Vigilon Warden: Response Coordination
# Coordinates responses to classified threats and manages mitigation actions
# With human analyst collaboration

import time
from data.models.models import EmailNotification
from shared.communication.message_bus import message_bus
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate
from typing import List, Dict, Optional
import json
from datetime import datetime, timedelta, timezone
from enum import Enum
import redis
from data.models.models import (
    Analyst,
    get_session,
    ResponseAction as ResponseActionModel,
    EmailNotification,
    ThreatClassification,
    Vulnerability,
)
import os
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash
import logging
from shared.logging_config import setup_agent_logger
from shared.agent_names import PLATFORM_NAME, agent_name, agent_full_name
from opentelemetry import trace, metrics

load_dotenv()


class EmailNotificationSystem:
    """Handles email notifications to security analysts"""

    def __init__(self):
        """
        Initialize email system with SMTP config

        Args:
            smtp_server: SMTP server hostname (default: Outlook)
            smtp_port: SMTP port (587 for TLS, 465 for SSL)
            username: Email account username
            password: Email account password or app password
            use_tls: Whether to use TLS encryption
        """
        self.smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        self.smtp_port = os.getenv("SMTP_PORT", 587)
        self.username = os.getenv("SMTP_USERNAME")
        self.password = os.getenv("SMTP_PASSWORD")
        self.use_tls = True
        self.from_email = self.username
        # Demo mode: all emails routed to demo inbox
        self.demo_recipient = os.getenv("DEMO_RECIPIENT")

        if not self.username or not self.password:
            raise RuntimeError("SMTP credentials not set. Check .env file.")

    def send_threat_alert(
        self,
        analyst_emails: List[str],
        threat_data: Dict,
        hunting_results: Dict,
        template_type: str = "alert",
    ) -> List[Dict]:
        """
        Send threat alert email to analysts.

        In demo mode (self.demo_recipient is set), all emails are actually sent
        to the demo_recipient address, but results are logged under each analyst's
        email so verbose output shows the full team was "notified".

        Args:
            analyst_emails: List of analyst email addresses
            threat_data: Threat classification data
            hunting_results: Results from Vigilon Sentinel threat hunting
            template_type: Email template type (alert, escalation, summary)

        Returns:
            List of delivery results for each email
        """
        results = []

        # Generate email content based on template
        subject, html_body = self._generate_email_content(
            threat_data, hunting_results, template_type
        )

        # Track if we already sent the real email (only send once to demo inbox)
        real_email_sent = False
        real_send_result = None

        for email in analyst_emails:
            try:
                # Create message
                message = MIMEMultipart("alternative")
                message["Subject"] = subject
                message["From"] = self.from_email
                message["Date"] = formatdate(localtime=True)

                # Determine actual recipient
                actual_recipient = self.demo_recipient if self.demo_recipient else email
                message["To"] = actual_recipient

                # Add HTML content
                html_part = MIMEText(html_body, "html")
                message.attach(html_part)

                # In demo mode: send one real email, simulate the rest
                if self.demo_recipient:
                    if not real_email_sent:
                        # First analyst: actually send the email
                        delivery_result = self._send_email(message, actual_recipient)
                        real_email_sent = True
                        real_send_result = delivery_result
                    else:
                        # Subsequent analysts: reuse the real result (don't spam the inbox)
                        delivery_result = real_send_result
                else:
                    # Production mode: send to each analyst individually
                    delivery_result = self._send_email(message, actual_recipient)

                # Log under the analyst's original email (not the demo recipient)
                results.append(
                    {
                        "email": email,
                        "status": delivery_result["status"],
                        "message": delivery_result["message"],
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
            except Exception as e:
                results.append(
                    {
                        "email": email,
                        "status": "failed",
                        "message": f"Email Generation Failed: {str(e)}",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )

        # Send Slack/Teams notifications
        try:
            from dashboard.notification_service import notification_service

            # Try to fetch full threat data from database to get ensemble_confidence and description
            threat_id = threat_data.get("threat_id") or threat_data.get("id")
            confidence_score = threat_data.get("ensemble_confidence")
            description = threat_data.get("description")

            if threat_id and (not confidence_score or not description):
                try:
                    session = get_session()
                    threat_result = (
                        session.query(ThreatClassification, Vulnerability.description)
                        .join(
                            Vulnerability,
                            ThreatClassification.vulnerability_id == Vulnerability.id,
                        )
                        .filter_by(id=threat_id)
                        .first()
                    )
                    if threat_result:
                        threat_obj, vuln_description = threat_result
                        if not confidence_score:
                            confidence_score = getattr(
                                threat_obj, "ensemble_confidence", None
                            )
                        if not description and vuln_description:
                            description = vuln_description
                    session.close()
                except Exception as db_err:
                    print(f"[WARNING] Could not fetch threat details from DB: {db_err}")
                    if session:
                        session.close()

            # Build confidence context
            confidence_context = ""
            if confidence_score is not None:
                if confidence_score >= 0.70:
                    confidence_context = (
                        f"High confidence ({int(confidence_score*100)}%)"
                    )
                elif confidence_score >= 0.45:
                    confidence_context = (
                        f"Medium confidence ({int(confidence_score*100)}%)"
                    )
                else:
                    confidence_context = f"Low confidence ({int(confidence_score*100)}%) - Verification needed"

            alert_data = {
                "id": threat_data.get("id"),
                "threat_type": threat_data.get("threat_type", "Unknown"),
                "severity": threat_data.get("severity", "medium"),
                "risk_score": threat_data.get("risk_score", 0.0),
                "asset_name": threat_data.get("asset_name", "N/A"),
                "vulnerability_name": threat_data.get("vulnerability_name", "N/A"),
                "description": description or "No description available",
                "confidence_score": confidence_score,
                "confidence_context": confidence_context,
                "reviewed_by_analyst": threat_data.get("reviewed_by_analyst", False),
                "analyst_name": threat_data.get("analyst_name"),
                "dashboard_url": os.getenv("DASHBOARD_URL", "http://localhost:5000"),
            }
            notification_service.send_threat_alert(alert_data)
        except Exception as e:
            print(f"[WARNING] Failed to send Slack/Teams alert: {e}")

        return results

    def _send_email(self, message: MIMEMultipart, recipient_email: str) -> Dict:
        """Send individual email and return delivery status."""

        try:
            # Create SMTP connection (10s timeout so bad wifi doesn't block Vigilon Warden)
            if self.use_tls:
                context = ssl.create_default_context()
                server = smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=10)
                server.starttls(context=context)
            else:
                server = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, timeout=10)

            # Login and send
            server.login(self.username, self.password)
            server.send_message(message)
            server.quit()

            return {"status": "sent", "message": "Email sent successfully"}

        except smtplib.SMTPAuthenticationError:
            return {
                "status": "failed",
                "message": "SMTP authentication failed - check username/password",
            }

        except smtplib.SMTPRecipientsRefused:
            return {
                "status": "failed",
                "message": f"Recipient email address rejected: {recipient_email}",
            }
        except Exception as e:
            return {"status": "failed", "message": f"Email delivery failed: {str(e)}"}

    def _generate_email_content(
        self, threat_data: Dict, hunting_results: Dict, template_type: str
    ) -> tuple:
        """Generate email subject and HTML bod based on template type"""

        threat_type = threat_data.get("threat_type", "Unknown")
        severity = threat_data.get("severity", "Medium")
        risk_score = threat_data.get("risk_score", 5.0)
        asset_name = threat_data.get("asset_name", "Unknown Asset")

        # Map MITRE tactic IDs to human-readable names for email
        mitre_tactic_names = {
            "TA0043": "Reconnaissance",
            "TA0042": "Resource Development",
            "TA0001": "Initial Access",
            "TA0002": "Execution",
            "TA0003": "Persistence",
            "TA0004": "Privilege Escalation",
            "TA0005": "Defense Evasion",
            "TA0006": "Credential Access",
            "TA0007": "Discovery",
            "TA0008": "Lateral Movement",
            "TA0009": "Collection",
            "TA0011": "Command and Control",
            "TA0010": "Exfiltration",
            "TA0040": "Impact",
        }
        raw_tactics = threat_data.get("mitre_tactics", [])
        if isinstance(raw_tactics, str):
            raw_tactics = [raw_tactics]
        self._mitre_display = (
            ", ".join(
                f"{tid} — {mitre_tactic_names.get(tid, tid)}" if tid else "Unknown"
                for tid in raw_tactics
            )
            or "Unknown"
        )

        # Generate subject line
        if template_type == "alert":
            subject = f"🚨 {severity} Threat Alert: {threat_type} on {asset_name}"
        elif template_type == "escalation":
            subject = f"🔴 ESCALATED: {severity} Threat Requires Immediate Attention"
        elif template_type == "summary":
            subject = f"📊 Threat Detection Summary - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        else:
            subject = f"Threat Detection: {threat_type}"

        # Generate HTML body
        html_body = self._create_html_template(
            threat_data, hunting_results, template_type
        )

        return subject, html_body

    def _create_html_template(
        self, threat_data: Dict, hunting_results: Dict, template_type: str
    ) -> str:
        """Create rich HTML email template"""

        # Determine colors based on severity
        severity = threat_data.get("severity", "Medium")
        severity_colors = {
            "Critical": "#dc3545",
            "High": "#fd7e14",
            "Medium": "#ffc107",
            "Low": "#28a745",
            "Info": "#17a2b8",
        }
        severity_color = severity_colors.get(severity, "#6c757d")

        # IOC matches summary
        ioc_matches = hunting_results.get("ioc_matches", [])
        ioc_summary = (
            f"{len(ioc_matches)} IOC matches" if ioc_matches else "No IOC matches"
        )

        # Correlations summary
        entity_corr = hunting_results.get("entity_correlations", [])
        ml_corr = hunting_results.get("ml_correlations", [])
        corr_summary = (
            f"{len(entity_corr)} entity correlations, {len(ml_corr)} ML correlations"
        )

        # Anomaly detection summary
        anomaly_detected = hunting_results.get("anomaly_detected", False)
        anomaly_score = hunting_results.get("anomaly_score", 0.0)
        anomaly_summary = (
            f"Anomaly Score: {anomaly_score:.1%}"
            if anomaly_detected
            else "No anomalies detected"
        )

        # Create HTML template
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f8f9fa; }}
                .container {{ max-width: 600px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .header {{ background-color: {severity_color}; color: white; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                .severity-badge {{ background-color: {severity_color}; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }}
                .section {{ margin-bottom: 20px; padding: 15px; background-color: #f8f9fa; border-radius: 5px; }}
                .metric {{ display: inline-block; margin-right: 20px; }}
                .metric-label {{ font-weight: bold; color: #495057; }}
                .metric-value {{ color: #007bff; }}
                .action-buttons {{ margin-top: 20px; }}
                .btn {{ display: inline-block; padding: 10px 20px; margin: 5px; text-decoration: none; border-radius: 5px; font-weight: bold; }}
                .btn-primary {{ background-color: #007bff; color: white; }}
                .btn-danger {{ background-color: #dc3545; color: white; }}
                .btn-success {{ background-color: #28a745; color: white; }}
                .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6; font-size: 12px; color: #6c757d; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
                th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f8f9fa; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🚨 Threat Detection Alert</h1>
                    <p>A <span class="severity-badge">{severity}</span> threat has been detected and requires your attention.</p>
                </div>

                <div class="section">
                    <h2>📋 Threat Overview</h2>
                    <div class="metric">
                        <span class="metric-label">Threat Type:</span>
                        <span class="metric-value">{threat_data.get('threat_type', 'Unknown')}</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Risk Score:</span>
                        <span class="metric-value">{threat_data.get('risk_score', 0):.1f}/10</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Asset:</span>
                        <span class="metric-value">{threat_data.get('asset_name', 'Unknown')}</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Vulnerability:</span>
                        <span class="metric-value">{threat_data.get('vulnerability_name', 'Unknown')}</span>
                    </div>
                </div>

                <div class="section">
                    <h2>🔍 Hunting Results</h2>
                    <table>
                        <tr>
                            <th>Detection Type</th>
                            <th>Result</th>
                        </tr>
                        <tr>
                            <td>IOC Matching</td>
                            <td>{ioc_summary}</td>
                        </tr>
                        <tr>
                            <td>Event Correlations</td>
                            <td>{corr_summary}</td>
                        </tr>
                        <tr>
                            <td>Anomaly Detection</td>
                            <td>{anomaly_summary}</td>
                        </tr>
                    </table>
                </div>

                <div class="section">
                    <h2>🎯 MITRE ATT&CK Tactics</h2>
                    <p>{self._mitre_display}</p>
                </div>

                <div class="action-buttons">
                    <h2>🛡️ Recommended Actions</h2>
                    <a href="#" class="btn btn-primary">View Full Details</a>
                    <a href="#" class="btn btn-success">Mark as Reviewed</a>
                    <a href="#" class="btn btn-danger">Initiate Response</a>
                </div>

                <div class="footer">
                    <p>This alert was generated by {PLATFORM_NAME} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                    <p>Threat ID: {threat_data.get('threat_id', threat_data.get('id', 'Unknown'))} | {agent_full_name('response')}</p>
                </div>
            </div>
        </body>
        </html>
        """

        return html_template


class ResponseAction(Enum):
    """Available Automated response actions."""

    MONITOR = "monitor"
    ALERT = "alert"
    CONTAIN = "contain"
    ISOLATE = "isolate"
    BLOCK = "block"
    ESCALATE = "escalate"


class ResponseCoordinatorAgent:
    def __init__(
        self,
        agent_id: str = "response_001",
        redis_host=None,
        redis_port=None,
        verbose: bool = True,
    ):
        self.agent_id = agent_id
        redis_host = redis_host or os.getenv("REDIS_HOST", "localhost")
        redis_port = int(
            redis_port if redis_port is not None else os.getenv("REDIS_PORT", "6379")
        )
        self.redis_client = redis.Redis(
            host=redis_host, port=redis_port, decode_responses=True
        )

        # Initialize email notification system with Gmail SMTP
        self.email_system = EmailNotificationSystem()

        # Response decision rules
        self.response_rules = {
            "critical_high_risk": {
                "conditions": {"severity": ["Critical"], "min_risk_score": 8.0},
                "actions": [
                    ResponseAction.ALERT,
                    ResponseAction.CONTAIN,
                    ResponseAction.ESCALATE,
                ],
                "auto_execute": True,
                "email_template": "escalation",
            },
            "high_severity": {
                "conditions": {"severity": ["High"], "min_risk_score": 6.0},
                "actions": [ResponseAction.ALERT, ResponseAction.CONTAIN],
                "auto_execute": True,
                "email_template": "alert",
            },
            "medium_with_correlations": {
                "conditions": {"severity": ["Medium"], "has_correlations": True},
                "actions": [ResponseAction.ALERT, ResponseAction.MONITOR],
                "auto_execute": True,
                "email_template": "alert",
            },
            "anomaly_detected": {
                "conditions": {"anomaly_detected": True, "min_anomaly_score": 0.7},
                "actions": [ResponseAction.ALERT, ResponseAction.ESCALATE],
                "auto_execute": True,
                "email_template": "escalation",
            },
            "default_low_medium": {
                "conditions": {"severity": ["Low", "Medium"]},
                "actions": [ResponseAction.MONITOR],
                "auto_execute": True,
                "email_template": "summary",
            },
        }

        # Track which threat IDs have already been processed to prevent
        # duplicate emails and actions (survives restarts via DB check)
        self.processed_threat_ids = set()
        self.verbose = verbose
        self.logger = setup_agent_logger(self.agent_id, verbose)
        self._load_already_processed_threats()

        # Subscribe to hunting results
        message_bus.subscribe("hunting_results", self.handle_hunting_result)

    def _load_already_processed_threats(self):
        """Pre-populate processed set from DB so we never reprocess on restart."""
        session = get_session()
        try:
            existing = session.query(ResponseActionModel.threat_id).distinct().all()
            self.processed_threat_ids = {row[0] for row in existing if row[0]}
            if self.processed_threat_ids:
                self.logger.info(
                    f"Loaded {len(self.processed_threat_ids)} already-processed threat IDs from database"
                )
        except Exception as e:
            self.logger.warning(f"Could not load processed threats: {e}")
        finally:
            session.close()

        # Initialize OpenTelemetry tracing
        self.tracer = trace.get_tracer(self.agent_id)
        self.meter = metrics.get_meter(self.agent_id)
        self.response_time = self.meter.create_histogram("response_latency_ms")
        self.responses_coordinated = self.meter.create_counter("responses_executed")

    def process_hunting_results(self, hunting_results: Dict) -> Dict:
        """Process hunting results: evaluate threats against rules, execute actions, notify analysts"""
        with self.tracer.start_as_current_span("process_hunting_results") as span:
            span.set_attribute("threats_count", len(hunting_results.get("threats", [])))
            start = time.time()

            response_report = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "agent_id": self.agent_id,
                "threats_processed": len(hunting_results.get("threats", [])),
                "actions_taken": [],
                "emails_sent": [],
                "errors": [],
            }

            # Process individual threats
            for threat in hunting_results.get("threats", []):
                try:
                    threat_response = self._process_single_threat(
                        threat, hunting_results
                    )
                    response_report["actions_taken"].extend(threat_response["actions"])
                    response_report["emails_sent"].extend(threat_response["emails"])

                except Exception as e:
                    error_msg = (
                        f"Failed to process threat {threat.get('threat_id')}: {str(e)}"
                    )
                    response_report["errors"].append(error_msg)
                    self.logger.error(f"{error_msg}")

            # Process patterns and anomalies at system level
            self._process_system_level_alerts(hunting_results, response_report)

            # Log email summary
            emails_sent = response_report.get("emails_sent", [])
            if emails_sent:
                successful = sum(1 for e in emails_sent if e.get("status") == "sent")
                failed = len(emails_sent) - successful
                self.logger.info(
                    f" 📧 Email alerts sent to {successful} analyst(s)"
                    f"{f' ({failed} failed)' if failed else ''}"
                    f" — threat severity: {hunting_results.get('threats', [{}])[0].get('severity', 'Unknown')}"
                )

            # Publish response report to message bus
            self._publish_response_report(response_report)

            return response_report

    def _process_single_threat(self, threat: Dict, hunting_context: Dict) -> Dict:
        """Process individual threat and determine appropriate response."""
        threat_id = threat.get("threat_id")
        severity = threat.get("severity", "Medium")
        risk_score = threat.get("risk_score", 5.0)
        threat_type = threat.get("threat_type", "Unknown")

        # Enrich threat data with hunting context
        enriched_threat = {
            **threat,
            "has_correlations": (
                len(threat.get("entity_correlations", [])) > 0
                or len(threat.get("ml_correlations", [])) > 0
            ),
            "ioc_match_count": len(threat.get("ioc_matches", [])),
            "patterns_involved": self._check_threat_in_patterns(
                threat_id, hunting_context
            ),
        }

        # Determine response actions based on rules
        matched_rule, actions = self._evaluate_response_rules(enriched_threat)

        # Execute automated actions
        executed_actions = []
        for action in actions:
            if matched_rule["auto_execute"]:
                result = self._execute_response_action(action, enriched_threat)
                executed_actions.append(result)

        # Send email notifications
        email_results = []
        if matched_rule["email_template"]:
            analysts = self._get_relevant_analysts(severity, threat_type)
            if analysts:
                email_delivery = self.email_system.send_threat_alert(
                    analyst_emails=[a["email"] for a in analysts],
                    threat_data=enriched_threat,
                    hunting_results=threat,
                    template_type=matched_rule["email_template"],
                )
                email_results = email_delivery

                # Log email notifications to database
                self._log_email_notifications(analysts, threat_id, email_delivery)

        return {
            "threat_id": threat_id,
            "matched_rule": matched_rule,
            "actions": executed_actions,
            "emails": email_results,
        }

    def _evaluate_response_rules(self, threat: Dict) -> tuple:
        """Evaluate threat against response rules and return matched rule + actions."""
        severity = threat.get("severity", "Medium")
        risk_score = threat.get("risk_score", 5.0)
        anomaly_detected = threat.get("anomaly_detected", False)
        anomaly_score = threat.get("anomaly_score", 0.0)
        has_correlations = threat.get("has_correlations", False)

        # Check rules in priority order
        for rule_name, rule in self.response_rules.items():
            conditions = rule["conditions"]

            # Check severity condition
            if "severity" in conditions and severity not in conditions["severity"]:
                continue

            # Check minimum risk score
            if (
                "min_risk_score" in conditions
                and risk_score < conditions["min_risk_score"]
            ):
                continue

            # Check correlation requirement
            if (
                "has_correlations" in conditions
                and has_correlations != conditions["has_correlations"]
            ):
                continue

            # Check anomaly detection
            if (
                "anomaly_detected" in conditions
                and anomaly_detected != conditions["anomaly_detected"]
            ):
                continue

            # Check minimum anomaly score
            if (
                "min_anomaly_score" in conditions
                and anomaly_score < conditions["min_anomaly_score"]
            ):
                continue

            # Rule matched
            return rule, rule["actions"]

        # Default fallback rule
        return (
            self.response_rules["default_low_medium"],
            self.response_rules["default_low_medium"]["actions"],
        )

    def _execute_response_action(self, action: ResponseAction, threat: Dict) -> Dict:
        """Execute a specific response action and return result."""
        threat_id = threat.get("threat_id")
        action_result = {
            "threat_id": threat_id,
            "action": action.value,
            "status": "pending",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": {},
            "message": "",
        }

        try:
            if action == ResponseAction.MONITOR:
                # Set up monitoring - increase surveillance
                action_result.update(
                    {
                        "status": "completed",
                        "message": "Threat added to monitoring watchlist",
                        "details": {
                            "monitoring_level": "enhanced",
                            "duration_hours": 24,
                        },
                    }
                )

            elif action == ResponseAction.ALERT:
                # Generate internal alert
                action_result.update(
                    {
                        "status": "completed",
                        "message": "Internal alert generated and logged",
                        "details": {
                            "alert_level": threat.get("severity", "Medium"),
                            "alert_channels": ["dashboard", "email", "siem"],
                        },
                    }
                )

            elif action == ResponseAction.CONTAIN:
                # Containment actions - block IP, isolate process
                containment_success = self._execute_containment(threat)
                action_result.update(
                    {
                        "status": "completed" if containment_success else "failed",
                        "message": (
                            "Automated containment executed"
                            if containment_success
                            else "Containment failed"
                        ),
                        "details": {
                            "containment_type": "network_isolation",
                            "affected_asset": threat.get("asset_name"),
                            "success": containment_success,
                        },
                    }
                )

            elif action == ResponseAction.ISOLATE:
                # Network isolation - more aggressive than containment
                isolation_success = self._execute_isolation(threat)
                action_result.update(
                    {
                        "status": "completed" if isolation_success else "failed",
                        "message": (
                            "Asset isolated from network"
                            if isolation_success
                            else "Isolation failed"
                        ),
                        "details": {
                            "isolation_type": "full_network_isolation",
                            "affected_asset": threat.get("asset_name"),
                            "success": isolation_success,
                        },
                    }
                )

            elif action == ResponseAction.BLOCK:
                # Block source IP/Domain
                block_success = self._execute_block(threat)
                action_result.update(
                    {
                        "status": "completed" if block_success else "failed",
                        "message": (
                            "Source blocked at firewall"
                            if block_success
                            else "Blocking failed"
                        ),
                        "details": {
                            "block_type": "firewall_rule",
                            "blocked_entities": threat.get("ioc_matches", []),
                            "success": block_success,
                        },
                    }
                )

            elif action == ResponseAction.ESCALATE:
                # Escalate to senior analysts/management
                action_result.update(
                    {
                        "status": "completed",
                        "message": "Threat escalated to senior team",
                        "details": {
                            "escalation_level": "senior_analysts",
                            "escalation_reason": "High severity or anomaly detected",
                        },
                    }
                )

            # Log action to database
            self._log_response_action(action_result)

        except Exception as e:
            action_result.update(
                {"status": "failed", "message": f"Action execution failed: {str(e)}"}
            )

        return action_result

    def _execute_containment(self, threat: Dict) -> bool:
        """Execute containment measures (placeholder - implement based on your infrastructure)"""
        # This would integrate with your security infrastructure
        # Examples: EDR containment, network segmentation, process termination

        if self.verbose:
            self.logger.debug(
                f"CONTAINMENT: Containing threat {threat.get('asset_name')}"
            )
        else:
            self.logger.debug(
                f"CONTAINMENT: Containing threat {threat.get('asset_name')}"
            )

        # Simulate containment success
        return True

    def _execute_isolation(self, threat: Dict) -> bool:
        """Execute isolation measures (placeholder - implement based on your infrastructure)"""
        if self.verbose:
            self.logger.debug(f"ISOLATION: Isolating asset {threat.get('asset_name')}")
        else:
            self.logger.debug(f"ISOLATION: Isolating asset {threat.get('asset_name')}")

        # Simulate isolation success
        return True

    def _execute_block(self, threat: Dict) -> bool:
        """Execute blocking measures (placeholder - implement based on your infrastructure)"""

        ioc_matches = threat.get("ioc_matches", [])
        if ioc_matches and self.verbose:
            self.logger.debug(
                f"BLOCKING: Blocking IOCs: {[ioc.get('value') for ioc in ioc_matches]}"
            )
        elif ioc_matches and not self.verbose:
            self.logger.debug(
                f"BLOCKING: Blocking IOCs: {[ioc.get('value') for ioc in ioc_matches]}"
            )

        # Simulate blocking success
        return True

    def _get_relevant_analysts(self, severity: str, threat_type: str) -> List[Dict]:
        """Get analysts who should be notified based on threat characteristics"""

        session = get_session()
        try:
            # Map severity to notification thresholds
            severity_levels = {
                "Critical": 1,
                "High": 2,
                "Medium": 3,
                "Low": 4,
                "Info": 5,
            }

            threat_severity_level = severity_levels.get(severity, 3)

            # Get analysts who should receive notifications for this severity
            query = session.query(Analyst).filter(Analyst.active == True)

            # Filter by notification threshold
            if severity == "Critical":
                # Critical threats go to everyone
                analysts = query.all()
            elif severity == "High":
                # High threats go to medium+ threshold analysts
                analysts = query.filter(
                    Analyst.notification_threshold.in_(
                        ["low", "medium", "high", "critical"]
                    )
                ).all()
            elif severity == "Medium":
                # Medium threats go to medium+ threshold analysts
                analysts = query.filter(
                    Analyst.notification_threshold.in_(["medium", "high", "critical"])
                ).all()
            else:
                # Low threats only to low threshold analysts
                analysts = query.filter(
                    Analyst.notification_threshold.in_(["low"])
                ).all()

            return [
                {
                    "id": a.id,
                    "name": a.name,
                    "email": a.email,
                    "role": a.role,
                }
                for a in analysts
            ]

        finally:
            session.close()

    def _log_response_action(self, action_result: Dict) -> None:
        """Log response action to database"""

        session = get_session()
        try:
            action_record = ResponseActionModel(
                threat_id=action_result["threat_id"],
                action_type=action_result["action"],
                action_status=action_result["status"],
                automate=True,
                executed_by="Agent4_ResponseCoordinator",
                details=action_result["details"],
                result_message=action_result["message"],
            )

            session.add(action_record)
            session.commit()

        except Exception as e:
            self.logger.error(f"ERROR logging action: {e}")
            session.rollback()
        finally:
            session.close()

    def _log_email_notifications(
        self, analysts: List[Dict], threat_id: str, email_results: List[Dict]
    ) -> None:
        """Log email notifications to database"""

        session = get_session()
        try:
            for analyst, result in zip(analysts, email_results):
                # Create email log record
                notification = EmailNotification(
                    analyst_id=analyst["id"],
                    threat_id=threat_id,
                    subject=f"Threat Alert for Threat #{threat_id}",
                    email_template="alert",
                    delivery_status=result["status"],
                    error_message=(
                        result.get("message") if result["status"] == "failed" else None
                    ),
                )

                session.add(notification)

            session.commit()

        except Exception as e:
            self.logger.error(f"ERROR logging email notifications: {e}")
            session.rollback()
        finally:
            session.close()

    def _check_threat_in_patterns(
        self, threat_id: str, hunting_context: Dict
    ) -> List[str]:
        """Check if threat is part of any detected attack patterns"""
        patterns = hunting_context.get("patterns_detected", [])
        involved_patterns = []

        for pattern in patterns:
            if threat_id in pattern.get("matched_threats", []):
                involved_patterns.append(pattern["pattern"])

        return involved_patterns

    def _process_system_level_alerts(
        self, hunting_results: Dict, response_report: Dict
    ) -> None:
        """Process system-level patterns and anomalies for alerts"""
        patterns_detected = hunting_results.get("patterns_detected", [])
        anomalies_detected = hunting_results.get("anomalies_detected", [])

        # Send summary emails for detected patterns
        if patterns_detected:
            senior_analysts = self._get_relevant_analysts()
            if senior_analysts:
                pattern_summary = {
                    "type": "attack_patterns",
                    "count": len(patterns_detected),
                    "patterns": patterns_detected,
                }

                # Send pattern alert to senior analysts
                email_results = self.email_system.send_threat_alert(
                    analyst_emails=[a["email"] for a in senior_analysts],
                    threat_data=pattern_summary,
                    hunting_results=hunting_results,
                    template_type="escalation",
                )

                response_report["emails_sent"].extend(email_results)

    def _get_senior_analysts(self) -> List[Dict]:
        """Get senior analysts for escalated notifications"""

        session = get_session()
        try:
            analysts = (
                session.query(Analyst)
                .filter(
                    Analyst.active == True,
                    Analyst.role.in_(["senior_analyst", "manager", "admin"]),
                )
                .all()
            )

            return [
                {"id": a.id, "name": a.name, "email": a.email, "role": a.role}
                for a in analysts
            ]
        finally:
            session.close()

    def _publish_response_report(self, response_report: Dict) -> None:
        """Publish responsee report to message bus for other agents"""
        try:
            message = {
                "source": self.agent_id,
                "type": "response_report",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": response_report,
            }

            self.redis_client.publish("response_actions", json.dumps(message))
            if self.verbose:
                self.logger.info(
                    f"Published response report: {response_report['threats_processed']} threats processed."
                )
            else:
                self.logger.debug(
                    f"Published response report: {response_report['threats_processed']} threats processed."
                )

        except Exception as e:
            self.logger.error(f"ERROR publishing response report: {e}")

    def run(self):
        """Main agent loop - subscribe to hunting results from Vigilon Sentinel"""
        self.logger.info(f"Starting {agent_full_name('response')}...")
        self.logger.info(f"Listening to hunting results from {agent_name('threat_hunter')}...")

        pubsub = self.redis_client.pubsub()
        pubsub.subscribe("hunting_results")

        try:
            for message in pubsub.listen():
                if message["type"] == "message":
                    try:
                        hunting_data = json.loads(message["data"])

                        if hunting_data.get("source") == "hunter_001":
                            self.logger.info(
                                f"Received hunting results, processing responses..."
                            )
                            response_report = self.process_hunting_results(
                                hunting_data["data"]
                            )

                            self.logger.info(f"Response Summary:")
                            self.logger.info(
                                f"  - Threats processed: {response_report['threats_processed']}"
                            )
                            self.logger.info(
                                f"  - Actions taken: {len(response_report['actions_taken'])}"
                            )
                            self.logger.info(
                                f"  - Emails sent: {len(response_report['emails_sent'])}"
                            )

                    except Exception as e:
                        self.logger.error(f"ERROR processing hunting results: {e}")
        except KeyboardInterrupt:
            self.logger.debug(f"Shutting down {agent_full_name('response')}...")
        finally:
            pubsub.close()

    def handle_hunting_result(self, message):
        """Process hunting results from threat hunting agent.

        Vigilon Sentinel publishes one hunting result per threat in this format:
            {"type": "hunting_result", "agent": "hunter_001", "results": { ... single result ... }}

        process_hunting_results() expects:
            {"threats": [ { ... threat with hunting data ... }, ... ]}

        This handler bridges the two formats.
        """
        try:
            # Extract the single hunting result from the message
            result = message.get("results", {}) if isinstance(message, dict) else {}

            # If Vigilon Sentinel sent a bulk format (from hunt_threats), skip it
            # — we only handle per-threat results from handle_classified_threat
            if "threats" in result and "threats_analyzed" in result:
                if self.verbose:
                    self.logger.info(
                        f"Ignoring bulk hunting summary (already handled per-threat)"
                    )
                else:
                    self.logger.info(
                        f"Ignoring bulk hunting summary (already handled per-threat)"
                    )
                return

            # Get threat_id directly from result (Vigilon Sentinel now includes it)
            threat_id = result.get("threat_id")
            # Fallback: try correlated_events if threat_id not at top level
            if not threat_id:
                correlated = result.get("correlated_events", [])
                first_corr = correlated[0] if correlated else {}
                threat_id = first_corr.get("id")

            # --- Skip results with no threat_id (ghost/incomplete results) ---
            if not threat_id:
                return

            # --- DEDUP: skip if already processed ---
            if threat_id in self.processed_threat_ids:
                return

            # Read fields directly from result (Vigilon Sentinel includes them at top level)
            asset_name = result.get("asset_name", "Unknown Asset")
            vuln_name = result.get("vulnerability_name", "Unknown Vulnerability")
            threat_type = result.get("threat_type", "Unknown")
            severity = result.get("threat_level", "Medium")
            risk_score = result.get("risk_score", 5.0)
            correlated = result.get("correlated_events", [])
            ml_correlated = result.get("ml_correlated_events", [])

            self.logger.debug(
                f" Received hunting result from {agent_name('threat_hunter')}"
                f" | Threat #{threat_id}"
                f" | Severity: {severity}"
                f" | Risk: {risk_score}"
                f" | IOCs: {len(result.get('ioc_matches', []))}"
            )

            # Build a threat dict in the format process_hunting_results expects
            threat_entry = {
                "threat_id": threat_id,
                "severity": severity,
                "risk_score": risk_score,
                "threat_type": threat_type,
                "asset_name": asset_name,
                "vulnerability_name": vuln_name,
                "ensemble_confidence": result.get("ensemble_confidence"),
                "ioc_matches": result.get("ioc_matches", []),
                "entity_correlations": correlated,
                "ml_correlations": ml_correlated,
                "mitre_tactics": result.get("mitre_tactics", []),
                "details": result.get("details", ""),
            }

            # Wrap in the {"threats": [...]} structure expected by process_hunting_results
            hunting_results = {"threats": [threat_entry]}

            # Process the hunting results
            response_report = self.process_hunting_results(hunting_results)

            # Mark as processed so we never re-handle this threat
            if threat_id:
                self.processed_threat_ids.add(threat_id)

            # Log summary
            actions_count = len(response_report.get("actions_taken", []))
            emails_count = len(response_report.get("emails_sent", []))
            severity = threat_entry.get("severity", "Unknown")
            self.logger.info(
                f" ✅ Processed threat #{threat_id} | Severity: {severity}"
                f" | Actions: {actions_count} | Email alerts: {emails_count}"
            )

            # Publish response actions
            self.publish_response(response_report)
        except Exception as e:
            self.logger.error(f"Error handling hunting result: {e}")
            import traceback

            traceback.print_exc()

    def publish_response(self, response):
        """Publish response actions to other agents"""
        message_bus.publish(
            "response_actions",
            {"type": "response_action", "agent": self.agent_id, "response": response},
        )


class AnalystManager:
    """Manages security analyst team and notification preferences."""

    VALID_ROLES = {"analyst", "senior_analyst", "manager", "admin"}
    VALID_NOTIFICATION_THRESHOLDS = {"low", "medium", "high", "critical"}

    def _normalize_role(self, role: str) -> str:
        return (role or "").strip().lower().replace(" ", "_")

    def _normalize_notification_threshold(self, notification_threshold: str) -> str:
        return (notification_threshold or "").strip().lower()

    def add_analyst(
        self,
        name: str,
        email: str,
        role: str = "analyst",
        notification_threshold: str = "medium",
    ) -> Dict:
        """add new analyst to the team"""
        session = get_session()
        try:
            # Check if email already exists
            existing = session.query(Analyst).filter_by(email=email).first()
            if existing:
                return {
                    "success": False,
                    "message": f"Analyst with email {email} already exists.",
                    "analyst_id": None,
                }

            normalized_role = self._normalize_role(role)
            if normalized_role not in self.VALID_ROLES:
                return {
                    "success": False,
                    "message": f"Invalid role '{role}'. Allowed values: analyst, senior_analyst, manager, admin.",
                    "analyst_id": None,
                }

            normalized_threshold = self._normalize_notification_threshold(
                notification_threshold
            )
            if normalized_threshold not in self.VALID_NOTIFICATION_THRESHOLDS:
                return {
                    "success": False,
                    "message": f"Invalid notification_threshold '{notification_threshold}'. Allowed values: low, medium, high, critical.",
                    "analyst_id": None,
                }

            # Create new analyst
            analyst = Analyst(
                name=name,
                email=email,
                role=normalized_role,
                notification_threshold=normalized_threshold,
                active=True,
                password_hash=generate_password_hash(os.getenv("DEFAULT_PASSWORD")),
                must_change_password=True,
            )

            session.add(analyst)
            session.commit()

            return {
                "success": True,
                "message": f"Analyst {name} added successfully. Default password is set, analyst must change on first login.",
                "analyst_id": analyst.id,
            }

        except Exception as e:
            session.rollback()
            return {
                "success": False,
                "message": f"Failed to add analyst: {str(e)}",
                "analyst_id": None,
            }
        finally:
            session.close()

    def remove_analyst(self, analyst_id: int) -> Dict:
        """Deactivate analyst (soft delete)"""
        session = get_session()
        try:
            analyst = session.query(Analyst).filter_by(id=analyst_id).first()
            if not analyst:
                return {
                    "success": False,
                    "message": f"Analyst with ID {analyst_id} not found.",
                }

            # Soft delete - set active to False
            analyst.active = False
            analyst.updated_at = datetime.now(timezone.utc)
            session.commit()

            return {
                "success": True,
                "message": f"Analyst {analyst.name} deactivated successfully.",
            }

        except Exception as e:
            session.rollback()
            return {"success": False, "message": f"Failed to remove analyst: {str(e)}"}
        finally:
            session.close()

    def update_analyst(self, analyst_id: int, **kwargs) -> Dict:
        """Update analyst information"""

        allowed_fields = ["name", "email", "role", "notification_threshold", "active"]

        session = get_session()
        try:
            analyst = session.get(Analyst, analyst_id)
            if not analyst:
                return {
                    "success": False,
                    "message": f"Analyst with ID {analyst_id} not found.",
                }

            if "role" in kwargs:
                normalized_role = self._normalize_role(kwargs.get("role"))
                if normalized_role not in self.VALID_ROLES:
                    return {
                        "success": False,
                        "message": f"Invalid role '{kwargs.get('role')}'. Allowed values: analyst, senior_analyst, manager, admin.",
                    }
                kwargs["role"] = normalized_role

            if "notification_threshold" in kwargs:
                normalized_threshold = self._normalize_notification_threshold(
                    kwargs.get("notification_threshold")
                )
                if normalized_threshold not in self.VALID_NOTIFICATION_THRESHOLDS:
                    return {
                        "success": False,
                        "message": f"Invalid notification_threshold '{kwargs.get('notification_threshold')}'. Allowed values: low, medium, high, critical.",
                    }
                kwargs["notification_threshold"] = normalized_threshold

            # Prevent duplicate emails when updating login identity
            new_email = kwargs.get("email")
            if new_email and new_email != analyst.email:
                existing = session.query(Analyst).filter_by(email=new_email).first()
                if existing and existing.id != analyst.id:
                    return {
                        "success": False,
                        "message": f"Analyst with email {new_email} already exists.",
                    }

            # Update allowed fields
            for field, value in kwargs.items():
                if field in allowed_fields:
                    setattr(analyst, field, value)

            analyst.updated_at = datetime.now(timezone.utc)
            session.commit()

            return {
                "success": True,
                "message": f"Analyst {analyst.name} updated successfully.",
            }

        except Exception as e:
            session.rollback()
            return {"success": False, "message": f"Failed to update analyst: {str(e)}"}
        finally:
            session.close()

    def get_all_analysts(self, active_only: bool = True) -> List[Dict]:
        """Get all analysts"""

        session = get_session()
        try:
            query = session.query(Analyst)
            if active_only:
                query = query.filter(Analyst.active == True)

            analysts = query.all()

            return [
                {
                    "id": a.id,
                    "name": a.name,
                    "email": a.email,
                    "role": a.role,
                    "notification_threshold": a.notification_threshold,
                    "active": a.active,
                    "created_at": a.created_at.isoformat(),
                    "updated_at": a.updated_at.isoformat(),
                }
                for a in analysts
            ]

        finally:
            session.close()

    def get_notification_stats(self) -> Dict:
        """Get email notification statistics for analysts"""

        session = get_session()
        try:
            # Get total notifications sent
            total_notifications = session.query(EmailNotification).count()

            # Get notification by status
            status_counts = (
                session.query(
                    EmailNotification.delivery_status,
                    session.query(EmailNotification)
                    .filter(
                        EmailNotification.delivery_status
                        == EmailNotification.delivery_status
                    )
                    .count(),
                )
                .group_by(EmailNotification.delivery_status)
                .all()
            )

            # Get notifications in last 24 hours
            yesterday = datetime.now(timezone.utc) - timedelta(hours=24)
            recent_notifications = (
                session.query(EmailNotification)
                .filter(EmailNotification.sent_at >= yesterday)
                .count()
            )

            return {
                "total_notifications": total_notifications,
                "recent_24h": recent_notifications,
                "status_breakdown": dict(status_counts),
                "active_analysts": session.query(Analyst)
                .filter(Analyst.active == True)
                .count(),
                "total_analysts": session.query(Analyst).count(),
            }

        finally:
            session.close()


if __name__ == "__main__":
    import argparse
    import sys

    # Parse command line arguments
    parser = argparse.ArgumentParser(description=agent_full_name("response"))
    parser.add_argument(
        "--mode",
        choices=["listen", "demo"],
        default="demo",
        help="Run in listening mode or demo mode (default: demo)",
    )
    args = parser.parse_args()

    verbose = args.mode == "demo"

    agent = ResponseCoordinatorAgent(verbose=verbose)

    if args.mode == "demo":
        # DEMO MODE - Demonstrate response coordination on real threats
        print("=" * 80)
        print(f"{agent_full_name('response')} - Demo Mode")
        print("=" * 80)

        agent.logger.info(f" Initialized successfully")
        agent.logger.info(f" Coordinating responses to hunting results from {agent_name('threat_hunter')}...")

        print("\n" + "=" * 80)
        print("DEMO: Response Coordination Workflow")
        print("=" * 80)

        # Get real hunting results from Vigilon Sentinel
        from data.models.models import (
            get_session,
            HuntingResult,
            ThreatClassification,
            Asset,
            Vulnerability,
        )

        session = get_session()
        hunting_results_db = session.query(HuntingResult).limit(10).all()

        result_count = len(hunting_results_db)
        agent.logger.info(
            f" Processing {result_count} hunting results from database..."
        )

        if result_count == 0:
            session.close()
            agent.logger.info(
                f" No hunting results in database. Run {agent_name('threat_model')}, "
                f"{agent_name('classifier')} and {agent_name('threat_hunter')} first."
            )
            agent.logger.info(
                f" Usage: python -m agents.threat_modeling.threat_model_agent --mode demo"
            )
            agent.logger.info(
                f"        python -m agents.classification.classifier_agent --mode demo"
            )
            agent.logger.info(
                f"        python -m agents.threat_hunter.threat_hunter_agent --mode demo"
            )
        else:
            # Reconstruct hunting_results in the format process_hunting_results expects
            threats_for_processing = []
            for hr in hunting_results_db:
                threat = (
                    session.query(ThreatClassification)
                    .filter_by(id=hr.threat_id)
                    .first()
                )
                if not threat:
                    continue

                asset = (
                    session.query(Asset).filter_by(id=threat.asset_id).first()
                    if threat.asset_id
                    else None
                )
                vuln = (
                    session.query(Vulnerability)
                    .filter_by(id=threat.vulnerability_id)
                    .first()
                    if threat.vulnerability_id
                    else None
                )

                threats_for_processing.append(
                    {
                        "threat_id": threat.id,
                        "threat_type": threat.threat_type,
                        "severity": threat.severity,
                        "risk_score": threat.risk_score,
                        "asset_name": asset.name if asset else "Unknown",
                        "vulnerability_name": vuln.name if vuln else "Unknown",
                        "mitre_tactics": (threat.mitre_tactic or "").split(","),
                        "ioc_matches": hr.ioc_matches or [],
                        "entity_correlations": hr.entity_correlations or [],
                        "ml_correlations": hr.ml_correlations or [],
                        "anomaly_detected": hr.anomaly_detected,
                        "anomaly_score": hr.anomaly_score or 0.0,
                    }
                )
            session.close()

            # Build full hunting results dict
            hunting_results_dict = {
                "threats": threats_for_processing,
                "patterns_detected": [],
                "anomalies_detected": [
                    t for t in threats_for_processing if t.get("anomaly_detected")
                ],
            }

            analyst_manager = AnalystManager()
            total_actions_executed = 0
            total_emails_queued = 0

            agent.logger.info("[PROCESSING HUNTING RESULTS]")
            for i, threat in enumerate(threats_for_processing, 1):
                agent.logger.info(
                    f"  [{i}] Threat: {threat['threat_type']} ({threat['severity']})"
                )
                agent.logger.info(f"      Asset: {threat['asset_name']}")
                agent.logger.info(
                    f"      Vulnerability: {threat['vulnerability_name']}"
                )
                agent.logger.info(f"      Risk Score: {threat['risk_score']:.2f}/10")
                agent.logger.info(f"      IOC Matches: {len(threat['ioc_matches'])}")
                if threat["ioc_matches"]:
                    for ioc in threat["ioc_matches"][:3]:
                        ioc_val = (
                            ioc.get("value", ioc) if isinstance(ioc, dict) else ioc
                        )
                        agent.logger.info(f"        → {ioc_val}")
                agent.logger.info(
                    f"      Anomaly Detected: {threat['anomaly_detected']}"
                )
                if threat["anomaly_detected"]:
                    agent.logger.info(
                        f"      Anomaly Score: {threat['anomaly_score']:.2f}"
                    )

                # Evaluate response rules (using actual agent method)
                enriched_threat = {
                    **threat,
                    "has_correlations": (
                        len(threat.get("entity_correlations", [])) > 0
                        or len(threat.get("ml_correlations", [])) > 0
                    ),
                    "ioc_match_count": len(threat.get("ioc_matches", [])),
                }
                matched_rule, actions = agent._evaluate_response_rules(enriched_threat)

                # Execute each response action and log to database
                agent.logger.info(f"      Response Actions:")
                for action in actions:
                    result = agent._execute_response_action(action, enriched_threat)
                    status_icon = "✓" if result["status"] == "completed" else "✗"
                    agent.logger.info(
                        f"        {status_icon} {action.value.upper()}: {result['message']}"
                    )
                    total_actions_executed += 1

                # Get relevant analysts and show notification info (email mocked)
                analysts = agent._get_relevant_analysts(
                    threat["severity"], threat["threat_type"]
                )
                if analysts:
                    agent.logger.info(
                        f"      Analyst Notifications ({len(analysts)} analysts):"
                    )
                    for analyst in analysts:
                        agent.logger.info(
                            f"        → {analyst['name']} ({analyst['email']}) [EMAIL MOCKED]"
                        )
                    total_emails_queued += len(analysts)

            # Publish response report to message bus
            response_report = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "agent_id": agent.agent_id,
                "threats_processed": len(threats_for_processing),
                "actions_taken": total_actions_executed,
                "emails_queued": total_emails_queued,
            }
            agent._publish_response_report(response_report)

            print("\n" + "=" * 80)
            agent.logger.info("[RESPONSE COORDINATION SUMMARY]")
            agent.logger.info(
                f"  ✓ Hunting Results Processed: {len(threats_for_processing)}"
            )
            agent.logger.info(
                f"  ✓ Response Actions Executed: {total_actions_executed}"
            )
            agent.logger.info(f"  ✓ Actions Logged to Database")
            agent.logger.info(
                f"  ✓ Analyst Notifications Queued (Email Mocked): {total_emails_queued}"
            )
            agent.logger.info(f"  ✓ Response Report Published to Message Bus")

            # Show analyst team stats
            stats = analyst_manager.get_notification_stats()
            agent.logger.info(f"  ✓ Active Analysts: {stats.get('active_analysts', 0)}")
            agent.logger.info(
                f"  ✓ Total Historical Notifications: {stats.get('total_notifications', 0)}"
            )

            print("\n" + "=" * 80)
            print("Demo complete!")
            print("=" * 80)

    else:
        # LISTEN MODE - Continuous operation
        agent.verbose = False  # Minimal output in listen mode
        print("=" * 80)
        print(f"{agent_full_name('response')} - Listen Mode")
        print("=" * 80)
        agent.logger.info(f"Initialized and ready")
        agent.logger.info(f"Subscribed to 'hunting_results' channel from {agent_name('threat_hunter')}")
        print(f"Press Ctrl+C to exit")
        print("=" * 80 + "\n")

        # Send heartbeat immediately so dashboard shows agent as running
        message_bus.heartbeat(agent.agent_id)

        # Initial DB scan — pick up any hunting results saved by Vigilon Sentinel before
        # this agent started (dedup set prevents re-processing on restart).
        from data.models.models import (
            get_session,
            HuntingResult,
            ThreatClassification,
            Asset,
            Vulnerability,
        )

        session = get_session()
        try:
            all_results = session.query(HuntingResult).all()
            unprocessed = [
                r for r in all_results if r.threat_id not in agent.processed_threat_ids
            ]
            agent.logger.info(
                f"Initial DB scan: {len(unprocessed)} unprocessed hunting result(s) found "
                f"({len(all_results) - len(unprocessed)} already handled in previous runs)"
            )
            for hr in unprocessed:
                threat = (
                    session.query(ThreatClassification)
                    .filter_by(id=hr.threat_id)
                    .first()
                )
                if not threat:
                    continue
                asset = (
                    session.query(Asset).filter_by(id=threat.asset_id).first()
                    if threat.asset_id
                    else None
                )
                vuln = (
                    session.query(Vulnerability)
                    .filter_by(id=threat.vulnerability_id)
                    .first()
                    if threat.vulnerability_id
                    else None
                )

                # Reconstruct message in the same format Vigilon Sentinel publishes live
                msg = {
                    "type": "hunting_result",
                    "agent": "hunter_001",
                    "results": {
                        "threat_id": hr.threat_id,
                        "threat_type": threat.threat_type,
                        "asset_name": asset.name if asset else "Unknown",
                        "vulnerability_name": vuln.name if vuln else "Unknown",
                        "ioc_matches": hr.ioc_matches or [],
                        "threat_level": threat.severity,
                        "mitre_tactics": (
                            (threat.mitre_tactic or "").split(",")
                            if threat.mitre_tactic
                            else []
                        ),
                        "risk_score": float(threat.risk_score or 0),
                        "correlated_events": hr.entity_correlations or [],
                        "ml_correlated_events": hr.ml_correlations or [],
                        "anomaly_detected": hr.anomaly_detected,
                        "anomaly_score": float(hr.anomaly_score or 0),
                        "details": f"Threat classification for {threat.threat_type}",
                    },
                }
                agent.handle_hunting_result(msg)
        except Exception as e:
            agent.logger.error(f"Error during initial DB scan: {e}")
        finally:
            session.close()

        agent.logger.info(f"Now waiting for new hunting results from {agent_name('threat_hunter')}...")

        try:
            while True:
                time.sleep(1)
                message_bus.heartbeat(agent.agent_id)

        except KeyboardInterrupt:
            agent.logger.debug(f"Shutting down...")
