import os
import json
import requests
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, List
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file


class NotificationService:
    """Send threat alerts via multiple channels"""

    def __init__(self):
        self.slack_webhook = os.getenv("SLACK_WEBHOOK_URL")
        self.teams_webhook = os.getenv("TEAMS_WEBHOOK_URL")
        self.slack_enabled = os.getenv("SLACK_ENABLED", "false").lower() == "true"
        self.teams_enabled = os.getenv("TEAMS_ENABLED", "false").lower() == "true"

    def send_threat_alert(
        self, threat_data: Dict, threat_obj=None, analyst_name: str = None
    ):
        """Send threat alert via all enabled channels."""

        confidence_context = ""
        if threat_obj and hasattr(threat_obj, "ensemble_confidence"):
            score = threat_obj.ensemble_confidence
            if score >= 0.70:
                confidence_context = f"High confidence ({int(score*100)}%)"
            elif score >= 0.45:
                confidence_context = f"Medium confidence ({int(score*100)}%)"
            else:
                confidence_context = (
                    f"Low confidence ({int(score*100)}%) - Verification needed"
                )

        # Add confidence/review status to threat_data
        if threat_obj:
            threat_data["confidence_score"] = getattr(
                threat_obj, "ensemble_confidence", None
            )
            threat_data["confidence_context"] = confidence_context
            threat_data["reviewed_by_analyst"] = getattr(
                threat_obj, "reviewed_by_analyst", False
            )
            threat_data["analyst_name"] = analyst_name

        results = {"slack": None, "teams": None, "email": None}

        # Send to Slack
        if self.slack_enabled:
            try:
                results["slack"] = self._send_slack(threat_data)
            except Exception as e:
                print(f"[ERROR] Slack notification failed: {e}")
                results["slack"] = False

        # Send to Teams
        if self.teams_enabled:
            try:
                results["teams"] = self._send_teams(threat_data)
            except Exception as e:
                print(f"[ERROR] Teams notification failed: {e}")
                results["teams"] = False

        # Send email as fallback
        try:
            results["email"] = self.send_email(threat_data)
        except Exception as e:
            print(f"[ERROR] Email notification failed: {e}")
            results["email"] = False

        return results

    def _send_slack(self, threat_data: Dict) -> bool:
        """Send threat alert to Slack via webhook."""

        severity = threat_data.get("severity", "medium").lower()
        risk_score = threat_data.get("risk_score", 0.0)
        confidence_context = threat_data.get("confidence_context", "")  # NEW
        analyst_name = threat_data.get("analyst_name", None)  # NEW
        reviewed_by_analyst = threat_data.get("reviewed_by_analyst", False)  # NEW

        # Color code by severity
        color_map = {
            "CRITICAL": "#dc2626",  # Red
            "HIGH": "#ea580c",  # Orange
            "MEDIUM": "#eab308",  # Yellow
            "LOW": "#10b981",  # Green
        }
        color = color_map.get(severity, "#6b7280")

        payload = {
            "attachments": [
                {
                    "color": color,
                    "title": f"🚨 {severity} Threat Alert",
                    "fields": [
                        {
                            "title": "Threat Type",
                            "value": threat_data.get("threat_type", "Unknown"),
                            "short": True,
                        },
                        {
                            "title": "Risk Score",
                            "value": f"{risk_score:.1f}/10",
                            "short": True,
                        },
                        {
                            "title": "Confidence",
                            "value": (
                                confidence_context
                                if confidence_context
                                else "Not available"
                            ),
                            "short": True,
                        },
                        {
                            "title": "Review Status",
                            "value": (
                                f"✅ Verified by {analyst_name}"
                                if reviewed_by_analyst and analyst_name
                                else "Machine-classified"
                            ),
                            "short": True,
                        },
                        {
                            "title": "Asset",
                            "value": threat_data.get("asset_name", "N/A"),
                            "short": True,
                        },
                        {
                            "title": "Source IP",
                            "value": threat_data.get("source_ip", "N/A"),
                            "short": True,
                        },
                        {
                            "title": "Description",
                            "value": threat_data.get(
                                "description", "No description provided."
                            ),
                            "short": False,
                        },
                    ],
                    "actions": [
                        {
                            "type": "button",
                            "text": "📋 Review in Dashboard",
                            "url": f"{threat_data.get('dashboard_url', 'http://localhost:5000')}/",
                        }
                    ],
                    "footer": "Vigilon",
                    "ts": int(datetime.now(timezone.utc).timestamp()),
                }
            ]
        }

        response = requests.post(self.slack_webhook, json=payload, timeout=10)
        if response.status_code != 200:
            raise Exception(
                f"Slack API returned {response.status_code}: {response.text}"
            )

        print(f"✅ Slack alert sent for threat {threat_data.get('id')}")
        return True

    def _send_teams(self, threat_data: Dict) -> bool:
        """Send threat alert to Teams via webhook."""

        severity = threat_data.get("severity", "medium").upper()
        risk_score = threat_data.get("risk_score", 0.0)

        # Color code by severity (hex RGB)
        color_map = {
            "CRITICAL": "E11D48",  # Red
            "HIGH": "D97706",  # Orange
            "MEDIUM": "EAB308",  # Yellow
            "LOW": "10B981",  # Green
        }
        color = color_map.get(severity, "6B7280")  # Default gray

        payload = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": f"{severity} Threat: {threat_data.get('threat_type')}",
            "themeColor": color,
            "title": f"🚨 {severity} Threat Alert",
            "sections": [
                {
                    "activityTitle": threat_data.get("threat_type", "Unknown"),
                    "facts": [
                        {"name": "Risk Score", "value": f"{risk_score:.1f}/10"},
                        {
                            "name": "Asset",
                            "value": threat_data.get("asset_name", "N/A"),
                        },
                        {
                            "name": "Source IP",
                            "value": threat_data.get("source_ip", "N/A"),
                        },
                        {
                            "name": "Time",
                            "value": datetime.now(timezone.utc).isoformat(),
                        },
                    ],
                    "text": threat_data.get("description", "No description provided."),
                }
            ],
            "potentialAction": [
                {
                    "@type": "OpenUri",
                    "name": "📋 View in Dashboard",
                    "targets": [
                        {
                            "os": "default",
                            "uri": f"{threat_data.get('dashboard_url', 'http://localhost:5000')}/",
                        }
                    ],
                }
            ],
        }

        response = requests.post(self.teams_webhook, json=payload, timeout=10)

        if response.status_code not in [200, 204]:
            raise Exception(
                f"Teams API returned {response.status_code}: {response.text}"
            )

        print(f"✅ Teams alert sent for threat {threat_data.get('id')}")
        return True

    def _send_email(self, threat_data: Dict) -> bool:
        """Send email notification (fallback)."""
        from flask_mail import Mail, Message
        from dashboard.app import app

        mail = Mail(app)

        threat_id = threat_data.get("id", "Unknown")
        threat_type = threat_data.get("threat_type", "Unknown")
        severity = threat_data.get("severity", "medium")
        risk_score = threat_data.get("risk_score", 0.0)
        asset_name = threat_data.get("asset_name", "N/A")
        confidence_context = threat_data.get("confidence_context", "Not available")
        analyst_name = threat_data.get("analyst_name", None)
        reviewed_by_analyst = threat_data.get("reviewed_by_analyst", False)

        # Build review status line for email
        review_line = ""
        if reviewed_by_analyst and analyst_name:
            review_line = (
                f"<p><strong>Review Status:</strong> Verified by {analyst_name}</p>"
            )
        else:
            review_line = f"<p><strong>Review Status:</strong> Machine-classified ({confidence_context})</p>"

        subject = f"🚨 [{severity.upper()}] {threat_type} ({confidence_context})"

        html_body = f"""
        <html>
            <body style="font-family: Arial; background-color: #f5f5f5; padding: 20px;">
                <div style="background-color: #fff; padding: 20px; border-radius: 4px; border-left: 4px solid #dc2626;">
                    <h2 style="color: #dc2626;">{threat_type}</h2>

                    <p><strong>Threat ID:</strong> {threat_id}</p>
                    <p><strong>Severity:</strong> {severity.upper()}</p>
                    <p><strong>Risk Score:</strong> {risk_score:.1f}/10</p>
                    <p><strong>Asset:</strong> {asset_name}</p>
                    <p><strong>Source IP:</strong> {threat_data.get('source_ip', 'N/A')}</p>

                    {review_line}

                    <hr>

                    <p><strong>Confidence Level:</strong> {confidence_context}</p>

                    <p><strong>Description:</strong></p>
                    <p>{threat_data.get('description', 'No description')}</p>

                    <hr>

                    <a href="{threat_data.get('dashboard_url', 'http://localhost:5000')}/"
                    style="display: inline-block; background-color: #2563eb; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">
                        View in Dashboard
                    </a>
                </div>
            </body>
        </html>
        """

        msg = Message(
            subject=subject,
            recipients=threat_data.get(
                "email_recipients",
                [os.getenv("DEMO_RECIPIENT", "admin@threatdefense.local")],
            ),
            html=html_body,
        )

        mail.send(msg)
        print(f"✅ Email alert sent for threat {threat_id}")
        return True


# Global instance
notification_service = NotificationService()
