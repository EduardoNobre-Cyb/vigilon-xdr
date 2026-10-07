import uuid
import os
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Optional
from flask import request
from flask_socketio import emit, join_room, leave_room
from sqlalchemy import func

from data.models.models import Agent, TelemetryEvent, AgentAction, ThreatClassification
from agents.classification.classifier_agent import ThreatClassificationAgent
from threading import Thread
from shared.notify import alerts_enabled, send_alert


logger = logging.getLogger(__name__)

ACTIVE_AGENTS = {}

EDR_STATUS_ALERTS = os.environ.get("EDR_STATUS_ALERTS", "true").lower() == "true"
OFFLINE_GRACE_SECONDS = int(os.environ.get("EDR_OFFLINE_GRACE_SECONDS", "60"))
_offline_alerted = set()

_socketio = None
_get_db_session = None


def _get_real_db_session():
    if _get_db_session is None:
        raise RuntimeError("Database session factory is not initialized")

    db = _get_db_session()
    if hasattr(db, "query"):
        return db, False

    if hasattr(db, "__enter__") and hasattr(db, "__exit__"):
        db_session = db.__enter__()
        return db_session, True

    raise TypeError("Database factory did not return a SQLAlchemy session or a valid session context manager")


def register_agent_handlers(socketio, get_db_session):
    global _socketio, _get_db_session
    _socketio = socketio
    _get_db_session = get_db_session

    @socketio.on("agent_register")
    def handle_agent_register(data):
        db, managed = _get_real_db_session()
        try:
            agent_id = data.get("agent_id")
            hostname = data.get("hostname")
            os_type = data.get("os_type")

            if not all([agent_id, hostname, os_type]):
                emit("error", {"message": "Missing required agent metadata"})
                return
            
            agent = db.query(Agent).filter_by(agent_id=agent_id).first()
            is_new = agent is None

            if agent:
                agent.status = "online"
                agent.last_heartbeat = datetime.now(timezone.utc)
                agent.os_version = data.get("os_version")
                agent.agent_version = data.get("agent_version")
                agent.ip_address = data.get("ip_address")
                logger.info(f"Agent heartbeat: {agent_id} ({hostname})")
            else:
                agent = Agent(
                    agent_id=agent_id,
                    hostname=hostname,
                    os_type=os_type,
                    os_version=data.get("os_version"),
                    agent_version=data.get("agent_version"),
                    ip_address=data.get("ip_address"),
                    status="online",
                )
                logger.info(f"New agent registered: {agent_id} ({hostname})")

            db.add(agent)
            db.commit()

            ACTIVE_AGENTS[agent_id] = request.sid
            join_room(agent_id)
            _announce_online(agent_id, hostname, os_type, is_new)

            pending_actions = db.query(AgentAction).filter_by(agent_id=agent.id, status="pending").all()

            for action in pending_actions:
                emit("action_dispatch", {
                    "action_id": str(action.id),
                    "action_type": action.action_type,
                    "action_params": action.action_params
                })
                action.status = "dispatched"
                action.sent_at = datetime.now(timezone.utc)

            db.commit()

            emit("registration_ack", {
                "agent_id": agent_id,
                "status": "registered",
                "timestamp": datetime.now(timezone.utc).isoformat()
            })

        except Exception as e:
            logger.error(f"Agent registration error: {str(e)}")
            emit("error", {"message": str(e)})
        finally:
            if managed:
                db.close()
            else:
                db.close()

    @socketio.on("telemetry")
    def handle_telemetry(data):
        db, managed = _get_real_db_session()
        try:
            agent_id = data.get("agent_id")
            events = data.get("events", [])

            agent = db.query(Agent).filter_by(agent_id=agent_id).first()
            if not agent:
                emit("error", {"message": f"Unknown Agent: {agent_id}"})
                return
        
            agent.last_heartbeat = datetime.now(timezone.utc)

            for event in events:
                try:
                    event_data = event.get("data") or event.get("event_data", {})

                    malware_confidence = _coerce_confidence(
                        event.get("malware_confidence")
                        if event.get("malware_confidence") is not None
                        else event.get("network_risk_score")
                    )
                    network_risk_score = _coerce_confidence(
                        event.get("network_risk_score")
                        if event.get("network_risk_score") is not None
                        else event.get("malware_confidence")
                    )

                    telemetry = TelemetryEvent(
                        agent_id=agent.id,
                        event_type=event.get("event_type"),
                        event_subtype=event.get("event_subtype"),
                        severity=event.get("severity", "info"),
                        malware_confidence=malware_confidence,
                        network_risk_score=network_risk_score,
                        event_data=event_data,
                        timestamp=datetime.fromisoformat(event.get("timestamp")) if event.get("timestamp") else datetime.now(timezone.utc)
                    )
                    db.add(telemetry)
                
                except Exception as e:
                    logger.warning(f"Failed to ingest telemetry event from agent {agent_id}: {str(e)}")
                    continue

            db.commit()

            logger.info("Ingested %s telemetry events from %s", len(events), agent_id)
            emit("telemetry_ack", {"count": len(events)})

            if events:
                def run_threat_analysis():
                    analysis_db, _ = _get_real_db_session()
                    try:
                        def normalize_event_confidence(event):
                            value = event.get("malware_confidence")
                            if value is None:
                                value = event.get("network_risk_score", 0)
                            return _coerce_confidence(value)

                        high_conf_events = [
                            e for e in events
                            if (normalize_event_confidence(e) > 0.70)
                        ]

                        if not high_conf_events:
                            logger.info("Telemetry received from %s but no high-confidence events to classify.", agent_id)
                            return
                        
                        classifier = ThreatClassificationAgent()

                        for event in high_conf_events:
                            confidence = _coerce_confidence(
                                event.get("malware_confidence")
                                or event.get("network_risk_score", 0)
                            )
                            threat_description = _build_threat_description(event, agent.hostname, confidence)
                            classification_input = _build_classification_input(event, agent.hostname, confidence)

                            logger.info("Threat event captured for classification: %s", threat_description)

                            classification_result = classifier.classify(classification_input)
                            threat_type = classification_result.get("threat_type") or "Needs Review"
                            severity = classification_result.get("severity") or "Informational"
                            risk_score = classification_result.get("risk_score", 0.0)
                            exploitability_score = classification_result.get("exploitability_score", 0.0)
                            impact_score = classification_result.get("impact_score", 0.0)

                            threat_classification = ThreatClassification(
                                asset_id=None,
                                vulnerability_id=None,
                                threat_type=threat_type,
                                exploitability_score=exploitability_score,
                                impact_score=impact_score,
                                risk_score=risk_score,
                                mitre_tactic=classification_result.get("mitre_tactic"),
                                severity=severity,
                                ensemble_confidence=float(classification_result.get("confidence", confidence)),
                                timestamp=datetime.now(timezone.utc),
                            )
                            analysis_db.add(threat_classification)

                        analysis_db.commit()
                        logger.info(f"Classified {len(high_conf_events)} events")

                    except Exception as e:
                        logger.error(f"Threat analysis error for agent {agent_id}: {str(e)}")
                    finally:
                        analysis_db.close()

                Thread(target=run_threat_analysis, daemon=True).start()

        except Exception as e:
            logger.error(f"Telemetry error: {e}")
            emit("error", {"message": str(e)})
        finally:
            db.close()

    @socketio.on("action_result")
    def handle_action_result(data):
        db, managed = _get_real_db_session()
        try:
            action_id = data.get("action_id")
            status = data.get("status")
            result_message = data.get("result_message")

            action = db.query(AgentAction).filter_by(id=action_id).first()
            if action:
                action.status = status
                action.executed_at = datetime.now(timezone.utc)
                action.result_message = result_message
                db.commit()

                logger.info(f"Action result: {action_id} = {status}")
                emit("action_result_ack", {"action_id": action_id})

        except Exception as e:
            logger.error(f"Action result processing error: {str(e)}")
        finally:
            db.close()

    @socketio.on("disconnect")
    def handle_disconnect():
        db, managed = _get_real_db_session()
        try:
            for agent_id, sid in list(ACTIVE_AGENTS.items()):
                if sid == request.sid:
                    agent = db.query(Agent).filter_by(agent_id=agent_id).first()
                    hostname = agent_id
                    if agent:
                        agent.status = "offline"
                        hostname = agent.hostname
                        db.commit()
                    del ACTIVE_AGENTS[agent_id]
                    leave_room(agent_id)
                    logger.info(f"Agent disconnected: {agent_id}")
                    _schedule_offline_check(agent_id, hostname)
                    break
        except Exception as e:
            logger.error(f"Error during agent disconnect: {str(e)}")
        finally:
            db.close()


def _status_alerts_on() -> bool:
    return EDR_STATUS_ALERTS and alerts_enabled()

def _schedule_offline_check(agent_id: str, hostname: str):
    if _status_alerts_on():
        _socketio.start_background_task(_alert_if_still_offline, agent_id, hostname)

def _alert_if_still_offline(agent_id: str, hostname: str):
    _socketio.sleep(OFFLINE_GRACE_SECONDS)
    if agent_id in ACTIVE_AGENTS or agent_id in _offline_alerted:
        return
    _offline_alerted.add(agent_id)
    logger.warning(f"Agent still offline after {OFFLINE_GRACE_SECONDS}s: {agent_id} ({hostname})")
    send_alert(
        f"EDR Sensor OFFLINE: {hostname}",
        f"It hasnt reconnected for {OFFLINE_GRACE_SECONDS}s. The machine may be shut down or off the network, "
        "or something stopped the agent. That machine is unprotected until it comes back.", 5, ["rotating_light"]
    )

def _announce_online(agent_id: str, hostname: str, os_type: str, is_new: bool):
    was_alerted = agent_id in _offline_alerted
    _offline_alerted.discard(agent_id)
    if not _status_alerts_on():
        return
    if is_new:
        title = f"New EDR Sensor: {hostname}"
        message = f"A {os_type} agent registered for the first time (ID {agent_id[:8]}). If you didn't install it, investigate."
        priority, tags = 4, ["new"]
    elif was_alerted:
        title = f"EDR Sensor back ONLINE: {hostname}"
        message = "It reconnected, so that machine is protected again."
        priority, tags = 3, ["white_check_mark"]
    else:
        return
    _socketio.start_background_task(send_alert, title, message, priority, tags)

def dispatch_action_to_agent(agent_id: str, action_type: str, action_params: dict) -> Optional[str]:
    if not _get_db_session or not _socketio:
        logger.error("Agent manager not initialized. Call register_agent_handlers() first.")
        return None
    
    db, _ = _get_real_db_session()
    try:
        agent = db.query(Agent).filter_by(agent_id=agent_id).first()
        if not agent:
            raise ValueError(f"Agent not found: {agent_id}")
        
        action = AgentAction(
            agent_id=agent.id,
            action_type=action_type,
            action_params=action_params,
            status="pending"
        )
        db.add(action)
        db.commit()

        if agent_id in ACTIVE_AGENTS:
            _socketio.emit("action_dispatch", {
                "action_id": str(action.id),
                "action_type": action_type,
                "action_params": action_params
            }, room=agent_id)

            action.status = "dispatched"
            action.sent_at = datetime.now(timezone.utc)
            db.commit()

            logger.info(f"Action dispatched to {agent_id}: {action_type}")
            return str(action.id)
        else:
            logger.warning(f"Agent {agent_id} is offline. Action queued.")
            return str(action.id)

    except Exception as e:
        logger.error(f"Error dispatching action to agent {agent_id}: {str(e)}")
        return None
    finally:
        db.close()


def _coerce_confidence(value) -> float:
    if value is None:
        return 0.0

    if isinstance(value, (int, float)):
        return float(value)

    if isinstance(value, str):
        cleaned = value.strip().replace('%', '').replace(',', '')
        try:
            numeric = float(cleaned)
        except ValueError:
            return 0.0
        if numeric > 1.0:
            numeric = numeric / 100.0
        return float(numeric)

    try:
        numeric = float(value)
        if numeric > 1.0:
            numeric = numeric / 100.0
        return float(numeric)
    except (TypeError, ValueError):
        return 0.0


def _build_threat_description(event: Dict, hostname: str, confidence: float) -> str:
    event_data = event.get("data") or event.get("event_data", {})
    confidence_value = _coerce_confidence(confidence)

    if event.get("event_type") == "process":
        description = (
            f"High-confidence process detection ({confidence_value:.2%}) on {hostname}: "
            f"Process '{event_data.get('name')}' (PID {event_data.get('pid')}) "
            f"executed from {event_data.get('path')} "
            f"with command line: {event_data.get('command_line')}. "
            f"Parent: {event_data.get('parent_name')} (PPID {event_data.get('ppid')}). "
            f"User: {event_data.get('user')}. "
            f"ML Model Confidence: {confidence_value:.2%}"
        )

    elif event.get("event_type") == "network":
        description = (
            f"High-confidence network detection ({confidence_value:.2%}) on {hostname}: "
            f"Process '{event_data.get('process_name')}' (PID {event_data.get('pid', '?')}) "
            f"connected to {event_data.get('dest_ip')}:{event_data.get('dest_port')}. "
            f"from {event_data.get('source_ip')}:{event_data.get('source_port')}. "
            f"ML Model Confidence: {confidence_value:.2%}"
        )

    else:
        description = f"Suspicious event on {hostname}: {event.get('event_subtype')}"

    return description


def _build_classification_input(event: Dict, hostname: str, confidence: float) -> str:
    event_data = event.get("data") or event.get("event_data", {})
    confidence_value = _coerce_confidence(confidence)
    event_type = str(event.get("event_type") or "unknown").lower()

    cmdline = str(event_data.get("command_line") or "")
    cmdline_lower = cmdline.lower()
    proc_name = str(event_data.get("name") or event_data.get("process_name") or "")
    proc_name_lower = proc_name.lower()
    dst_port = str(event_data.get("dest_port") or "")
    path = str(event_data.get("path") or "")

    hints = []

    if proc_name_lower in {"nc", "ncat", "netcat"} or "nc " in cmdline_lower:
        hints.append("hint:nc_usage")
    if " -e " in cmdline_lower or "/bin/bash" in cmdline_lower or "/bin/sh" in cmdline_lower:
        hints.append("hint:reverse_shell_pattern")
    if "curl " in cmdline_lower or "wget " in cmdline_lower:
        hints.append("hint:download_exec_chain")
    if dst_port in {"4444", "1337", "6667", "9001"}:
        hints.append("hint:high_risk_port")
    if path.startswith("/tmp/") or path.startswith("/dev/shm/"):
        hints.append("hint:ephemeral_exec_path")

    hint_blob = " ".join(hints) if hints else "hint:none"

    if event.get("event_type") == "process":
        return (
            f"source=edr_telemetry family=process host={hostname} "
            f"proc={event_data.get('name')} pid={event_data.get('pid')} ppid={event_data.get('ppid')} "
            f"path={event_data.get('path')} parent={event_data.get('parent_name')} user={event_data.get('user')} "
            f"cmdline={event_data.get('command_line')} ml_conf={confidence_value:.4f} {hint_blob}"
        )

    if event.get("event_type") == "network":
        return (
            f"source=edr_telemetry family=network host={hostname} "
            f"proc={event_data.get('process_name')} pid={event_data.get('pid')} "
            f"src={event_data.get('source_ip')}:{event_data.get('source_port')} "
            f"dst={event_data.get('dest_ip')}:{event_data.get('dest_port')} "
            f"proto={event_data.get('protocol')} ml_conf={confidence_value:.4f} {hint_blob}"
        )

    return (
        f"source=edr_telemetry family=unknown host={hostname} "
        f"subtype={event.get('event_subtype')} event_type={event.get('event_type')} "
        f"ml_conf={confidence_value:.4f} {hint_blob}"
    )