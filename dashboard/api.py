"""
REST API endpoints for analyst dashboard
"""

from flask import Flask, jsonify, request
from dashboard.app import app, db
from data.models.models import Agent, TelemetryEvent, ThreatClassification, AgentAction
from agents.agent_manager import dispatch_action_to_agent


@app.route('/api/agents', methods=['GET'])
def get_agents():
    """Get list of registered agents"""
    agents = db.session.query(Agent).all()
    return jsonify([{
        "agent_id": a.agent_id,
        "hostname": a.hostname,
        "os_type": a.os_type,
        "status": a.status,
        "last_heartbeat": a.last_heartbeat.isoformat(),
        "ip_address": a.ip_address
    } for a in agents])


@app.route('/api/agents/<agent_id>/telemetry', methods=['GET'])
def get_agent_telemetry(agent_id):
    """Get telemetry from a specific agent"""
    limit = request.args.get("limit", 100, type=int)

    agent = db.session.query(Agent).filter_by(agent_id=agent_id).first()
    if not agent:
        return jsonify({"error": "Agent not found"}), 404

    telemetry = db.session.query(TelemetryEvent).filter_by(
        agent_id=agent.id
    ).order_by(TelemetryEvent.timestamp.desc()).limit(limit).all()

    return jsonify([{
        "event_type": t.event_type,
        "event_subtype": t.event_subtype,
        "timestamp": t.timestamp.isoformat(),
        "severity": t.severity,
        "data": t.event_data
    } for t in telemetry])


@app.route('/api/detections', methods=['GET'])
def get_detections():
    """Get high-conf detections (analyst queue)"""
    limit = request.args.get("limit", 100, type=int)

    classifications = db.session.query(ThreatClassification).filter(
        ThreatClassification.ensemble_confidence > 0.7
    ).order_by(ThreatClassification.timestamp.desc()).limit(limit).all()

    return jsonify([{
        "threat_type": c.threat_type,
        "severity": c.severity,
        "confidence": c.ensemble_confidence,
        "mitre_tactic": c.mitre_tactic,
        "timestamp": c.timestamp.isoformat()
    } for c in classifications])


@app.route('/api/agents/<agent_id>/execute-action', methods=['POST'])
def execute_action(agent_id):
    """Dispatch action to agent"""
    data = request.json
    action_type = data.get("action_type")
    action_params = data.get("action_params", {})

    try:
        action_id = dispatch_action_to_agent(agent_id, action_type, action_params)
        return jsonify({
            "action_id": action_id,
            "status": "dispatched"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

