from flask import Flask, render_template, jsonify, Response
from flask_socketio import SocketIO
from flask_cors import CORS
import os
from flask import request, redirect, url_for
from shared.communication.message_bus import message_bus
from data.models.models import (
    Asset,
    Vulnerability,
    AssetVulnerability,
    ThreatClassification,
    ResponseAction,
    EmailNotification,
    Analyst,
    LogEvent,
    ThreatReview,
    AnalystCuratedTrainingData,
    ReviewerAnalytics,
    AttackPath,
    Model,
    Agent,
    TelemetryEvent,
    AgentAction,
    get_session,
)
from agents.threat_hunter.threat_hunter_agent import ThreatHunterAgent
from agents.log_ingestor.log_ingestor_agent1 import Agent1LogIngestion
from agents.response_coordinator.response_coordinator_agent import AnalystManager
from agents.classification.classifier_agent import ThreatClassificationAgent
from shared.agent_names import agent_name, agent_role
import json
import socket
import redis
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt,
    get_jwt_identity,
)
from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from functools import wraps
import sys
import signal
from pathlib import Path
import subprocess
import time
import atexit
from apscheduler.schedulers.background import BackgroundScheduler
from contextlib import contextmanager

load_dotenv()  # Load environment variables from .env file


@contextmanager
def get_db_session():
    """Context manager for database sessions - ensures proper cleanup."""
    session = get_session()
    try:
        yield session
    finally:
        session.close()


app = Flask(__name__)
CORS(app)  # Enable CORS for all routes and origins
socketio = SocketIO(app, cors_allowed_origins="*")


def _classification_origin(classification) -> str:
    """Infer whether a threat came from legacy log ingestion or EDR telemetry."""
    if getattr(classification, "asset_id", None) is None and getattr(
        classification, "vulnerability_id", None
    ) is None:
        return "edr_telemetry"
    return "log_ingestion"


def _telemetry_confidence(event) -> float:
    """Extract the best available confidence score from a telemetry event."""
    confidence = event.malware_confidence
    if confidence is None:
        confidence = event.network_risk_score
    if confidence is None and event.event_data:
        confidence = (
            event.event_data.get("malware_confidence")
            or event.event_data.get("network_risk_score")
            or event.event_data.get("confidence")
            or 0
        )
    return float(confidence or 0)

# Import agent_manager AFTER socketio is created to avoid circular import
from agents.agent_manager import dispatch_action_to_agent, ACTIVE_AGENTS, register_agent_handlers

# Register agent WebSocket handlers after socketio is initialized
register_agent_handlers(socketio, get_db_session)

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB = int(os.getenv("REDIS_DB", "0"))
redis_client = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=REDIS_DB,
    decode_responses=True,
)
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=12)
app.config["JWT_TOKEN_LOCATION"] = ["headers", "query_string"]
app.config["JWT_QUERY_STRING_NAME"] = "token"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # Max upload size: 16MB

jwt = JWTManager(app)

AGENT_BASE_DIR = Path(__file__).resolve().parent.parent

PID_DIR = AGENT_BASE_DIR / "pids"  # Directory to store PID files for agents
PID_DIR.mkdir(exist_ok=True)  # Create PID directory if it doenst exist

# Maps agent_id to the python command to launch it
AGENT_COMMANDS = {
    "threat_model_001": [
        sys.executable,
        "-m",
        "agents.threat_modeling.threat_model_agent",
        "--mode",
        "listen",
    ],
    "classifier_001": [
        sys.executable,
        "-m",
        "agents.classification.classifier_agent",
        "--mode",
        "listen",
    ],
    "hunter_001": [
        sys.executable,
        "-m",
        "agents.threat_hunter.threat_hunter_agent",
        "--mode",
        "listen",
    ],
    "response_001": [
        sys.executable,
        "-m",
        "agents.response_coordinator.response_coordinator_agent",
        "--mode",
        "listen",
    ],
}


# Any logged-in analyst
def login_required(f):
    @wraps(f)
    @jwt_required()
    def decorated(*args, **kwargs):
        return f(*args, **kwargs)

    return decorated


# Admin only
def admin_required(f):
    @wraps(f)
    @jwt_required()
    def decorated(*args, **kwargs):
        claims = get_jwt()
        if claims.get("role") != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)

    return decorated


# --- Routes ---


@app.route("/")
def index():
    # The JS in dashboard.html handles the redirect to /login if no token is stored.
    return render_template("dashboard.html")


@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    email = data.get("email", "").strip()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    session = get_session()
    try:
        analyst = session.query(Analyst).filter_by(email=email, active=True).first()

        # Same message for both "not found" and "wrong password" — don't leak which
        if not analyst or not analyst.password_hash:
            return jsonify({"error": "Invalid credentials"}), 401
        if not check_password_hash(analyst.password_hash, password):
            return jsonify({"error": "Invalid credentials"}), 401

        must_change = bool(analyst.must_change_password)
        token = create_access_token(
            identity=str(analyst.id),
            additional_claims={
                "role": analyst.role,
                "name": analyst.name,
                "must_change_password": must_change,
            },
        )

        analyst.last_login = datetime.now(timezone.utc)
        session.commit()

        return jsonify(
            {
                "token": token,
                "role": analyst.role,
                "name": analyst.name,
                "must_change_password": must_change,
            }
        )
    finally:
        session.close()


@app.route("/api/auth/me")
@login_required
def auth_me():
    """Returns the current user's identity from the token. Used by dashboard on load."""
    claims = get_jwt()
    analyst_id = get_jwt_identity()  # This is the analyst.id as a string
    return jsonify(
        {
            "analyst_id": int(analyst_id) if analyst_id else None,
            "name": claims.get("name"),
            "role": claims.get("role"),
            "must_change_password": claims.get("must_change_password", False),
        }
    )


@app.route("/change-password")
def change_password_page():
    """Serve the password-change page. Auth guard is handled client-side."""
    return render_template("change_password.html")


@app.route("/api/auth/change-password", methods=["POST"])
@login_required
def api_change_password():
    """Validates the current password, applies the new one, and returns a fresh token."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    current_password = data.get("current_password", "")
    new_password = data.get("new_password", "")

    if not current_password or not new_password:
        return jsonify({"error": "current_password and new_password are required"}), 400

    if len(new_password) < 8:
        return jsonify({"error": "New password must be at least 8 characters"}), 400

    if new_password == "ChangeMe123!":
        return jsonify({"error": "You must choose a unique password"}), 400

    analyst_id = get_jwt_identity()
    session = get_session()
    try:
        analyst = session.query(Analyst).filter_by(id=analyst_id, active=True).first()
        if not analyst:
            return jsonify({"error": "Account not found"}), 404

        if not check_password_hash(analyst.password_hash, current_password):
            return jsonify({"error": "Current password is incorrect"}), 401

        analyst.password_hash = generate_password_hash(new_password)
        analyst.must_change_password = False
        analyst.last_login = datetime.now(timezone.utc)
        session.commit()

        # Issue a fresh token with the updated must_change_password flag cleared
        new_token = create_access_token(
            identity=str(analyst.id),
            additional_claims={
                "role": analyst.role,
                "name": analyst.name,
                "must_change_password": False,
            },
        )

        return jsonify({"token": new_token, "message": "Password updated successfully"})
    finally:
        session.close()


@app.route("/api/server-info")
def server_info():
    """Return server connection information for mobile clients"""
    try:
        # Get the server's local IP address
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)

        server_data = {
            "server_ip": local_ip,
            "port": 5000,
            "base_url": f"http://{local_ip}:5000",
            "status": "online",
        }
        return jsonify(server_data)
    except Exception as e:
        return jsonify({"error": str(e), "status": "offline"}), 500


@app.route("/api/agents/status")
@login_required
def agents_status():
    # Placeholder for agent status data
    # "id" is internal (Redis keys, logs, buttons), so never rename it.
    # "key" looks up the display name in shared/agent_names.py.
    agent_definitions = [
        {"id": "threat_model_001", "key": "threat_model", "number": 1},
        {"id": "classifier_001", "key": "classifier", "number": 2},
        {"id": "hunter_001", "key": "threat_hunter", "number": 3},
        {"id": "response_001", "key": "response", "number": 4},
    ]

    agents = []
    for agent_def in agent_definitions:
        agent_id = agent_def["id"]

        # Read heartbeak key from Redis
        # If agent is running, returns ISO timestamp
        # If agent is stopped/crashed, returns None (key expired)
        last_heartbeat = redis_client.get(f"agent:{agent_id}:heartbeat")
        status = redis_client.get(f"agent:{agent_id}:status")

        agents.append(
            {
                "id": agent_id,
                "name": agent_name(agent_def["key"]),
                "role": agent_role(agent_def["key"]),
                "agent_number": agent_def["number"],
                "status": "Running" if status == "running" else "Stopped",
                "last_heartbeat": (
                    last_heartbeat if last_heartbeat else "No heartbeat detected"
                ),
            }
        )

    return jsonify({"agents": agents})


@app.route("/api/agents/<agent_id>/logs", methods=["GET"])
@login_required  # Auth Protected
def get_agent_logs(agent_id):
    """Fetch logs for a specific agent."""

    try:
        lines_to_fetch = request.args.get("lines", 100, type=int)
        level_filter = request.args.get("level", "").upper()

        # Safety check: dont allow fetching more than 1000 lines at once
        if lines_to_fetch > 1000:
            lines_to_fetch = 1000
        if lines_to_fetch < 1:
            lines_to_fetch = 1

        # Building log file path
        log_file = os.path.join("logs", f"{agent_id}.log")

        # Check if log file exists
        if not os.path.exists(log_file):
            return (
                jsonify(
                    {
                        "agents_id": agent_id,
                        "logs": [],
                        "total_lines": 0,
                        "message": f"No logs found for agent '{agent_id}'.",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                ),
                404,
            )  # 404 = Not found

        # Read log file
        with open(log_file, "r", encoding="utf-8") as f:
            all_lines = f.readlines()

        # Get only last N lines (if file has more than requested)
        if len(all_lines) > lines_to_fetch:
            recent_lines = all_lines[-lines_to_fetch:]
        else:
            recent_lines = all_lines

        if level_filter:
            filtered_lines = [
                line for line in recent_lines if f" {level_filter} " in line
            ]
            recent_lines = filtered_lines

        # Return Success Response
        return (
            jsonify(
                {
                    "agent_id": agent_id,
                    "logs": recent_lines,
                    "total_lines": len(recent_lines),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ),
            200,
        )  # 200 = OK

    except FileNotFoundError:
        return jsonify({"error": f"Log file for agent '{agent_id}' not found"}), 404

    except Exception as e:
        # Catch any unexpected errors
        return (
            jsonify({"error": f"Failed to read agent logs: {str(e)}"}),
            500,
        )  # 500 = Internal Server Error


@app.route("/api/agents/<agent_id>/logs/stream")
@login_required
def stream_agent_logs(agent_id):
    log_file = os.path.join("logs", f"{agent_id}.log")

    def generate():
        file_handle = None

        def open_active_log(seek_to_end: bool = True):
            fh = open(log_file, "r", encoding="utf-8")
            if seek_to_end:
                fh.seek(0, os.SEEK_END)
            return fh

        while True:
            if file_handle is None:
                try:
                    file_handle = open_active_log(seek_to_end=True)
                except FileNotFoundError:
                    time.sleep(0.3)
                    continue

            line = file_handle.readline()
            if line:
                yield f"data: {line.rstrip()}\n\n"
                continue

            # No new line right now — check if log file was rotated/replaced.
            try:
                current_stat = os.fstat(file_handle.fileno())
                active_stat = os.stat(log_file)

                same_file = (
                    current_stat.st_dev == active_stat.st_dev
                    and current_stat.st_ino == active_stat.st_ino
                )
                truncated = active_stat.st_size < file_handle.tell()

                if (not same_file) or truncated:
                    file_handle.close()
                    file_handle = open_active_log(seek_to_end=True)
                    continue

            except FileNotFoundError:
                # During rollover there may be a tiny window with no active file.
                try:
                    file_handle.close()
                except Exception:
                    pass
                file_handle = None
            except Exception:
                # Keep stream alive on transient fs/read issues.
                pass

            time.sleep(0.3)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # Disable buffering for nginx
        },
    )


@app.route("/api/agents/<agent_id>/start", methods=["POST"])
@admin_required
def start_agent(agent_id):
    """Start a specific agent as a background process."""
    # Validate the agent_id is one we know about
    if agent_id not in AGENT_COMMANDS:
        return jsonify({"error": f"Unknown agent_id: {agent_id}"}), 400

    # Check if PID file exists
    pid_file = PID_DIR / f"{agent_id}.pid"
    if pid_file.exists():
        # Exists but is process still alive?
        try:
            pid = int(pid_file.read_text().strip())
            os.kill(pid, 0)
            return (
                jsonify(
                    {
                        "status": "already_running",
                        "message": f"Agent {agent_id} is already running (PID {pid}).",
                    }
                ),
                200,
            )
        except (ProcessLookupError, ValueError):
            # Process is dead but PID file is stale
            pid_file.unlink(missing_ok=True)  # Clean it up and continue

    # Start agent as background process
    command = AGENT_COMMANDS[agent_id]

    # Redirect stderr to the agent's log file so startup crashes are visible in the Logs viewer
    log_file_path = AGENT_BASE_DIR / "logs" / f"{agent_id}.log"
    log_file_path.parent.mkdir(exist_ok=True)

    try:
        log_fh = open(log_file_path, "a")
        process = subprocess.Popen(
            command,
            cwd=str(AGENT_BASE_DIR),  # CRITICAL: must run from root directory
            stdout=subprocess.DEVNULL,
            stderr=log_fh,  # Crash tracebacks go to the log file
            start_new_session=True,
        )
        # Parent process no longer needs this file handle.
        log_fh.close()
    except Exception as e:
        return jsonify({"error": f"Failed to start agent: {str(e)}"}), 500

    # Detect fast-fail startup (common when imports/env are broken) so UI sees real error.
    time.sleep(0.8)
    exit_code = process.poll()
    if exit_code is not None:
        pid_file.unlink(missing_ok=True)
        error_tail = ""
        try:
            with open(log_file_path, "r") as fh:
                lines = fh.readlines()
                error_tail = "".join(lines[-25:]).strip()
        except Exception:
            pass

        return (
            jsonify(
                {
                    "status": "failed",
                    "message": f"Agent {agent_id} exited immediately (code {exit_code}).",
                    "error_tail": error_tail,
                }
            ),
            500,
        )

    # Write PID to file so we can stop later
    pid_file.write_text(str(process.pid))

    return (
        jsonify(
            {
                "status": "started",
                "message": f"Agent {agent_id} started",
                "pid": process.pid,
            }
        ),
        200,
    )


@app.route("/api/agents/<agent_id>/stop", methods=["POST"])
@admin_required
def stop_agent(agent_id):
    """Stop a running agent by sending SIGTERM to its PID."""

    # Validate agent_id
    if agent_id not in AGENT_COMMANDS:
        return jsonify({"error": f"Unknown agent_id: {agent_id}"}), 400

    pid_file = PID_DIR / f"{agent_id}.pid"
    if not pid_file.exists():
        return (
            jsonify(
                {
                    "status": "not_running",
                    "message": f"Agent {agent_id} is not running (No PID file found).",
                }
            ),
            200,
        )

    try:
        pid = int(pid_file.read_text().strip())
        # SIGTERM = graceful shutdown signal agents while true loop will catch and exit cleanly
        os.kill(pid, signal.SIGTERM)

        # Clear Redis keys immediately so the dashboard shows Stopped without waiting for staleness
        redis_client.delete(f"agent:{agent_id}:status")
        redis_client.delete(f"agent:{agent_id}:heartbeat")

        # Clean up PID file
        pid_file.unlink(missing_ok=True)
        return (
            jsonify(
                {
                    "status": "stopped",
                    "message": f"Agent {agent_id} stopped (PID {pid}).",
                }
            ),
            200,
        )

    except ProcessLookupError:
        # PID file existed but process was already dead (crashed)
        pid_file.unlink(missing_ok=True)
        return (
            jsonify(
                {
                    "status": "not_running",
                    "message": f"Agent {agent_id} was not running (stale PID file cleaned up).",
                }
            ),
            200,
        )

    except ValueError:
        # PID file is corrupted
        pid_file.unlink(missing_ok=True)
        return (
            jsonify({"error": "Corrupted PID file - cleaned up. Try starting again."}),
            500,
        )

    except PermissionError:
        return (
            jsonify(
                {
                    "error": "Permission denied. Flask and agent must run as the same user."
                }
            ),
            500,
        )


@app.route("/api/models", methods=["GET"])
def list_models():
    """Get models filtered by agent_id and status"""

    agent_id = request.args.get("agent_id")
    status = request.args.get("status")

    if not agent_id:
        return jsonify({"status": "error", "message": "agent_id required"}), 400

    try:
        with get_db_session() as session:
            query = session.query(Model).filter_by(agent_id=agent_id)

            # Filter by status if provided
            if status == "pending":
                # Pending = not approved and not active and not rejected
                query = query.filter_by(
                    is_approved=False, is_active=False, is_rejected=False
                )
            elif status == "active":
                query = query.filter_by(is_active=True)
            elif status == "approved":
                query = query.filter_by(is_approved=True, is_active=False)

            models = query.order_by(Model.created_at.desc()).all()

            # Convert to dicts (ORM -> JSON-serializable)
            models_data = []
            for model in models:
                models_data.append(
                    {
                        "id": model.id,
                        "agent_id": model.agent_id,
                        "version": model.version,
                        "model_type": model.model_type,
                        "accuracy": float(model.accuracy),
                        "macro_f1": float(model.macro_f1),
                        "recall_per_class": model.recall_per_class,
                        "precision_per_class": model.precision_per_class,
                        "training_duration_seconds": model.training_duration_seconds,
                        "is_active": model.is_active,
                        "is_approved": model.is_approved,
                        "created_at": (
                            model.created_at.isoformat() if model.created_at else None
                        ),
                    }
                )

            return jsonify(
                {"status": "success", "models": models_data, "count": len(models_data)}
            )

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/models/<int:model_id>", methods=["GET"])
def get_model(model_id):
    """Get single model by ID"""
    try:

        session = get_session()
        model = session.query(Model).filter_by(id=model_id).first()

        if not model:
            return jsonify({"status": "error", "message": "Model not found"}), 404

        model_dict = {
            "id": model.id,
            "agent_id": model.agent_id,
            "version": model.version,
            "accuracy": float(model.accuracy),
            "macro_f1": float(model.macro_f1),
            "recall_per_class": model.recall_per_class,
            "precision_per_class": model.precision_per_class,
            "training_duration_seconds": model.training_duration_seconds,
            "is_active": model.is_active,
            "is_approved": model.is_approved,
            "created_at": model.created_at.isoformat() if model.created_at else None,
        }

        return jsonify({"status": "success", "model": model_dict})

    except Exception as e:
        app.logger.error(f"Error fetching model: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/models/<int:model_id>/approve", methods=["POST"])
def approve_model(model_id):
    """Analyst approves a pending model"""
    try:
        data = request.json
        analyst_id = data.get("analyst_id")

        if not analyst_id:
            return jsonify({"status": "error", "message": "analyst_id required"}), 400

        with get_db_session() as session:
            model = session.query(Model).filter_by(id=model_id).first()

            if not model:
                return jsonify({"status": "error", "message": "Model not found"}), 404

            if model.is_approved:
                return (
                    jsonify(
                        {"status": "error", "message": "Model is already approved"}
                    ),
                    400,
                )

            # Update model
            model.is_approved = True
            model.approved_by = analyst_id
            model.approved_at = datetime.now(timezone.utc)
            session.commit()

            app.logger.info(f"Model {model_id} approved by {analyst_id}")

            return jsonify(
                {"status": "success", "message": f"Model {model_id} approved"}
            )

    except Exception as e:
        app.logger.error(f"Error approving model: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/models/<int:model_id>/reject", methods=["POST"])
def reject_model(model_id):
    """Analyst rejects a pending model"""
    try:
        data = request.json
        analyst_id = data.get("analyst_id")
        reason = data.get("reason", "")

        if not analyst_id:
            return jsonify({"status": "error", "message": "analyst_id required"}), 400

        with get_db_session() as session:
            model = session.query(Model).filter_by(id=model_id).first()

            if not model:
                return jsonify({"status": "error", "message": "Model not found"}), 404

            if model.is_active:
                return (
                    jsonify(
                        {"status": "error", "message": "Cannot reject an active model"}
                    ),
                    400,
                )

            # Mark as rejected
            model.is_rejected = True
            model.rejected_by = analyst_id
            model.rejected_at = datetime.now(timezone.utc)
            model.rejection_reason = reason
            session.commit()

            app.logger.info(f"Model {model_id} rejected by {analyst_id}: {reason}")

            return jsonify(
                {"status": "success", "message": f"Model {model_id} rejected"}
            )

    except Exception as e:
        app.logger.error(f"Error rejecting model: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/models/<int:model_id>/deploy", methods=["POST"])
def deploy_model(model_id):
    """Deploy an approved model (hot-reload agent)"""
    try:
        from data.models.model_prom_workflow import ModelPromotionWorkflow
        from agents.agent_factory import get_agent

        data = request.json
        analyst_id = data.get("analyst_id")

        if not analyst_id:
            return jsonify({"status": "error", "message": "analyst_id required"}), 400

        with get_db_session() as session:
            model = session.query(Model).filter_by(id=model_id).first()

            if not model:
                return jsonify({"status": "error", "message": "Model not found"}), 404

            if not model.is_approved:
                return (
                    jsonify(
                        {
                            "status": "error",
                            "message": "Model must be approved before deployment",
                        }
                    ),
                    400,
                )

            # Find and deactivate current active model
            old_active = (
                session.query(Model)
                .filter_by(agent_id=model.agent_id, is_active=True)
                .first()
            )

            if old_active:
                old_active.is_active = False
                app.logger.info(f"Deactivated {old_active.version}")

            # Activate new model
            model.is_active = True
            session.commit()
            app.logger.info(f"Activated {model.version}")

            # Store these values before closing session
            model_id_local = model.id
            agent_id_local = model.agent_id
            model_path_local = model.model_path
            version_local = model.version

        # Hot-reload: Call agent.load_model() OUTSIDE the session context
        try:
            agent = get_agent(agent_id_local)
            agent.load_model(model_path_local)
            app.logger.info(
                f"✅ Hot-reloaded agent {agent_id_local} with model {version_local}"
            )
        except Exception as e:
            app.logger.error(f"❌ Failed to hot-reload agent: {e}")
            # Rollback if hot-reload fails
            with get_db_session() as session:
                model = session.query(Model).filter_by(id=model_id_local).first()
                if model:
                    model.is_active = False
                    old_active = (
                        session.query(Model)
                        .filter(
                            Model.agent_id == agent_id_local, Model.id != model_id_local
                        )
                        .order_by(Model.training_date.desc())
                        .first()
                    )
                    if old_active:
                        old_active.is_active = True
                    session.commit()
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": f"Failed to hot-reload agent: {str(e)}",
                    }
                ),
                500,
            )

        return jsonify(
            {
                "status": "success",
                "message": f"Model {version_local} deployed successfully",
            }
        )

    except Exception as e:
        app.logger.error(f"Error deploying model: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/edr-agents", methods=["GET"])
@login_required
def get_edr_agents():
    """Get list of all EDR endpoint agents (Windows/Linux)"""
    session = get_session()

    agents = session.query(Agent).all()

    # Separate by OS type for dashboard
    response = {
        "windows": [],
        "linux": [],
        "summary": {
            "total": len(agents),
            "online": sum(1 for a in agents if a.status == "online"),
            "offline": sum(1 for a in agents if a.status == "offline"),
            "error": sum(1 for a in agents if a.status == "error")
        }
    }

    for agent in agents:
        agent_data = {
            "id": str(agent.id),
            "agent_id": agent.agent_id,
            "hostname": agent.hostname,
            "os_type": agent.os_type,
            "os_version": agent.os_version,
            "agent_version": agent.agent_version,
            "status": agent.status,
            "ip_address": agent.ip_address,
            "last_heartbeat": agent.last_heartbeat.isoformat(),
            "created_at": agent.created_at.isoformat(),
            "is_online": agent.agent_id in ACTIVE_AGENTS,
        }

        if agent.os_type == "windows":
            response["windows"].append(agent_data)
        elif agent.os_type == "linux":
            response["linux"].append(agent_data)
    
    return jsonify(response), 200

@app.route("/api/edr-agents/<agent_id>/telemetry", methods=["GET"])
@login_required
def get_edr_agent_telemetry(agent_id):
    """Get recent telemetry from EDR endpoint agent"""
    session = get_session()

    limit = request.args.get("limit", 100, type=int)
    event_type = request.args.get("event_type", None) # "process", "network", "file"

    agent = session.query(Agent).filter_by(agent_id=agent_id).first()
    if not agent:
        return jsonify({"error": "EDR agent not found"}), 404
    
    query = session.query(TelemetryEvent).filter_by(agent_id=agent.id)
    if event_type:
        query = query.filter_by(event_type=event_type)

    events = query.order_by(TelemetryEvent.timestamp.desc()).limit(limit).all()

    return jsonify([{
        "id": str(event.id),
        "event_type": event.event_type,
        "event_subtype": event.event_subtype,
        "timestamp": event.timestamp.isoformat(),
        "severity": event.severity,
        "data": event.event_data, # Simply json string
    } for event in events ])

@app.route("/api/edr-agents/<agent_id>/actions", methods=["POST"])
@login_required
def dispatch_edr_agent_action(agent_id):
    """Dispatch an action to EDR endpoint agent"""
    session = get_session()

    data = request.get_json()
    action_type = data.get("action_type")
    action_params = data.get("action_params", {})

    if not action_type:
        return jsonify({"error": "action_type is required"}), 400
    
    try:
        action_id = dispatch_action_to_agent(agent_id, action_type, action_params)
        return jsonify({
            "action_id": action_id,
            "status": "dispatched",
            "agent_id": agent_id,
        }), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 404

@app.route("/api/edr-agents/<agent_id>/actions", methods=["GET"])
@login_required
def get_edr_agent_actions(agent_id):
    """Get action history/status for EDR endpoint agent"""
    session = get_session()

    agent = session.query(Agent).filter_by(agent_id=agent_id).first()
    if not agent:
        return jsonify({"error": "EDR agent not found"}), 404

    actions = session.query(AgentAction).filter_by(agent_id=agent.id).order_by(AgentAction.created_at.desc()).all()

    return jsonify([{
        "id": str(action.id),
        "action_type": action.action_type,
        "status": action.status, # "pending", "sent", "executed", "failed"
        "created_at": action.created_at.isoformat(),
        "sent_at": action.sent_at.isoformat() if action.sent_at else None,
        "executed_at": action.executed_at.isoformat() if action.executed_at else None,
        "result": action.result_message
    } for action in actions])

@app.route("/api/edr-agents/detections", methods=["GET"])
@login_required
def get_edr_detections():
    """Get high-conffidence detections for analyst review queue"""
    session = get_session()
    
    limit = request.args.get("limit", 50, type=int)
    os_type = request.args.get("os_type", None) # "windows", "linux"
    min_confidence = request.args.get("min_confidence", 0.7, type=float)

    # Get events from agents
    query = session.query(TelemetryEvent).join(Agent)

    if os_type:
        query = query.filter(Agent.os_type == os_type)

    events = query.order_by(TelemetryEvent.timestamp.desc()).all()

    # Filter by confidence scores
    results = []
    for event in events:
        confidence = _telemetry_confidence(event)
        if confidence >= min_confidence:
            results.append({
                "id": str(event.id),
                "agent_id": event.agent.agent_id,
                "hostname": event.agent.hostname,
                "os_type": event.agent.os_type,
                "event_type": event.event_type,
                "event_subtype": event.event_subtype,
                "severity": event.severity,
                "timestamp": event.timestamp.isoformat(),
                "confidence": confidence,
                "source": "edr_telemetry",
                "data": event.event_data,
            })

    return jsonify(results[:limit])


@app.route("/api/edr-agents/summary", methods=["GET"])
@login_required
def get_edr_summary():
    """Get 24h EDR telemetry and detection summary counts."""
    session = get_session()

    hours = request.args.get("hours", 24, type=int)
    min_confidence = request.args.get("min_confidence", 0.45, type=float)
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    telemetry_threats = [
        classification
        for classification in (
            session.query(ThreatClassification)
            .filter(ThreatClassification.timestamp >= since)
            .order_by(ThreatClassification.timestamp.desc())
            .all()
        )
        if _classification_origin(classification) == "edr_telemetry"
    ]

    total_events = len(telemetry_threats)
    high_conf_detections = sum(
        1
        for classification in telemetry_threats
        if float(classification.ensemble_confidence or 0) >= min_confidence
    )

    return jsonify({
        "hours": hours,
        "total_events": total_events,
        "high_conf_detections": high_conf_detections,
        "min_confidence": min_confidence,
    })

@app.route("/api/edr-agents/search", methods=["POST"])
@login_required
def search_edr_telemety():
    """Cross-endpoint EDR telemetry search"""
    session = get_session()

    data = request.get_json()
    event_type = data.get("event_type")
    hostname = data.get("hostname")
    os_type = data.get("os_type")
    limit = data.get("limit", 100)

    query = session.query(TelemetryEvent)

    if event_type:
        query = query.filter_by(event_type=event_type)

    if hostname:
        query = query.join(Agent).filter(Agent.hostname.ilike(f"%{hostname}%"))

    if os_type:
        query = query.join(Agent).filter(Agent.os_type == os_type)

    events = query.order_by(TelemetryEvent.timestamp.desc()).limit(limit).all()

    return jsonify([{
        "id": str(event.id),
        "agent_id": event.agent.agent_id,
        "hostname": event.agent.hostname,
        "os_type": event.agent.os_type,
        "event_type": event.event_type,
        "event_subtype": event.event_subtype,
        "timestamp": event.timestamp.isoformat(),
        "severity": event.severity,
        "data": event.event_data,
    } for event in events])

@app.route("/api/assets")
@login_required
def get_assets():
    """Get all assets from database"""
    session = get_session()
    try:
        assets = session.query(Asset).all()
        assets_data = [
            {
                "id": asset.id,
                "name": asset.name,
                "type": asset.type,
                "risk_level": asset.risk_level,
            }
            for asset in assets
        ]
        return jsonify({"assets": assets_data})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()


@app.route("/api/vulnerabilities")
@login_required
def get_vulnerabilities():
    """Get all vulnerabilities from database"""
    session = get_session()
    try:
        vulns = session.query(Vulnerability).all()
        vulns_data = [
            {
                "id": vuln.id,
                "name": vuln.name,
                "description": vuln.description,
                "severity": vuln.severity,
            }
            for vuln in vulns
        ]
        return jsonify({"vulnerabilities": vulns_data})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()


@app.route("/api/asset-vulnerabilities")
@login_required
def get_asset_vulnerabilities():
    """Get all asset-vulnerability relationships"""
    session = get_session()
    try:
        links = (
            session.query(
                AssetVulnerability.asset_id,
                AssetVulnerability.vulnerability_id,
                Asset.name.label("asset_name"),
                Asset.type.label("asset_type"),
                Asset.risk_level,
                Vulnerability.name.label("vuln_name"),
                Vulnerability.description.label("vuln_description"),
                Vulnerability.severity,
            )
            .join(Asset, AssetVulnerability.asset_id == Asset.id)
            .join(
                Vulnerability, AssetVulnerability.vulnerability_id == Vulnerability.id
            )
            .all()
        )

        links_data = [
            {
                "asset_id": link.asset_id,
                "asset_name": link.asset_name,
                "asset_type": link.asset_type,
                "risk_level": link.risk_level,
                "vulnerability_id": link.vulnerability_id,
                "vulnerability_name": link.vuln_name,
                "description": link.vuln_description,
                "severity": link.severity,
            }
            for link in links
        ]
        return jsonify({"asset_vulnerabilities": links_data})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()


@app.route("/api/threats/recent")
@login_required
def recent_threats():
    """Get recent threat classifications from database"""
    session = get_session()
    try:
        # Extract pagination parameters with query string
        page = request.args.get("page", 1, type=int)
        page_size = request.args.get("page_size", 20, type=int)

        # Validate pagination parameters
        if page < 1:
            page = 1
        if page_size > 100:
            page_size = 100  # Max 100 per request to prevent resource abuse
        if page_size < 1:
            page_size = 20

        # Calculate database offset
        offset = (page - 1) * page_size

        # Get total threat count BEFORE applying limits
        total_count = session.query(ThreatClassification).count()

        # Main query with OFFSET and LIMIT instead of just LIMIT
        threats = (
            session.query(
                ThreatClassification,
                Analyst.name,  # Get analyst name if reviewed
                Asset.name.label("asset_name"),
                Asset.type.label("asset_type"),
                Vulnerability.name.label("vuln_name"),
                Vulnerability.description.label("vuln_description"),
            )
            .outerjoin(Asset, ThreatClassification.asset_id == Asset.id)
            .outerjoin(
                Vulnerability, ThreatClassification.vulnerability_id == Vulnerability.id
            )
            .outerjoin(
                Analyst, ThreatClassification.reviewed_by_id == Analyst.id
            )  # Left join so non-reviewed show null
            .order_by(ThreatClassification.id.desc())
            .offset(offset)
            .limit(page_size)
            .all()
        )

        threats_data = [
            {
                "id": tc[0].id,
                "threat_type": tc[0].threat_type,
                "severity": tc[0].severity,
                "risk_score": round(tc[0].risk_score, 2) if tc[0].risk_score else 0,
                "exploitability_score": (
                    round(tc[0].exploitability_score, 2)
                    if tc[0].exploitability_score
                    else 0
                ),
                "impact_score": (
                    round(tc[0].impact_score, 2) if tc[0].impact_score else 0
                ),
                "mitre_tactic": tc[0].mitre_tactic,
                "confidence_score": getattr(tc[0], "ensemble_confidence", None),
                "reviewed_by_analyst": getattr(tc[0], "reviewed_by_analyst", False),
                "reviewed_by_name": tc[1],
                "asset_name": tc[2],
                "asset_type": tc[3],
                "vulnerability_name": tc[4],
                "vulnerability_description": tc[5],
                "origin": _classification_origin(tc[0]),
            }
            for tc in threats
        ]
        # Sort by severity levels before sending to front end
        severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, None: 0}
        threats_data.sort(
            key=lambda x: (severity_order.get(x["severity"], 0), x["risk_score"]),
            reverse=True,
        )

        # Calculate pagination metadata
        total_pages = (total_count + page_size - 1) // page_size  # Ceiling division
        has_next = page < total_pages
        has_prev = page > 1

        return jsonify(
            {
                "threats": threats_data,
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total_count": total_count,
                    "total_pages": total_pages,
                    "has_next": has_next,
                    "has_prev": has_prev,
                },
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()


@app.route("/api/threats/<int:threat_id>/review", methods=["PUT"])
@login_required
def review_recent_threat(threat_id):
    """Mark a recent threat as reviewed by analyst and feed to ML models for training."""
    data = request.json or {}
    threat_type = (data.get("threat_type") or "").strip()
    analyst_notes = (data.get("analyst_notes") or "").strip()
    action = (data.get("action") or "confirm").strip().lower()
    analyst_id = int(get_jwt_identity())

    if not threat_type:
        return jsonify({"success": False, "message": "Threat type is required."}), 400

    session = get_session()
    try:
        classification = session.get(ThreatClassification, threat_id)
        if not classification:
            return jsonify({"success": False, "message": "Threat not found."}), 404

        # Determine if analyst confirmed model's prediction or changed it
        original_threat_type = classification.threat_type
        is_confirmed = threat_type == original_threat_type

        # Update threat classification
        classification.threat_type = threat_type
        classification.reviewed_by_id = analyst_id
        classification.reviewed_by_analyst = True

        # Add to training dataset so ML models learn from this review
        # Whether confirmed or changed, analyst feedback strengthens model confidence
        vulnerability = (
            session.query(Vulnerability)
            .filter_by(id=classification.vulnerability_id)
            .first()
        )
        vuln_description = vulnerability.description if vulnerability else ""

        # Build notes indicating if this is confirmation or correction
        if is_confirmed:
            # Confirmation of model's original prediction - increases confidence
            feedback_type = "Confirmed"
        else:
            # Correction/change - model needs to learn the right classification
            feedback_type = f"Corrected from {original_threat_type}"

        notes = f"{feedback_type}: {analyst_notes}" if analyst_notes else feedback_type

        training = AnalystCuratedTrainingData(
            vulnerability_description=vuln_description,
            analyst_corrected_threat_type=threat_type,
            analyst_notes=notes,  # Pass analyst reasoning to training data
            threat_severity=classification.severity,
            analyst_id=analyst_id,
        )
        session.add(training)
        session.commit()

        message = (
            "Confirmed - adds to training data to increase model confidence."
            if is_confirmed
            else f"Changed to {threat_type} - model learns the correction."
        )

        return jsonify(
            {
                "success": True,
                "message": message,
                "threat_id": threat_id,
                "threat_type": threat_type,
                "analyst_confirmed": is_confirmed,
            }
        )
    except Exception as e:
        session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        session.close()


@app.route("/api/anomalies")
@login_required
def get_anomalies():
    """Get detected anomalies from threat hunting results."""
    threat_hunter = ThreatHunterAgent(agent_id="hunter_api", verbose=False)

    try:
        with get_db_session() as session:
            # Get recent threats
            classifications = (
                session.query(ThreatClassification)
                .order_by(ThreatClassification.timestamp.desc())
                .limit(50)
                .all()
            )

            threat_dicts = [
                {
                    "id": c.id,
                    "threat_type": c.threat_type,
                    "severity": c.severity,
                    "risk_score": c.risk_score,
                    "mitre_tactics": (
                        c.mitre_tactic.split(",") if c.mitre_tactic else []
                    ),
                }
                for c in classifications
            ]

            # Hunt threats (includes anomaly detection)
            hunting_results = threat_hunter.hunt_threats(threat_dicts)

            return jsonify(
                {
                    "anomalies": hunting_results["anomalies_detected"],
                    "count": len(hunting_results["anomalies_detected"]),
                    "total_threats_analyzed": hunting_results["threats_analyzed"],
                }
            )
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/patterns")
@login_required
def get_patterns():
    """Get detected attack patterns from threat hunting."""
    threat_hunter = ThreatHunterAgent(agent_id="hunter_api", verbose=False)

    try:
        with get_db_session() as session:
            # Get recent threats
            classifications = (
                session.query(ThreatClassification)
                .order_by(ThreatClassification.timestamp.desc())
                .limit(100)
                .all()
            )

            threat_dicts = [
                {
                    "id": c.id,
                    "threat_type": c.threat_type,
                    "severity": c.severity,
                    "risk_score": c.risk_score,
                    "mitre_tactics": (
                        c.mitre_tactic.split(",") if c.mitre_tactic else []
                    ),
                }
                for c in classifications
            ]

            # Hunt threats (includes pattern detection)
            hunting_results = threat_hunter.hunt_threats(threat_dicts)

            # Combine rule-based patterns and ML-detected patterns
            all_patterns = hunting_results.get(
                "patterns_detected", []
            ) + hunting_results.get("ml_detected_patterns", [])

            return jsonify(
                {
                    "patterns": all_patterns,
                    "count": len(all_patterns),
                    "rule_based_count": len(
                        hunting_results.get("patterns_detected", [])
                    ),
                    "ml_detected_count": len(
                        hunting_results.get("ml_detected_patterns", [])
                    ),
                }
            )
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/attack-paths")
@login_required
def get_attack_paths():
    """Fetch ranked attack paths with risk scores for dashboard display."""
    try:
        session = get_session()

        # Query all attack paths, join with asset names
        paths = session.query(AttackPath).all()

        if not paths:
            return jsonify({"success": True, "count": 0, "paths": []})

        # Convert to list of dicts for dashboard
        path_data = []
        for path in paths:
            # Get source and target asset names
            source_asset = (
                session.query(Asset).filter_by(id=path.source_asset_id).first()
            )
            target_asset = (
                session.query(Asset).filter_by(id=path.target_asset_id).first()
            )

            path_data.append(
                {
                    "id": path.id,
                    "source": (
                        source_asset.name
                        if source_asset
                        else f"Asset {path.source_asset_id}"
                    ),
                    "target": (
                        target_asset.name
                        if target_asset
                        else f"Asset {path.target_asset_id}"
                    ),
                    "risk_score": float(path.risk_score) if path.risk_score else 0,
                    "difficulty_score": (
                        float(path.difficulty_score) if path.difficulty_score else 5
                    ),
                    "time_to_exploit": (
                        path.time_to_exploit if path.time_to_exploit else 0
                    ),
                    "success_probability": (
                        float(path.success_probability)
                        if path.success_probability
                        else 0.5
                    ),
                    "actor_profile": (
                        path.threat_actor_profile
                        if path.threat_actor_profile
                        else "unknown"
                    ),
                }
            )

        # Sort by risk score (highest first)
        path_data.sort(key=lambda x: x["risk_score"], reverse=True)

        return jsonify(
            {
                "success": True,
                "count": len(path_data),
                "paths": path_data[:50],  # Return top 50 paths
            }
        )
    except Exception as e:
        app.logger.error(f"Error fetching attack paths: {str(e)}")
        return (
            jsonify({"success": False, "error": str(e), "count": 0, "paths": []}),
            500,
        )
    finally:
        session.close()


@app.route("/api/reviews/<int:threat_id>/decision", methods=["POST"])
@login_required
def save_review_decision(threat_id):
    data = request.json or {}
    decision = (data.get("decision") or "").strip().lower()
    final_threat_type = (data.get("final_threat_type") or "").strip()
    notes = (data.get("notes") or "").strip()
    analyst_id = int(get_jwt_identity())

    allowed = {"confirm", "false_positive", "escalate"}
    if decision not in allowed:
        return (
            jsonify({"success": False, "message": "Invalid decision."}),
            400,
        )

    if len(notes) < 10:
        return (
            jsonify(
                {"success": False, "message": "Notes must be at least 10 characters."}
            ),
            400,
        )

    if decision in {"confirm", "escalate"} and not final_threat_type:
        return (
            jsonify({"success": False, "message": "Final classification is required."}),
            400,
        )

    session = get_session()
    try:
        classification = session.get(ThreatClassification, threat_id)
        if not classification:
            return (jsonify({"success": False, "message": "Threat not found."}), 404)

        review = (
            session.query(ThreatReview)
            .filter_by(threat_classification_id=threat_id)
            .first()
        )
        if not review:
            return (
                jsonify({"success": False, "message": "Review record not found."}),
                404,
            )

        original_type = classification.threat_type or "Needs Review"

        # Decision Logic
        if decision == "false_positive":
            new_type = "False Positive"
            status = "resolved"
        elif decision == "confirm":
            new_type = final_threat_type
            status = "resolved"
        else:
            new_type = final_threat_type or "Escalated Threat"
            status = "escalated"

        classification.threat_type = new_type

        # Calculate review time
        now = datetime.now(timezone.utc)
        review_seconds = None
        if review.locked_at:
            review_seconds = int((now - review.locked_at).total_seconds())

        # Update review record
        review.status = status
        review.decision = decision
        review.original_threat_type = original_type
        review.final_threat_type = new_type
        review.notes = notes
        review.reviewer_analyst_id = analyst_id
        review.decided_at = now
        review.updated_at = now
        review.review_time_seconds = review_seconds
        review.locked_by = None  # Clear lock on decision
        review.locked_at = None
        review.lock_expires_at = None

        # Check SLA compliance
        sla_met = True
        if review.sla_deadline and now > review.sla_deadline:
            sla_met = False
            review.sla_breached = True

        # Add to training dataset
        if decision != "false_positive":
            # Get vulnerability description from relationship
            vulnerability = (
                session.query(Vulnerability)
                .filter_by(id=classification.vulnerability_id)
                .first()
            )
            vuln_description = vulnerability.description if vulnerability else ""

            training = AnalystCuratedTrainingData(
                threat_review_id=review.id,
                vulnerability_description=vuln_description,
                analyst_corrected_threat_type=new_type,
                analyst_notes=notes,  # Pass analyst reasoning to training data
                threat_severity=classification.severity,
                analyst_id=analyst_id,
            )
            review.is_training_data = True
            session.add(training)

        # Update reviewer analytics
        analytics = (
            session.query(ReviewerAnalytics).filter_by(analyst_id=analyst_id).first()
        )
        if not analytics:
            analytics = ReviewerAnalytics(
                analyst_id=analyst_id,
                total_reviews=0,
                confirmed_count=0,
                false_positive_count=0,
                escalated_count=0,
                total_review_time_seconds=0,
                avg_review_seconds=0,
                sla_compliant=0,
                sla_breached=0,
                sla_compliance_pct=0.0,
            )
            session.add(analytics)

        analytics.total_reviews += 1
        if decision == "confirm":
            analytics.confirmed_count += 1
        elif decision == "false_positive":
            analytics.false_positive_count += 1
        else:
            analytics.escalated_count += 1

        if review_seconds:
            analytics.total_review_time_seconds += review_seconds
            analytics.avg_review_seconds = (
                analytics.total_review_time_seconds / analytics.total_reviews
            )

        if sla_met:
            analytics.sla_compliant += 1
        else:
            analytics.sla_breached += 1

        if analytics.total_reviews > 0:
            analytics.sla_compliance_pct = (
                analytics.sla_compliant / analytics.total_reviews
            ) * 100

        analytics.last_review_at = now
        analytics.updated_at = now

        session.commit()

        return jsonify(
            {
                "success": True,
                "message": "Review save.",
                "new_threat_type": new_type,
                "review_time_seconds": review_seconds,
                "sla_met": sla_met,
            }
        )

    except Exception as e:
        session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        session.close()


@app.route("/api/reviews/pending", methods=["GET"])
@login_required
def get_pending_reviews():
    try:
        with get_db_session() as session:
            rows = (
                session.query(
                    ThreatClassification.id,
                    ThreatClassification.threat_type,
                    ThreatClassification.severity,
                    ThreatClassification.risk_score,
                    Asset.name.label("asset_name"),
                    Vulnerability.name.label("vulnerability_name"),
                    ThreatClassification.timestamp.label("created_at"),
                )
                .join(Asset, ThreatClassification.asset_id == Asset.id)
                .join(
                    Vulnerability,
                    ThreatClassification.vulnerability_id == Vulnerability.id,
                )
                .filter(ThreatClassification.threat_type == "Needs Review")
                .order_by(ThreatClassification.id.desc())
                .all()
            )

            items = [
                {
                    "id": r.id,
                    "threat_type": r.threat_type,
                    "severity": r.severity,
                    "risk_score": round(r.risk_score or 0, 2),
                    "asset_name": r.asset_name,
                    "vulnerability_name": r.vulnerability_name,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                    "origin": "log_ingestion",
                }
                for r in rows
            ]

            return jsonify({"items": items})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/reviews/<int:threat_id>", methods=["GET"])
@login_required
def get_review_context(threat_id):
    session = get_session()
    try:
        row = (
            session.query(
                ThreatClassification.id,
                ThreatClassification.threat_type,
                ThreatClassification.severity,
                ThreatClassification.risk_score,
                ThreatClassification.mitre_tactic,
                ThreatClassification.ensemble_confidence,
                Asset.name.label("asset_name"),
                Asset.type.label("asset_type"),
                Vulnerability.name.label("vulnerability_name"),
                Vulnerability.description.label("vulnerability_description"),
            )
            .outerjoin(Asset, ThreatClassification.asset_id == Asset.id)
            .outerjoin(
                Vulnerability, ThreatClassification.vulnerability_id == Vulnerability.id
            )
            .filter(ThreatClassification.id == threat_id)
            .first()
        )

        if not row:
            return jsonify({"success": False, "message": "Threat not found."}), 404

        return jsonify(
            {
                "id": row.id,
                "threat_type": row.threat_type,
                "severity": row.severity,
                "risk_score": round(row.risk_score or 0, 2),
                "ensemble_confidence": row.ensemble_confidence,
                "mitre_tactic": row.mitre_tactic,
                "asset_name": row.asset_name,
                "asset_type": row.asset_type,
                "vulnerability_name": row.vulnerability_name,
                "vulnerability_description": row.vulnerability_description,
                "origin": (
                    "edr_telemetry"
                    if row.asset_name is None and row.vulnerability_name is None
                    else "log_ingestion"
                ),
            }
        )
    finally:
        session.close()


@app.route("/api/reviews/<int:threat_id>/claim", methods=["POST"])
@login_required
def claim_review(threat_id):
    """Analyst claims a threat for review, preventing double handling."""
    analyst_id = int(get_jwt_identity())

    session = get_session()
    try:
        review = (
            session.query(ThreatReview)
            .filter_by(threat_classification_id=threat_id)
            .first()
        )

        if not review:
            return jsonify({"success": False, "message": "Review not found."}), 404

        if review.claimed_by and review.claimed_by != analyst_id:
            other_analyst = session.get(Analyst, review.claimed_by).name
            return (
                jsonify(
                    {
                        "success": False,
                        "message": f"This threat is already claimed by {other_analyst}.",
                    }
                ),
                409,
            )

        # Claim it
        review.claimed_by = analyst_id
        review_claimed_at = datetime.now(timezone.utc)
        session.commit()

        return jsonify({"success": True, "message": "Threat claimed."})
    except Exception as e:
        session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        session.close()


@app.route("/api/reviews/<int:threat_id>/lock", methods=["POST"])
@login_required
def lock_threat(threat_id):
    """Lock threat while analyst has modal open (10 min timeout)."""
    analyst_id = int(get_jwt_identity())

    session = get_session()
    try:
        review = (
            session.query(ThreatReview)
            .filter_by(threat_classification_id=threat_id)
            .first()
        )

        if not review:
            return jsonify({"success": False, "message": "Review not found."}), 404

        # Check if locked by someone else
        if review.locked_by and review.locked_by != analyst_id:
            if review.lock_expires_at > datetime.now(timezone.utc):
                other = session.get(Analyst, review.locked_by).name
                minutes_left = (
                    review.lock_expires_at - datetime.now(timezone.utc)
                ).total_seconds() / 60
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": f"Threat is locked by {other} for {minutes_left:.0f} more minutes.",
                        }
                    ),
                    409,
                )

        # Lock it
        now = datetime.now(timezone.utc)
        review.locked_by = analyst_id
        review.locked_at = now
        review.lock_expires_at = now + timedelta(minutes=10)
        session.commit()

        return jsonify({"success": True, "message": "Threat locked."})
    except Exception as e:
        session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        session.close()


@app.route("/api/reviews/<int:threat_id>/unlock", methods=["POST"])
@login_required
def unlock_threat(threat_id):
    """Release lock when modal closes."""
    analyst_id = int(get_jwt_identity())

    session = get_session()
    try:
        review = (
            session.query(ThreatReview)
            .filter_by(threat_classification_id=threat_id)
            .first()
        )

        if not review or review.locked_by != analyst_id:
            return jsonify({"success": False, "message": "Not locked by you."}), 403

        review.locked_by = None
        review.locked_at = None
        review.lock_expires_at = None
        session.commit()

        return jsonify({"success": True, "message": "Lock Released."})
    except Exception as e:
        session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        session.close()


@app.route("/api/reviews/<int:threat_id>/force-unlock", methods=["POST"])
@admin_required
def force_unlock_threat(threat_id):
    """Admin force-unlocks stuck threats (admin only)."""

    session = get_session()
    try:
        review = (
            session.query(ThreatReview)
            .filter_by(threat_classification_id=threat_id)
            .first()
        )

        if not review:
            return jsonify({"success": False, "message": "Review not found."}), 404

        review.locked_by = None
        review.locked_at = None
        review.lock_expires_at = None
        session.commit()

        return jsonify({"success": True, "message": "Lock force-released."})
    except Exception as e:
        session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        session.close()


@app.route("/api/analytics/reviewers", methods=["GET"])
@login_required
def get_reviewer_analytics():
    """Return all reviewer performance metrics."""
    session = get_session()
    try:
        analytics = (
            session.query(ReviewerAnalytics)
            .order_by(ReviewerAnalytics.total_reviews.desc())
            .all()
        )

        items = [
            {
                "analyst_id": a.analyst_id,
                "analyst_name": session.get(Analyst, a.analyst_id).name,
                "total_reviews": a.total_reviews,
                "confirmed": a.confirmed_count,
                "false_positives": a.false_positive_count,
                "escalated": a.escalated_count,
                "avg_review_minutes": (
                    round(a.avg_review_seconds / 60, 1) if a.avg_review_seconds else 0
                ),
                "sla_compliance_pct": round(a.sla_compliance_pct, 1),
                "last_review": (
                    a.last_review_at.isoformat() if a.last_review_at else None
                ),
            }
            for a in analytics
        ]

        return jsonify({"items": items})
    finally:
        session.close()


@app.route("/api/logs")
@login_required
def get_logs():
    try:
        with get_db_session() as session:
            logs = (
                session.query(LogEvent)
                .order_by(LogEvent.timestamp.desc())
                .limit(200)
                .all()
            )
            logs_data = [
                {
                    "id": log.id,
                    "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                    "source": log.source,
                    "level": log.level,
                    "message": log.message,
                    "data": json.loads(log.data) if log.data else None,
                }
                for log in logs
            ]
            return jsonify({"logs": logs_data, "count": len(logs_data)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/upload_log", methods=["POST"])
@login_required
def upload_log():
    if "logfile" not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files["logfile"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    # Security: sanitise the filename to prevent path traversal
    filename = f"{int(time.time())}_{secure_filename(file.filename)}"

    # Security: Allow only certain file extensions
    ALLOWED_EXTENSIONS = {".json", ".csv", ".log", ".txt"}
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({"error": f"File type '{ext}' not supported"}), 400

    save_path = os.path.join("test_logs", filename)
    file.save(save_path)
    # Publish message to ingest the log
    message_bus.publish("log_uploaded", {"path": save_path})
    Agent1LogIngestion([{"type": "file", "path": save_path}]).run()

    return jsonify(
        {
            "status": "success",
            "message": f"File '{filename}' uploaded and ingested",
            "filename": filename,
        }
    )


@app.route("/api/analysts")
@admin_required
def get_analysts():
    """Get all analysts."""
    manager = AnalystManager()
    analysts = manager.get_all_analysts()
    return jsonify({"analyst": analysts})


@app.route("/api/analysts", methods=["POST"])
@admin_required
def add_analyst():
    """Add new analyst."""
    data = request.json
    manager = AnalystManager()
    result = manager.add_analyst(
        name=data["name"],
        email=data["email"],
        role=data.get("role", "analyst"),
        notification_threshold=data.get("notification_threshold", "medium"),
    )
    return jsonify(result)


@app.route("/api/analysts/<int:analyst_id>", methods=["PUT"])
@admin_required
def update_analyst(analyst_id):
    """Update analyst."""
    data = request.json
    manager = AnalystManager()
    result = manager.update_analyst(analyst_id, **data)
    return jsonify(result)


@app.route("/api/analysts/<int:analyst_id>", methods=["DELETE"])
@admin_required
def remove_analyst(analyst_id):
    """Remove analyst."""
    manager = AnalystManager()
    result = manager.remove_analyst(analyst_id)
    return jsonify(result)


@app.route("/api/analysts/<int:analyst_id>/reset-password", methods=["POST"])
@admin_required
def reset_analyst_password(analyst_id):
    """Reset an analyst's password to the default and force change on next login."""
    session = get_session()
    try:
        analyst = session.query(Analyst).filter_by(id=analyst_id).first()
        if not analyst:
            return jsonify({"success": False, "message": "Analyst not found"}), 404

        analyst.password_hash = generate_password_hash("ChangeMe123!")
        analyst.must_change_password = True
        session.commit()

        return jsonify(
            {
                "success": True,
                "message": f"Password reset for {analyst.name}. They will be prompted to change it on next login.",
            }
        )
    finally:
        session.close()


@app.route("/api/response-actions")
@login_required
def get_response_actions():
    """Get recent response actions."""
    session = get_session()
    try:
        actions = (
            session.query(ResponseAction)
            .order_by(ResponseAction.executed_at.desc())
            .limit(50)
            .all()
        )

        return jsonify(
            [
                {
                    "id": a.id,
                    "threat_id": a.threat_id,
                    "action_type": a.action_type,
                    "action_status": a.action_status,
                    "automated": a.automated,
                    "executed_by": a.executed_by,
                    "executed_at": a.executed_at.isoformat(),
                    "details": a.details,
                    "result_message": a.result_message,
                }
                for a in actions
            ]
        )
    finally:
        session.close()


@app.route("/api/email-notifications")
@login_required
def get_email_notifications():
    """Get email notification history."""
    session = get_session()
    try:
        notifications = (
            session.query(EmailNotification)
            .order_by(EmailNotification.sent_at.desc())
            .limit(100)
            .all()
        )

        return jsonify(
            [
                {
                    "id": n.id,
                    "analyst_name": n.analyst.name if n.analyst else "Unknown",
                    "threat_id": n.threat_id,
                    "subject": n.subject,
                    "email_template": n.email_template,
                    "sent_at": n.sent_at.isoformat(),
                    "delivery_status": n.delivery_status,
                    "error_message": n.error_message,
                }
                for n in notifications
            ]
        )
    finally:
        session.close()


@app.route("/api/notification-stats")
@login_required
def get_notification_stats():
    """Get notification statistics."""
    manager = AnalystManager()
    stats = manager.get_notification_stats()
    return jsonify(stats)


# SLA Scheduler
SLA_THRESHOLDS = {
    "critical": 1,  # 1 Hour
    "high": 4,  # 4 Hours
    "medium": 24,  # 24 Hours
    "low": 72,  # 72 Hours
}


def calculate_sla_deadline(severity):
    """Return datetime SLA deadline based on severity."""
    hours = SLA_THRESHOLDS.get(severity.lower(), 24)
    return datetime.now(timezone.utc) + timedelta(hours=hours)


def check_and_escalate_overdue_threats():
    """Run every 5 minutes: check for overdue reviews and escalate."""

    session = get_session()
    try:
        now = datetime.now(timezone.utc)

        # Find threats with breached SLAs
        breached_threats = (
            session.query(ThreatReview)
            .filter(
                ThreatReview.sla_deadline < now,  # Deadline passed
                ThreatReview.escalation_notified_at == None,  # Not yet escalated
                ThreatReview.status == "pending",  # Still pending
            )
            .all()
        )

        for threat_review in breached_threats:
            # Get threat classification for context
            classification = (
                session.query(ThreatClassification)
                .filter_by(id=threat_review.threat_classification_id)
                .first()
            )

            if not classification:
                continue

            # Calculate how long overdue
            minutes_overdue = (now - threat_review.sla_deadline).total_seconds() / 60

            print(
                f"[SLA] Threat {threat_review.threat_id} is {minutes_overdue:.0f}minutes overdue"
            )

            # Find senior analyst to escalate to
            senior = (
                session.query(Analyst)
                .filter(
                    Analyst.active == True,
                    Analyst.role.in_(["senior_analyst", "manager", "admin"]),
                )
                .first()
            )

            if senior:
                threat_review.escalated_to_analyst_id = senior.id

            threat_review.escalation_notes = (
                f"⚠️ SLA BREACHED - Overdue by {minutes_overdue:.0f} minutes.\n"
                f"Threat Type: {classification.threat_type}\n"
                f"Risk Score: {classification.risk_score:.1f}\n"
                f"SLA Deadline: {threat_review.sla_deadline.isoformat()}\n"
                f"Auto-escalated to: {senior.name if senior else 'Manager'}"
            )
            threat_review.escalation_notified_at = now

            # Send email to supervisor/manager
            try:
                send_escalation_email(
                    threat_id=threat_review.threat_id,
                    threat_type=classification.threat_type,
                    minutes_overdue=minutes_overdue,
                    supervisor_email=(
                        senior.email
                        if senior
                        else os.getenv(
                            "DEFAULT_ESCALATION_EMAIL",
                            os.getenv(
                                "MAIL_DEFAULT_SENDER", "admin@threatdefense.local"
                            ),
                        )
                    ),
                )
            except Exception as e:
                print(f"[ERROR] Failed to send escalation email: {e}")

            # Create crititcal alert comment
            threat_review.comments = threat_review.comments or ""
            threat_review.comments += (
                f"\n\n[SYSTEM - {now.isoformat()}] "
                f"🚨 SLA Escalation Alert: This threat has exceeded its SLA deadline by "
                f"{minutes_overdue:.0f} minutes and has been escalated to {senior.name if senior else 'management'}. "
                f"Immediate action required."
            )

            session.commit()
            print(f"✅ Escalated Threat {threat_review.threat_id}")

        return len(breached_threats)

    except Exception as e:
        session.rollback()
        print(f"[ERROR] SLA check failed: {e}")
    finally:
        session.close()


def send_escalation_email(threat_id, threat_type, minutes_overdue, supervisor_email):
    """Send SLA breach escalation email."""
    from flask_mail import Mail, Message

    mail = Mail(app)

    # For demo/project
    demo_email = os.getenv("DEMO_EMAIL")
    recipient_email = demo_email if demo_email else supervisor_email

    msg = Message(
        subject=f"🚨 URGENT: SLA Breached - Threat {threat_id}",
        recipients=[recipient_email],
        html=f"""
        <html>
            <body style="font-family: Arial; background-color: #f5f5f5; padding: 20px;">
                <div style="background-color: #fff; padding: 20px; border-left: 4px solid #dc2626;">
                    <h2 style="color: #dc2626;">⚠️ SLA BREACH ALERT</h2>

                    <p><strong>Threat ID:</strong> {threat_id}</p>
                    <p><strong>Threat Type:</strong> {threat_type}</p>
                    <p><strong>Overdue By:</strong> <span style="color: #dc2626; font-weight: bold;">{minutes_overdue:.0f} minutes</span></p>

                    <p>This threat has exceeded its SLA deadline and requires immediate action.</p>

                    <a href="{request.host_url}dashboard/threats/{threat_id}"
                       style="display: inline-block; background-color: #2563eb; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">
                        Review Threat Now
                    </a>
                </div>
            </body>
        </html>
        """,
    )
    try:
        mail.send(msg)
        print(f"✅ Escalation email sent to {supervisor_email} for Threat {threat_id}")
    except Exception as e:
        print(f"[ERROR] Failed to send escalation email for Threat {threat_id}: {e}")
        raise


def retrain_agent2_on_fb():
    """Periodic retraining job using analyst feedback."""
    agent = ThreatClassificationAgent(verbose=True)
    success = agent.incorporate_analyst_feedback()
    if success:
        print(f"[Feedback Loop] {agent_name('classifier')} model successfully retrained and promoted.")
    else:
        print("[Feedback Loop] Retraining did not meet promotion gates.")


scheduler = BackgroundScheduler()
scheduler.add_job(
    func=check_and_escalate_overdue_threats,
    trigger="interval",
    minutes=5,
    id="sla_escalation_check",
    name="Check and escalate overdue threats",
    replace_existing=True,
)

scheduler.add_job(
    func=retrain_agent2_on_fb,
    trigger="interval",
    days=7,
    id="agent2_retraining",
    name=f"Retrain {agent_name('classifier')} on Feedback",
    replace_existing=True,
)


def _start_scheduler_once():
    """Start APScheduler once per process and register clean shutdown."""
    if scheduler.running:
        return
    scheduler.start()
    atexit.register(lambda: scheduler.shutdown(wait=False))


if __name__ == "__main__":
    _start_scheduler_once()
    socketio.run(
        app,
        host="0.0.0.0",
        debug=False,
        use_reloader=False,
        port=5000,
        allow_unsafe_werkzeug=True,
    )
