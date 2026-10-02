"""Vigilon Sensor - Linux Endpoint Collector"""

import os
import sys
import uuid
import time
import signal
import socket
import hashlib
import platform
import logging
import threading
from urllib.parse import urlparse
from datetime import datetime, timezone
from typing import Dict, List, Optional
from collections import deque

import psutil
import socketio
import joblib
import numpy as np

from agents.feature_extractor import (
    ProcessFeatureExtractor,
    NetworkFeatureExtractor,
)
from agents.endpoint_agent.linux_event_collector import AuditdProcessCollector

# Configuration
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:5000")
AGENT_VERSION = "1.0.0"
TELEMETRY_BATCH_SIZE = 10
TELEMETRY_BATCH_TIMEOUT = 5
PROCESS_EVENT_MIN_SCORE = float(os.getenv("PROCESS_EVENT_MIN_SCORE", "0.70"))
PROCESS_EVENT_DEDUP_WINDOW_SEC = int(os.getenv("PROCESS_EVENT_DEDUP_WINDOW_SEC", "90"))
ML_FIRST_MODE = os.getenv("ML_FIRST_MODE", "true").lower() == "true"
ML_EVENT_MIN_SCORE = float(os.getenv("ML_EVENT_MIN_SCORE", "0.70"))
TELEMETRY_POLL_INTERVAL = float(os.getenv("TELEMETRY_POLL_INTERVAL", "0.25"))
PROCESS_COLLECTOR = os.getenv("PROCESS_COLLECTOR", "polling").lower()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger(__name__)

class EndpointMLModelManager:
    """Load and run endpoint behavioral models."""

    def __init__(self, model_dir=None):
        self.model_dir = model_dir or os.getenv("EDR_MODEL_DIR", "data/models/EDR")
        self.process_model = joblib.load(os.path.join(self.model_dir, "process_model.pkl"))
        self.process_scaler = joblib.load(os.path.join(self.model_dir, "process_scaler.pkl"))
        self.network_model = joblib.load(os.path.join(self.model_dir, "network_model.pkl"))
        self.network_scaler = joblib.load(os.path.join(self.model_dir, "network_scaler.pkl"))

        self.process_extractor = ProcessFeatureExtractor()
        self.network_extractor = NetworkFeatureExtractor()

        logger.info("Loaded endpoint behavioral models from %s", self.model_dir)

    @staticmethod
    def _positive_probability(model, probabilities):
        classes = list(model.classes_)
        if 1 not in classes:
            return 0.0
        return float(probabilities[classes.index(1)])

    def score_process(self, event_data):
        """Score a process event using the ML Models."""
        features = self.process_extractor.extract_features(event_data)
        values = np.array([list(features.values())])
        scaled = self.process_scaler.transform(values)
        probabilities = self.process_model.predict_proba(scaled)[0]
        return self._positive_probability(self.process_model, probabilities)

    def score_network(self, event_data):
        """Score a network event using the ML Models."""
        features = self.network_extractor.extract_features(event_data)
        values = np.array([list(features.values())])
        scaled = self.network_scaler.transform(values)
        probabilities = self.network_model.predict_proba(scaled)[0]
        return self._positive_probability(self.network_model, probabilities)


class ProcessMonitor:
    """Monitor process creation on Linux."""

    def __init__(self, ml_manager):
        self.previous_pids = set(psutil.pids())
        self.recent_process_signatures = {}
        self.seen_executables = set()
        self.ml_manager = ml_manager

    def get_process_hash(self, path: str) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    h.update(chunk)
            return f"sha256:{h.hexdigest()}"
        except Exception:
            return None
        
    @staticmethod
    def normalize_process_name(value: str) -> str:
        """Map versioned Linux executable names to training names."""
        name = os.path.basename(value or "").lower()

        if name in {"nc.traditional", "netcat.openbsd"}:
            return "nc"
        if name.startswith("python3."):
            return "python3"
        if name.startswith("python2."):
            return "python2"

        return name

    def score_process_risk(self, exe: str, command_line: str) -> float:
        """Lightweight heuristic confidence for suspicious process launches."""
        cmd = (command_line or "").lower()
        exe_name = self.normalize_process_name(exe)

        # Strong reverse-shell and shell-spawn indicators.
        if ("nc " in cmd or "netcat" in cmd or exe_name in {"nc", "ncat", "netcat"}) and (
            " -e " in cmd or "/bin/bash" in cmd or "/bin/sh" in cmd
        ):
            return 0.96

        # Suspicious command obfuscation/execution chains.
        if "base64" in cmd and ("bash" in cmd or "sh" in cmd):
            return 0.88
        if "curl" in cmd and ("| bash" in cmd or "| sh" in cmd):
            return 0.84

        # Netcat use without direct shell spawn is still noteworthy.
        if "nc " in cmd or "netcat" in cmd or exe_name in {"nc", "ncat", "netcat"}:
            return 0.74

        return 0.15

    def _cleanup_expired_signatures(self, now: float) -> None:
        cutoff = now - PROCESS_EVENT_DEDUP_WINDOW_SEC
        self.recent_process_signatures = {
            sig: ts for sig, ts in self.recent_process_signatures.items() if ts >= cutoff
        }

    def should_emit_process_event(self, name: str, command_line: str, score: float) -> bool:
        """Drop low-signal process churn and short-term duplicates."""
        if score < PROCESS_EVENT_MIN_SCORE:
            return False

        now = time.time()
        self._cleanup_expired_signatures(now)

        signature = f"{(name or '').lower()}::{(command_line or '').lower()}"
        if signature in self.recent_process_signatures:
            return False

        self.recent_process_signatures[signature] = now
        return True

    def poll(self) -> List[Dict]:
        events = []
        current_pids = set(psutil.pids())
        new_pids = current_pids - self.previous_pids

        for pid in new_pids:
            try:
                process = psutil.Process(pid)
                exe = process.exe()
                command_line = " ".join(process.cmdline())
                risk_score = self.score_process_risk(exe, command_line)
                process_name = self.normalize_process_name(exe)

                parent_name = "unknown"
                try:
                    parent = psutil.Process(process.ppid())
                    parent_name = parent.name()
                except Exception:
                    pass

                is_first_seen = exe not in self.seen_executables
                self.seen_executables.add(exe)
                
                ml_event_data = {
                    "pid": pid,
                    "ppid": process.ppid(),
                    "name": process_name,
                    "path": exe,
                    "command_line": command_line,
                    "parent_name": parent_name,
                    "user": process.username(),
                    "is_first_seen": is_first_seen,
                }

                ml_score = self.ml_manager.score_process(ml_event_data)

                logger.info(
                    "Process ML score: name=%s pid=%s score=%.4f heuristic=%.4f",
                    process_name,
                    pid,
                    ml_score,
                    risk_score,
                )

                heuristic_candidate = risk_score >= PROCESS_EVENT_MIN_SCORE
                ml_candidate = ml_score >= ML_EVENT_MIN_SCORE

                logger.info(
                    "Process decision: name=%s pid=%s heuristic=%.4f ml=%.4f "
                    "heuristic_candidate=%s ml_candidate=%s",
                    process_name,
                    pid,
                    risk_score,
                    ml_score,
                    heuristic_candidate,
                    ml_candidate,
                )

                if ML_FIRST_MODE:
                    if not ml_candidate and not heuristic_candidate:
                        continue
                else:
                    if not self.should_emit_process_event(process_name, command_line, risk_score):
                        continue

                emitted_score = ml_score if ML_FIRST_MODE else risk_score
                emitted_candidate = ml_candidate if ML_FIRST_MODE else heuristic_candidate

                event = {
                    "event_type": "process",
                    "event_subtype": "process_create",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "severity": "warning" if emitted_candidate >= 0.7 else "info",
                    "malware_confidence": emitted_score,
                    "data": {
                        "pid": pid,
                        "ppid": process.ppid(),
                        "name": process_name,
                        "path": exe,
                        "command_line": command_line,
                        "user": process.username(),
                        "parent_name": parent_name,
                        "heuristic_score": risk_score,
                        "heuristic_candidate": heuristic_candidate,
                        "ml_score": ml_score,
                        "ml_candidate": ml_candidate,
                        "is_first_seen": False,
                        "hash": self.get_process_hash(exe),
                        "create_time": process.create_time(),
                    }
                }
                events.append(event)
            except Exception:
                continue

        self.previous_pids = current_pids
        return events


class NetworkMonitor:
    """Monitor network connections on Linux."""

    def __init__(self, ml_manager):
        self.previous_conns = set()
        self.ml_manager = ml_manager

        backend_url = BACKEND_URL
        parsed = urlparse(backend_url)
        self.backend_host = parsed.hostname
        self.backend_port = parsed.port or (443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else 0)

        if self.backend_host:
            try:
                self.backend_ip = socket.gethostbyname(self.backend_host)
            except Exception:
                self.backend_ip = self.backend_host
        else:
            self.backend_ip = None

    def _is_backend_connection(self, dst_ip: str, dst_port: int) -> bool:
        if self.backend_ip and dst_ip == self.backend_ip and dst_port == self.backend_port:
            return True

        if self.backend_host and dst_ip == self.backend_host and dst_port == self.backend_port:
            return True

        return False

    def score_network_risk(self, process_name: str, dst_port: int) -> float:
        """Lightweight heuristic confidence for suspicious outbound connections."""
        name = (process_name or "").lower()
        port = int(dst_port or 0)

        high_risk_ports = {4444, 1337, 6667, 9001, 1080}
        if name in {"nc", "ncat", "netcat"} and port in high_risk_ports:
            return 0.96
        if name in {"nc", "ncat", "netcat"}:
            return 0.78
        if port in high_risk_ports:
            return 0.74
        if port not in {53, 80, 123, 443, 587, 993, 995}:
            return 0.42

        return 0.18

    def poll(self) -> List[Dict]:
        events = []
        try:
            current_conns = set()
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "ESTABLISHED":
                    current_conns.add((conn.laddr[0], conn.laddr[1], conn.raddr[0], conn.raddr[1], conn.pid))

            new_conns = current_conns - self.previous_conns

            for src_ip, src_port, dst_ip, dst_port, pid in new_conns:
                if self._is_backend_connection(dst_ip, dst_port):
                    continue

                try:
                    process = psutil.Process(pid)
                    process_name = process.name()
                    risk_score = self.score_network_risk(process_name, dst_port)

                    ml_event_data = {
                        "source_ip": src_ip,
                        "source_port": src_port,
                        "dest_ip": dst_ip,
                        "dest_port": dst_port,
                        "process_name": process_name,
                        "protocol": "tcp",
                        "bytes_sent": 0,
                        "bytes_received": 0,
                    }

                    ml_score = self.ml_manager.score_network(ml_event_data)

                    logger.info(
                        "Network ML score: process=%s destination=%s:%s score=%.4f heuristic=%.4f",
                        process_name,
                        dst_ip,
                        dst_port,
                        ml_score,
                        risk_score,
                    )

                    ml_candidate = ml_score >= ML_EVENT_MIN_SCORE
                    heuristic_candidate = risk_score >= PROCESS_EVENT_MIN_SCORE
                    emitted_score = ml_score if ML_FIRST_MODE else risk_score
                    emitted_candidate = ml_candidate if ML_FIRST_MODE else heuristic_candidate

                    event = {
                        "event_type": "network",
                        "event_subtype": "connection_established",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "severity": "warning" if emitted_candidate >= 0.7 else "info",
                        "network_risk_score": emitted_score,
                        "data": {
                            "source_ip": src_ip,
                            "source_port": src_port,
                            "dest_ip": dst_ip,
                            "dest_port": dst_port,
                            "process_name": process_name,
                            "pid": pid,
                            "heuristic_score": risk_score,
                            "heuristic_candidate": heuristic_candidate,
                            "ml_score": ml_score,
                            "ml_candidate": ml_candidate,
                        }
                    }
                    events.append(event)
                except Exception:
                    continue

            self.previous_conns = current_conns
        except Exception as e:
            logger.warning(f"Network monitoring error: {e}")

        return events


class LinuxEndpointAgent:
    """Main Linux endpoint agent orchestration."""

    def __init__(self):
        self.agent_id = self._get_or_create_agent_id()
        self.sio = socketio.Client()
        self.running = False
        self.telemetry_buffer = deque(maxlen=TELEMETRY_BATCH_SIZE)
        self.last_flush_time = time.time()

        self.ml_manager = EndpointMLModelManager()
        self.process_monitor = ProcessMonitor(self.ml_manager)
        self.network_monitor = NetworkMonitor(self.ml_manager)
        self.auditd_collector = AuditdProcessCollector() if PROCESS_COLLECTOR == "auditd" else None
        if self.auditd_collector is not None:
            self.auditd_collector.start()

        self.sio.on("connect", self.on_connect)
        self.sio.on("disconnect", self.on_disconnect)
        self.sio.on("telemetry_ack", self.on_telemetry_ack)
        self.sio.on("action_dispatch", self.on_action_dispatch)
        self.sio.on("error", self.on_error)

    def _get_or_create_agent_id(self) -> str:
        config_path = "/etc/threat-defense/agent_config.json"
        if os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    return f.read().strip()
            except Exception:
                pass

        agent_id = str(uuid.uuid4())
        try:
            os.makedirs("/etc/threat-defense", exist_ok=True)
            with open(config_path, "w") as f:
                f.write(agent_id)
            os.chmod(config_path, 0o600)
        except Exception as e:
            logger.error(f"Could not store agent ID: {e}")
        return agent_id

    def on_connect(self):
        logger.info("Connected to backend")
        self.register_agent()

    def on_disconnect(self):
        logger.info("Disconnected from backend")

    def register_agent(self):
        payload = {
            "agent_id": self.agent_id,
            "hostname": socket.gethostname(),
            "os_type": "linux",
            "os_version": platform.platform(),
            "agent_version": AGENT_VERSION,
            "ip_address": socket.gethostbyname(socket.gethostname())
        }
        self.sio.emit("agent_register", payload)
        logger.info(f"Registered agent: {self.agent_id}")

    def on_action_dispatch(self, data):
        action_id = data.get("action_id")
        action_type = data.get("action_type")
        action_params = data.get("action_params", {})

        try:
            if action_type == "kill_process":
                pid = action_params.get("pid")
                os.kill(pid, signal.SIGKILL)
                result_message = f"Process {pid} terminated"

            elif action_type == "quarantine_file":
                file_path = action_params.get("file_path")
                quarantine_dir = "/var/threat-defense/quarantine"
                os.makedirs(quarantine_dir, exist_ok=True)
                quarantine_path = os.path.join(quarantine_dir, os.path.basename(file_path))
                os.rename(file_path, quarantine_path)
                result_message = f"File moved to quarantine: {quarantine_path}"

            else:
                result_message = f"Unknown action type: {action_type}"

            self.sio.emit("action_result", {
                "agent_id": self.agent_id,
                "action_id": action_id,
                "status": "executed",
                "result_message": result_message,
            })
        except Exception as e:
            logger.error(f"Action execution failed: {e}")
            self.sio.emit("action_result", {
                "agent_id": self.agent_id,
                "action_id": action_id,
                "status": "failed",
                "result_message": str(e),
            })

    def on_error(self, data):
        logger.error(f"Backend error: {data}")

    def on_telemetry_ack(self, data):
        count = (data or {}).get("count", 0)
        logger.info(f"Backend acknowledged {count} telemetry events")

    def score_process_event(self, event_data):
        """Build the existing telemetry event from a normalized process event."""
        process_name = event_data.get("name", "")
        command_line = event_data.get("command_line", "")
        path = event_data.get("path", "")
        heuristic_score = self.process_monitor.score_process_risk(path, command_line)
        ml_score = self.ml_manager.score_process(event_data)
        heuristic_candidate = heuristic_score >= PROCESS_EVENT_MIN_SCORE
        ml_candidate = ml_score >= ML_EVENT_MIN_SCORE

        logger.info(
            "Auditd process decision: name=%s pid=%s command=%r "
            "heuristic=%.4f ml=%.4f heuristic_candidate=%s ml_candidate=%s ",
            process_name,
            event_data.get("pid"),
            command_line,
            heuristic_score,
            ml_score,
            heuristic_candidate,
            ml_candidate, 
        )

        if not heuristic_candidate and not ml_candidate:
            return None

        emitted_score = ml_score if ML_FIRST_MODE else heuristic_score
        emitted_candidate = ml_candidate if ML_FIRST_MODE else heuristic_candidate

        return {
            "event_type": "process",
            "event_subtype": "process_create",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": "warning" if emitted_candidate else "info",
            "malware_confidence": emitted_score,
            "data": {
                **event_data,
                "heuristic_score": heuristic_score,
                "ml_score": ml_score,
                "heuristic_candidate": heuristic_candidate,
                "ml_candidate": ml_candidate,
            },
        }

    def collect_telemetry(self) -> List[Dict]:
        events = []

        if self.auditd_collector is not None:
            for event_data in self.auditd_collector.poll():
                event = self.score_process_event(event_data)
                if event is not None:
                    events.append(event)
        else:
            events.extend(self.process_monitor.poll())

        events.extend(self.network_monitor.poll())
        return events

    def run(self):
        self.running = True
        logger.info(f"Starting Linux endpoint agent: {self.agent_id}")

        telemetry_thread = threading.Thread(target=self.telemetry_worker, daemon=True)
        telemetry_thread.start()

        try:
            self.sio.connect(BACKEND_URL)
            self.sio.wait()
        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            while self.running:
                try:
                    time.sleep(10)
                    self.sio.connect(BACKEND_URL)
                    self.sio.wait()
                except Exception:
                    pass

    def telemetry_worker(self):
        while self.running:
            try:
                for event in self.collect_telemetry():
                    self.telemetry_buffer.append(event)

                now = time.time()
                should_flush = (
                    len(self.telemetry_buffer) >= TELEMETRY_BATCH_SIZE
                    or (
                        len(self.telemetry_buffer) > 0
                        and (now - self.last_flush_time) >= TELEMETRY_BATCH_TIMEOUT
                    )
                )

                if should_flush and self.send_telemetry():
                    self.last_flush_time = now

                time.sleep(TELEMETRY_POLL_INTERVAL)
            except Exception as e:
                logger.error(f"Telemetry collection error: {e}")

    def send_telemetry(self):
        if not self.telemetry_buffer or not self.sio.connected:
            return False

        events = list(self.telemetry_buffer)
        self.telemetry_buffer.clear()
        try:
            self.sio.emit("telemetry", {
                "agent_id": self.agent_id,
                "events": events,
            })
            type_counts = {}
            for event in events:
                event_type = event.get("event_type", "unknown")
                type_counts[event_type] = type_counts.get(event_type, 0) + 1

            breakdown = ", ".join(
                f"{event_type}={count}" for event_type, count in sorted(type_counts.items())
            )
            logger.info("Sent %s telemetry events (%s)", len(events), breakdown)
            return True
        except Exception as e:
            logger.error(f"Telemetry send error: {e}")
            for event in events:
                self.telemetry_buffer.append(event)
            return False

    def stop(self):
        self.running = False
        self.send_telemetry()
        if self.sio.connected:
            self.sio.disconnect()


if __name__ == "__main__":
    agent = LinuxEndpointAgent()
    try:
        agent.run()
    except KeyboardInterrupt:
        agent.stop()