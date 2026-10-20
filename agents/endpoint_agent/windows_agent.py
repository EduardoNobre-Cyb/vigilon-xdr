import os
import winreg
import sys
import json
import uuid
import time
import threading
import logging
import signal
import subprocess
import socket
import platform
import ipaddress
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from collections import deque

import joblib
import socketio
import psutil
import requests
import numpy as np
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from feature_extractor import ProcessFeatureExtractor, NetworkFeatureExtractor
from agents.endpoint_agent.windows_event_collector import SysmonProcessCollector


BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:5000")
AGENT_VERSION = "2.0.0"
TELEMETRY_BATCH_SIZE = 50
TELEMETRY_BATCH_TIMEOUT = 5
CONFIDENCE_THRESHOLD_SEND = 0.0
CONFIDENCE_THRESHOLD_ALERT = 0.70
CONFIDENCE_THRESHOLD_AUTO_RESPONSE = 0.95
PROCESS_COLLECTOR = os.getenv("PROCESS_COLLECTOR", "polling").lower()

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger(__name__)


class MLModelManager:

    def __init__(self, model_dir: str = None):

        self.model_dir = model_dir or os.getenv("EDR_MODEL_DIR", "data/models/EDR/windows")
        self.process_model = None
        self.network_model = None
        self.process_scaler = None
        self.network_scaler = None
        self.process_feature_extractor = ProcessFeatureExtractor()
        self.network_feature_extractor = NetworkFeatureExtractor()

        self._load_models()

    def _load_models(self):
        logger.info(f"Model directory: {self.model_dir}")
        try:
            process_model_path = os.path.join(self.model_dir, "process_model.pkl")
            network_model_path = os.path.join(self.model_dir, "network_model.pkl")
            process_scaler_path = os.path.join(self.model_dir, "process_scaler.pkl")
            network_scaler_path = os.path.join(self.model_dir, "network_scaler.pkl")

            if os.path.exists(process_model_path):
                self.process_model = joblib.load(process_model_path)
                logger.info("✓ Loaded process_model.pkl")
            else:
                logger.warning("⚠ process_model.pkl not found, falling back to heuristics")

            if os.path.exists(network_model_path):
                self.network_model = joblib.load(network_model_path)
                logger.info("✓ Loaded network_model.pkl")
            else:
                logger.warning("⚠ network_model.pkl not found, falling back to heuristics")

            if os.path.exists(process_scaler_path):
                self.process_scaler = joblib.load(process_scaler_path)

            if os.path.exists(network_scaler_path):
                self.network_scaler = joblib.load(network_scaler_path)

        except Exception as e:
            logger.error(f"Failed to load models: {e}")

    def score_process(self, event_data: Dict) -> float:

        if not self.process_model:
            logger.debug("Process model unavailable, returning 0.0")
            return 0.0

        try:
            features_dict = self.process_feature_extractor.extract_features(event_data)
            feature_values = list(features_dict.values())

            features_scaled = self.process_scaler.transform([feature_values])[0]

            confidence = self.process_model.predict_proba([features_scaled])[0][1]

            return float(confidence)
        
        except Exception as e:
            logger.error(f"Process scoring error: {e}")
            return 0.0

    def score_network(self, event_data: Dict) -> float:

        if not self.network_model:
            logger.debug("Network model unavailable, returning 0.0")
            return 0.0

        try:
            features_dict = self.network_feature_extractor.extract_features(event_data)
            feature_values = list(features_dict.values())

            features_scaled = self.network_scaler.transform([feature_values])[0]

            confidence = self.network_model.predict_proba([features_scaled])[0][1]

            return float(confidence)

        except Exception as e:
            logger.debug(f"Network scoring error: {e}")
            return 0.0

    def has_models(self) -> bool:
        return self.process_model is not None and self.network_model is not None

class ProcessMonitor:

    def __init__(self, ml_manager: MLModelManager):
        self.previous_pids = set(psutil.pids())
        self.ml_manager = ml_manager
        self.seen_executables = set()

    def poll(self) -> List[Dict]:
        events = []
        current_pids = set(psutil.pids())
        new_pids = current_pids - self.previous_pids

        for pid in new_pids:
            try:
                p = psutil.Process(pid)
                exe = p.exe()

                is_first_seen = exe not in self.seen_executables
                self.seen_executables.add(exe)

                event_data = {
                    "pid": pid,
                    "ppid": p.ppid(),
                    "name": os.path.basename(exe),
                    "path": exe,
                    "command_line": " ".join(p.cmdline()),
                    "parent_name": self._get_parent_name(p.ppid()),
                    "user": p.username(),
                    "create_time": p.create_time(),
                    "is_first_seen": is_first_seen,
                }

                confidence = self.ml_manager.score_process(event_data)

                event = {
                    "event_type": "process",
                    "event_subtype": "process_create",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "severity": "critical" if confidence > CONFIDENCE_THRESHOLD_AUTO_RESPONSE else ("warning" if confidence > CONFIDENCE_THRESHOLD_ALERT else "info"),
                    "malware_confidence": confidence,
                    "data": event_data,
                }
                events.append(event)

                if confidence > CONFIDENCE_THRESHOLD_ALERT:
                    logger.warning(f"Process alert: {event_data['name']} "
                                   f"confidence={confidence:.2f}")
            
            except (psutil.NoSuchProcess, psutil.AccessDenied, Exception) as e:
                continue

        self.previous_pids = current_pids
        return events
    
    def _get_parent_name(self, ppid: int) -> str:
        try:
            p = psutil.Process(ppid)
            return os.path.basename(p.exe())
        except:
            return "unknown"

class NetworkMonitor:

    def __init__(self, ml_manager: MLModelManager):
        self.previous_connections = set()
        self.ml_manager = ml_manager

    @staticmethod
    def _is_loopback(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip.split("%")[0])
        except ValueError:
            return False

        if addr.version == 6 and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        return addr.is_loopback

    def _is_loopback_abuse(self, event_data: Dict) -> bool:
        features = self.ml_manager.network_feature_extractor.extract_features(event_data)
        return (features["is_c2_port"] == 1.0 and features["suspicious_process_connects"] == 1.0)

    def poll(self) -> List[Dict]:
        events = []
        try:
            current_connections = set()

            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "ESTABLISHED":
                    current_connections.add((
                        conn.laddr[0], conn.laddr[1],
                        conn.raddr[0], conn.raddr[1], conn.pid
                    ))

            new_connections = current_connections - self.previous_connections

            for src_ip, src_port, dst_ip, dst_port, pid in new_connections:
                try:
                    process = psutil.Process(pid)

                    event_data = {
                        "source_ip": src_ip,
                        "source_port": src_port,
                        "dest_ip": dst_ip,
                        "dest_port": dst_port,
                        "process_name": process.name(),
                        "protocol": "tcp",
                        "bytes_sent": 0,
                        "bytes_received": 0,
                    }

                    ml_score = self.ml_manager.score_network(event_data)
                    confidence = ml_score

                    loopback = self._is_loopback(dst_ip)
                    loopback_suppressed = loopback and not self._is_loopback_abuse(event_data)
                    if loopback_suppressed:
                        confidence = 0.0
                        if ml_score > CONFIDENCE_THRESHOLD_ALERT:
                            logger.info(f"Loopback connection recorded, not alerted: "
                                        f"{process.name()} → {dst_ip}:{dst_port} "
                                        f"ml_score={ml_score:.2f}")

                    event_data["ml_score"] = ml_score
                    event_data["loopback"] = loopback
                    event_data["loopback_suppressed"] = loopback_suppressed

                    event = {
                        "event_type": "network",
                        "event_subtype": "connection_established",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "severity": "warning" if confidence > CONFIDENCE_THRESHOLD_ALERT else "info",
                        "network_risk_score": confidence,
                        "data": event_data,
                    }
                    events.append(event)

                    if confidence > CONFIDENCE_THRESHOLD_ALERT:
                        logger.warning(f"Network alert: {process.name()} → "
                                       f"{dst_ip}:{dst_port} confidence={confidence:.2f}")

                except Exception as e:
                    continue

            self.previous_connections = current_connections

        except Exception as e:
            logger.warning(f"Network monitoring error: {e}")

        return events
    
class WindowsEndpointAgent:

    def __init__(self):
        self.agent_id = self._get_or_create_agent_id()
        self.sio = socketio.Client()
        self.telemetry_buffer = deque(maxlen=TELEMETRY_BATCH_SIZE)
        self.running = False
        self.last_telemetry_send = time.time()

        logger.info("Loading ML models...")
        self.ml_manager = MLModelManager()

        self.process_monitor = ProcessMonitor(self.ml_manager)
        self.network_monitor = NetworkMonitor(self.ml_manager)

        self.sysmon_collector = SysmonProcessCollector() if PROCESS_COLLECTOR  == "sysmon" else None
        if self.sysmon_collector is not None:
            self.sysmon_collector.start()
            logger.info("Process collection: sysmon")
        else:
            logger.info("Process collection: polling")

        self.sio.on("connect", self.on_connect)
        self.sio.on("disconnect", self.on_disconnect)
        self.sio.on("action_dispatch", self.on_action_dispatch)
        self.sio.on("error", self.on_error)

    def _get_or_create_agent_id(self) -> str:
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\ThreatDefense', 0, winreg.KEY_READ)
            agent_id, _ = winreg.QueryValueEx(key, "AgentID")
            winreg.CloseKey(key)
            return agent_id
        except:
            agent_id = str(uuid.uuid4())
            try:
                key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\ThreatDefense')
                winreg.SetValueEx(key, "AgentID", 0, winreg.REG_SZ, agent_id)
                winreg.CloseKey(key)
            except Exception as e:
                logger.error(f"Could not store agent ID: {e}")
            return agent_id
        
    def on_connect(self):
        logger.info("Connected to backend")
        self.register_agent()

    def on_disconnect(self):
        logger.warning("Disconnected from backend")

    def register_agent(self):
        payload = {
            "agent_id": self.agent_id,
            "hostname": socket.gethostname(),
            "os_type": "windows",
            "os_version": platform.platform(),
            "agent_version": AGENT_VERSION,
            "ip_address": socket.gethostbyname(socket.gethostname()),
            "ml_models_deployed": self.ml_manager.has_models(),
        }
        self.sio.emit("agent_register", payload)
        logger.info(f"Registered agent {self.agent_id}")

    def on_action_dispatch(self, data):
        action_id = data.get("action_id")
        action_type = data.get("action_type")
        action_params = data.get("action_params", {})

        logger.info(f"Executing action: {action_type}")

        try:
            if action_type == "kill_process":
                pid = action_params.get("pid")
                p = psutil.Process(pid)
                p.terminate()
                result = f"Process {pid} terminated"

            elif action_type == "quarantine_file":
                file_path = action_params.get("file_path")

                quarantine_path = f"C:\\ThreatDefense\\Quarantine\\{os.path.basename(file_path)}"
                os.makedirs("C:\\ThreatDefense\\Quarantine", exist_ok=True)
                os.rename(file_path, quarantine_path)
                result = f"File quarantined to {quarantine_path}"

            else:
                result = f"Unknown action: {action_type}"
            
            self.sio.emit("action_result", {
                "agent_id": self.agent_id,
                "action_id": action_id,
                "status": "executed",
                "result_message": result
            })

        except Exception as e:
            logger.error(f"Action failed: {e}")
            self.sio.emit("action_result", {
                "agent_id": self.agent_id,
                "action_id": action_id,
                "status": "failed",
                "result_message": str(e)
            })

    def on_error(self, data):
        logger.error(f"Backend error: {data}")

    def score_process_event(self, event_data: Dict) -> Dict:
        confidence = self.ml_manager.score_process(event_data)

        logger.info(
            "Sysmon process decision: name=%s pid=%s command=%r ml=%.4f",
            event_data.get("name"),
            event_data.get("pid"),
            event_data.get("command_line"),
            confidence,
        )

        if confidence > CONFIDENCE_THRESHOLD_ALERT:
            logger.warning(
                f"Process alert: {event_data.get('name')} confidence={confidence:.2f}"
            )

        return {
            "event_type": "process",
            "event_subtype": "process_create",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": "critical" if confidence > CONFIDENCE_THRESHOLD_AUTO_RESPONSE else ("warning" if confidence > CONFIDENCE_THRESHOLD_ALERT else "info"),
            "malware_confidence": confidence,
            "data": event_data,
        }


    def collect_telemetry(self) -> List[Dict]:
        events = []

        if self.sysmon_collector is not None:
            for event_data in self.sysmon_collector.poll():
                events.append(self.score_process_event(event_data))
        else:
            events.extend(self.process_monitor.poll())

        events.extend(self.network_monitor.poll())
        return events
    
    def telemetry_worker(self):
        while self.running:
            try:
                events = self.collect_telemetry()
                for event in events:
                    self.telemetry_buffer.append(event)

                if len(self.telemetry_buffer) >= TELEMETRY_BATCH_SIZE:
                    self.send_telemetry()
                elif time.time() - self.last_telemetry_send > TELEMETRY_BATCH_TIMEOUT:
                    self.send_telemetry()

                time.sleep(1)
            except Exception as e:
                logger.error(f"Telemetry error: {e}")
    
    def send_telemetry(self):
        if not self.telemetry_buffer or not self.sio.connected:
            return
        
        events = list(self.telemetry_buffer)
        self.telemetry_buffer.clear()

        try:
            self.sio.emit("telemetry", {
                "agent_id": self.agent_id,
                "events": events
            })
            self.last_telemetry_send = time.time()
            logger.debug(f"Sent {len(events)} telemetry events")
        except Exception as e:
            logger.error(f"Telemetry send error: {e}")
            for event in events:
                self.telemetry_buffer.append(event)

    def run(self):
        self.running = True
        logger.info(f"Starting Windows endpoint agent {self.agent_id}")

        telemetry_thread = threading.Thread(target=self.telemetry_worker, daemon=True)
        telemetry_thread.start()

        while self.running:
            try:
                if not self.sio.connected:
                    self.sio.connect(BACKEND_URL)
                time.sleep(1)
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Connection failed: {e}")
                logger.info("Reconnecting in 10 seconds...")
                for _ in range(10):          
                    if not self.running:
                        break
                    time.sleep(1)

    def stop(self):
        logger.info("Stopping agent...")
        self.running = False
        if self.sysmon_collector is not None:
            self.sysmon_collector.stop()
        self.send_telemetry()
        if self.sio.connected:
            self.sio.disconnect()



if __name__ == "__main__":
    agent = WindowsEndpointAgent()

    def _handle_shutdown(signum, frame):
        logger.info("Shutdown signal received, stopping...")
        agent.stop()

    signal.signal(signal.SIGINT, _handle_shutdown)
    try:
        signal.signal(signal.SIGTERM, _handle_shutdown)
    except (AttributeError, ValueError, OSError):
        pass

    try:
        agent.run()
    except KeyboardInterrupt:
        agent.stop()
    logger.info("Agent stopped")

