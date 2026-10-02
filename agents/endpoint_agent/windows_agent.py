"""Vigilon Sensor - Windows Endpoint Collector"""

import os
import winreg
import sys
import json
import uuid
import time
import threading
import logging
import subprocess
import socket
import platform
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from collections import deque

import joblib
import socketio
import psutil
import requests
import numpy as np
from sklearn.preprocessing import StandardScaler
from feature_extractor import ProcessFeatureExtractor, NetworkFeatureExtractor

# Configuration
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:5000")
AGENT_VERSION = "2.0.0"
TELEMETRY_BATCH_SIZE = 50
TELEMETRY_BATCH_TIMEOUT = 5
CONFIDENCE_THRESHOLD_SEND = 0.0 # Send all events
CONFIDENCE_THRESHOLD_ALERT = 0.70 # Flag high-confidence
CONFIDENCE_THRESHOLD_AUTO_RESPONSE = 0.95 # Auto-kill at very high


# Logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger(__name__)

# Import feature extractors 
sys.path.append(0, os.path.join(os.path.dirname(__file__), "..", ".."))

class MLModelManager:
    """Load and manage trained ML models"""

    def __init__(self, model_dir: str = None):
        if model_dir is None:
            model_dir = os.path.join(os.path.dirname(__file__), "..", "ml_training", "models")

        self.model_dir = model_dir
        self.process_model = None
        self.network_model = None
        self.process_scaler = None
        self.network_scaler = None
        self.process_feature_extractor = ProcessFeatureExtractor()
        self.network_feature_extractor = NetworkFeatureExtractor()

        self._load_models()

    def _load_models(self):
        """Load ML models and scalers from disk"""
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
        """Score process event using ML model"""

        if not self.process_model:
            logger.debug("Process model unavailable, returning 0.0")
            return 0.0

        try:
            # Extract features
            features_dict = self.process_feature_extractor.extract_Features(event_data)
            feature_values = list(features_dict.values())

            # Scale
            features_scaled = self.process_scaler.transform([feature_values])[0]

            # Predict
            confidence = self.process_model.predict_proba([features_scaled])[0][1]

            return float(confidence)
        
        except Exception as e:
            logger.error(f"Process scoring error: {e}")
            return 0.0

    def score_network(self, event_data: Dict) -> float:
        """Score network event using ML model"""

        if not self.network_model:
            logger.debug("Network model unavailable, returning 0.0")
            return 0.0

        try:
            # Extract features
            features_dict = self.network_feature_extractor.extract_features(event_data)
            feature_values = list(features_dict.values())

            # Scale
            features_scaled = self.network_scaler.transform([feature_values])[0]

            # Predict
            confidence = self.network_model.predict_proba([features_scaled])[0][1]

            return float(confidence)

        except Exception as e:
            logger.debug(f"Network scoring error: {e}")
            return 0.0

    def has_models(self) -> bool:
        """Check if models were loaded"""
        return self.process_model is not None and self.network_model is not None

class ProcessMonitor:
    """Monitor process creation and score with ML"""

    def __init__(self, ml_manager: MLModelManager):
        self.previous_pids = set(psutil.pids())
        self.ml_manager = ml_manager

    def poll(self) -> List[Dict]:
        """Poll for new processes"""
        events = []
        current_pids = set(psutil.pids())
        new_pids = current_pids - self.previous_pids

        for pid in new_pids:
            try:
                p = psutil.Process(pid)
                exe = p.exe()

                event_data = {
                    "pid": pid,
                    "ppid": p.ppid(),
                    "name": os.path.basename(exe),
                    "path": exe,
                    "command_line": " ".join(p.cmdline()),
                    "parent_name": self._get_parent_name(p.ppid()),
                    "user": p.username(),
                    "create_time": p.create_time(),
                    "is_first_seen": False, # TODO: Check process hash against db
                }

                # ML Scoring
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
        """Get parent process name"""
        try:
            p = psutil.Process(ppid)
            return os.path.basename(p.exe())
        except:
            return "unknown"

class NetworkMonitor:
    """Monitor network connections and score with ML"""

    def __init__(self, ml_manager: MLModelManager):
        self.previous_connections = set()
        self.ml_manager = ml_manager

        def poll(self) -> List[Dict]:
            """Poll for new network connections"""
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

                        # ML Scoring
                        confidence = self.ml_manager.score_network(event_data)

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
    """Main Windows agent with ML-based detection"""

    def __init__(self):
        self.agent_id = self._get_or_create_agent_id()
        self.sio = socketio.Client()
        self.telemetry_buffer = deque(maxlen=TELEMETRY_BATCH_SIZE)
        self.running = False
        self.last_telemetry_send = time.time()

        # Load ML models
        logger.info("Loading ML models...")
        self.ml_manager = MLModelManager()

        # Create monitors
        self.process_monitor = ProcessMonitor(self.ml_manager)
        self.network_monitor = NetworkMonitor(self.ml_manager)

        # Setup WebSocket events
        self.sio.on("connect", self.on_connect)
        self.sio.on("disconnect", self.on_disconnect)
        self.sio.on("action_dispatch", self.on_action_dispatch)
        self.sio.on("error", self.on_error)

    def _get_or_create_agent_id(self) -> str:
        """Get or create persistent agent ID from registry"""
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
        """Connect to backend"""
        logger.info("Connected to backend")
        self.register_agent()

    def on_disconnect(self):
        """Disconnected from backend"""
        logger.warning("Disconnected from backend")

    def register_agent(self):
        """Send agent registration"""
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
        """Execute action from backend"""
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
        """Backend error"""
        logger.error(f"Backend error: {data}")

    def collect_telemetry(self) -> List[Dict]:
        """Collect evnets from monitors"""
        events = []
        events.extend(self.process_monitor.poll())
        events.extend(self.network_monitor.poll())
        return events
    
    def telemetry_worker(self):
        """Background thread collection telemetry"""
        while self.running:
            try:
                events = self.collect_telemetry()
                for event in events:
                    self.telemetry_buffer.append(event)

                # Send if buffer full or timeout
                if len(self.telemetry_buffer) >= TELEMETRY_BATCH_SIZE:
                    self.send_telemetry()
                elif time.time() - self.last_telemetry_send > TELEMETRY_BATCH_TIMEOUT:
                    self.send_telemetry()

                time.sleep(1)
            except Exception as e:
                logger.error(f"Telemetry error: {e}")
    
    def send_telemtry(self):
        """Send telemetry with confidence scores"""
        if not self.telemetry_buffer or not self.sio.connected:
            return
        
        events = list(self.telemetry_buffer)
        self.telemetry_buffer.clear()

        try:
            self.sio.emit("telemetry", {
                "agent_id": self.agent_id,
                "events": events # Each event includes confidence scores
            })
            self.last_telemetry_send = time.time()
            logger.debug(f"Sent {len(events)} telemetry events")
        except Exception as e:
            logger.error(f"Telemetry send error: {e}")
            for event in events:
                self.telemetry_buffer.append(event)

    def run(self):
        """Start agent"""
        self.running = True
        logger.info(f"Starting Windows endpoint agent {self.agent_id}")

        # Start telemetry collection thread
        telemetry_thread = threading.Thread(target=self.telemetry_worker, daemon=True)
        telemetry_thread.start()

        # Connect to backend
        try:
            self.sio.connect(BACKEND_URL)
            self.sio.wait()
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            while self.running:
                try:
                    logger.info("Reconnecting in 10 seconds...")
                    time.sleep(10)
                    self.sio.connect(BACKEND_URL)
                    self.sio.wait()
                except:
                    pass

    def stop(self):
        """Graceful shutdown"""
        logger.info("Stopping agent...")
        self.running = False
        self.send_telemetry()
        if self.sio.connected:
            self.sio.disconnect()



if __name__ == "__main__":
    agent = WindowsEndpointAgent()
    try:
        agent.run()
    except KeyboardInterrupt:
        agent.stop()
        logger.info("Agent stopped")

