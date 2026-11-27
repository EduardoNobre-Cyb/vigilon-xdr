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
import hashlib
import glob
import ctypes
import ctypes.wintypes as wt
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
from static_feature_extractor import (
    StaticBinaryFeatureExtractor, get_feature_names,
    DocumentFeatureExtractor, get_doc_feature_names,
    verify_authenticode,
)
from agents.endpoint_agent.windows_event_collector import SysmonProcessCollector

try:
    import win32file
    import win32con
    HAS_WIN32FILE = True
except ImportError:
    HAS_WIN32FILE = False

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:5000")
AGENT_VERSION = "2.0.0"
TELEMETRY_BATCH_SIZE = 50
TELEMETRY_BATCH_TIMEOUT = 5
CONFIDENCE_THRESHOLD_SEND = 0.0
CONFIDENCE_THRESHOLD_ALERT = 0.70
CONFIDENCE_THRESHOLD_AUTO_RESPONSE = 0.95
AUTO_RESPONSE_MODE = os.getenv("AUTO_RESPONSE_MODE", "dry_run").lower()
AUTO_RESPONSE_KILL_THRESHOLD = 0.95
AUTO_RESPONSE_QUARANTINE_THRESHOLD = 0.75
QUARANTINE_DIR_WINDOWS = r"C:\ProgramData\Vigilon EDR\Quarantine"
PROCESS_COLLECTOR = os.getenv("PROCESS_COLLECTOR", "polling").lower()
HEARTBEAT_INTERVAL = 30
EDR_API_KEY = os.getenv("EDR_API_KEY", "").strip()

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
        self.doc_extractor = DocumentFeatureExtractor()
        self.static_extractor = StaticBinaryFeatureExtractor()

        self._load_models()

    def _load_models(self):
        logger.info(f"Model directory: {self.model_dir}")
        try:
            process_model_path = os.path.join(self.model_dir, "process_model.pkl")
            network_model_path = os.path.join(self.model_dir, "network_model.pkl")
            process_scaler_path = os.path.join(self.model_dir, "process_scaler.pkl")
            network_scaler_path = os.path.join(self.model_dir, "network_scaler.pkl")
            file_model_path = os.path.join(self.model_dir, "file_model.pkl")
            file_scaler_path = os.path.join(self.model_dir, "file_scaler.pkl")
            doc_model_path = os.path.join(self.model_dir, "doc_model.pkl")
            doc_scaler_path = os.path.join(self.model_dir, "doc_scaler.pkl")

            if os.path.exists(file_model_path):
                self.file_model = joblib.load(file_model_path)
                self.file_scaler = joblib.load(file_scaler_path)
                self.file_feature_names = get_feature_names()
                logger.info("✓ Loaded file_model.pkl and file_scaler.pkl (Static Binary Analysis)")
            else:
                self.file_model = None
                self.file_scaler = None
                self.file_feature_names = None
                logger.warning("⚠ file_model.pkl not found — static file scoring disabled")

            if os.path.exists(doc_model_path):
                self.doc_model = joblib.load(doc_model_path)
                self.doc_scaler = joblib.load(doc_scaler_path)
                self.doc_feature_names = get_doc_feature_names()
                logger.info("✓ Loaded doc_model.pkl and doc_scaler.pkl (Document Analysis)")
            else:
                self.doc_model = None
                self.doc_scaler = None
                self.doc_feature_names = None
                logger.warning("⚠ doc_model.pkl not found — document scoring disabled")

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

    def score_file(self, file_path: str):
        if self.file_model is None:
            return None, None

        features = self.static_extractor.extract_features(file_path)
        if features is None:
            return None, None

        values = np.array([[features.get(name, 0.0) for name in self.file_feature_names]])
        scaled = self.file_scaler.transform(values)
        probabilities = self.file_model.predict_proba(scaled)[0]
        classes = list(self.file_model.classes_)
        score = float(probabilities[classes.index(1)]) if 1 in classes else 0.0
        return score, features

    def score_document(self, file_path: str):
        if self.doc_model is None:
            return None, None

        features = self.doc_extractor.extract_features(file_path)
        if features is None:
            return None, None

        values = np.array([[features.get(name, 0.0) for name in self.doc_feature_names]])
        scaled = self.doc_scaler.transform(values)
        probabilities = self.doc_model.predict_proba(scaled)[0]
        classes = list(self.doc_model.classes_)
        score = float(probabilities[classes.index(1)]) if 1 in classes else 0.0
        return score, features

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

def _build_watched_dirs_windows() -> list:
    dirs = [
        r"C:\Users\Public",
        r"C:\ProgramData",
        os.environ.get("TEMP", r"C:\Windows\Temp"),
        r"C:|Windows\Temp",
    ]
    per_user_subdirs = ["Downloads", "Desktop", "Documents", "Pictures", "Videos", "Music"]
    for profile in glob.glob(r"C:\Users\*"):
        basename = os.path.basename(profile)
        if basename in ("Public", "Default", "Default User", "All Users"):
            continue
        if not os.path.isdir(profile):
            continue
        dirs.append(profile)
        for sub in per_user_subdirs:
            candidate = os.path.join(profile, sub)
            if os.path.isdir(candidate):
                dirs.append(candidate)
    return dirs

WATCHED_DIRS_WINDOWS = _build_watched_dirs_windows()

FILE_SCAN_MIN_SIZE = 1024
FILE_SCAN_MAX_SIZE = 100_000_000
FILE_SCAN_MIN_SCORE = 0.0

FILE_SKIP_EXTENSIONS = {
    ".crdownload", ".part", ".partial", ".downloading", ".vdm"
}

FILE_SKIP_PATH_FRAGMENTS = {
    "\\Google\\Chrome\\User Data\\Default\\Cache\\",
    "\\Google\\Chrome\\User Data\\Default\\Code Cache\\",
    "\\Microsoft\\Edge\\User Data\\Default\\Cache\\",
}

AUTHENTICODE_DAMPEN_FACTOR = 0.4

FILE_ACTION_ADDED = 1
FILE_ACTION_RENAMED_NEW = 5


class FileMonitor:
    def __init__(self, ml_manager: MLModelManager):
        self.ml_manager = ml_manager
        self.scanned_paths = set()
        self.dir_handles = {}
        self.pending_events = []
        self._monitor_thread = None
        self._stop = threading.Event()

        if not HAS_WIN32FILE:
            logger.warning("win32file not available — file monitoring disabled")
            return

        for dir_path in WATCHED_DIRS_WINDOWS:
            if os.path.isdir(dir_path):
                try:
                    handle = win32file.CreateFile(
                        dir_path,
                        1,
                        win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
                        None,
                        win32con.OPEN_EXISTING,
                        win32con.FILE_FLAG_BACKUP_SEMANTICS,
                        None,
                    )
                    self.dir_handles[dir_path] = handle
                    logger.info("FileMonitor watching: %s", dir_path)
                except Exception as e:
                    logger.warning("FileMonitor: cannot watch %s: %s", dir_path, e)

        self._monitor_threads = []
        for dir_path, handle in self.dir_handles.items():
            t = threading.Thread(target=self._watch_dir, args=(dir_path, handle), daemon=True)
            t.start()
            self._monitor_threads.append(t)

    def _watch_dir(self, dir_path, handle):
        while not self._stop.is_set():
            results = []
            try:
                results = win32file.ReadDirectoryChangesW(
                    handle, 4096, True, 0x11, None, None,
                )
                for action, filename in results:
                    if action in (FILE_ACTION_ADDED, FILE_ACTION_RENAMED_NEW):
                        full_path = os.path.join(dir_path, filename)
                        self.pending_events.append(full_path)
            except Exception as e:
                break

    def poll(self) -> list:
        events = []
        paths_to_scan = list(self.pending_events)
        self.pending_events.clear()

        for file_path in paths_to_scan:
            if file_path in self.scanned_paths:
                continue
            self.scanned_paths.add(file_path)

            if not os.path.isfile(file_path):
                continue

            ext = os.path.splitext(file_path)[1].lower()
            if ext in FILE_SKIP_EXTENSIONS:
                continue

            if file_path.startswith(QUARANTINE_DIR_WINDOWS):
                continue

            if any(frag in file_path for frag in FILE_SKIP_PATH_FRAGMENTS):
                continue

            try:
                file_size = os.path.getsize(file_path)
            except OSError:
                continue
            if file_size < FILE_SCAN_MIN_SIZE or file_size > FILE_SCAN_MAX_SIZE:
                continue

            score, features = self.ml_manager.score_file(file_path)
            is_document = False
            if score is None:
                score, features = self.ml_manager.score_document(file_path)
                is_document = True
            if score is None:
                continue

            auth_info = {"signed": False, "valid": False, "trusted": False, "publisher": ""}
            if not is_document and score >= 0.3:
                auth_info = verify_authenticode(file_path)
                if auth_info["trusted"]:
                    original_score = score
                    score = score * AUTHENTICODE_DAMPEN_FACTOR
                    logger.info(
                        "Authenticode trust: %s signed by '%s' - score dampened %.2f → %.2f",
                        file_path, auth_info["publisher"], original_score, score
                    )

            logger.info(
                "File ML score: path=%s size=%d entropy=%.2f score=%.4f",
                file_path, file_size,
                features.get("whole_file_entropy", 0),
                score,
            )

            try:
                with open(file_path, "rb") as fh:
                    file_hash = hashlib.sha256(fh.read()).hexdigest()
            except (OSError, PermissionError):
                file_hash = ""

            event_data = {
                "file_path": file_path,
                "file_name": os.path.basename(file_path),
                "file_size": file_size,
                "file_hash": f"sha256:{file_hash}",
                "entropy": round(features.get("whole_file_entropy", 0), 4),
                "num_sections": int(features.get("num_sections", 0)),
                "suspicious_imports": int(features.get("suspicious_import_count", 0)),
                "has_signature": bool(features.get("has_signature", 0)),
                "authenticode_signed": auth_info["signed"],
                "authenticode_valid": auth_info["valid"],
                "authenticode_trusted": auth_info["trusted"],
                "authenticode_publisher": auth_info["publisher"], 
                "is_pe": not is_document,
                "is_document": is_document,
                "writable_executable_sections": int(features.get("writable_executable_sections", 0)),
                "ml_score": score,
            }

            severity = "info"
            if score >= 0.95:
                severity = "critical"
            elif score >= 0.70:
                severity = "warning"

            response_action = None
            if AUTO_RESPONSE_MODE in ("dry_run", "enforce"):
                if score >= AUTO_RESPONSE_KILL_THRESHOLD:
                    response_action = "delete_and_kill"
                elif score >= AUTO_RESPONSE_QUARANTINE_THRESHOLD:
                    response_action = "quarantine_file"

            if response_action and AUTO_RESPONSE_MODE == "enforce":
                try:
                    if response_action == "delete_and_kill":
                        os.remove(file_path)
                        logger.warning(
                            "AUTO-RESPONSE: deleted %s (score=%.2f)",
                            file_path, score,
                        )
                    elif response_action == "quarantine_file":
                        os.makedirs(QUARANTINE_DIR_WINDOWS, exist_ok=True)
                        quarantine_dest = os.path.join(
                            QUARANTINE_DIR_WINDOWS,
                            f"{int(time.time())}_{os.path.basename(file_path)}",
                        )
                        os.rename(file_path, quarantine_dest)
                        logger.warning(
                            "AUTO-RESPONSE: quarantined %s → %s (score=%.2f)",
                            file_path, quarantine_dest, score,
                        )
                except OSError as e:
                    logger.error("AUTO-RESPONSE failed for %s: %s", file_path, e)
            elif response_action and AUTO_RESPONSE_MODE == "dry_run":
                logger.info(
                    "AUTO-RESPONSE (dry_run): would %s %s (score=%.2f)",
                    response_action, file_path, score,
                )

            telemetry_event = {
                "event_type": "file",
                "event_subtype": "file_write",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "severity": severity,
                "malware_confidence": score,
                "data": {
                    **event_data,
                    "auto_response_action": response_action,
                    "auto_response_mode": AUTO_RESPONSE_MODE,
                    "auto_response_file_path": file_path,
                },
            }
            events.append(telemetry_event)

            if score >= 0.70:
                logger.warning(
                    "FILE ALERT: %s score=%.2f entropy=%.2f",
                    file_path, score,
                    features.get("whole_file_entropy", 0),
                )

        if len(self.scanned_paths) > 10000:
            self.scanned_paths.clear()

        return events

    def stop(self):
        self._stop.set()
        for handle in self.dir_handles.values():
            try:
                win32file.CloseHandle(handle)
            except Exception:
                pass

_MEM_SCAN_PROCESS_QUERY = 0x0400
_MEM_SCAN_PROCESS_VM_READ = 0x0010
_MEM_SCAN_PAGE_EXECUTE_READWRITE = 0x40
_MEM_SCAN_MEM_COMMIT = 0x1000

_MEM_SCAN_EXECUTABLE_FLAGS = {0x10, 0x20, 0x40, 0x80}
_MEM_SCAN_RWX_FLAGS = {0x40}

MEMORY_SCAN_INTERVAL = 60

MEMORY_SKIP_PROCESSES = {"system", "registry", "idle", "smss.exe", "csrss.exe", "mem compression"}

MEMORY_KNOWN_JIT_PROCESSES = {
    "msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe",
    "msedgewebview2.exe", "microsoftedgeupdate.exe", "node.exe",
    "java.exe", "javaw.exe", "powershell.exe", "pwsh.exe", "dotnet.exe",
    "msbuild.exe", "devenv.exe", "code.exe", "sdxhelper.exe", "onenotem.exe",
    "searchhost.exe", "startmenuexperiencehost.exe", "searchfilterhost.exe",
    "textinputhost.exe", "widgetservice.exe", "dllhost.exe", "smartscreen.exe", 
    "windowsterminal.exe", "dwm.exe", "shellhost.exe", "crossdeviceresume.exe", 
    "sppextcomobj.exe", "searchprotocolhost.exe",
}

class _MEM_BASIC_INFO(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]

_mem_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_mem_psapi = ctypes.WinDLL("psapi", use_last_error=True)

_mem_OpenProcess = _mem_kernel32.OpenProcess
_mem_OpenProcess.restype = wt.HANDLE
_mem_OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]

_mem_CloseHandle = _mem_kernel32.CloseHandle
_mem_VirtualQueryEx = _mem_kernel32.VirtualQueryEx

_mem_GetMappedFileNameW = _mem_psapi.GetMappedFileNameW
_mem_GetMappedFileNameW.restype = wt.DWORD
_mem_GetMappedFileNameW.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_wchar_p, wt.DWORD]


class MemoryAnomalyMonitor:
    def __init__(self):
        self._stop = threading.Event()
        self._findings_queue = []
        self._seen_findings = set()
        self._thread = threading.Thread(target=self._scan_loop, daemon=True)
        self._thread.start()
        logger.info("MemoryAnomalyMonitor started (interval=%ds)", MEMORY_SCAN_INTERVAL)

    def _scan_loop(self):
        while not self._stop.is_set():
            try:
                self._run_full_scan()
            except Exception as e:
                logger.error("Memory anomaly scan error: %s", e)
            self._stop.wait(MEMORY_SCAN_INTERVAL)

    def _run_full_scan(self):
        for proc in psutil.process_iter(["pid", "name"]):
            if self._stop.is_set():
                break
            try:
                pid = proc.info["pid"]
                name = (proc.info["name"] or "").lower()
                if name in MEMORY_SKIP_PROCESSES:
                    continue
                self._scan_process(pid, proc.info["name"] or "unknown")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _scan_process(self, pid: int, proc_name: str):
        is_jit = proc_name.lower() in MEMORY_KNOWN_JIT_PROCESSES

        handle = _mem_OpenProcess(_MEM_SCAN_PROCESS_QUERY | _MEM_SCAN_PROCESS_VM_READ, False, pid)
        if not handle:
            return

        try:
            address = 0
            mbi = _MEM_BASIC_INFO()

            while True:
                ret = _mem_VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
                if not ret:
                    break

                prot = mbi.Protect & 0xFF
                is_committed = mbi.State == _MEM_SCAN_MEM_COMMIT
                is_rwx = prot in _MEM_SCAN_RWX_FLAGS

                if is_committed and is_rwx and not is_jit:
                    region_base = hex(mbi.BaseAddress) if mbi.BaseAddress else hex(address)

                    finding_key = f"{pid}:{region_base}"
                    if finding_key not in self._seen_findings:
                        self._seen_findings.add(finding_key)

                        backing = self._get_backing(handle, mbi.BaseAddress or address)

                        self._findings_queue.append({
                            "event_type": "memory",
                            "event_subtype": "rwx_region",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "severity": "critical",
                            "malware_confidence": 0.95,
                            "data": {
                                "pid": pid,
                                "process_name": proc_name,
                                "finding_type": "rwx_region",
                                "region_base": region_base,
                                "region_size": mbi.RegionSize,
                                "protection": "EXECUTE_READWRITE",
                                "backing_file": backing or "none (private)",
                            },
                        })
                        logger.warning(
                            "MEMORY ALERT: %s PID=%d RWX region at %s size=%d backing=%s",
                            proc_name, pid, region_base, mbi.RegionSize, backing or "private"
                        )

                address = (mbi.BaseAddress or address) + mbi.RegionSize
                if address >= 0x7FFFFFFFFFFF:
                    break

        except Exception as e:
            logger.debug("Memory scan error PID %d: %s", pid, e)
        finally:
            _mem_CloseHandle(handle)

    @staticmethod
    def _get_backing(handle, addr: int) -> str:
        buf = ctypes.create_unicode_buffer(512)
        length = _mem_GetMappedFileNameW(handle, ctypes.c_void_p(addr), buf, 512)
        return buf.value if length > 0 else ""

    def poll(self) -> list:
        events = list(self._findings_queue)
        self._findings_queue.clear()
        return events

    def stop(self):
        self._stop.set()
        self._seen_findings.clear()
            
    
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

        self.file_monitor = FileMonitor(self.ml_manager)
        self.memory_monitor = MemoryAnomalyMonitor()

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
        if EDR_API_KEY:
            payload["api_key"] = EDR_API_KEY
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

                quarantine_path = os.path.join(
                    QUARANTINE_DIR_WINDOWS,
                    f"{int(time.time())}_{os.path.basename(file_path)}"
                )
                os.makedirs(QUARANTINE_DIR_WINDOWS, exist_ok=True)
                os.rename(file_path, quarantine_path)
                result = f"File quarantined to {quarantine_path}"

            elif action_type == "restore_quarantine":
                file_name = action_params.get("file_name", "")
                original_path = action_params.get("original_path", "")
                quarantine_match = None
                if os.path.isdir(QUARANTINE_DIR_WINDOWS):
                    for entry in os.listdir(QUARANTINE_DIR_WINDOWS):
                        if entry.endswith("_" + file_name) or entry == file_name:
                            quarantine_match = os.path.join(QUARANTINE_DIR_WINDOWS, entry)
                            break
                if not quarantine_match:
                    result = f"File not found in quarantine: {file_name}"
                elif not original_path:
                    restore_to = os.path.join(
                        os.path.expandvars(r"%USERPROFILE%\Desktop"), file_name
                    )
                    os.rename(quarantine_match, restore_to)
                    result = f"File restored to {restore_to}"
                else:
                    os.rename(quarantine_match, original_path)
                    result = f"File restored to {original_path}"

            elif action_type == "delete_quarantine":
                file_name = action_params.get("file_name", "")
                deleted = False
                if os.path.isdir(QUARANTINE_DIR_WINDOWS):
                    for entry in os.listdir(QUARANTINE_DIR_WINDOWS):
                        if entry.endswith("_" + file_name) or entry == file_name:
                            os.remove(os.path.join(QUARANTINE_DIR_WINDOWS, entry))
                            deleted = True
                            break
                result = f"Deleted {file_name}" if deleted else f"File not found: {file_name}"

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
        cmd = (event_data.get("command_line") or "").lower()
        if "get-authenticodesignature" in cmd:
            return {
                "event_type": "process",
                "event_subtype": "process_create",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "severity": "info",
                "malware_confidence": 0.0,
                "data": event_data,
            }

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
        events.extend(self.file_monitor.poll())
        events.extend(self.memory_monitor.poll())
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

                if time.time() - self.last_telemetry_send >= HEARTBEAT_INTERVAL:
                    self._send_heartbeat()
                    self.last_telemetry_send = time.time()

                time.sleep(1)
            except Exception as e:
                logger.error(f"Telemetry error: {e}")
    
    def send_telemetry(self):
        if not self.telemetry_buffer or not self.sio.connected:
            return
        
        events = list(self.telemetry_buffer)
        self.telemetry_buffer.clear()

        try:
            payload = {
                "agent_id": self.agent_id,
                "events": events,
            }
            if EDR_API_KEY:
                payload["api_key"] = EDR_API_KEY
            self.sio.emit("telemetry", payload)
            self.last_telemetry_send = time.time()
            logger.debug(f"Sent {len(events)} telemetry events")
        except Exception as e:
            logger.error(f"Telemetry send error: {e}")
            for event in events:
                self.telemetry_buffer.append(event)

    def _send_heartbeat(self):
        if not self.sio.connected:
            return
        payload = {"agent_id": self.agent_id, "events": []}
        if EDR_API_KEY:
            payload["api_key"] = EDR_API_KEY
        try:
            self.sio.emit("telemetry", payload)
            logger.debug("Sent heartbeat (idle keepalive)")
        except Exception as e:
            logger.error(f"Heartbeat error: {e}")

    def run(self):
        self.running = True
        logger.info(f"Starting Windows endpoint agent {self.agent_id}")

        telemetry_thread = threading.Thread(target=self.telemetry_worker, daemon=True)
        telemetry_thread.start()

        while self.running:
            try:
                if not self.sio.connected:
                    self.sio.connect(BACKEND_URL, transports=["polling"])
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
        self.memory_monitor.stop()
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

