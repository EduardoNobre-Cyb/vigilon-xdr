import os
import math
import re
import hashlib
from typing import Dict, List
from datetime import datetime

import pandas as pd
import numpy as np

class ProcessFeatureExtractor:
    """Extract features from process execution events"""

    def __init__(self):
        # Known suspicious process names (for feature encoding)
        self.suspicious_processes = {
            "cmd", "cmd.exe", "powershell", "powershell.exe", "psexec",
            "psexec.exe", "wmic", "wmic.exe", "rundll32",
            "rundll32.exe", "regsvcs", "certutil", "certutil.exe", "cscript", "cscript.exe",
            "wscript", "wscript.exe", "mshta", "mshta.exe", "schtasks", "sc", "taskkill",
            "reg", "whoami", "nc", "ncat", "netcat", "sh", "bash", "dash", "zsh", "perl", "gawk", "awk", "find", "socat", "php"
        }

        # Known benign parent processes
        self.benign_parents = {
            "explorer.exe", "svchost.exe", "services.exe", "lsass.exe",
            "winlogon.exe", "csrss.exe", "conhost.exe", "audiodg.exe", "systemd", "init", "sshd", "cron", "login", "systemd-logind", "containerd", "containerd-shim", "dockerd", "xfce4-panel", "xfce4-session"
        }

        # System directories
        self.system_dirs = {
            "c:\\windows\\system32", "c:\\windows\\syswow64",
            "c:\\program files", "c:\\program files (x86)"
        }

        self.suspicious_dirs = {
            "c:\\temp", "c:\\users\\", "c:\\programdata",
            "c:\\appdata", "c:\\windows\\temp", "/tmp",
            "/var/tmp", "/dev/shm", "/run/user/"
        }

    def extract_features(self, event: Dict) -> Dict[str, float]:
        """Extract feature vetor from process event"""

        features = {}

        # Process name features
        proc_name = event.get("name", "").lower()
        name_aliases = {
            "nc.traditional": "nc",
            "nc.openbsd": "nc",
            "netcat": "nc",
        }
        proc_name = name_aliases.get(proc_name, proc_name)
        proc_name = self._strip_version(proc_name)
        features["is_suspicious_process"] = 1.0 if proc_name in self.suspicious_processes else 0.0
        features["process_name_length"] = min(len(proc_name) / 50, 1.0)
        # Normalize

        # Command line features
        cmdline = event.get("command_line", "").lower()
        features["cmdline_length"] = min(len(cmdline) / 1000, 1.0)
        features["cmdline_entropy"] = self._calculate_entropy(cmdline)

        # Suspicious keywords count
        keywords = ["powershell", "cmd", "-enc", "execute", "bypass", "hidden", "obf", "base64", "curl", "wget", "| bash", "| sh", "/dev/tcp/", "nc -e", "nc -vz", "ncat", "chmod +s", "/dev/shm", "-qo-", "system(", "pty.spawn", "-exec /bin/sh", "-exec /bin/bash", "fsockopen", "tcp-connect:", "exec:/bin/", "sh -i", "socket.socket"]
        keyword_count = sum(1 for kw in keywords if kw in cmdline)
        features["suspicious_keywords_count"] = min(keyword_count / 5, 1.0)

        # Path features
        path = event.get("path", "").lower()
        path_and_cmd = f"{path} {cmdline}"
        features["execution_in_temp"] = 1.0 if any(d in path_and_cmd for d in self.suspicious_dirs) else 0.0
        features["execution_in_system"] = 1.0 if any(d in path for d in self.system_dirs) else 0.0

        # Parent process features
        parent_name = event.get("parent_name", "").lower()
        features["is_benign_parent"] = 1.0 if parent_name in self.benign_parents else 0.0
        features["parent_is_system_process"] = 1.0 if parent_name in {"services.exe", "csrss.exe"} else 0.0

        # User/Elevation features
        user = event.get("user", "").upper()
        features["is_elevated"] = 1.0 if user in {"SYSTEM", "NT AUTHORITY\\SYSTEM"} else 0.0
        features["is_admin"] = 1.0 if "ADMIN" in user or "Administrator" in user else 0.0

        # Temporal features
        features["is_first_seen"] = float(event.get("is_first_seen", False))

        # Filename features
        filename = self._strip_version(os.path.basename(path))
        features["filename_length"] = min(len(filename) / 100, 1.0)
        features["has_long_extension"] = 1.0 if filename.count(".") > 1 else 0.0

        return features

    def _strip_version(self, name: str) -> str:
        match = re.match(r"^(python3|php|socat|perl|ruby|lua|note)[\d.]+$", name)
        return match.group(1) if match else name
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text [0-1]"""
        if not text:
            return 0.0
        
        # Count character frequencies
        frequencies = {}
        for char in text:
            frequencies[char] = frequencies.get(char, 0) + 1

        # Calcuate entropy
        entropy = 0.0
        for freq in frequencies.values():
            p = freq / len(text)
            entropy -= p * math.log2(p)

        # Normalize to [0, 1]
        max_entropy = math.log2(len(set(text))) if len(set(text)) > 0 else 1
        return entropy / max_entropy if max_entropy > 0 else 0.0

class NetworkFeatureExtractor:
    """Extract features from network connection events"""

    def __init__(self):
        self.c2_ports = {
            4444, 5555, 8888, 9999, 31337, 12345,
            6667, 6666, # IRC
            1433, 3306, # Databases
        }

        self.suspicious_destinations = {
            "0.0.0.0", "255.255.255.255", "127.0.0.1"
        }

    def extract_features(self, event: Dict) -> Dict[str, float]:
        """Extract feature vector from network event"""

        features = {}

        # Destination port features
        dst_port = event.get("dest_port", 0)
        features["is_c2_port"] = 1.0 if dst_port in self.c2_ports else 0.0
        features["is_high_port"] = 1.0 if dst_port > 10000 else 0.0
        features["is_privileged_port"] = 1.0 if dst_port < 1024 else 0.0
        features["port_frequency"] = min(dst_port / 65535, 1.0) # Normalize

        # Destination IP features
        dst_ip = event.get("dest_ip", "")
        features["is_private_destination"] = self._is_private_ip(dst_ip)
        features["is_suspicious_destination"] = 1.0 if dst_ip in self.suspicious_destinations else 0.0

        # Process context features
        proc_name = event.get("process_name", "").lower()
        suspicious_procs = {"cmd", "cmd.exe", "powershell.exe", "powershell", "psexec", "psexec.exe", "rundll32", "rundll32.exe", "nc", "ncat", "netcat", "nc.traditional"}
        features["suspicious_process_connects"] = 1.0 if proc_name in suspicious_procs else 0.0

        # Timing/Protocol features
        features["is_udp"] = 1.0 if event.get("protocol", "").lower() == "udp" else 0.0

        # Data transfer features
        bytes_sent = event.get("bytes_sent", 0)
        bytes_received = event.get("bytes_received", 0)
        total_bytes = bytes_sent + bytes_received

        features["small_transfer"] = 1.0 if total_bytes < 100 else 0.0
        features["large_transfer"] = 1.0 if total_bytes > 10_000_000 else 0.0
        features["bytes_ratio"] = min(max(bytes_sent, bytes_received) / (total_bytes + 1), 1.0)

        return features

    def _is_private_ip(self, ip: str) -> float:
        """Check if IP is in private range"""
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return 0.0

            octets = [int(p) for p in parts]

            # Check private ranges
            if octets[0] == 10:
                return 1.0
            if octets[0] == 172 and 16 <= octets[1] <= 31:
                return 1.0
            if octets[0] == 192 and octets[1] == 168:
                return 1.0
            if octets[0] ==127: # Localhost
                return 1.0
            
            return 0.0
        except:
            return 0.0
        

class FileFeatureExtractor: 
    """Extract features from file operation events"""

    def __init__(self):
        self.risky_extensions = {
            ".exe", ".dll", ".sys", ".scr", ".bat", ".ps1", ".vbs",
            ".js", ".jar", ".com", ".pif", ".msi", ".cab"
        }

        self.risky_directories = {
            "c:\\temp", "c:\\windows\\temp", "c:\\users\\",
            "c:\\programdata", "c:\\appdata"
        }

    def extract_features(self, event: Dict) -> Dict[str, float]:
        """Extract feature vector from file operation event"""

        features = {}

        # Extension features
        file_path = event.get("file_path", "").lower()
        ext = os.path.splitext(file_path)[1]
        features["risky_extension"] = 1.0 if ext in self.risky_extensions else 0.0
        features["executable_extension"] = 1.0 if ext in {".exe", ".dll", ".sys"} else 0.0

        # Location features
        features["write_to_risky_dir"] = 1.0 if any(d in file_path for d in self.risky_directories) else 0.0
        features["write_to_system_dir"] = 1.0 if "c:\\windows" in file_path or "c:\\program files" in file_path else 0.0

        # Signature features
        features["unsigned_executable"] = 1.0 if not event.get("is_signed", True) and ext in {".exe", ".dll"} else 0.0

        # First-seen features
        features["is_first_seen"] = float(event.get("is_first_seen", False))

        # Operation features
        operation = event.get("operation", "").lower()
        features["is_suspicious_operation"] = 1.0 if operation in {"execute", "write"} else 0.0

        # Size features
        file_size = event.get("file_size", 0)
        features["very_small_file"] = 1.0 if file_size < 1000 else 0.0
        features["very_large_file"] = 1.0 if file_size > 100_000_000 else 0.0

        return features

def extract_dataset_features(events: List[Dict], extractor_type: str) -> pd.DataFrame:
    """Extract features from list of events"""

    if extractor_type == "process":
        extractor = ProcessFeatureExtractor()
    elif extractor_type == "network":
        extractor = NetworkFeatureExtractor()
    elif extractor_type == "file":
        extractor = FileFeatureExtractor()
    else:
        raise ValueError(f"Unknown extractor type: {extractor_type}")
    
    feature_list = []
    for event in events:
        features = extractor.extract_features(event)
        feature_list.append(features)

    return pd.DataFrame(feature_list)
    
