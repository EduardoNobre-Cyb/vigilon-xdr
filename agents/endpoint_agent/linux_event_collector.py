import os
import pwd
import queue
import re
import subprocess
import threading
from typing import Dict, Optional
import logging


AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", "/var/log/audit/audit.log")
AUDIT_KEY = os.getenv("AUDIT_KEY", "edr_process_exec")

logger = logging.getLogger(__name__)


def _field(pattern: str, text: str, default: str = "") -> str:
    match = re.search(pattern, text)
    return match.group(1) if match else default

def _event_id(text: str) -> Optional[str]:
    match = re.search(r"msg=audit\([^:]+:(\d+)\)", text)
    return match.group(1) if match else None

def _user_name(uid: str) -> str:
    try:
        return pwd.getpwuid(int(uid)).pw_name
    except (KeyError, TypeError, ValueError):
        return uid or "unknown"

def _parent_name(ppid) -> str:
    try:
        with open(f"/proc/{int(ppid)}/comm", "r", encoding="utf-8") as handle:
            return handle.read().strip() or "unknown"
    except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError, TypeError):
        return "unknown"

def _decode_args(execve_line: str) -> list:
    argc_match = re.search(r"\bargc=(\d+)", execve_line)
    argc = int(argc_match.group(1)) if argc_match else 0
    args = []
    for index in range(argc if argc else 64):
        quoted = re.search(rf'\ba{index}="([^"]*)"', execve_line)
        if quoted:
            args.append(quoted.group(1))
            continue
        hexed = re.search(rf"\ba{index}=([0-9A-Fa-f]+)(?=\s|$)", execve_line)
        if hexed:
            try:
                args.append(bytes.fromhex(hexed.group(1)).decode("utf-8", "replace"))
            except ValueError:
                args.append("")
            continue
        if not argc:
            break
    return args


class AuditdProcessCollector:
    """Read auditd EXECVE records and emit normalized process events."""

    def __init__(self, log_path: str = AUDIT_LOG_PATH, audit_key: str = AUDIT_KEY):
        self.log_path = log_path
        self.audit_key = audit_key
        self.seen_executables = set()
        self.pending_records = {}
        self.event_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.reader_thread = None
        self.reader_process = None

    def _normalize(self, syscall_line: str, execve_line: str) -> Dict:
        executable = _field(r'exe="([^"]+)"', syscall_line)
        process_name = os.path.basename(executable) or _field(r'comm="([^"]+)"', syscall_line)
        pid = int(_field(r"\bpid=(\d+)", syscall_line, "0"))
        ppid = int(_field(r"\bppid=(\d+)", syscall_line, "0"))
        uid = _field(r"\buid=(\d+)", syscall_line, "")

        arguments = _decode_args(execve_line)

        command_line = " ".join(arguments) or process_name
        is_first_seen = executable not in self.seen_executables
        self.seen_executables.add(executable)


        return {
            "pid": pid,
            "ppid": ppid,
            "name": process_name,
            "path": executable,
            "command_line": command_line,
            "parent_name": _parent_name(ppid),
            "user": _user_name(uid),
            "is_first_seen": is_first_seen,
            "event_source": "auditd",
            "audit_event_id": _event_id(execve_line)
        }

    def _read_events(self):
        command = ["tail", "-F", "-n", "0", self.log_path]
        try:
            self.reader_process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        except Exception:
            logger.exception("Failed to start audit log reader process")
            return
        try:
            for line in self.reader_process.stdout:
                if self.stop_event.is_set():
                    break
                if "type=SYSCALL" in line:
                    event_id = _event_id(line)
                    if event_id:
                        records = self.pending_records.setdefault(event_id, {})
                        records["syscall"] = line

                        if "execve" in records:
                            self.event_queue.put(
                                self._normalize(records["syscall"], records["execve"])
                            )
                            self.pending_records.pop(event_id, None)
                    continue

                if "type=EXECVE" not in line:
                    continue

                event_id = _event_id(line)
                if event_id:
                    records = self.pending_records.setdefault(event_id, {})
                    records["execve"] = line

                    if "syscall" in records:
                        self.event_queue.put(
                            self._normalize(records["syscall"], records["execve"])
                        )
                        self.pending_records.pop(event_id, None)
        except Exception:
            logger.exception("Audit log reader stopped unexpectedly")
        finally:
            if self.reader_process is not None:
                logger.info("Terminating audit log reader process")
                self.reader_process.terminate()
                try:
                    self.reader_process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    logger.warning("Audit log reader process did not terminate in time. Forcing termination")
                    self.reader_process.kill()

    def start(self):
        self.stop_event.clear()
        self.reader_thread = threading.Thread(target=self._read_events, daemon=True)
        self.reader_thread.start()

    def poll(self, max_events: int = 100):
        events = []
        for _ in range(max_events):
            try:
                events.append(self.event_queue.get_nowait())
            except queue.Empty:
                break
        return events

    def stop(self):
        self.stop_event.set()
        if self.reader_process is not None:
            self.reader_process.terminate()
        if self.reader_thread is not None:
            self.reader_thread.join(timeout=3)