import os
import json
import csv
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from data.models.models import get_session, LogEvent
import re
import calendar
import gzip


# RFC 3164 syslog regex pattern
_SYSLOG_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<service>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)
# Message-level regexes for common services
_NGINX_ACCESS_RE = re.compile(
    r"(?P<client_ip>\d+\.\d+\.\d+\.\d+) - \S+ \[[^\]]+\] "
    r'"(?P<method>\w+) (?P<uri>\S+) HTTP/[\d.]+" (?P<status>\d+) (?P<bytes>\d+)'
)
_SSHD_FAIL_RE = re.compile(
    r"Failed password for (?P<user>\S+) from (?P<client_ip>[\d.]+)"
)
_SSHD_ACCEPT_RE = re.compile(
    r"Accepted \S+ for (?P<user>\S+) from (?P<client_ip>[\d.]+)"
)
_MODSEC_RE = re.compile(
    r'\[id "(?P<rule_id>\d+)"\].*\[msg "(?P<attack_msg>[^"]+)"\].*\[severity "(?P<severity>[^"]+)"\].*\[uri "(?P<uri>[^"]+)"\]'
)
_CVE_RE = re.compile(r"(CVE-\d{4}-\d+)")
_IP_RE = re.compile(r"\b(?P<client_ip>\d{1,3}(?:\.\d{1,3}){3})\b")
_LEVEL_WORDS_RE = re.compile(
    r"\b(CRITICAL|ERROR|WARN(?:ING)?|INFO|DEBUG|NOTICE)\b", re.I
)


class LogIngestor:
    """Ingests and normalizes log files from multiple sources."""

    def __init__(self, sources: List[Dict[str, Any]], batch_size: int = 100):
        """
        sources: List of dicts, e.g. [{"type": "file", "path": "/var/log/syslog"}, ...]
        batch_size: How many logs to process at once
        """
        self.sources = sources
        self.batch_size = batch_size
        self.buffer = []

    def ingest(self) -> List[Dict[str, Any]]:
        """Ingest logs from all sources and return normalized events with source info."""
        all_events = []
        for source in self.sources:
            if source["type"] == "file":
                events = self._read_file(source["path"], source=source["path"])
                all_events.extend(events)
            # Add more source types (syslog, API, etc.) as needed
        return all_events

    def _read_file(self, path: str, source=None) -> List[Dict[str, Any]]:
        """Read and parse logs from a file, attach source info."""
        events = []

        # Check if gzipped
        is_gzipped = path.endswith(".gz") or path.endswith(".gzip")

        try:
            # Open file (gzipped or raw)
            if is_gzipped:
                # Open gzipped file
                file_handle = gzip.open(
                    path, "rt", encoding="utf-8"
                )  # "rt" = read text
                print(f"📂 Reading gzipped log file: {path}")
            else:
                # Open raw file
                file_handle = open(path, "r", encoding="utf-8")
                print(f"📂 Reading log file: {path}")

            # Keep file open for entire process
            with file_handle as f:
                # Detect format (JSON, syslog, CSV, etc..)
                first_line = f.readline()
                if not first_line:
                    print(f"⚠️  Empty file: {path}")
                    return events

                # Determine format
                log_format = self._detect_format(first_line)
                print(f"🔍 Detected format: {log_format}")

                # Reset to beginning
                f.seek(0)

                # Parse based on detected format
                events = self._parse_file(f, log_format, source)

        except gzip.BadGzipFile:
            print(f"❌ BadGzipFile: {path} appears to be corrupted or not gzipped")
            return []
        except Exception as e:
            print(f"❌ Error reading {path}: {e}")
            return []

        print(f"✅ Parsed {len(events)} events from {path}")
        return events

    def _detect_format(self, first_line: str) -> str:
        """Detect log format from first line."""

        first_line_stripped = first_line.strip()

        # Try JSON
        if first_line_stripped.startswith("{"):
            return "json"

        # Try syslog
        if any(
            month in first_line
            for month in [
                "Jan",
                "Feb",
                "Mar",
                "Apr",
                "May",
                "Jun",
                "Jul",
                "Aug",
                "Sep",
                "Oct",
                "Nov",
                "Dec",
            ]
        ):
            return "syslog"

        # Try CSV
        if "," in first_line and ('"' in first_line or "'" in first_line):
            return "csv"

        # Default to plain text
        return "plain_text"

    def _parse_log_line(self, line: str, format: str) -> Optional[Dict[str, Any]]:
        """Parse a single log line based on detected format."""
        line = line.strip()
        if not line:
            return None

        if format == "json":
            try:
                return json.loads(line)
            except Exception:
                return None
        elif format == "syslog":
            m = _SYSLOG_RE.match(line)
            if m:
                event = m.groupdict()
                event["pid"] = int(event["pid"]) if event["pid"] else None
                event["raw"] = line
                return event
            return None
        elif format == "csv":
            parts = line.split(",")
            return {f"field_{i}": part for i, part in enumerate(parts)}
        else:  # plain_text
            # Use timezone-aware UTC datetime for future compatibility
            return {
                "message": line,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    def _parse_file(self, f, format: str, source=None) -> List[Dict[str, Any]]:
        """Parse log file based on detected format."""
        events = []
        for line in f:
            event = self._parse_log_line(line, format=format)
            if event:
                event["source"] = source
                events.append(event)
        return events


class LogPreprocessor:
    """Preprocesses and normalizes log events."""

    def __init__(self, filters: Optional[List[str]] = None):

        self.filters = filters or []

    def preprocess(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:

        processed = []
        for event in events:
            event = self._normalize_timestamp(event)
            event = self._enrich(event)
            if self._filter(event):
                processed.append(event)
        return processed

    def _normalize_timestamp(self, event: Dict[str, Any]) -> Dict[str, Any]:
        # Try to parse and standardize timestamp
        ts = event.get("timestamp")
        if ts:
            try:
                event["timestamp"] = datetime.fromisoformat(ts).isoformat()
                return event
            except Exception:
                pass

        # Syslog fields produced by the new syslog parser
        month = event.get("month")
        day = event.get("day")
        time_ = event.get("time")
        if month and day and time_:
            try:
                month_num = list(calendar.month_abbr).index(month)
                year = datetime.now(timezone.utc).year
                ts_str = f"{year}-{month_num:02d}-{int(day):02d}T{time_}+00:00"
                event["timestamp"] = datetime.fromisoformat(ts_str).isoformat()
            except Exception:
                event["timestamp"] = datetime.now(timezone.utc).isoformat()
            return event

        # Nothing worked
        event["timestamp"] = datetime.now(timezone.utc).isoformat()
        return event

    def _enrich_syslog_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract structured fields from the message body of a parsed syslog event."""
        msg = event.get("message", "")
        svc = (event.get("service") or "").lower()

        # Derive level from message keywords if not set
        if not event.get("level"):
            m = _LEVEL_WORDS_RE.search(msg)
            if m:
                event["level"] = m.group(1).upper().replace("WARNING", "WARN")

        # nginx / apache access logs
        if svc in ("nginx", "apache", "apache2", "httpd"):
            m = _NGINX_ACCESS_RE.search(msg)
            if m:
                event.update(m.groupdict())
                event["status"] = int(event["status"])
                event["bytes"] = int(event["bytes"])

        # sshd
        elif svc == "sshd":
            m = _SSHD_FAIL_RE.search(msg) or _SSHD_ACCEPT_RE.search(msg)
            if m:
                event.update(m.groupdict())
            event["event_type"] = (
                "login_failure"
                if "Failed" in msg
                else (
                    "login_success"
                    if "Accepted" in msg
                    else "account_lockout" if "locked" in msg else "ssh_event"
                )
            )
            if not event.get("level"):
                event["level"] = "WARN" if "Failed" in msg else "INFO"

        # ModSecurity / WAF
        elif svc in ("modsec", "modsecurity"):
            m = _MODSEC_RE.search(msg)
            if m:
                event.update(m.groupdict())
            event["event_type"] = "waf_block"
            event["level"] = event.get("severity", "WARN")
            # classify attack type from rule message
            lower = msg.lower()
            if "sql" in lower:
                event["attack_type"] = "sqli"
            elif "xss" in lower:
                event["attack_type"] = "xss"
            elif "traversal" in lower:
                event["attack_type"] = "path_traversal"
            elif "ssrf" in lower:
                event["attack_type"] = "ssrf"
            elif "xxe" in lower:
                event["attack_type"] = "xxe"
            elif "smuggl" in lower:
                event["attack_type"] = "request_smuggling"
            elif "deserializ" in lower:
                event["attack_type"] = "insecure_deserialization"

        # snort / IDS
        elif svc in ("snort", "suricata", "ids"):
            event["event_type"] = "ids_alert"
            if not event.get("level"):
                event["level"] = "CRITICAL" if "Priority: 1" in msg else "ERROR"

        # postgresql
        elif svc in ("postgresql", "postgres"):
            if not event.get("level"):
                for word in ("ERROR", "WARNING", "LOG", "FATAL", "PANIC", "NOTICE"):
                    if f" {word}:" in msg:
                        event["level"] = (
                            word if word not in ("LOG", "NOTICE") else "INFO"
                        )
                        break

        # Always try to pull a CVE id and a fallback IP
        cve = _CVE_RE.search(msg)
        if cve:
            event["cve_id"] = cve.group(1)

        if not event.get("client_ip"):
            ip = _IP_RE.search(msg)
            if ip:
                event["client_ip"] = ip.group("client_ip")

        return event

    def _enrich(self, event: Dict[str, Any]) -> Dict[str, Any]:
        # Enrich syslog events that came through the syslog header parser
        if event.get("host") and event.get("service") and not event.get("ingested_by"):
            event = self._enrich_syslog_event(event)
        event["ingested_by"] = "Agent1"
        # Add more enrichment as needed
        return event

    def _filter(self, event: Dict[str, Any]) -> bool:
        # Example: drop events with certain keywords
        for f in self.filters:
            if f in str(event):
                return False
        return True


class Agent1LogIngestion:
    """Vigilon Intake: Log Ingestion Pipeline"""

    def __init__(self, sources, filters=None):
        self.ingestor = LogIngestor(sources)
        self.preprocessor = LogPreprocessor(filters)

    def run(self):
        raw_logs = self.ingestor.ingest()
        clean_logs = self.preprocessor.preprocess(raw_logs)
        self._store_logs(clean_logs)

    def _store_logs(self, logs: List[Dict[str, Any]]):
        session = get_session()
        for log in logs:
            # Extract fields if present
            timestamp = log.get("timestamp")
            # For syslog events, "host" is the natural source
            source = log.get("source") or log.get("host")
            level = log.get("level")
            message = log.get("message") or log.get("raw")  # raw set by syslog parser
            event = LogEvent(
                timestamp=timestamp,
                source=source,
                level=level,
                message=message,
                data=json.dumps(log),
            )
            session.add(event)
        try:
            session.commit()
        except Exception as e:
            session.rollback()
            print(f"Error saving logs: {e}")
        finally:
            session.close()
