import logging
import os
import sys
from pathlib import Path
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler


class SizeAndTimeRotatingFileHandler(TimedRotatingFileHandler):
    """Rotate logs at time boundary or when file exceeds size cap.

    - Time rotation: handled by TimedRotatingFileHandler (midnight)
    - Size rotation: custom safeguard (maxBytes)
    - Retention: delete rotated files older than retention_days
    """

    def __init__(
        self,
        filename,
        when="midnight",
        interval=1,
        backupCount=0,
        encoding=None,
        delay=False,
        utc=False,
        atTime=None,
        maxBytes: int = 0,
        retention_days: int = 30,
    ):
        super().__init__(
            filename=filename,
            when=when,
            interval=interval,
            backupCount=backupCount,
            encoding=encoding,
            delay=delay,
            utc=utc,
            atTime=atTime,
        )
        self.maxBytes = max(0, int(maxBytes or 0))
        self.retention_days = max(1, int(retention_days or 30))
        self._rollover_reason = None

    def shouldRollover(self, record):
        if super().shouldRollover(record):
            self._rollover_reason = "time"
            return 1

        if self.maxBytes <= 0:
            return 0

        if self.stream is None:
            self.stream = self._open()

        msg = "%s\n" % self.format(record)
        try:
            message_size = len(msg.encode(self.encoding or "utf-8", errors="replace"))
        except Exception:
            message_size = len(msg)

        self.stream.seek(0, os.SEEK_END)
        if self.stream.tell() + message_size >= self.maxBytes:
            self._rollover_reason = "size"
            return 1

        return 0

    def doRollover(self):
        reason = self._rollover_reason
        self._rollover_reason = None

        if reason == "time":
            super().doRollover()
            self._cleanup_old_logs()
            return

        # Size-based safeguard rollover
        if self.stream:
            self.stream.close()
            self.stream = None

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        destination = f"{self.baseFilename}.{timestamp}"
        counter = 1
        while os.path.exists(destination):
            destination = f"{self.baseFilename}.{timestamp}.{counter}"
            counter += 1

        if os.path.exists(self.baseFilename):
            self.rotate(self.baseFilename, destination)

        if not self.delay:
            self.stream = self._open()

        self._cleanup_old_logs()

    def _cleanup_old_logs(self):
        cutoff_ts = datetime.now().timestamp() - (self.retention_days * 24 * 60 * 60)
        log_path = Path(self.baseFilename)
        for rotated_file in log_path.parent.glob(f"{log_path.name}.*"):
            try:
                if rotated_file.is_file() and rotated_file.stat().st_mtime < cutoff_ts:
                    rotated_file.unlink()
            except Exception:
                # Never break logging on cleanup failure
                pass


def setup_agent_logger(agent_id: str, verbose: bool = True) -> logging.Logger:
    """Configure logging for a specific agent with both file and console output."""
    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)  # No error if it already exists

    # Using agent_id as logger mean for all messages to be tagged with it
    logger = logging.getLogger(agent_id)
    logger.setLevel(logging.DEBUG)  # Capture everything from DEBUG and above

    # Prevents Duplicate logs
    if logger.hasHandlers():
        return logger

    # File handler for detailed logs (pure Python: daily + size safeguard)
    logs_file_path = logs_dir / f"{agent_id}.log"
    log_max_mb = int(os.getenv("LOG_MAX_MB", "10"))
    retention_days = int(os.getenv("LOG_RETENTION_DAYS", "30"))
    file_handler = SizeAndTimeRotatingFileHandler(
        logs_file_path,
        when="midnight",
        interval=1,
        backupCount=0,
        encoding="utf-8",
        maxBytes=log_max_mb * 1024 * 1024,
        retention_days=retention_days,
    )
    file_handler.suffix = "%Y-%m-%d"
    file_handler.setLevel(logging.DEBUG)  # Log everything to file

    # Console handler — explicitly use stdout so that when agents are spawned
    # by Flask (stderr → log file), console output goes to stdout (DEVNULL)
    # and does NOT duplicate into the log file
    console_handler = logging.StreamHandler(sys.stdout)
    if verbose:
        console_handler.setLevel(
            logging.DEBUG
        )  # Demo mode: show DEBUG and above (detailed scores, etc)
    else:
        console_handler.setLevel(
            logging.INFO
        )  # Listen mode: show INFO and above (milestones only)

    # Format
    formatter = logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    # Prevent messages from propagating to the root logger.
    # Without this, libraries that call logging.basicConfig() add a
    # StreamHandler(stderr) to root.  When agents are spawned by Flask
    # with stderr redirected to the log file, every message would be
    # written twice (once by our FileHandler, once by root’s stderr handler).
    logger.propagate = False

    return logger
