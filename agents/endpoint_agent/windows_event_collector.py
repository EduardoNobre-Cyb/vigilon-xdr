import os 
import queue
import logging
import threading
import xml.etree.ElementTree as ET

import win32event
import win32evtlog


SYSMON_CHANNEL = os.getenv("SYSMON_CHANNEL", "Microsoft-Windows-Sysmon/Operational")
SYSMON_QUERY = os.getenv("SYSMON_QUERY", "*[System[(EventID=1)]]")

_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

logger = logging.getLogger(__name__)


def _event_data(root: ET.Element) -> dict:
    fields = {}
    for data in root.findall("./e:EventData/e:Data", _NS):
        name = data.get("Name")
        if name:
            fields[name] = data.text or ""
    return fields


class SysmonProcessCollector:
    def __init__(self, channel: str = SYSMON_CHANNEL, query: str = SYSMON_QUERY):
        self.channel = channel
        self.query = query
        self.seen_executables = set()
        self.event_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.reader_thread = None
        self.signal = None
        self.subscription = None

    def _normalize(self, fields: dict) -> dict:
        image = fields.get("Image", "")
        parent_image = fields.get("ParentImage", "")
        command_line = fields.get("CommandLine", "") or os.path.basename(image)

        is_first_seen = image not in self.seen_executables
        self.seen_executables.add(image)

        def _as_int(value):
            try:
                return int(value)
            except (TypeError, ValueError):
                return 0

        return {
            "pid": _as_int(fields.get("ProcessId")),
            "ppid": _as_int(fields.get("ParentProcessId")),
            "name": os.path.basename(image),
            "path": image,
            "command_line": command_line,
            "parent_name": os.path.basename(parent_image) or "unknown",
            "user": fields.get("User", "") or "unknown",
            "is_first_seen": is_first_seen,
            "event_source": "sysmon",
        }

    def _read_events(self):
        self.signal = win32event.CreateEvent(None, 0, 0, None)
        try:
            self.subscription = win32evtlog.EvtSubscribe(
                self.channel,
                win32evtlog.EvtSubscribeToFutureEvents,
                SignalEvent=self.signal,
                Query=self.query,
            )
        except Exception:
            logger.exception("Failed to subscribe to the Sysmon event channel")
            return

        while not self.stop_event.is_set():
            win32event.WaitForSingleObject(self.signal, 1000)
            while not self.stop_event.is_set():
                try:
                    handles = win32evtlog.EvtNext(self.subscription, 20)
                except Exception:
                    break
                if not handles:
                    break
                for handle in handles:
                    try:
                        xml = win32evtlog.EvtRender(handle, win32evtlog.EvtRenderEventXml)
                        root = ET.fromstring(xml)
                        self.event_queue.put(self._normalize(_event_data(root)))
                    except Exception:
                        logger.exception("Failed to render/parse a Sysmon event")

    def start(self):
        self.stop_event.clear()
        self.reader_thread = threading.Thread(target=self._read_events, daemon=True)
        self.reader_thread.start()
        logger.info("Sysmon collector started on channel %s", self.channel)

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
        if self.signal is not None:
            win32event.SetEvent(self.signal)
        if self.reader_thread is not None:
            self.reader_thread.join(timeout=3)
