import logging
import os

import requests

log = logging.getLogger(__name__)

NTFY_URL = os.environ.get("NTFY_URL", "https://ntfy.sh").rstrip("/")
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "").strip()
NTFY_TOKEN = os.environ.get("NTFY_TOKEN", "").strip()
BARK_URL = os.environ.get("BARK_URL", "https://api.day.app").rstrip("/")
BARK_KEY = os.environ.get("BARK_KEY", "").strip()
ICON_URL = os.environ.get("NOTIFY_ICON_URL", "").strip()

BARK_LEVEL = {5: "timeSensitive", 4: "active", 3: "active"}

def alerts_enabled() -> bool:
    return bool(BARK_KEY)

def send_alert(title: str, message: str, priority: int = 3, tags=None):
    if NTFY_TOPIC:
        headers = {"Authorization": f"Bearer {NTFY_TOKEN}"} if NTFY_TOKEN else {}
        payload = {"topic": NTFY_TOPIC, "title": title, "message": message, "priority": priority, "tags": tags or []}
        if ICON_URL:
            payload["icon"] = ICON_URL
        _post(NTFY_URL, payload, headers, title)
    if BARK_KEY:
        payload = {"device_key": BARK_KEY, "title": title, "body": message, "group": "Vigilon", "level": BARK_LEVEL.get(priority, "passive")}
        if ICON_URL:
            payload["icon"] = ICON_URL
        _post(f"{BARK_URL}/push", payload, {}, title)

def _post(url: str, payload: dict, headers: dict, title: str):
    try:
        requests.post(url, json=payload, headers=headers, timeout=10).raise_for_status()
    except requests.RequestException as exc:
        log.warning("Could not send alert '%s' to %s: %s", title, url, exc)