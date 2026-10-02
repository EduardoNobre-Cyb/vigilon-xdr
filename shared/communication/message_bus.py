# Message bus for inter-agent communication


# Redis-based Message Bus for inter-agent communication
import json
from datetime import datetime, timezone
from typing import Dict, Callable
import threading
import os
import redis


class RedisMessageBus:
    def __init__(self, host=None, port=None, db=None):
        host = host or os.getenv("REDIS_HOST", "localhost")
        port = int(port if port is not None else os.getenv("REDIS_PORT", "6379"))
        db = int(db if db is not None else os.getenv("REDIS_DB", "0"))
        self.redis = redis.Redis(host=host, port=port, db=db, decode_responses=True)
        self.sub_threads = []

    def publish(self, channel: str, message: Dict):
        # Add timestamp and channel info
        msg = {**message, "timestamp": datetime.now().isoformat(), "channel": channel}
        self.redis.publish(channel, json.dumps(msg))
        print(
            f"[RedisMessageBus] Published to '{channel}': {message.get('type', 'unknown')}"
        )

    def subscribe(self, channel: str, callback: Callable):
        def listen():
            pubsub = self.redis.pubsub()
            pubsub.subscribe(channel)
            print(f"[RedisMessageBus] Subscribed to '{channel}'")
            for item in pubsub.listen():
                if item["type"] == "message":
                    try:
                        msg = json.loads(item["data"])
                        callback(msg)
                    except Exception as e:
                        print(f"[RedisMessageBus] Error: {e}")

        t = threading.Thread(target=listen, daemon=True)
        t.start()
        self.sub_threads.append(t)

    def heartbeat(self, agent_id: str, status: str = "running"):
        """Write agent heartbeat to Redis for dashboard monitoring"""
        # UTC with offset (+00:00) so browsers convert it to the viewer's local time
        now = datetime.now(timezone.utc).isoformat()
        # setex = SET with EXpiry. Key auto-deletes after 30 seconds
        # if agent fails to update, it will appear "Stopped"
        self.redis.setex(f"agent:{agent_id}:heartbeat", 30, now)
        self.redis.setex(f"agent:{agent_id}:status", 30, status)


# Global message bus instance
message_bus = RedisMessageBus()
