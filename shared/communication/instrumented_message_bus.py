from opentelemetry import trace, metrics
import time
from typing import Dict
from .message_bus import MessageBus
import logging


class InstrumentedMessageBus(MessageBus):
    """Message bus with tracing."""

    def __init__(self):
        super().__init__()
        self.tracer = trace.get_tracer(__name__)
        self.meter = metrics.get_meter(__name__)

        # Metrics
        self.msg_counter = self.meter.create_counter("message_published")
        self.msg_latency = self.meter.create_histogram("message_latency_ms")

    def publish(self, topic: str, message: Dict):
        """Publish with tracing."""
        with self.tracer.start_as_current_span(f"publish_{topic}") as span:
            span.set_attribute("topic", topic)
            span.set_attribute("message_id", message.get("id"))

            start = time.time()
            super().publish(topic, message)
            latency_ms = (time.time() - start) * 1000

            self.msg_counter.add(1, {"topic": topic})
            self.msg_latency.record(latency_ms, {"topic": topic})
