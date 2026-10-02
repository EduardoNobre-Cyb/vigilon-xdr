import time
import logging
from typing import Dict, Any
from opentelemetry import trace, metrics


class MonitoredAgent:
    """Base class for monitored agents."""

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.tracer = trace.get_tracer(agent_id)
        self.meter = metrics.get_meter(agent_id)
        self.logger = logging.getLogger(agent_id)

        # Metrics
        self.processed_count = self.meter.create_counter("events_processed")
        self.error_count = self.meter.create_counter("errors")
        self.processing_time = self.meter.create_histogram("processing_time_ms")
        self.queue_size = self.meter.create_gauge("queue_size")

    def process_event(self, event: Dict):
        """Process with metrics."""
        with self.tracer.start_as_current_span(f"{self.agent_id}_process") as span:
            span.set_attribute("event_id", event.get("id"))

            try:
                start = time.time()
                result = self._process(event)
                latency_ms = (time.time() - start) * 1000

                self.processed_count.add(1)
                self.processing_time.record(latency_ms)

                span.set_attribute("success", True)
            except Exception as e:
                self.error_count.add(1)
                span.record_exception(e)
                span.set_attribute("success", False)
                raise
