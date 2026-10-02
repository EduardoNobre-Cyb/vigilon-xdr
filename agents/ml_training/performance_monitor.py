import time
from datetime import datetime, timedelta
from typing import Dict, List
import logging

logger = logging.getLogger(__name__)


class PerformanceMonitor:
    """Track inference latency, FP rate, and model accuracy"""

    def __init__(self):
        self.process_inference_times: List[float] = []
        self.network_inference_times: List[float] = []
        self.telemetry_round_trips: List[float] = []
        self.classifications_per_minute = 0
        self.false_positives = 0
        self.true_positives = 0
        self.start_time = datetime.now()

    def record_process_inference(self, elapsed_ms: float):
        """Record process model inference time"""
        self.process_inference_times.append(elapsed_ms)
        if len(self.process_inference_times) > 10000:
            self.process_inference_times = self.process_inference_times[-10000:]

    def record_network_inference(self, elapsed_ms: float):
        """Record network model inference time"""
        self.network_inference_times.append(elapsed_ms)
        if len(self.network_inference_times) > 10000:
            self.network_inference_times = self.network_inference_times[-10000:]

    def get_stats(self) -> Dict:
        """Get performance statistics"""
        def calc_stats(times):
            if not times:
                return {'avg': 0, 'min': 0, 'max': 0,  'p95': 0}
            times_sorted = sorted(times)
            return {
                "avg": sum(times) / len(times),
                "min": min(times),
                "max": max(times),
                "p95": times_sorted[int(len(times) * 0.95)]
            }

        uptime_hours = (datetime.now() - self.start_time).total_seconds() / 3600

        return {
            "process_inference_ms": calc_stats(self.process_inference_times),
            "network_inference_ms": calc_stats(self.network_inference_times),
            "uptime_hours": uptime_hours,
            "false_positives": self.false_positives,
            "true_positives": self.true_positives,
            "fp_rate": self.false_positives / (self.true_positives + self.false_positives + 1)
        }

# Global monitor instance
_performance_monitor = PerformanceMonitor()

def record_inference(model_type: str, elapsed_ms: float):
    """Record inference timing"""
    if model_type == "process":
        _performance_monitor.record_process_inference(elapsed_ms)
    elif model_type == "network":
        _performance_monitor.record_network_inference(elapsed_ms)

def get_performance_stats() -> Dict:
    """Get current performance stats"""
    return _performance_monitor.get_stats()