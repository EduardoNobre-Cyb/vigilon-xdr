"""Windows-specific Phase 3 validation for the Windows endpoint agent."""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
import time

from agents.ml_training.synthetic_data_generator import SyntheticDataGenerator
from agents.feature_extractor import ProcessFeatureExtractor, NetworkFeatureExtractor
from agents.endpoint_agent.windows_agent import MLModelManager, ProcessMonitor, NetworkMonitor


def test_model_loading():
    """Test ML models load successfully."""
    ml_manager = MLModelManager()
    assert ml_manager.has_models(), "Models should load successfully"


def test_process_scoring():
    """Test process model inference."""
    ml_manager = MLModelManager()

    benign_event = {
        'pid': 1234,
        'ppid': 567,
        'name': 'notepad.exe',
        'path': 'C:\\Program Files\\Notepad\\notepad.exe',
        'command_line': 'C:\\Programm Files\\Notepad\\notepad.exe',
        'parent_name': 'explorer.exe',
        'user': 'Administrator',
        'create_time': time.time(),
        'is_first_seen': False,
    }

    confidence = ml_manager.score_process(benign_event)
    assert 0 <= confidence <= 1, "Confidence should be [0-1]"
    assert confidence < 0.5, "Benign process should score low confidence"


def test_malicious_process_scoring():
    """Test malicious process detection."""
    ml_manager = MLModelManager()

    malicious_event = {
        "pid": 5678,
        "ppid": 432,
        "name": "powershell.exe",
        "path": "C:\\Temp\\powershell.exe",
        'command_line': 'powershell.exe -enc AAAAAAAAA...',
        'parent_name': 'explorer.exe',
        'user': 'Administrator',
        'create_time': time.time(),
        'is_first_seen': True,
    }

    confidence = ml_manager.score_process(malicious_event)
    assert 0 <= confidence <= 1
    assert confidence > 0.5, "Malicious process should score high confidence"


def test_network_scoring():
    """Test network model inference."""
    ml_manager = MLModelManager()

    benign_connection = {
        'source_ip': '192.168.1.100',
        'source_port': 52341,
        'dest_ip': '8.8.8.8',
        'dest_port': 443,
        'process_name': 'chrome.exe',
        'protocol': 'tcp',
        'bytes_sent': 1024,
        'bytes_received': 8192,
    }

    confidence = ml_manager.score_network(benign_connection)
    assert 0 <= confidence <= 1
    assert confidence < 0.5, "Benign connection should score low confidence"


def test_c2_detection():
    """Test C2 connection detection."""
    ml_manager = MLModelManager()

    c2_connection = {
        'source_ip': '192.168.1.100',
        'source_port': 52341,
        'dest_ip': '1.2.3.4',
        'dest_port': 4444,
        'process_name': 'svchost.exe',
        'protocol': 'tcp',
        'bytes_sent': 50,
        'bytes_received': 50,
    }

    confidence = ml_manager.score_network(c2_connection)
    assert confidence > 0.5, "C2 connection should score high confidence"


def test_inference_latency():
    """Test inference is fast enough."""
    ml_manager = MLModelManager()

    event = {
        "pid": 1234,
        "ppid": 567,
        "name": "test.exe",
        "path": "C:\\test.exe",
        "command_line": "test.exe",
        "parent_name": "explorer.exe",
        "user": "user",
        "create_time": time.time(),
        "is_first_seen": False,
    }

    start = time.time()
    for _ in range(100):
        ml_manager.score_process(event)
    elapsed_ms = (time.time() - start) * 1000 / 100

    assert elapsed_ms < 100, f"Inference too slow: {elapsed_ms:.2f}ms"
    print(f"Average inference: {elapsed_ms:.2f}ms")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
