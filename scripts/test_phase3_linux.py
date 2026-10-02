"""Linux-specific Phase 3 validation for the Linux endpoint agent."""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from agents.endpoint_agent.linux_agent import LinuxEndpointAgent, NetworkMonitor, ProcessMonitor


def test_linux_agent_imports_cleanly(monkeypatch):
    """The Linux agent should import without Windows-specific dependencies."""
    monkeypatch.setattr(LinuxEndpointAgent, "_get_or_create_agent_id", lambda self: "linux-test-agent-001")
    agent = LinuxEndpointAgent()

    assert agent.agent_id == "linux-test-agent-001"
    assert agent.process_monitor is not None
    assert isinstance(agent.process_monitor, ProcessMonitor)
    assert agent.network_monitor is not None
    assert isinstance(agent.network_monitor, NetworkMonitor)


def test_linux_process_monitor_returns_list():
    """The process monitor should return a list of process events."""
    monitor = ProcessMonitor()
    events = monitor.poll()

    assert isinstance(events, list)


def test_linux_network_monitor_returns_list():
    """The network monitor should return a list of network events."""
    monitor = NetworkMonitor()
    events = monitor.poll()

    assert isinstance(events, list)


def test_linux_agent_action_dispatch_works_for_known_action(monkeypatch):
    """Action dispatch should accept the core action types without crashing."""
    monkeypatch.setattr(LinuxEndpointAgent, "_get_or_create_agent_id", lambda self: "linux-test-agent-001")
    agent = LinuxEndpointAgent()

    class DummySocketIO:
        def emit(self, event_name, payload):
            assert event_name == "action_result"
            assert payload["action_id"] == "action-001"
            assert payload["status"] == "executed"
            return None

    monkeypatch.setattr(agent, "sio", DummySocketIO())
    monkeypatch.setattr("agents.endpoint_agent.linux_agent.os.kill", lambda pid, sig: None)

    agent.on_action_dispatch({
        "action_id": "action-001",
        "action_type": "kill_process",
        "action_params": {"pid": 1234},
    })

    assert agent.agent_id == "linux-test-agent-001"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
