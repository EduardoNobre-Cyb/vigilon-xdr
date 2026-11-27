PLATFORM_NAME = "Vigilon"
PLATFORM_TAGLINE = "Multi-Agent XDR Platform for Unified Log and Endpoint Threat Defense"

# key -> codename + role. Keys describe WHAT the agent does, so they never need renaming.
AGENTS = {
    "log_ingestor": {"codename": "Intake", "role": "Log Ingestion"},
    "threat_model": {"codename": "Atlas", "role": "Threat Modeling & Attack Paths"},
    "classifier": {"codename": "Triage", "role": "Threat Classification"},
    "threat_hunter": {"codename": "Sentinel", "role": "Threat Hunting"},
    "response": {"codename": "Warden", "role": "Response Coordination"},
    "endpoint": {"codename": "Sensor", "role": "Endpoint Collector"},
    "waf": {"codename": "Rampart", "role": "Web Application Firewall"},
    "file_monitor": {"codename": "Spectra", "role": "Static File Analysis"},
    "process_monitor": {"codename": "Pulse", "role": "Process Behaviour Analysis"},
    "network_monitor": {"codename": "Beacon", "role": "Network Anomaly Detection"},
}


def agent_name(key: str) -> str:
    """'threat_hunter' -> 'Vigilon Sentinel'"""
    return f"{PLATFORM_NAME} {AGENTS[key]['codename']}"


def agent_role(key: str) -> str:
    """'threat_hunter' -> 'Threat Hunting'"""
    return AGENTS[key]["role"]


def agent_full_name(key: str) -> str:
    """'threat_hunter' -> 'Vigilon Sentinel — Threat Hunting'"""
    return f"{agent_name(key)} — {agent_role(key)}"
