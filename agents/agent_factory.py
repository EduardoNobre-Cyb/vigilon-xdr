"""
Agent Factory - Central registry for instantiating and managing agents.
Provides a single point of access for the model promotion workflow to hot-reload models.
"""

import logging
from typing import Optional
from agents.classification.classifier_agent import ThreatClassificationAgent
from agents.threat_hunter.threat_hunter_agent import ThreatHunterAgent

logger = logging.getLogger(__name__)

# Global agent instances (singletons for each agent type)
_agent_instances = {}


def get_agent(agent_id: str):
    """Factory method to get or create an agent instance.

    Accepts both canonical agent types ('classifier', 'threat_hunter')
    and instance IDs ('classifier_001', 'hunter_001')
    """

    # Map instance IDs to canonical agent types
    agent_type_mapping = {
        "classifier_001": "classifier",
        "classifier": "classifier",
        "hunter_001": "threat_hunter",
        "threat_hunter": "threat_hunter",
        "threat_hunter_001": "threat_hunter",
    }

    # Normalize to canonical type
    canonical_type = agent_type_mapping.get(agent_id)
    if not canonical_type:
        raise ValueError(
            f"Unknown agent_id: {agent_id}. Supported agents: 'classifier' (or 'classifier_001'), 'threat_hunter' (or 'hunter_001')"
        )

    # Use canonical type as cache key
    if canonical_type in _agent_instances:
        return _agent_instances[canonical_type]

    if canonical_type == "classifier":
        agent = ThreatClassificationAgent(agent_id="classifier_001")
        _agent_instances[canonical_type] = agent
        return agent

    elif canonical_type == "threat_hunter":
        agent = ThreatHunterAgent(agent_id="threat_hunter_001")
        _agent_instances[canonical_type] = agent
        return agent


def reset_agent(agent_id: str) -> None:
    """Reset (destroy) an agent instance to force re-instantiation on next get_agent() call.
    Useful for testing or forcing full reload."""
    if agent_id in _agent_instances:
        del _agent_instances[agent_id]
        logger.info(f"Reset agent: {agent_id}")


def reset_all_agents() -> None:
    """Reset all agent instances."""
    global _agent_instances
    _agent_instances.clear()
    logger.info("Reset all agents")


def list_active_agents():
    """Return list of currently instantiated agent IDs."""
    return list(_agent_instances.keys())
