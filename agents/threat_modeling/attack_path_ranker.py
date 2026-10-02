from typing import Dict, List
from data.models.models import AttackPath


class AttackPathRanker:
    """Score and rank attack paths by feasibility"""

    # MITRE tactic difficulty
    TACTIC_DIFFICULTY = {
        "TA0043": 1,  # Reconnaissance (easy, public data)
        "TA0042": 2,  # Resource Development
        "TA0001": 3,  # Initial Access (phishing, 0-day)
        "TA0002": 4,  # Execution (get code running)
        "TA0003": 5,  # Persistence (maintain access)
        "TA0004": 6,  # Privilege Escalation
        "TA0005": 5,  # Defense Evasion
        "TA0006": 4,  # Credential Access
        "TA0007": 3,  # Discovery
        "TA0008": 8,  # Lateral Movement
        "TA0009": 7,  # Collection
        "TA0011": 7,  # Command & Control
        "TA0010": 9,  # Exfiltration (hard to avoid detection)
        "TA0040": 6,  # Impact
    }

    # Threat actor profiles - defines what complexity each actor can handle
    THREAT_ACTOR_PROFILES = {
        "script_kiddie": {
            "max_complexity": 4,  # Can't do lateral movement
            "tools": ["metasploit", "public exploits"],
        },
        "equipped": {
            "max_complexity": 7,  # Can do most things
            "tools": ["custom exploits", "malware"],
        },
        "apt": {
            "max_complexity": 10,  # Can do anything
            "tools": ["0-days", "custom malware"],
        },
    }

    def score_path(self, path: Dict) -> AttackPath:
        """Calculate feasibility score for an attack path."""
        attack_path = AttackPath()

        # Sum tactical difficulties
        steps = path.get("steps", [])
        total_difficulty = sum(
            self.TACTIC_DIFFICULTY.get(s["tactic"], 5) for s in steps
        )
        attack_path.difficulty_score = total_difficulty / len(steps) if steps else 5

        # Estimate time
        attack_path.time_to_exploit = sum(
            self.TACTIC_DIFFICULTY.get(s["tactic"], 5) * 5 for s in steps
        )  # Minutes

        # Success probability decreases with difficulty
        attack_path.success_probability = max(
            0.1, 1.0 - (attack_path.difficulty_score / 20)
        )

        # Risk = (impact x success_probability) / difficulty
        impact = path.get("impact_score", 5)  # 1-10
        attack_path.risk_score = (
            impact * attack_path.success_probability
        ) / attack_path.difficulty_score

        return attack_path

    def rank_paths_by_risk(self, paths: List[Dict]) -> List[AttackPath]:
        """Rank paths: highest-risk first."""
        scored = [self.score_path(p) for p in paths]
        return sorted(scored, key=lambda x: x.risk_score, reverse=True)

    def filter_paths_by_actor(
        self, paths: List[AttackPath], actor: str
    ) -> List[AttackPath]:
        """Filter paths feasible for threat actor."""
        profile = self.THREAT_ACTOR_PROFILES.get(actor)
        if not profile:
            return paths
        return [p for p in paths if p.difficulty_score <= profile["max_complexity"]]
