def get_attack_pattern_sequences():
    """
    Return listof tuples (threat_sequence, is_real_pattern, pattern_name)
    is_real_pattern = bool (True if coordinated attack, False if random)
    """

    sequences = [
        (
            [
                {
                    "threat_type": "Injection Attack",
                    "severity": "critical",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 9.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Injection Attack",
                    "severity": "critical",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 9.5,
                    "time_delta": 5,
                },
                {
                    "threat_type": "Code Execution",
                    "severity": "critical",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 9.8,
                    "time_delta": 10,
                },
            ],
            True,
            "SQL Injection to RCE",
        ),
        (
            [
                {
                    "threat_type": "Remote Code Execution",
                    "severity": "critical",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 9.8,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Privilege Escalation",
                    "severity": "high",
                    "mitre_tactics": ["Privilege Escalation"],
                    "risk_score": 8.5,
                    "time_delta": 15,
                },
                {
                    "threat_type": "Persistence",
                    "severity": "high",
                    "mitre_tactics": ["Persistence"],
                    "risk_score": 8.0,
                    "time_delta": 30,
                },
                {
                    "threat_type": "Data Exfiltration",
                    "severity": "critical",
                    "mitre_tactics": ["Exfiltration"],
                    "risk_score": 9.0,
                    "time_delta": 120,
                },
            ],
            True,
            "Post-Exploitation Chain",
        ),
        (
            [
                {
                    "threat_type": "Authentication Bypass",
                    "severity": "high",
                    "mitre_tactics": ["Credential Access"],
                    "risk_score": 8.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Lateral Movement",
                    "severity": "high",
                    "mitre_tactics": ["Lateral Movement"],
                    "risk_score": 8.0,
                    "time_delta": 30,
                },
                {
                    "threat_type": "Privilege Escalation",
                    "severity": "high",
                    "mitre_tactics": ["Privilege Escalation"],
                    "risk_score": 8.5,
                    "time_delta": 45,
                },
            ],
            True,
            "Credential Compromise Chain",
        ),
        (
            [
                {
                    "threat_type": "Cross-Site Scripting",
                    "severity": "medium",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 6.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Cross-Site Scripting",
                    "severity": "medium",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 6.5,
                    "time_delta": 10,
                },
                {
                    "threat_type": "Cross-Site Scripting",
                    "severity": "medium",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 6.5,
                    "time_delta": 15,
                },
            ],
            True,
            "Web Application XSS Campaign",
        ),
        (
            [
                {
                    "threat_type": "Denial of Service",
                    "severity": "high",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 8.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Denial of Service",
                    "severity": "high",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 8.0,
                    "time_delta": 5,
                },
            ],
            True,
            "DDoS Attack",
        ),
        (
            [
                {
                    "threat_type": "Reconnaissance",
                    "severity": "low",
                    "mitre_tactics": ["Reconnaissance"],
                    "risk_score": 3.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Initial Access",
                    "severity": "high",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 8.0,
                    "time_delta": 120,
                },
                {
                    "threat_type": "Execution",
                    "severity": "high",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 8.5,
                    "time_delta": 30,
                },
            ],
            True,
            "Reconnaissance to Exploitation",
        ),
        (
            [
                {
                    "threat_type": "Defense Evasion",
                    "severity": "high",
                    "mitre_tactics": ["Defense Evasion"],
                    "risk_score": 7.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Impact",
                    "severity": "critical",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 9.5,
                    "time_delta": 60,
                },
            ],
            True,
            "Defense Evasion to Impact",
        ),
        (
            [
                {
                    "threat_type": "Collection",
                    "severity": "medium",
                    "mitre_tactics": ["Collection"],
                    "risk_score": 6.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Exfiltration",
                    "severity": "critical",
                    "mitre_tactics": ["Exfiltration"],
                    "risk_score": 9.0,
                    "time_delta": 300,
                },
            ],
            True,
            "Data Exfiltration Chain",
        ),
        # FALSE POSITIVES (random threat sequences, not coordinated attacks)
        (
            [
                {
                    "threat_type": "Injection Attack",
                    "severity": "medium",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 5.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Denial of Service",
                    "severity": "low",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 3.0,
                    "time_delta": 3600,
                },
                {
                    "threat_type": "Authentication Bypass",
                    "severity": "high",
                    "mitre_tactics": ["Credential Access"],
                    "risk_score": 8.0,
                    "time_delta": 7200,
                },
            ],
            False,
            "Random Unrelated Threats 1",
        ),
        (
            [
                {
                    "threat_type": "Cross-Site Scripting",
                    "severity": "low",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 4.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Buffer Overflow",
                    "severity": "high",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 7.5,
                    "time_delta": 1800,
                },
            ],
            False,
            "Random Unrelated Threats 2",
        ),
        (
            [
                {
                    "threat_type": "Memory Corruption",
                    "severity": "medium",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 5.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Path Traversal",
                    "severity": "medium",
                    "mitre_tactics": ["Discovery"],
                    "risk_score": 5.0,
                    "time_delta": 900,
                },
            ],
            False,
            "Random Unrelated Threats 3",
        ),
        (
            [
                {
                    "threat_type": "Input Validation",
                    "severity": "medium",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 5.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Cryptographic Weakness",
                    "severity": "low",
                    "mitre_tactics": ["Defense Evasion"],
                    "risk_score": 3.5,
                    "time_delta": 2000,
                },
            ],
            False,
            "Random Unrelated Threats 4",
        ),
    ]

    return sequences
