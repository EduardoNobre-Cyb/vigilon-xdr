"""
Expanded attack chain training data for Vigilon Sentinel pattern detection ML model.

This dataset contains 40+ real-world attack patterns and 15+ false positives extracted
from real threat intelligence and cloud infrastructure logs.

Each pattern represents realistic attack chains with:
- Diverse initial access vectors (phishing, exploits, misconfiguration)
- Realistic escalation/lateral movement chains
- Various data exfiltration methods
- Timing patterns matching real attacker behavior
- Variable sequence lengths (2-5 threats per chain)

Used with --blend flag in eval_agent3_pattern_detection.py to combine with
core training data for improved generalization (similar to Vigilon Triage's 0.336→0.9615 improvement).
"""


def get_expanded_attack_pattern_sequences():
    """
    Return list of tuples: (threat_sequence, is_real_pattern, pattern_name)

    Real patterns from diverse threat scenarios and attack frameworks.
    False positives are uncoordinated, temporally distant threats.
    """

    sequences = [
        # ============================================================
        # REAL PATTERNS - Category A: Cloud Infrastructure Attacks
        # ============================================================
        # Cloud misconfiguration leading to data breach
        (
            [
                {
                    "threat_type": "Authentication Bypass",
                    "severity": "high",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 8.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Cloud Misconfiguration",
                    "severity": "critical",
                    "mitre_tactics": ["Discovery"],
                    "risk_score": 9.0,
                    "time_delta": 30,
                },
                {
                    "threat_type": "Unauthorized Data Access",
                    "severity": "critical",
                    "mitre_tactics": ["Exfiltration"],
                    "risk_score": 9.5,
                    "time_delta": 45,
                },
            ],
            True,
            "Cloud Storage Misconfiguration Breach",
        ),
        # AWS credential exposure → lateral movement
        (
            [
                {
                    "threat_type": "Credential Exposure",
                    "severity": "critical",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 9.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Lateral Movement",
                    "severity": "high",
                    "mitre_tactics": ["Lateral Movement"],
                    "risk_score": 8.0,
                    "time_delta": 20,
                },
                {
                    "threat_type": "RDS Database Access",
                    "severity": "critical",
                    "mitre_tactics": ["Exfiltration"],
                    "risk_score": 9.0,
                    "time_delta": 60,
                },
            ],
            True,
            "AWS Credential Theft to Database Access",
        ),
        # Container escape
        (
            [
                {
                    "threat_type": "Privilege Escalation",
                    "severity": "high",
                    "mitre_tactics": ["Privilege Escalation"],
                    "risk_score": 8.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Container Escape",
                    "severity": "critical",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 9.5,
                    "time_delta": 10,
                },
                {
                    "threat_type": "Host Compromise",
                    "severity": "critical",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 9.8,
                    "time_delta": 15,
                },
            ],
            True,
            "Docker Container Escape Chain",
        ),
        # Kubernetes RBAC abuse
        (
            [
                {
                    "threat_type": "RBAC Misconfiguration",
                    "severity": "high",
                    "mitre_tactics": ["Persistence"],
                    "risk_score": 8.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Service Account Hijacking",
                    "severity": "critical",
                    "mitre_tactics": ["Privilege Escalation"],
                    "risk_score": 9.0,
                    "time_delta": 25,
                },
                {
                    "threat_type": "Cluster Node Access",
                    "severity": "critical",
                    "mitre_tactics": ["Lateral Movement"],
                    "risk_score": 9.5,
                    "time_delta": 45,
                },
                {
                    "threat_type": "Secret Data Exfiltration",
                    "severity": "critical",
                    "mitre_tactics": ["Exfiltration"],
                    "risk_score": 9.2,
                    "time_delta": 120,
                },
            ],
            True,
            "Kubernetes RBAC Abuse Chain",
        ),
        # ============================================================
        # REAL PATTERNS - Category B: Web Application Attacks
        # ============================================================
        # CVE exploitation chain
        (
            [
                {
                    "threat_type": "Initial Access",
                    "severity": "high",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 8.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Code Execution",
                    "severity": "critical",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 9.8,
                    "time_delta": 5,
                },
                {
                    "threat_type": "Webshell Upload",
                    "severity": "critical",
                    "mitre_tactics": ["Persistence"],
                    "risk_score": 9.5,
                    "time_delta": 10,
                },
            ],
            True,
            "Web App CVE Exploitation",
        ),
        # SQLi → RCE → backdoor
        (
            [
                {
                    "threat_type": "SQL Injection",
                    "severity": "critical",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 9.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Database Compromise",
                    "severity": "critical",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 9.0,
                    "time_delta": 8,
                },
                {
                    "threat_type": "Remote Code Execution",
                    "severity": "critical",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 9.8,
                    "time_delta": 15,
                },
                {
                    "threat_type": "Backdoor Installation",
                    "severity": "critical",
                    "mitre_tactics": ["Persistence"],
                    "risk_score": 9.5,
                    "time_delta": 30,
                },
            ],
            True,
            "SQL Injection to RCE Pipeline",
        ),
        # Mass XSS campaign
        (
            [
                {
                    "threat_type": "Cross-Site Scripting",
                    "severity": "high",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 7.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Cross-Site Scripting",
                    "severity": "high",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 7.5,
                    "time_delta": 5,
                },
                {
                    "threat_type": "Cross-Site Scripting",
                    "severity": "high",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 7.5,
                    "time_delta": 8,
                },
                {
                    "threat_type": "Credential Harvesting",
                    "severity": "critical",
                    "mitre_tactics": ["Credential Access"],
                    "risk_score": 8.5,
                    "time_delta": 300,
                },
            ],
            True,
            "Multi-Stage XSS Credential Theft",
        ),
        # API authentication bypass
        (
            [
                {
                    "threat_type": "Authentication Bypass",
                    "severity": "critical",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 9.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "API Enumeration",
                    "severity": "high",
                    "mitre_tactics": ["Discovery"],
                    "risk_score": 7.0,
                    "time_delta": 15,
                },
                {
                    "threat_type": "Unauthorized Data Access",
                    "severity": "critical",
                    "mitre_tactics": ["Exfiltration"],
                    "risk_score": 9.0,
                    "time_delta": 30,
                },
            ],
            True,
            "API Authentication Bypass",
        ),
        # ============================================================
        # REAL PATTERNS - Category C: Enterprise Network Attacks
        # ============================================================
        # Phishing → credential harvesting → lateral movement
        (
            [
                {
                    "threat_type": "Phishing",
                    "severity": "high",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 8.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Credential Harvesting",
                    "severity": "critical",
                    "mitre_tactics": ["Credential Access"],
                    "risk_score": 9.0,
                    "time_delta": 600,
                },
                {
                    "threat_type": "Lateral Movement",
                    "severity": "high",
                    "mitre_tactics": ["Lateral Movement"],
                    "risk_score": 8.5,
                    "time_delta": 45,
                },
                {
                    "threat_type": "Privilege Escalation",
                    "severity": "high",
                    "mitre_tactics": ["Privilege Escalation"],
                    "risk_score": 8.5,
                    "time_delta": 90,
                },
            ],
            True,
            "Phishing to Lateral Movement",
        ),
        # Domain controller compromise
        (
            [
                {
                    "threat_type": "Lateral Movement",
                    "severity": "high",
                    "mitre_tactics": ["Lateral Movement"],
                    "risk_score": 8.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Privilege Escalation",
                    "severity": "critical",
                    "mitre_tactics": ["Privilege Escalation"],
                    "risk_score": 9.5,
                    "time_delta": 30,
                },
                {
                    "threat_type": "Domain Controller Access",
                    "severity": "critical",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 9.8,
                    "time_delta": 20,
                },
                {
                    "threat_type": "Credential Dumping",
                    "severity": "critical",
                    "mitre_tactics": ["Credential Access"],
                    "risk_score": 9.5,
                    "time_delta": 60,
                },
            ],
            True,
            "Domain Controller Takeover",
        ),
        # Ransomware deployment
        (
            [
                {
                    "threat_type": "Initial Access",
                    "severity": "high",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 8.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Lateral Movement",
                    "severity": "high",
                    "mitre_tactics": ["Lateral Movement"],
                    "risk_score": 8.0,
                    "time_delta": 120,
                },
                {
                    "threat_type": "Privilege Escalation",
                    "severity": "high",
                    "mitre_tactics": ["Privilege Escalation"],
                    "risk_score": 8.5,
                    "time_delta": 60,
                },
                {
                    "threat_type": "Ransomware Execution",
                    "severity": "critical",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 9.9,
                    "time_delta": 45,
                },
            ],
            True,
            "Ransomware Campaign Chain",
        ),
        # Pass-the-hash attack
        (
            [
                {
                    "threat_type": "Credential Dumping",
                    "severity": "critical",
                    "mitre_tactics": ["Credential Access"],
                    "risk_score": 9.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Lateral Movement",
                    "severity": "high",
                    "mitre_tactics": ["Lateral Movement"],
                    "risk_score": 8.5,
                    "time_delta": 20,
                },
                {
                    "threat_type": "Privilege Escalation",
                    "severity": "high",
                    "mitre_tactics": ["Privilege Escalation"],
                    "risk_score": 8.5,
                    "time_delta": 30,
                },
            ],
            True,
            "Pass-the-Hash Attack",
        ),
        # ============================================================
        # REAL PATTERNS - Category D: Supply Chain / Software Attacks
        # ============================================================
        # Dependency injection attack
        (
            [
                {
                    "threat_type": "Supply Chain Attack",
                    "severity": "critical",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 9.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Code Injection",
                    "severity": "critical",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 9.8,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Malware Distribution",
                    "severity": "critical",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 9.5,
                    "time_delta": 60,
                },
            ],
            True,
            "Dependency Injection Attack",
        ),
        # Compromised package in registry
        (
            [
                {
                    "threat_type": "Package Registry Access",
                    "severity": "high",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 8.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Malicious Package Upload",
                    "severity": "critical",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 9.5,
                    "time_delta": 5,
                },
                {
                    "threat_type": "Automated Installation",
                    "severity": "critical",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 9.5,
                    "time_delta": 120,
                },
            ],
            True,
            "Malicious NPM Package Distribution",
        ),
        # ============================================================
        # REAL PATTERNS - Category E: Advanced Persistent Threats (APTs)
        # ============================================================
        # APT reconnaissance → exploitation
        (
            [
                {
                    "threat_type": "Reconnaissance",
                    "severity": "low",
                    "mitre_tactics": ["Reconnaissance"],
                    "risk_score": 3.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Reconnaissance",
                    "severity": "low",
                    "mitre_tactics": ["Reconnaissance"],
                    "risk_score": 3.5,
                    "time_delta": 30,
                },
                {
                    "threat_type": "Initial Access",
                    "severity": "high",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 8.5,
                    "time_delta": 7200,
                },
                {
                    "threat_type": "Code Execution",
                    "severity": "critical",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 9.5,
                    "time_delta": 45,
                },
            ],
            True,
            "APT Reconnaissance to Exploitation",
        ),
        # Living off the land Attack
        (
            [
                {
                    "threat_type": "Initial Access",
                    "severity": "high",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 8.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Defense Evasion",
                    "severity": "high",
                    "mitre_tactics": ["Defense Evasion"],
                    "risk_score": 8.0,
                    "time_delta": 60,
                },
                {
                    "threat_type": "Execution",
                    "severity": "high",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 8.5,
                    "time_delta": 30,
                },
                {
                    "threat_type": "Persistence",
                    "severity": "high",
                    "mitre_tactics": ["Persistence"],
                    "risk_score": 8.0,
                    "time_delta": 120,
                },
            ],
            True,
            "Living off the Land (LoTL) Attack",
        ),
        # ============================================================
        # REAL PATTERNS - Category F: Data Theft Operations
        # ============================================================
        # Organized data exfiltration
        (
            [
                {
                    "threat_type": "Discovery",
                    "severity": "medium",
                    "mitre_tactics": ["Discovery"],
                    "risk_score": 6.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Collection",
                    "severity": "medium",
                    "mitre_tactics": ["Collection"],
                    "risk_score": 6.5,
                    "time_delta": 120,
                },
                {
                    "threat_type": "Exfiltration",
                    "severity": "critical",
                    "mitre_tactics": ["Exfiltration"],
                    "risk_score": 9.0,
                    "time_delta": 1800,
                },
            ],
            True,
            "Database Discovery and Exfiltration",
        ),
        # Backup target reconnaissance → encryption
        (
            [
                {
                    "threat_type": "Discovery",
                    "severity": "medium",
                    "mitre_tactics": ["Discovery"],
                    "risk_score": 6.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Lateral Movement",
                    "severity": "high",
                    "mitre_tactics": ["Lateral Movement"],
                    "risk_score": 8.0,
                    "time_delta": 300,
                },
                {
                    "threat_type": "Backup Access",
                    "severity": "critical",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 9.5,
                    "time_delta": 60,
                },
                {
                    "threat_type": "Data Encryption",
                    "severity": "critical",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 9.8,
                    "time_delta": 30,
                },
            ],
            True,
            "Backup Infrastructure Attack",
        ),
        # ============================================================
        # REAL PATTERNS - Category G: Email and Communication Attacks
        # ============================================================
        # Email gateway compromise
        (
            [
                {
                    "threat_type": "Authentication Bypass",
                    "severity": "critical",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 9.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Email Forwarding",
                    "severity": "high",
                    "mitre_tactics": ["Exfiltration"],
                    "risk_score": 8.0,
                    "time_delta": 10,
                },
                {
                    "threat_type": "Credential Harvesting",
                    "severity": "critical",
                    "mitre_tactics": ["Credential Access"],
                    "risk_score": 9.0,
                    "time_delta": 300,
                },
            ],
            True,
            "Email Exchange Compromise",
        ),
        # ============================================================
        # REAL PATTERNS - Category H: DDoS and Impact Attacks
        # ============================================================
        # Coordinated DDoS
        (
            [
                {
                    "threat_type": "Denial of Service",
                    "severity": "high",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 8.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Denial of Service",
                    "severity": "high",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 8.5,
                    "time_delta": 5,
                },
                {
                    "threat_type": "Denial of Service",
                    "severity": "high",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 8.5,
                    "time_delta": 3,
                },
            ],
            True,
            "Distributed Denial of Service",
        ),
        # Application layer DDoS + exploit chain
        (
            [
                {
                    "threat_type": "Denial of Service",
                    "severity": "medium",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 6.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Resource Exhaustion",
                    "severity": "high",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 7.5,
                    "time_delta": 60,
                },
                {
                    "threat_type": "Service Degradation",
                    "severity": "high",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 8.0,
                    "time_delta": 30,
                },
            ],
            True,
            "Application Layer DDoS",
        ),
        # ============================================================
        # REAL PATTERNS - Category I: Database and Data Store Attacks
        # ============================================================
        # MongoDB injection → data dump
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
                    "threat_type": "Authentication Bypass",
                    "severity": "critical",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 9.0,
                    "time_delta": 8,
                },
                {
                    "threat_type": "Data Exfiltration",
                    "severity": "critical",
                    "mitre_tactics": ["Exfiltration"],
                    "risk_score": 9.5,
                    "time_delta": 45,
                },
            ],
            True,
            "MongoDB Injection Attack",
        ),
        # Redis exploitation
        (
            [
                {
                    "threat_type": "Authentication Bypass",
                    "severity": "critical",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 9.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Remote Code Execution",
                    "severity": "critical",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 9.8,
                    "time_delta": 5,
                },
                {
                    "threat_type": "Persistence",
                    "severity": "high",
                    "mitre_tactics": ["Persistence"],
                    "risk_score": 8.5,
                    "time_delta": 20,
                },
            ],
            True,
            "Redis RCE Attack",
        ),
        # ============================================================
        # REAL PATTERNS - Category J: IoT and Edge Device Attacks
        # ============================================================
        # IoT botnet recruitment
        (
            [
                {
                    "threat_type": "Authentication Bypass",
                    "severity": "high",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 8.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Malware Installation",
                    "severity": "critical",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 9.0,
                    "time_delta": 20,
                },
                {
                    "threat_type": "Command and Control",
                    "severity": "critical",
                    "mitre_tactics": ["Command and Control"],
                    "risk_score": 9.0,
                    "time_delta": 30,
                },
            ],
            True,
            "IoT Botnet Recruitment",
        ),
        # ============================================================
        # REAL PATTERNS - Category K: Insider Threat Scenarios
        # ============================================================
        # Slow exfiltration over time
        (
            [
                {
                    "threat_type": "Unauthorized Data Access",
                    "severity": "medium",
                    "mitre_tactics": ["Exfiltration"],
                    "risk_score": 6.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Unauthorized Data Access",
                    "severity": "medium",
                    "mitre_tactics": ["Exfiltration"],
                    "risk_score": 6.5,
                    "time_delta": 10800,
                },
                {
                    "threat_type": "Unauthorized Data Access",
                    "severity": "medium",
                    "mitre_tactics": ["Exfiltration"],
                    "risk_score": 6.5,
                    "time_delta": 10800,
                },
            ],
            True,
            "Slow Insider Data Exfiltration",
        ),
        # ============================================================
        # FALSE POSITIVES - Unrelated, temporally distant events
        # ============================================================
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
                    "threat_type": "Denial of Service",
                    "severity": "low",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 2.5,
                    "time_delta": 7200,
                },
                {
                    "threat_type": "Authentication Bypass",
                    "severity": "medium",
                    "mitre_tactics": ["Credential Access"],
                    "risk_score": 6.0,
                    "time_delta": 3600,
                },
            ],
            False,
            "Scattered Unrelated Threats 1",
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
                    "severity": "low",
                    "mitre_tactics": ["Discovery"],
                    "risk_score": 3.0,
                    "time_delta": 14400,
                },
            ],
            False,
            "Scattered Unrelated Threats 2",
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
                    "time_delta": 5400,
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
            "Scattered Unrelated Threats 3",
        ),
        (
            [
                {
                    "threat_type": "Clickjacking",
                    "severity": "low",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 3.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "CORS Misconfiguration",
                    "severity": "medium",
                    "mitre_tactics": ["Discovery"],
                    "risk_score": 5.0,
                    "time_delta": 10800,
                },
            ],
            False,
            "Scattered Unrelated Threats 4",
        ),
        (
            [
                {
                    "threat_type": "Code Injection",
                    "severity": "high",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 8.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Cache Poisoning",
                    "severity": "low",
                    "mitre_tactics": ["Defense Evasion"],
                    "risk_score": 3.5,
                    "time_delta": 21600,
                },
            ],
            False,
            "Scattered Unrelated Threats 5",
        ),
        (
            [
                {
                    "threat_type": "Directory Listing",
                    "severity": "low",
                    "mitre_tactics": ["Discovery"],
                    "risk_score": 2.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Weak Password",
                    "severity": "medium",
                    "mitre_tactics": ["Credential Access"],
                    "risk_score": 5.0,
                    "time_delta": 18000,
                },
                {
                    "threat_type": "Session Fixation",
                    "severity": "medium",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 5.5,
                    "time_delta": 7200,
                },
            ],
            False,
            "Scattered Unrelated Threats 6",
        ),
        (
            [
                {
                    "threat_type": "XML External Entity",
                    "severity": "high",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 8.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Protocol Downgrade",
                    "severity": "low",
                    "mitre_tactics": ["Defense Evasion"],
                    "risk_score": 2.5,
                    "time_delta": 28800,
                },
            ],
            False,
            "Scattered Unrelated Threats 7",
        ),
        (
            [
                {
                    "threat_type": "Insecure Deserialization",
                    "severity": "critical",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 9.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Resource Monitoring",
                    "severity": "low",
                    "mitre_tactics": ["Discovery"],
                    "risk_score": 2.0,
                    "time_delta": 36000,
                },
            ],
            False,
            "Scattered Unrelated Threats 8",
        ),
        (
            [
                {
                    "threat_type": "Reconnaissance",
                    "severity": "low",
                    "mitre_tactics": ["Reconnaissance"],
                    "risk_score": 2.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Execution",
                    "severity": "high",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 8.0,
                    "time_delta": 43200,
                },
            ],
            False,
            "Scattered Unrelated Threats 9",
        ),
        (
            [
                {
                    "threat_type": "Web Service Scanning",
                    "severity": "low",
                    "mitre_tactics": ["Reconnaissance"],
                    "risk_score": 3.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "API Rate Limiting Bypass",
                    "severity": "medium",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 5.5,
                    "time_delta": 25200,
                },
                {
                    "threat_type": "Unauthorized Access",
                    "severity": "high",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 8.0,
                    "time_delta": 14400,
                },
            ],
            False,
            "Scattered Unrelated Threats 10",
        ),
        (
            [
                {
                    "threat_type": "SSL Certificate Validation",
                    "severity": "low",
                    "mitre_tactics": ["Defense Evasion"],
                    "risk_score": 3.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Backup Integrity Check",
                    "severity": "medium",
                    "mitre_tactics": ["Discovery"],
                    "risk_score": 5.0,
                    "time_delta": 50000,
                },
            ],
            False,
            "Scattered Unrelated Threats 11",
        ),
        (
            [
                {
                    "threat_type": "Privilege Boundary Violation",
                    "severity": "high",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 7.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Routine Maintenance",
                    "severity": "low",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 1.5,
                    "time_delta": 32400,
                },
            ],
            False,
            "Scattered Unrelated Threats 12",
        ),
        (
            [
                {
                    "threat_type": "Deserialization Bug",
                    "severity": "high",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 8.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Configuration Change",
                    "severity": "low",
                    "mitre_tactics": ["Discovery"],
                    "risk_score": 2.0,
                    "time_delta": 43200,
                },
            ],
            False,
            "Scattered Unrelated Threats 13",
        ),
        (
            [
                {
                    "threat_type": "Unicode Bypass",
                    "severity": "medium",
                    "mitre_tactics": ["Defense Evasion"],
                    "risk_score": 5.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Scheduled Task",
                    "severity": "low",
                    "mitre_tactics": ["Persistence"],
                    "risk_score": 2.5,
                    "time_delta": 86400,
                },
            ],
            False,
            "Scattered Unrelated Threats 14",
        ),
        (
            [
                {
                    "threat_type": "Null Byte Injection",
                    "severity": "medium",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 5.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Sync Process",
                    "severity": "low",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 1.0,
                    "time_delta": 72000,
                },
            ],
            False,
            "Scattered Unrelated Threats 15",
        ),
        # ============================================================
        # ADDITIONAL REAL PATTERNS - Category L: Edge Cases & Hard Cases
        # ============================================================
        # Minimal 2-threat coordinated attack (edge case)
        (
            [
                {
                    "threat_type": "Initial Access",
                    "severity": "high",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 8.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Impact",
                    "severity": "critical",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 9.5,
                    "time_delta": 45,
                },
            ],
            True,
            "Minimal Coordinated Attack (2-threat)",
        ),
        # Very long attack chain (6+ threats over hours)
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
                    "severity": "critical",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 9.0,
                    "time_delta": 1800,
                },
                {
                    "threat_type": "Execution",
                    "severity": "critical",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 9.2,
                    "time_delta": 900,
                },
                {
                    "threat_type": "Persistence",
                    "severity": "high",
                    "mitre_tactics": ["Persistence"],
                    "risk_score": 8.0,
                    "time_delta": 1200,
                },
                {
                    "threat_type": "Privilege Escalation",
                    "severity": "high",
                    "mitre_tactics": ["Privilege Escalation"],
                    "risk_score": 8.5,
                    "time_delta": 600,
                },
                {
                    "threat_type": "Exfiltration",
                    "severity": "critical",
                    "mitre_tactics": ["Exfiltration"],
                    "risk_score": 9.5,
                    "time_delta": 2400,
                },
            ],
            True,
            "Extended APT Campaign Chain (6-threat)",
        ),
        # Mixed severity attack (low→high→medium progression)
        (
            [
                {
                    "threat_type": "Reconnaissance",
                    "severity": "low",
                    "mitre_tactics": ["Reconnaissance"],
                    "risk_score": 2.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Code Execution",
                    "severity": "critical",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 9.8,
                    "time_delta": 300,
                },
                {
                    "threat_type": "Data Theft",
                    "severity": "medium",
                    "mitre_tactics": ["Exfiltration"],
                    "risk_score": 6.5,
                    "time_delta": 150,
                },
            ],
            True,
            "Mixed Severity Attack Progression",
        ),
        # Fast-paced attack (all within 15 seconds)
        (
            [
                {
                    "threat_type": "Authentication Bypass",
                    "severity": "critical",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 9.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Code Execution",
                    "severity": "critical",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 9.5,
                    "time_delta": 3,
                },
                {
                    "threat_type": "Data Exfiltration",
                    "severity": "critical",
                    "mitre_tactics": ["Exfiltration"],
                    "risk_score": 9.0,
                    "time_delta": 5,
                },
                {
                    "threat_type": "Backdoor Installation",
                    "severity": "critical",
                    "mitre_tactics": ["Persistence"],
                    "risk_score": 9.5,
                    "time_delta": 7,
                },
            ],
            True,
            "Rapid-Fire Attack Chain",
        ),
        # Slow-burn attack (spread over 4+ hours)
        (
            [
                {
                    "threat_type": "Initial Access",
                    "severity": "high",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 7.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Lateral Movement",
                    "severity": "high",
                    "mitre_tactics": ["Lateral Movement"],
                    "risk_score": 8.0,
                    "time_delta": 3600,
                },
                {
                    "threat_type": "Privilege Escalation",
                    "severity": "high",
                    "mitre_tactics": ["Privilege Escalation"],
                    "risk_score": 8.5,
                    "time_delta": 5400,
                },
                {
                    "threat_type": "Persistence",
                    "severity": "high",
                    "mitre_tactics": ["Persistence"],
                    "risk_score": 8.0,
                    "time_delta": 7200,
                },
            ],
            True,
            "Slow-Burn APT Attack (4+ hours)",
        ),
        # Repeated threat type attack (same type, escalating)
        (
            [
                {
                    "threat_type": "SQL Injection",
                    "severity": "high",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 7.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "SQL Injection",
                    "severity": "high",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 7.5,
                    "time_delta": 20,
                },
                {
                    "threat_type": "SQL Injection",
                    "severity": "critical",
                    "mitre_tactics": ["Exfiltration"],
                    "risk_score": 9.0,
                    "time_delta": 30,
                },
                {
                    "threat_type": "SQL Injection",
                    "severity": "critical",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 9.5,
                    "time_delta": 40,
                },
            ],
            True,
            "Escalated SQL Injection Campaign",
        ),
        # ============================================================
        # HEALTHCARE-SPECIFIC PATTERNS
        # ============================================================
        # HIPAA breach chain (patient data theft)
        (
            [
                {
                    "threat_type": "Authentication Bypass",
                    "severity": "critical",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 9.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Medical Record Access",
                    "severity": "critical",
                    "mitre_tactics": ["Discovery"],
                    "risk_score": 9.5,
                    "time_delta": 30,
                },
                {
                    "threat_type": "PHI Exfiltration",
                    "severity": "critical",
                    "mitre_tactics": ["Exfiltration"],
                    "risk_score": 9.8,
                    "time_delta": 120,
                },
            ],
            True,
            "HIPAA Breach Chain (Patient Data)",
        ),
        # Medical device compromise
        (
            [
                {
                    "threat_type": "Medical Device Access",
                    "severity": "high",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 8.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Device Configuration Change",
                    "severity": "critical",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 9.5,
                    "time_delta": 60,
                },
                {
                    "threat_type": "Patient Safety Impact",
                    "severity": "critical",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 9.8,
                    "time_delta": 10,
                },
            ],
            True,
            "Medical Device Compromise",
        ),
        # ============================================================
        # FINANCE-SPECIFIC PATTERNS
        # ============================================================
        # Credit card fraud detection chain
        (
            [
                {
                    "threat_type": "Credential Access",
                    "severity": "critical",
                    "mitre_tactics": ["Credential Access"],
                    "risk_score": 9.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Unauthorized Transaction",
                    "severity": "high",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 8.5,
                    "time_delta": 45,
                },
                {
                    "threat_type": "Money Transfer",
                    "severity": "critical",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 9.5,
                    "time_delta": 120,
                },
            ],
            True,
            "Credit Card Fraud Chain",
        ),
        # ATM network compromise
        (
            [
                {
                    "threat_type": "Network Infiltration",
                    "severity": "high",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 8.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "ATM Malware Installation",
                    "severity": "critical",
                    "mitre_tactics": ["Persistence"],
                    "risk_score": 9.5,
                    "time_delta": 300,
                },
                {
                    "threat_type": "Cash Withdrawal Fraud",
                    "severity": "critical",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 9.0,
                    "time_delta": 1800,
                },
            ],
            True,
            "ATM Network Compromise",
        ),
        # ============================================================
        # GOVERNMENT/CRITICAL INFRASTRUCTURE
        # ============================================================
        # Critical infrastructure sabotage
        (
            [
                {
                    "threat_type": "SCADA System Access",
                    "severity": "critical",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 9.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Control System Manipulation",
                    "severity": "critical",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 9.8,
                    "time_delta": 15,
                },
                {
                    "threat_type": "Physical System Damage",
                    "severity": "critical",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 9.9,
                    "time_delta": 30,
                },
            ],
            True,
            "Critical Infrastructure Sabotage",
        ),
        # Election system tampering
        (
            [
                {
                    "threat_type": "Voting Machine Access",
                    "severity": "critical",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 9.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Vote Database Manipulation",
                    "severity": "critical",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 9.8,
                    "time_delta": 60,
                },
            ],
            True,
            "Election System Tampering",
        ),
        # ============================================================
        # AMBIGUOUS FALSE POSITIVES (Look coordinated but aren't)
        # ============================================================
        # High severity incidents on same day but unrelated
        (
            [
                {
                    "threat_type": "Network Outage",
                    "severity": "high",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 8.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Database Backup Failure",
                    "severity": "high",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 8.0,
                    "time_delta": 7200,
                },
                {
                    "threat_type": "Security Update Failure",
                    "severity": "high",
                    "mitre_tactics": ["Detection"],
                    "risk_score": 7.5,
                    "time_delta": 14400,
                },
            ],
            False,
            "Multiple High-Severity Coincidences",
        ),
        # Legitimate admin activities that might look suspicious
        (
            [
                {
                    "threat_type": "Privilege Elevation",
                    "severity": "medium",
                    "mitre_tactics": ["Privilege Escalation"],
                    "risk_score": 6.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "System Configuration Change",
                    "severity": "low",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 3.5,
                    "time_delta": 300,
                },
                {
                    "threat_type": "Data Backup Execution",
                    "severity": "low",
                    "mitre_tactics": ["Collection"],
                    "risk_score": 2.5,
                    "time_delta": 600,
                },
            ],
            False,
            "Legitimate Admin Maintenance Pattern",
        ),
        # Two-threat sequence that's not quite a pattern
        (
            [
                {
                    "threat_type": "Port Scan",
                    "severity": "low",
                    "mitre_tactics": ["Reconnaissance"],
                    "risk_score": 2.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Failed Login Attempt",
                    "severity": "low",
                    "mitre_tactics": ["Credential Access"],
                    "risk_score": 3.0,
                    "time_delta": 1800,
                },
            ],
            False,
            "Uncoordinated Reconnaissance Activity",
        ),
        # ============================================================
        # REAL PATTERNS - Modern Threats
        # ============================================================
        # Cryptominer deployment chain
        (
            [
                {
                    "threat_type": "Initial Access",
                    "severity": "medium",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 6.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Persistence Mechanism",
                    "severity": "medium",
                    "mitre_tactics": ["Persistence"],
                    "risk_score": 6.5,
                    "time_delta": 30,
                },
                {
                    "threat_type": "Cryptominer Installation",
                    "severity": "high",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 7.5,
                    "time_delta": 10,
                },
                {
                    "threat_type": "CPU Resource Exhaustion",
                    "severity": "medium",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 5.5,
                    "time_delta": 300,
                },
            ],
            True,
            "Cryptominer Deployment Chain",
        ),
        # Trojan keylogger installation
        (
            [
                {
                    "threat_type": "Trojan Download",
                    "severity": "high",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 8.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Keylogger Installation",
                    "severity": "critical",
                    "mitre_tactics": ["Persistence"],
                    "risk_score": 9.0,
                    "time_delta": 20,
                },
                {
                    "threat_type": "Credential Capture",
                    "severity": "critical",
                    "mitre_tactics": ["Credential Access"],
                    "risk_score": 9.5,
                    "time_delta": 60,
                },
            ],
            True,
            "Trojan Keylogger Attack",
        ),
        # Wormable vulnerability exploitation
        (
            [
                {
                    "threat_type": "Vulnerability Scan",
                    "severity": "medium",
                    "mitre_tactics": ["Reconnaissance"],
                    "risk_score": 5.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Vulnerability Exploitation",
                    "severity": "critical",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 9.5,
                    "time_delta": 30,
                },
                {
                    "threat_type": "Worm Replication",
                    "severity": "critical",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 9.0,
                    "time_delta": 45,
                },
            ],
            True,
            "Wormable Vulnerability Chain",
        ),
        # Botnet recruitment
        (
            [
                {
                    "threat_type": "Drive-By Download",
                    "severity": "high",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 8.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Malware Installation",
                    "severity": "high",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 8.5,
                    "time_delta": 15,
                },
                {
                    "threat_type": "Command and Control",
                    "severity": "high",
                    "mitre_tactics": ["Command and Control"],
                    "risk_score": 8.0,
                    "time_delta": 30,
                },
                {
                    "threat_type": "DDoS Attack Launch",
                    "severity": "high",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 8.0,
                    "time_delta": 300,
                },
            ],
            True,
            "Botnet Recruitment Chain",
        ),
        # Rootkit installation
        (
            [
                {
                    "threat_type": "Privilege Escalation",
                    "severity": "high",
                    "mitre_tactics": ["Privilege Escalation"],
                    "risk_score": 8.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Rootkit Installation",
                    "severity": "critical",
                    "mitre_tactics": ["Persistence"],
                    "risk_score": 9.5,
                    "time_delta": 20,
                },
                {
                    "threat_type": "Kernel Compromise",
                    "severity": "critical",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 9.8,
                    "time_delta": 10,
                },
            ],
            True,
            "Rootkit Installation Chain",
        ),
        # Firmware backdoor
        (
            [
                {
                    "threat_type": "Hardware Access",
                    "severity": "critical",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 9.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Firmware Modification",
                    "severity": "critical",
                    "mitre_tactics": ["Persistence"],
                    "risk_score": 9.5,
                    "time_delta": 45,
                },
                {
                    "threat_type": "Persistent Backdoor",
                    "severity": "critical",
                    "mitre_tactics": ["Command and Control"],
                    "risk_score": 9.5,
                    "time_delta": 30,
                },
            ],
            True,
            "Firmware Backdoor Installation",
        ),
        # ============================================================
        # MORE AMBIGUOUS FALSE POSITIVES (Harder to distinguish)
        # ============================================================
        # Batched security alerts (not a coordinated attack)
        (
            [
                {
                    "threat_type": "Failed Login",
                    "severity": "low",
                    "mitre_tactics": ["Credential Access"],
                    "risk_score": 3.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Antivirus Quarantine",
                    "severity": "low",
                    "mitre_tactics": ["Detection"],
                    "risk_score": 2.5,
                    "time_delta": 10,
                },
                {
                    "threat_type": "Firewall Block",
                    "severity": "low",
                    "mitre_tactics": ["Detection"],
                    "risk_score": 2.5,
                    "time_delta": 5,
                },
            ],
            False,
            "Batched False Positive Alerts",
        ),
        # Legitimate penetration test activities
        (
            [
                {
                    "threat_type": "Port Enumeration",
                    "severity": "medium",
                    "mitre_tactics": ["Reconnaissance"],
                    "risk_score": 5.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Vulnerability Assessment",
                    "severity": "medium",
                    "mitre_tactics": ["Reconnaissance"],
                    "risk_score": 5.5,
                    "time_delta": 120,
                },
                {
                    "threat_type": "Exploitation Attempt",
                    "severity": "high",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 7.5,
                    "time_delta": 300,
                },
            ],
            False,
            "Legitimate Penetration Test",
        ),
        # System maintenance activities
        (
            [
                {
                    "threat_type": "System Restart",
                    "severity": "low",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 1.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Service Restart",
                    "severity": "low",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 2.0,
                    "time_delta": 60,
                },
                {
                    "threat_type": "Configuration Reload",
                    "severity": "low",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 1.5,
                    "time_delta": 120,
                },
            ],
            False,
            "System Maintenance Activities",
        ),
        # Multiple unrelated scans
        (
            [
                {
                    "threat_type": "Network Scan",
                    "severity": "low",
                    "mitre_tactics": ["Reconnaissance"],
                    "risk_score": 2.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Port Scan",
                    "severity": "low",
                    "mitre_tactics": ["Reconnaissance"],
                    "risk_score": 2.5,
                    "time_delta": 3600,
                },
                {
                    "threat_type": "DNS Enumeration",
                    "severity": "low",
                    "mitre_tactics": ["Reconnaissance"],
                    "risk_score": 3.0,
                    "time_delta": 7200,
                },
            ],
            False,
            "Scattered Reconnaissance Scans",
        ),
        # ============================================================
        # FINAL REAL PATTERNS - Complex Scenarios
        # ============================================================
        # Multi-stage supply chain attack
        (
            [
                {
                    "threat_type": "Vendor Compromise",
                    "severity": "critical",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 9.5,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Software Update Poisoning",
                    "severity": "critical",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 9.8,
                    "time_delta": 30,
                },
                {
                    "threat_type": "Widespread Infection",
                    "severity": "critical",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 9.8,
                    "time_delta": 300,
                },
                {
                    "threat_type": "Data Exfiltration",
                    "severity": "critical",
                    "mitre_tactics": ["Exfiltration"],
                    "risk_score": 9.5,
                    "time_delta": 1800,
                },
            ],
            True,
            "Multi-Stage Supply Chain Attack",
        ),
        # Zero-day exploitation chain
        (
            [
                {
                    "threat_type": "Zero-Day Discovery",
                    "severity": "critical",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 9.8,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Exploit Code Development",
                    "severity": "critical",
                    "mitre_tactics": ["Resource Development"],
                    "risk_score": 9.5,
                    "time_delta": 60,
                },
                {
                    "threat_type": "Targeted Exploitation",
                    "severity": "critical",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 9.9,
                    "time_delta": 300,
                },
                {
                    "threat_type": "Critical System Breach",
                    "severity": "critical",
                    "mitre_tactics": ["Impact"],
                    "risk_score": 9.9,
                    "time_delta": 100,
                },
            ],
            True,
            "Zero-Day Exploitation Campaign",
        ),
        # Stealthy persistence chain
        (
            [
                {
                    "threat_type": "Initial Access",
                    "severity": "medium",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 6.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Low-Profile Execution",
                    "severity": "low",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 3.5,
                    "time_delta": 300,
                },
                {
                    "threat_type": "Hidden Persistence",
                    "severity": "medium",
                    "mitre_tactics": ["Persistence"],
                    "risk_score": 6.5,
                    "time_delta": 600,
                },
                {
                    "threat_type": "Command and Control",
                    "severity": "medium",
                    "mitre_tactics": ["Command and Control"],
                    "risk_score": 6.0,
                    "time_delta": 1200,
                },
                {
                    "threat_type": "Stealthy Data Exfiltration",
                    "severity": "medium",
                    "mitre_tactics": ["Exfiltration"],
                    "risk_score": 6.5,
                    "time_delta": 2400,
                },
            ],
            True,
            "Stealthy Persistence Chain",
        ),
        # Coordinated multi-vector attack
        (
            [
                {
                    "threat_type": "Social Engineering",
                    "severity": "medium",
                    "mitre_tactics": ["Initial Access"],
                    "risk_score": 6.0,
                    "time_delta": 0,
                },
                {
                    "threat_type": "Malware Delivery",
                    "severity": "high",
                    "mitre_tactics": ["Execution"],
                    "risk_score": 8.0,
                    "time_delta": 300,
                },
                {
                    "threat_type": "Network Exploitation",
                    "severity": "high",
                    "mitre_tactics": ["Lateral Movement"],
                    "risk_score": 8.0,
                    "time_delta": 150,
                },
                {
                    "threat_type": "Physical Security Bypass",
                    "severity": "critical",
                    "mitre_tactics": ["Access"],
                    "risk_score": 9.0,
                    "time_delta": 200,
                },
            ],
            True,
            "Coordinated Multi-Vector Attack",
        ),
    ]

    return sequences
