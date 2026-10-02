#!/usr/bin/env python3

# CVSS Utility Module for calculating and managing CVSS scores.


from cvss import CVSS3

# CVSS Vector Mapping for Common Vulnerability Types
# Format: CVSS:3.1/AV:?/AC:?/PR:?/UI:?/S:?/C:?/I:?/A:?
#
# AV (Attack Vector): N=Network, A=Adjacent, L=Local, P=Physical
# AC (Attack Complexity): L=Low, H=High
# PR (Privileges Required): N=None, L=Low, H=High
# UI (User Interaction): N=None, R=Required
# S (Scope): U=Unchanged, C=Changed
# C/I/A (Confidentiality/Integrity/Availability Impact): N=None, L=Low, H=High

VULN_TYPE_TO_CVSS_VECTOR = {
    # SQL Injection - Remote, Low complexity, No auth, High impact
    "sql injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8 Critical
    # XSS - Remote, Low complexity, Needs user interaction
    "xss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",  # 6.1 Medium
    "cross-site scripting": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    # Broken Authentication - Remote, Low complexity, High impact
    "broken authentication": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  # 9.1 Critical
    "authentication bypass": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    # API Rate Limiting - Remote, Low complexity, Availability impact
    "api rate limiting": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",  # 5.3 Medium
    "rate limiting": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
    # Unencrypted Traffic - Network sniffing, requires adjacent access
    "unencrypted traffic": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 6.5 Medium
    "plaintext": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    # Weak Protocols - Network, confidentiality impact
    "weak protocols": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 5.9 Medium
    # Remote Code Execution - Critical, full impact
    "remote code execution": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",  # 10.0 Critical
    "rce": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    # Privilege Escalation - Local, requires low privileges
    "privilege escalation": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",  # 7.8 High
    # Denial of Service - Availability impact only
    "denial of service": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",  # 7.5 High
    "dos": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    # Information Disclosure - Confidentiality impact
    "information disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 7.5 High
    "data exposure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    # Buffer Overflow - Can lead to code execution
    "buffer overflow": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8 Critical
    # Default - Medium severity baseline
    "default": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",  # 5.4 Medium
}


def calculate_cvss_score(vector_string: str) -> float:

    # Calculate CVSS 3.1 base score from a vector string.
    # Args:vector_string: CVSS vector (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    # Returns:Base score as float (0.0 - 10.0)

    try:
        cvss = CVSS3(vector_string)
        return float(cvss.base_score)
    except Exception as e:
        print(f"[CVSS] Error calculating score: {e}")
        return 5.0  # Default to medium


def get_cvss_for_vulnerability(vuln_name: str, description: str = "") -> dict:
    # Get CVSS vector and score for a vulnerability based on its name/description.
    # Args: vuln_name: Vulnerability name, description: Vulnerability description
    # Returns: dict with 'vector' and 'base_score'

    # Combine name and description for matching
    search_text = f"{vuln_name} {description}".lower()

    # Find matching vector
    matched_vector = VULN_TYPE_TO_CVSS_VECTOR["default"]

    for vuln_type, vector in VULN_TYPE_TO_CVSS_VECTOR.items():
        if vuln_type in search_text:
            matched_vector = vector
            break

    # Calculate score
    base_score = calculate_cvss_score(matched_vector)

    return {"vector": matched_vector, "base_score": base_score}


def get_severity_from_cvss(score: float) -> str:
    # Convert CVSS score to severity rating (CVSS 3.1 standard).
    # Args: score: CVSS base score (0.0 - 10.0)
    # Returns: Severity string: Critical, High, Medium, Low, or None

    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score >= 0.1:
        return "Low"
    else:
        return "None"


# Quick test
if __name__ == "__main__":
    print("=" * 60)
    print("CVSS Utility Test")
    print("=" * 60)

    test_vulns = [
        ("SQL Injection", "Allows attackers to execute SQL commands"),
        ("XSS", "Cross-site scripting in user input"),
        ("Broken Authentication", "Session management flaw"),
        ("Buffer Overflow", "Memory corruption vulnerability"),
        ("Unknown Vuln", "Some generic issue"),
    ]

    for name, desc in test_vulns:
        result = get_cvss_for_vulnerability(name, desc)
        severity = get_severity_from_cvss(result["base_score"])
        print(f"\n{name}:")
        print(f"  Score: {result['base_score']}")
        print(f"  Severity: {severity}")
        print(f"  Vector: {result['vector']}")
