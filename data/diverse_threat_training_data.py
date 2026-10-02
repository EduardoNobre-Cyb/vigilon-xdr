import random
from typing import List, Dict


def get_diverse_threat_scenarios() -> List[Dict]:
    """
    Returns 150+ unique threat scenarios with varied descriptions.
    Each threat type is represented 15 times with different phrasings.
    """
    threats = []

    # Remote Code Execution (15 examples, varied phrasings)
    rce_scenarios = [
        {
            "description": "Metadata service SSRF steals cloud instance credentials via internal HTTP call",
            "threat_type": "Server-Side Request Forgery",
            "cvss_score": 8.4,
            "severity": "High",
            "exploitability": 8.9,
            "asset_type": "Cloud Infrastructure",
        },
        {
            "description": "Image fetcher SSRF accesses localhost admin panel on loopback interface",
            "threat_type": "Server-Side Request Forgery",
            "cvss_score": 7.4,
            "severity": "High",
            "exploitability": 8.1,
            "asset_type": "Web Application",
        },
        {
            "description": "Webhook SSRF pivots into internal Redis management endpoint",
            "threat_type": "Server-Side Request Forgery",
            "cvss_score": 7.6,
            "severity": "High",
            "exploitability": 8.0,
            "asset_type": "API Server",
        },
        {
            "description": "PDF converter SSRF enumerates internal services through gopher protocol",
            "threat_type": "Server-Side Request Forgery",
            "cvss_score": 7.1,
            "severity": "High",
            "exploitability": 7.6,
            "asset_type": "Document Service",
        },
        {
            "description": "Remote code execution via unsafe deserialization in Java objects",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.8,
            "severity": "Critical",
            "exploitability": 9.8,
            "asset_type": "Application Server",
        },
        {
            "description": "Unauthenticated RCE through command injection in web form parameters",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.9,
            "severity": "Critical",
            "exploitability": 10.0,
            "asset_type": "Web Server",
        },
        {
            "description": "Log4Shell: JNDI injection leading to arbitrary code execution via crafted log messages",
            "threat_type": "Remote Code Execution",
            "cvss_score": 10.0,
            "severity": "Critical",
            "exploitability": 10.0,
            "asset_type": "Java Service",
        },
        {
            "description": "PHP-FPM buffer underflow allows code execution via crafted requests",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.8,
            "severity": "Critical",
            "exploitability": 9.8,
            "asset_type": "Web Server",
        },
        {
            "description": "Template injection in Jinja2 allows arbitrary Python code execution",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.9,
            "severity": "Critical",
            "exploitability": 9.5,
            "asset_type": "Python Application",
        },
        {
            "description": "Spring4Shell remote code execution through expression language injection",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.8,
            "severity": "Critical",
            "exploitability": 9.8,
            "asset_type": "Java Service",
        },
        {
            "description": "NodeJS child_process execution vulnerability via unvalidated input",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.9,
            "severity": "Critical",
            "exploitability": 9.5,
            "asset_type": "Node.js Service",
        },
        {
            "description": "Unsafe pickle deserialization in Python leads to arbitrary code execution",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.8,
            "severity": "Critical",
            "exploitability": 9.0,
            "asset_type": "Python Application",
        },
        {
            "description": "GraphQL query execution allows shell command invocation through resolvers",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.5,
            "severity": "Critical",
            "exploitability": 8.5,
            "asset_type": "API Server",
        },
        {
            "description": "Eval function misuse in web framework allows direct code injection",
            "threat_type": "Remote Code Execution",
            "cvss_score": 10.0,
            "severity": "Critical",
            "exploitability": 10.0,
            "asset_type": "Web Application",
        },
        {
            "description": "Ruby on Rails mass assignment vulnerability leading to code execution",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.8,
            "severity": "Critical",
            "exploitability": 8.8,
            "asset_type": "Rails Application",
        },
        {
            "description": "Express.js prototype pollution enables remote code execution",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.8,
            "severity": "Critical",
            "exploitability": 9.3,
            "asset_type": "Node.js Service",
        },
        {
            "description": "ASP.NET ViewState deserialization gadget chain leads to code execution",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.8,
            "severity": "Critical",
            "exploitability": 9.0,
            "asset_type": ".NET Application",
        },
        {
            "description": "YAML deserialization in Ruby leads to arbitrary method calls",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.9,
            "severity": "Critical",
            "exploitability": 9.5,
            "asset_type": "Ruby Service",
        },
        {
            "description": "Server-side template injection in Freemarker allows code execution",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.8,
            "severity": "Critical",
            "exploitability": 9.0,
            "asset_type": "Java Service",
        },
    ]

    # Path Traversal / Directory Traversal (10 examples)
    traversal_scenarios = [
        {
            "description": "Path traversal vulnerability allows reading arbitrary files via ../ sequences",
            "threat_type": "Path Traversal",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 8.0,
            "asset_type": "Web Server",
        },
        {
            "description": "Directory traversal in file upload handler enables access to system files",
            "threat_type": "Path Traversal",
            "cvss_score": 7.2,
            "severity": "High",
            "exploitability": 7.8,
            "asset_type": "Web Application",
        },
        {
            "description": "Local file inclusion via malicious URL parameters",
            "threat_type": "Path Traversal",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 8.5,
            "asset_type": "Web Server",
        },
        {
            "description": "Arbitrary file read through symbolic link following in API endpoint",
            "threat_type": "Path Traversal",
            "cvss_score": 7.3,
            "severity": "High",
            "exploitability": 7.5,
            "asset_type": "API Server",
        },
        {
            "description": "Zip slip vulnerability allows extraction to arbitrary directories",
            "threat_type": "Path Traversal",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 8.0,
            "asset_type": "Web Application",
        },
        {
            "description": "Null byte injection bypasses file extension validation",
            "threat_type": "Path Traversal",
            "cvss_score": 6.5,
            "severity": "High",
            "exploitability": 7.5,
            "asset_type": "Web Server",
        },
        {
            "description": "URL encoding bypass allows path traversal in file download functionality",
            "threat_type": "Path Traversal",
            "cvss_score": 7.2,
            "severity": "High",
            "exploitability": 8.2,
            "asset_type": "Web Application",
        },
        {
            "description": "Double URL encoding defeats path traversal filters",
            "threat_type": "Path Traversal",
            "cvss_score": 7.1,
            "severity": "High",
            "exploitability": 8.0,
            "asset_type": "Web Server",
        },
        {
            "description": "Case sensitivity bypass in file access controls allows unauthorized reads",
            "threat_type": "Path Traversal",
            "cvss_score": 6.8,
            "severity": "High",
            "exploitability": 7.2,
            "asset_type": "Web Application",
        },
        {
            "description": "Backslash conversion in path traversal bypasses forward slash validation",
            "threat_type": "Path Traversal",
            "cvss_score": 7.0,
            "severity": "High",
            "exploitability": 7.8,
            "asset_type": "Web Server",
        },
        {
            "description": "Unicode encoding bypass in path validation allows file access",
            "threat_type": "Path Traversal",
            "cvss_score": 6.9,
            "severity": "High",
            "exploitability": 7.5,
            "asset_type": "Web Application",
        },
        {
            "description": "Nested encoding bypass defeats multiple validation layers",
            "threat_type": "Path Traversal",
            "cvss_score": 7.3,
            "severity": "High",
            "exploitability": 8.0,
            "asset_type": "Web Server",
        },
        {
            "description": "Absolute path bypass allows access to root filesystem",
            "threat_type": "Path Traversal",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 8.2,
            "asset_type": "Application Server",
        },
        {
            "description": "Archive extraction path traversal escapes intended directory",
            "threat_type": "Path Traversal",
            "cvss_score": 7.4,
            "severity": "High",
            "exploitability": 7.8,
            "asset_type": "Web Application",
        },
    ]

    # SQL Injection (15 examples)
    sqli_scenarios = [
        {
            "description": "SQL injection in login form allows authentication bypass and data exfiltration",
            "threat_type": "SQL Injection",
            "cvss_score": 9.8,
            "severity": "Critical",
            "exploitability": 8.6,
            "asset_type": "Web Application",
        },
        {
            "description": "Blind SQL injection in search parameter enables database enumeration and modification",
            "threat_type": "SQL Injection",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 6.5,
            "asset_type": "Web Server",
        },
        {
            "description": "Time-based blind SQLi in user input field allows data extraction",
            "threat_type": "SQL Injection",
            "cvss_score": 7.3,
            "severity": "High",
            "exploitability": 6.2,
            "asset_type": "Database Application",
        },
        {
            "description": "Error-based SQL injection reveals database structure and sensitive data",
            "threat_type": "SQL Injection",
            "cvss_score": 8.0,
            "severity": "High",
            "exploitability": 7.5,
            "asset_type": "Web Application",
        },
        {
            "description": "Union-based SQLi combines attacker queries with legitimate results",
            "threat_type": "SQL Injection",
            "cvss_score": 8.5,
            "severity": "High",
            "exploitability": 8.0,
            "asset_type": "Web Server",
        },
        {
            "description": "Stacked queries SQL injection allows arbitrary SQL execution",
            "threat_type": "SQL Injection",
            "cvss_score": 9.2,
            "severity": "Critical",
            "exploitability": 8.8,
            "asset_type": "Database Application",
        },
        {
            "description": "Second-order SQL injection stored in database executes on retrieval",
            "threat_type": "SQL Injection",
            "cvss_score": 7.8,
            "severity": "High",
            "exploitability": 6.5,
            "asset_type": "Web Application",
        },
        {
            "description": "NoSQL injection in MongoDB query allows unauthorized data access",
            "threat_type": "SQL Injection",
            "cvss_score": 8.2,
            "severity": "High",
            "exploitability": 7.8,
            "asset_type": "Database Application",
        },
        {
            "description": "ORM injection in parameterized query builder bypasses protections",
            "threat_type": "SQL Injection",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 7.0,
            "asset_type": "Web Application",
        },
        {
            "description": "LDAP injection in authentication query allows unauthorized access",
            "threat_type": "SQL Injection",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 7.5,
            "asset_type": "Authentication Service",
        },
        {
            "description": "GraphQL query injection extracts multiple database records",
            "threat_type": "SQL Injection",
            "cvss_score": 8.0,
            "severity": "High",
            "exploitability": 7.8,
            "asset_type": "API Server",
        },
        {
            "description": "Operator-based NoSQL injection bypasses authentication",
            "threat_type": "SQL Injection",
            "cvss_score": 8.3,
            "severity": "High",
            "exploitability": 8.0,
            "asset_type": "Database Application",
        },
        {
            "description": "Regex-based database query injection allows pattern matching attacks",
            "threat_type": "SQL Injection",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 7.2,
            "asset_type": "NoSQL Database",
        },
        {
            "description": "Cassandra CQL injection in distributed database",
            "threat_type": "SQL Injection",
            "cvss_score": 7.8,
            "severity": "High",
            "exploitability": 7.0,
            "asset_type": "Distributed Database",
        },
    ]

    # Authentication Bypass (15 examples)
    auth_scenarios = [
        {
            "description": "Authentication bypass through JWT token manipulation or signature forgery",
            "threat_type": "Authentication Bypass",
            "cvss_score": 9.1,
            "severity": "Critical",
            "exploitability": 8.8,
            "asset_type": "API Server",
        },
        {
            "description": "Default credentials in admin panel allow unauthorized access",
            "threat_type": "Authentication Bypass",
            "cvss_score": 8.2,
            "severity": "High",
            "exploitability": 7.5,
            "asset_type": "Network Device",
        },
        {
            "description": "Session fixation attack allows attacker to hijack authenticated session",
            "threat_type": "Authentication Bypass",
            "cvss_score": 7.8,
            "severity": "High",
            "exploitability": 8.2,
            "asset_type": "Web Application",
        },
        {
            "description": "Weak password reset token enables account takeover",
            "threat_type": "Authentication Bypass",
            "cvss_score": 8.5,
            "severity": "High",
            "exploitability": 8.5,
            "asset_type": "Web Application",
        },
        {
            "description": "OAuth 2.0 redirect URI bypass allows authorization code interception",
            "threat_type": "Authentication Bypass",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 7.2,
            "asset_type": "OAuth Provider",
        },
        {
            "description": "Multi-factor authentication bypass through SMS interception",
            "threat_type": "Authentication Bypass",
            "cvss_score": 8.3,
            "severity": "High",
            "exploitability": 7.8,
            "asset_type": "Web Application",
        },
        {
            "description": "SAML authentication vulnerability allows impersonation of users",
            "threat_type": "Authentication Bypass",
            "cvss_score": 8.6,
            "severity": "High",
            "exploitability": 7.5,
            "asset_type": "SSO Provider",
        },
        {
            "description": "API key exposed in client-side code allows unauthorized API access",
            "threat_type": "Authentication Bypass",
            "cvss_score": 8.0,
            "severity": "High",
            "exploitability": 9.0,
            "asset_type": "API Server",
        },
        {
            "description": "Broken session validation allows replay of stolen session tokens to impersonate users",
            "threat_type": "Authentication Bypass",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 8.5,
            "asset_type": "Web Application",
        },
        {
            "description": "Cookie theft via XSS enables session hijacking without authentication",
            "threat_type": "Authentication Bypass",
            "cvss_score": 8.0,
            "severity": "High",
            "exploitability": 8.2,
            "asset_type": "Web Application",
        },
        {
            "description": "Kerberos relay attack impersonates authenticated users",
            "threat_type": "Authentication Bypass",
            "cvss_score": 8.5,
            "severity": "High",
            "exploitability": 7.5,
            "asset_type": "Windows Domain",
        },
        {
            "description": "NTLM relay attack intercepts authentication handshake",
            "threat_type": "Authentication Bypass",
            "cvss_score": 8.2,
            "severity": "High",
            "exploitability": 7.8,
            "asset_type": "Windows Network",
        },
        {
            "description": "Passwordless authentication vulnerability allows SMS spoofing",
            "threat_type": "Authentication Bypass",
            "cvss_score": 8.0,
            "severity": "High",
            "exploitability": 7.5,
            "asset_type": "Authentication System",
        },
        {
            "description": "Private key compromise enables SSL/TLS certificate impersonation",
            "threat_type": "Authentication Bypass",
            "cvss_score": 8.8,
            "severity": "High",
            "exploitability": 6.5,
            "asset_type": "Certificate Authority",
        },
    ]

    # Cross-Site Scripting (15 examples)
    xss_scenarios = [
        {
            "description": "Stored XSS in comment section allows arbitrary JavaScript execution in user browsers",
            "threat_type": "Cross-Site Scripting",
            "cvss_score": 6.1,
            "severity": "Medium",
            "exploitability": 8.8,
            "asset_type": "Web Application",
        },
        {
            "description": "Reflected XSS via URL parameters leads to session hijacking",
            "threat_type": "Cross-Site Scripting",
            "cvss_score": 6.1,
            "severity": "Medium",
            "exploitability": 8.2,
            "asset_type": "Web Server",
        },
        {
            "description": "DOM-based XSS in JavaScript allows client-side code injection",
            "threat_type": "Cross-Site Scripting",
            "cvss_score": 6.1,
            "severity": "Medium",
            "exploitability": 7.8,
            "asset_type": "Web Application",
        },
        {
            "description": "Mutation XSS via SVG filter bypass enables code execution",
            "threat_type": "Cross-Site Scripting",
            "cvss_score": 6.0,
            "severity": "Medium",
            "exploitability": 7.2,
            "asset_type": "Web Browser",
        },
        {
            "description": "CSS-based XSS through style attribute injection",
            "threat_type": "Cross-Site Scripting",
            "cvss_score": 5.5,
            "severity": "Medium",
            "exploitability": 7.0,
            "asset_type": "Web Application",
        },
        {
            "description": "Dangling markup injection leads to data exfiltration",
            "threat_type": "Cross-Site Scripting",
            "cvss_score": 5.8,
            "severity": "Medium",
            "exploitability": 7.5,
            "asset_type": "Web Application",
        },
        {
            "description": "XSS in error messages bypasses input validation filters",
            "threat_type": "Cross-Site Scripting",
            "cvss_score": 6.0,
            "severity": "Medium",
            "exploitability": 8.0,
            "asset_type": "Web Server",
        },
        {
            "description": "Server-side template injection leads to client-side script injection",
            "threat_type": "Cross-Site Scripting",
            "cvss_score": 6.5,
            "severity": "Medium",
            "exploitability": 7.5,
            "asset_type": "Web Application",
        },
        {
            "description": "JSON hijacking via script tag allows data theft",
            "threat_type": "Cross-Site Scripting",
            "cvss_score": 5.5,
            "severity": "Medium",
            "exploitability": 6.5,
            "asset_type": "API Server",
        },
        {
            "description": "Content-Type confusion allows HTML injection and XSS",
            "threat_type": "Cross-Site Scripting",
            "cvss_score": 6.2,
            "severity": "Medium",
            "exploitability": 8.0,
            "asset_type": "Web Server",
        },
        {
            "description": "Character encoding bypass exploits charset interpretation",
            "threat_type": "Cross-Site Scripting",
            "cvss_score": 5.8,
            "severity": "Medium",
            "exploitability": 7.5,
            "asset_type": "Web Application",
        },
        {
            "description": "SVG animation XSS via JavaScript event handlers",
            "threat_type": "Cross-Site Scripting",
            "cvss_score": 6.1,
            "severity": "Medium",
            "exploitability": 7.2,
            "asset_type": "Web Server",
        },
        {
            "description": "PDF embedded JavaScript execution in browser",
            "threat_type": "Cross-Site Scripting",
            "cvss_score": 6.3,
            "severity": "Medium",
            "exploitability": 7.8,
            "asset_type": "Web Application",
        },
        {
            "description": "Flash object ExternalInterface XSS callback",
            "threat_type": "Cross-Site Scripting",
            "cvss_score": 5.9,
            "severity": "Medium",
            "exploitability": 6.5,
            "asset_type": "Web Browser",
        },
    ]

    # Privilege Escalation (15 examples)
    privesc_scenarios = [
        {
            "description": "Local privilege escalation through kernel vulnerability in Windows service",
            "threat_type": "Privilege Escalation",
            "cvss_score": 8.8,
            "severity": "High",
            "exploitability": 7.8,
            "asset_type": "Windows Server",
        },
        {
            "description": "Sudo configuration error allows unprivileged user to run privileged commands",
            "threat_type": "Privilege Escalation",
            "cvss_score": 7.8,
            "severity": "High",
            "exploitability": 8.2,
            "asset_type": "Linux Server",
        },
        {
            "description": "Polkit authorization bypass grants root access to unprivileged processes",
            "threat_type": "Privilege Escalation",
            "cvss_score": 8.0,
            "severity": "High",
            "exploitability": 7.5,
            "asset_type": "Linux System",
        },
        {
            "description": "DLL hijacking in Windows allows privilege elevation",
            "threat_type": "Privilege Escalation",
            "cvss_score": 8.5,
            "severity": "High",
            "exploitability": 8.0,
            "asset_type": "Windows Server",
        },
        {
            "description": "Improper file permissions on setuid binary enables privilege escalation",
            "threat_type": "Privilege Escalation",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 8.5,
            "asset_type": "Linux System",
        },
        {
            "description": "Docker escape through cgroup vulnerability grants root access",
            "threat_type": "Privilege Escalation",
            "cvss_score": 8.5,
            "severity": "High",
            "exploitability": 7.8,
            "asset_type": "Container Platform",
        },
        {
            "description": "MySQL privilege escalation via symlink following",
            "threat_type": "Privilege Escalation",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 7.2,
            "asset_type": "Database Server",
        },
        {
            "description": "Cron job misconfiguration allows arbitrary command execution as root",
            "threat_type": "Privilege Escalation",
            "cvss_score": 8.0,
            "severity": "High",
            "exploitability": 8.8,
            "asset_type": "Linux Server",
        },
        {
            "description": "SUID binary buffer overflow leads to privilege escalation",
            "threat_type": "Privilege Escalation",
            "cvss_score": 8.8,
            "severity": "High",
            "exploitability": 7.8,
            "asset_type": "Unix System",
        },
        {
            "description": "SeImpersonate token abuse allows token impersonation in Windows",
            "threat_type": "Privilege Escalation",
            "cvss_score": 8.2,
            "severity": "High",
            "exploitability": 8.0,
            "asset_type": "Windows Server",
        },
        {
            "description": "Dirty COW kernel vulnerability allows privilege escalation",
            "threat_type": "Privilege Escalation",
            "cvss_score": 7.8,
            "severity": "High",
            "exploitability": 7.5,
            "asset_type": "Linux System",
        },
        {
            "description": "PwnKit Local Privilege Escalation via crafted Polkit query",
            "threat_type": "Privilege Escalation",
            "cvss_score": 8.4,
            "severity": "High",
            "exploitability": 8.2,
            "asset_type": "Linux Desktop",
        },
        {
            "description": "DBus privilege escalation via systemd service files",
            "threat_type": "Privilege Escalation",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 7.8,
            "asset_type": "Linux System",
        },
        {
            "description": "Kernel module loading via modprobe allows code execution as root",
            "threat_type": "Privilege Escalation",
            "cvss_score": 8.0,
            "severity": "High",
            "exploitability": 7.2,
            "asset_type": "Linux Server",
        },
    ]

    # Denial of Service (15 examples)
    dos_scenarios = [
        {
            "description": "HTTP/2 Rapid Reset DoS attack sends rapid stream resets causing service crash",
            "threat_type": "Denial of Service",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 7.5,
            "asset_type": "Web Server",
        },
        {
            "description": "Algorithmic complexity DoS via malformed requests triggers infinite loops",
            "threat_type": "Denial of Service",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 8.0,
            "asset_type": "Web Application",
        },
        {
            "description": "Slowloris attack exhausts server connections via slow HTTP requests",
            "threat_type": "Denial of Service",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 8.5,
            "asset_type": "Web Server",
        },
        {
            "description": "XML external entity denial of service consumes memory",
            "threat_type": "Denial of Service",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 7.8,
            "asset_type": "XML Processor",
        },
        {
            "description": "Regular expression denial of service via catastrophic backtracking",
            "threat_type": "Denial of Service",
            "cvss_score": 7.0,
            "severity": "High",
            "exploitability": 8.0,
            "asset_type": "Application",
        },
        {
            "description": "Distributed denial of service via botnet flood attacks",
            "threat_type": "Denial of Service",
            "cvss_score": 8.0,
            "severity": "High",
            "exploitability": 7.0,
            "asset_type": "Internet",
        },
        {
            "description": "Memory leak exploitation causes gradual service degradation",
            "threat_type": "Denial of Service",
            "cvss_score": 6.5,
            "severity": "Medium",
            "exploitability": 7.2,
            "asset_type": "Application",
        },
        {
            "description": "DNS amplification attack uses DNS servers for traffic multiplication",
            "threat_type": "Denial of Service",
            "cvss_score": 7.8,
            "severity": "High",
            "exploitability": 8.5,
            "asset_type": "DNS Server",
        },
        {
            "description": "Compression bomb decompression consumes CPU and memory resources",
            "threat_type": "Denial of Service",
            "cvss_score": 6.5,
            "severity": "Medium",
            "exploitability": 8.0,
            "asset_type": "Web Server",
        },
        {
            "description": "Hash collision DoS in hash tables causes performance degradation",
            "threat_type": "Denial of Service",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 8.0,
            "asset_type": "Application",
        },
        {
            "description": "Billion laughs XML entity expansion attack",
            "threat_type": "Denial of Service",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 8.5,
            "asset_type": "XML Parser",
        },
        {
            "description": "UDP flood amplification attack via open DNS resolvers",
            "threat_type": "Denial of Service",
            "cvss_score": 8.2,
            "severity": "High",
            "exploitability": 8.8,
            "asset_type": "Network Infrastructure",
        },
        {
            "description": "HTTP request smuggling causes service disruption",
            "threat_type": "Denial of Service",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 7.8,
            "asset_type": "Web Server",
        },
        {
            "description": "OpenSSL handshake flood causes worker exhaustion and service timeout",
            "threat_type": "Denial of Service",
            "cvss_score": 7.6,
            "severity": "High",
            "exploitability": 7.8,
            "asset_type": "Web Server",
        },
        {
            "description": "OpenSSL certificate parsing crash leads to repeated service restarts",
            "threat_type": "Denial of Service",
            "cvss_score": 7.4,
            "severity": "High",
            "exploitability": 7.2,
            "asset_type": "API Server",
        },
        {
            "description": "Malformed TLS traffic triggers OpenSSL CPU spike and request backlog",
            "threat_type": "Denial of Service",
            "cvss_score": 7.7,
            "severity": "High",
            "exploitability": 7.9,
            "asset_type": "Network Service",
        },
        {
            "description": "Repeated renegotiation requests overload OpenSSL connection handling",
            "threat_type": "Denial of Service",
            "cvss_score": 7.3,
            "severity": "High",
            "exploitability": 7.1,
            "asset_type": "Web Server",
        },
        {
            "description": "Crafted SSL payload causes OpenSSL memory pressure and process slowdown",
            "threat_type": "Denial of Service",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 7.4,
            "asset_type": "Application Server",
        },
        {
            "description": "TLS handshake abuse exhausts OpenSSL worker threads under load",
            "threat_type": "Denial of Service",
            "cvss_score": 7.8,
            "severity": "High",
            "exploitability": 8.0,
            "asset_type": "Web Server",
        },
        {
            "description": "Large burst of invalid HTTPS sessions causes OpenSSL listener saturation",
            "threat_type": "Denial of Service",
            "cvss_score": 7.6,
            "severity": "High",
            "exploitability": 7.7,
            "asset_type": "Network Service",
        },
        {
            "description": "Repeated malformed client hello packets trigger OpenSSL crash loop",
            "threat_type": "Denial of Service",
            "cvss_score": 7.9,
            "severity": "High",
            "exploitability": 8.1,
            "asset_type": "Web Server",
        },
        {
            "description": "OpenSSL renegotiation abuse blocks legitimate traffic and degrades availability",
            "threat_type": "Denial of Service",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 7.6,
            "asset_type": "API Server",
        },
        {
            "description": "Excessive TLS connection attempts exhaust OpenSSL processing capacity",
            "threat_type": "Denial of Service",
            "cvss_score": 7.4,
            "severity": "High",
            "exploitability": 7.5,
            "asset_type": "Web Server",
        },
        {
            "description": "Packet fragmentation attack bypasses firewall rules",
            "threat_type": "Denial of Service",
            "cvss_score": 7.0,
            "severity": "High",
            "exploitability": 7.5,
            "asset_type": "Network Device",
        },
    ]

    # Server-Side Request Forgery (15 examples)
    ssrf_scenarios = [
        {
            "description": "SSRF vulnerability allows attacker to make internal network requests from server",
            "threat_type": "Server-Side Request Forgery",
            "cvss_score": 8.6,
            "severity": "High",
            "exploitability": 8.2,
            "asset_type": "Web Server",
        },
        {
            "description": "URL parameter vulnerability leads to internal service enumeration via SSRF",
            "threat_type": "Server-Side Request Forgery",
            "cvss_score": 7.1,
            "severity": "High",
            "exploitability": 7.3,
            "asset_type": "Web Application",
        },
        {
            "description": "SSRF via image proxy allows access to internal APIs",
            "threat_type": "Server-Side Request Forgery",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 8.0,
            "asset_type": "Web Application",
        },
        {
            "description": "Webhook SSRF to localhost enables server-side port scanning",
            "threat_type": "Server-Side Request Forgery",
            "cvss_score": 7.2,
            "severity": "High",
            "exploitability": 7.8,
            "asset_type": "API Server",
        },
        {
            "description": "XML external entity via SSRF exfiltrates local files",
            "threat_type": "Server-Side Request Forgery",
            "cvss_score": 8.0,
            "severity": "High",
            "exploitability": 7.5,
            "asset_type": "XML Parser",
        },
        {
            "description": "SSRF via open redirect allows internal resource access",
            "threat_type": "Server-Side Request Forgery",
            "cvss_score": 6.5,
            "severity": "High",
            "exploitability": 8.0,
            "asset_type": "Web Application",
        },
        {
            "description": "Data URI exploitation enables SSRF bypass of URL validation",
            "threat_type": "Server-Side Request Forgery",
            "cvss_score": 7.0,
            "severity": "High",
            "exploitability": 7.5,
            "asset_type": "Web Server",
        },
        {
            "description": "Gopher protocol SSRF accesses legacy network services",
            "threat_type": "Server-Side Request Forgery",
            "cvss_score": 6.8,
            "severity": "High",
            "exploitability": 7.0,
            "asset_type": "Network Application",
        },
        {
            "description": "File protocol SSRF reads local files bypassing HTTP-only policies",
            "threat_type": "Server-Side Request Forgery",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 8.5,
            "asset_type": "Web Application",
        },
        {
            "description": "Webhook fetches internal metadata service URL and exposes cloud credentials",
            "threat_type": "Server-Side Request Forgery",
            "cvss_score": 8.4,
            "severity": "High",
            "exploitability": 8.3,
            "asset_type": "Web Server",
        },
        {
            "description": "Image proxy allows requests to localhost admin endpoint through URL parameter",
            "threat_type": "Server-Side Request Forgery",
            "cvss_score": 7.6,
            "severity": "High",
            "exploitability": 7.9,
            "asset_type": "Web Application",
        },
        {
            "description": "PDF conversion service can be forced to call internal Redis management port",
            "threat_type": "Server-Side Request Forgery",
            "cvss_score": 7.8,
            "severity": "High",
            "exploitability": 8.0,
            "asset_type": "API Server",
        },
        {
            "description": "FTP protocol SSRF commands internal FTP servers for data exfiltration",
            "threat_type": "Server-Side Request Forgery",
            "cvss_score": 7.3,
            "severity": "High",
            "exploitability": 7.2,
            "asset_type": "Application Server",
        },
        {
            "description": "Redis SSRF exploit executes arbitrary commands",
            "threat_type": "Server-Side Request Forgery",
            "cvss_score": 8.0,
            "severity": "High",
            "exploitability": 7.8,
            "asset_type": "Cache Server",
        },
        {
            "description": "Memcached SSRF leads to internal cache poisoning",
            "threat_type": "Server-Side Request Forgery",
            "cvss_score": 7.2,
            "severity": "High",
            "exploitability": 7.5,
            "asset_type": "Cache Layer",
        },
        {
            "description": "SMTP SSRF allows email header injection and spoofing",
            "threat_type": "Server-Side Request Forgery",
            "cvss_score": 6.5,
            "severity": "High",
            "exploitability": 7.2,
            "asset_type": "Mail Server",
        },
        {
            "description": "Telnet SSRF executes arbitrary commands on network services",
            "threat_type": "Server-Side Request Forgery",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 7.0,
            "asset_type": "Network Device",
        },
    ]

    # Insecure Deserialization (15 examples)
    deser_scenarios = [
        {
            "description": "Insecure object deserialization in Java leads to arbitrary code execution",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.8,
            "severity": "Critical",
            "exploitability": 8.1,
            "asset_type": "Java Service",
        },
        {
            "description": "Python pickle deserialization gadget chain enables remote code execution",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.8,
            "severity": "Critical",
            "exploitability": 9.0,
            "asset_type": "Python Application",
        },
        {
            "description": "Ruby Marshal object deserialization allows code execution",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.9,
            "severity": "Critical",
            "exploitability": 9.2,
            "asset_type": "Ruby Service",
        },
        {
            "description": ".NET binary serialization via BinaryFormatter enables RCE",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.8,
            "severity": "Critical",
            "exploitability": 8.5,
            "asset_type": ".NET Application",
        },
        {
            "description": "Java XMLDecoder exploitation through unsafe XML deserialization",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.8,
            "severity": "Critical",
            "exploitability": 8.3,
            "asset_type": "Java Service",
        },
        {
            "description": "PHP unserialize function vulnerability with object injection",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.8,
            "severity": "Critical",
            "exploitability": 8.7,
            "asset_type": "PHP Application",
        },
        {
            "description": "Java serialization via Commons Collections gadget chain",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.8,
            "severity": "Critical",
            "exploitability": 8.0,
            "asset_type": "Java Service",
        },
        {
            "description": "Go gob deserialization allows type confusion and code execution",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.5,
            "severity": "Critical",
            "exploitability": 8.2,
            "asset_type": "Go Application",
        },
        {
            "description": "Java JNDI injection via deserialization enables remote code execution",
            "threat_type": "Remote Code Execution",
            "cvss_score": 10.0,
            "severity": "Critical",
            "exploitability": 9.8,
            "asset_type": "Java Service",
        },
        {
            "description": "Protobuf message deserialization bypass via field confusion",
            "threat_type": "Remote Code Execution",
            "cvss_score": 8.5,
            "severity": "High",
            "exploitability": 7.0,
            "asset_type": "Service",
        },
        {
            "description": "FastJSON deserialization gadget chain RCE",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.8,
            "severity": "Critical",
            "exploitability": 9.0,
            "asset_type": "Java Service",
        },
        {
            "description": "JEXL expression evaluation in deserialized objects",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.5,
            "severity": "Critical",
            "exploitability": 8.5,
            "asset_type": "Application",
        },
        {
            "description": "OGNL injection in deserialized Struts action objects",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.8,
            "severity": "Critical",
            "exploitability": 8.8,
            "asset_type": "Java Web Application",
        },
        {
            "description": "Jodd deserialization code injection vulnerability",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.5,
            "severity": "Critical",
            "exploitability": 8.2,
            "asset_type": "Java Application",
        },
    ]

    # Insecure Direct Object Reference / Business Logic (15 examples)
    idor_scenarios = [
        {
            "description": "Insecure direct object reference allows viewing other users accounts",
            "threat_type": "Insecure Direct Object Reference",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 8.8,
            "asset_type": "Web Application",
        },
        {
            "description": "API parameter tampering enables unauthorized access to resources",
            "threat_type": "Insecure Direct Object Reference",
            "cvss_score": 7.0,
            "severity": "High",
            "exploitability": 8.5,
            "asset_type": "API Server",
        },
        {
            "description": "Sequential ID enumeration allows scanning all user records",
            "threat_type": "Insecure Direct Object Reference",
            "cvss_score": 6.5,
            "severity": "Medium",
            "exploitability": 9.0,
            "asset_type": "Web Application",
        },
        {
            "description": "Changing transfer_id during concurrent payment requests reveals another user's transaction record",
            "threat_type": "Insecure Direct Object Reference",
            "cvss_score": 7.2,
            "severity": "High",
            "exploitability": 6.5,
            "asset_type": "Payment System",
        },
        {
            "description": "Editing shipment_id in out-of-order API calls returns another customer shipment details",
            "threat_type": "Insecure Direct Object Reference",
            "cvss_score": 6.8,
            "severity": "High",
            "exploitability": 7.5,
            "asset_type": "Web Application",
        },
        {
            "description": "Workflow task endpoint accepts modified task_id and exposes another employee approval records",
            "threat_type": "Insecure Direct Object Reference",
            "cvss_score": 7.0,
            "severity": "High",
            "exploitability": 8.0,
            "asset_type": "Workflow Engine",
        },
        {
            "description": "Changing payout_id in transaction API allows viewing another merchant payout details",
            "threat_type": "Insecure Direct Object Reference",
            "cvss_score": 7.8,
            "severity": "High",
            "exploitability": 7.8,
            "asset_type": "Payment Application",
        },
        {
            "description": "Tampering cart_id in checkout request exposes another user's cart contents and discounts",
            "threat_type": "Insecure Direct Object Reference",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 8.5,
            "asset_type": "E-Commerce",
        },
        {
            "description": "Modifying role_assignment_id allows unauthorized access to other users role assignment records",
            "threat_type": "Insecure Direct Object Reference",
            "cvss_score": 8.2,
            "severity": "High",
            "exploitability": 8.5,
            "asset_type": "Web Application",
        },
        {
            "description": "Changing coupon_redemption_id returns another customer's coupon redemption history",
            "threat_type": "Insecure Direct Object Reference",
            "cvss_score": 6.5,
            "severity": "Medium",
            "exploitability": 8.0,
            "asset_type": "E-Commerce",
        },
        {
            "description": "Transaction ID guessing enables viewing other orders",
            "threat_type": "Insecure Direct Object Reference",
            "cvss_score": 7.0,
            "severity": "High",
            "exploitability": 8.8,
            "asset_type": "E-Commerce",
        },
        {
            "description": "Invoice number enumeration accesses confidential documents",
            "threat_type": "Insecure Direct Object Reference",
            "cvss_score": 6.8,
            "severity": "High",
            "exploitability": 8.5,
            "asset_type": "Billing System",
        },
        {
            "description": "Altering subscription_id in billing API reveals another tenant subscription and payment records",
            "threat_type": "Insecure Direct Object Reference",
            "cvss_score": 6.5,
            "severity": "Medium",
            "exploitability": 8.0,
            "asset_type": "SaaS Platform",
        },
        {
            "description": "Content access control bypass via resource ID prediction",
            "threat_type": "Insecure Direct Object Reference",
            "cvss_score": 7.2,
            "severity": "High",
            "exploitability": 8.2,
            "asset_type": "Content Management",
        },
        {
            "description": "Predictable order IDs allow unauthorized invoice access",
            "threat_type": "Insecure Direct Object Reference",
            "cvss_score": 7.4,
            "severity": "High",
            "exploitability": 9.0,
            "asset_type": "Billing System",
        },
        {
            "description": "Resource ID tampering exposes other customers profile records",
            "threat_type": "Insecure Direct Object Reference",
            "cvss_score": 7.1,
            "severity": "High",
            "exploitability": 8.8,
            "asset_type": "Web Application",
        },
        {
            "description": "Sequential API IDs let attacker download private documents",
            "threat_type": "Insecure Direct Object Reference",
            "cvss_score": 6.9,
            "severity": "Medium",
            "exploitability": 8.7,
            "asset_type": "API Server",
        },
        {
            "description": "Changing invoice_id in the URL returns another customer billing record",
            "threat_type": "Insecure Direct Object Reference",
            "cvss_score": 7.4,
            "severity": "High",
            "exploitability": 8.8,
            "asset_type": "Billing System",
        },
        {
            "description": "User profile endpoint exposes other accounts when the account number is modified",
            "threat_type": "Insecure Direct Object Reference",
            "cvss_score": 7.2,
            "severity": "High",
            "exploitability": 8.6,
            "asset_type": "Web Application",
        },
        {
            "description": "Order detail API accepts sequential IDs and reveals unauthorized records",
            "threat_type": "Insecure Direct Object Reference",
            "cvss_score": 7.0,
            "severity": "High",
            "exploitability": 8.5,
            "asset_type": "API Server",
        },
        {
            "description": "Missing authorization on account export endpoint leaks organization data",
            "threat_type": "Insecure Direct Object Reference",
            "cvss_score": 7.8,
            "severity": "High",
            "exploitability": 8.4,
            "asset_type": "SaaS Platform",
        },
    ]

    # Sensitive Data Exposure (15 examples)
    sensitive_data_scenarios = [
        {
            "description": "Sensitive data transmitted over unencrypted HTTP connection",
            "threat_type": "Sensitive Data Exposure",
            "cvss_score": 7.0,
            "severity": "High",
            "exploitability": 8.0,
            "asset_type": "Web Server",
        },
        {
            "description": "Database credentials hardcoded in application source code",
            "threat_type": "Sensitive Data Exposure",
            "cvss_score": 8.5,
            "severity": "High",
            "exploitability": 8.0,
            "asset_type": "Application",
        },
        {
            "description": "API keys exposed in git repository history",
            "threat_type": "Sensitive Data Exposure",
            "cvss_score": 8.0,
            "severity": "High",
            "exploitability": 9.0,
            "asset_type": "Code Repository",
        },
        {
            "description": "Weak encryption algorithm allows decryption of sensitive data",
            "threat_type": "Sensitive Data Exposure",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 7.0,
            "asset_type": "Application",
        },
        {
            "description": "Backup files left accessible with unencrypted database dumps",
            "threat_type": "Sensitive Data Exposure",
            "cvss_score": 8.0,
            "severity": "High",
            "exploitability": 8.5,
            "asset_type": "Storage",
        },
        {
            "description": "SSL certificate key exposed in client-side JavaScript",
            "threat_type": "Sensitive Data Exposure",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 8.0,
            "asset_type": "Web Application",
        },
        {
            "description": "Cached sensitive data in browser history allows retrieval",
            "threat_type": "Sensitive Data Exposure",
            "cvss_score": 6.0,
            "severity": "Medium",
            "exploitability": 7.5,
            "asset_type": "Browser",
        },
        {
            "description": "Password stored in reversible encryption instead of hash",
            "threat_type": "Sensitive Data Exposure",
            "cvss_score": 8.5,
            "severity": "High",
            "exploitability": 6.0,
            "asset_type": "Authentication System",
        },
        {
            "description": "PII logged in application logs without redaction",
            "threat_type": "Sensitive Data Exposure",
            "cvss_score": 6.5,
            "severity": "High",
            "exploitability": 8.0,
            "asset_type": "Logging System",
        },
        {
            "description": "Verbose serialized API responses expose customer PII fields to unauthorized users",
            "threat_type": "Sensitive Data Exposure",
            "cvss_score": 7.0,
            "severity": "High",
            "exploitability": 7.2,
            "asset_type": "Application",
        },
        {
            "description": "Debug information exposed in error messages reveals system details",
            "threat_type": "Sensitive Data Exposure",
            "cvss_score": 5.5,
            "severity": "Medium",
            "exploitability": 8.5,
            "asset_type": "Web Application",
        },
        {
            "description": "Memory dump analysis reveals encryption keys and credentials",
            "threat_type": "Sensitive Data Exposure",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 6.0,
            "asset_type": "System",
        },
        {
            "description": "Browser cache stores sensitive user data unencrypted",
            "threat_type": "Sensitive Data Exposure",
            "cvss_score": 6.2,
            "severity": "High",
            "exploitability": 8.0,
            "asset_type": "Browser",
        },
        {
            "description": "Session token transmitted in query parameter instead of secure cookie",
            "threat_type": "Sensitive Data Exposure",
            "cvss_score": 7.0,
            "severity": "High",
            "exploitability": 8.5,
            "asset_type": "Web Server",
        },
        {
            "description": "Debug endpoint exposes API secrets and JWT signing keys",
            "threat_type": "Sensitive Data Exposure",
            "cvss_score": 8.3,
            "severity": "High",
            "exploitability": 8.6,
            "asset_type": "Web Application",
        },
        {
            "description": "Public S3 bucket leaks unencrypted customer backups",
            "threat_type": "Sensitive Data Exposure",
            "cvss_score": 8.6,
            "severity": "High",
            "exploitability": 8.9,
            "asset_type": "Cloud Storage",
        },
        {
            "description": "Password reset logs store full tokens in application logs",
            "threat_type": "Sensitive Data Exposure",
            "cvss_score": 7.2,
            "severity": "High",
            "exploitability": 8.1,
            "asset_type": "Logging System",
        },
        {
            "description": "TLS downgrade exposes session cookies and authentication tokens to interception",
            "threat_type": "Sensitive Data Exposure",
            "cvss_score": 7.7,
            "severity": "High",
            "exploitability": 7.9,
            "asset_type": "Web Server",
        },
        {
            "description": "Verbose error message leaks API keys and database connection strings",
            "threat_type": "Sensitive Data Exposure",
            "cvss_score": 7.8,
            "severity": "High",
            "exploitability": 8.2,
            "asset_type": "Web Application",
        },
        {
            "description": "Weak TLS configuration allows interception of session tokens in transit",
            "threat_type": "Sensitive Data Exposure",
            "cvss_score": 7.6,
            "severity": "High",
            "exploitability": 7.8,
            "asset_type": "Web Server",
        },
        {
            "description": "Application logs expose personal data and authentication headers",
            "threat_type": "Sensitive Data Exposure",
            "cvss_score": 7.1,
            "severity": "High",
            "exploitability": 8.0,
            "asset_type": "Logging System",
        },
    ]

    # Additional scenarios for expanded training set (Run 6 enhancement)
    extra_rce_scenarios = [
        {
            "description": "Unsafe exec() function allows Python code injection from user input",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.9,
            "severity": "Critical",
            "exploitability": 9.5,
            "asset_type": "Python App",
        },
        {
            "description": "Dynamic SQL query construction enables command injection",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.5,
            "severity": "Critical",
            "exploitability": 8.8,
            "asset_type": "Database App",
        },
        {
            "description": "ImageMagick arbitrary command execution via filename",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.8,
            "severity": "Critical",
            "exploitability": 8.5,
            "asset_type": "Image Service",
        },
        {
            "description": "FFmpeg filter injection enables arbitrary codec execution",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.5,
            "severity": "Critical",
            "exploitability": 8.2,
            "asset_type": "Media Service",
        },
        {
            "description": "Pug template injection via user input leads to code execution",
            "threat_type": "Remote Code Execution",
            "cvss_score": 9.8,
            "severity": "Critical",
            "exploitability": 8.8,
            "asset_type": "Node.js App",
        },
    ]

    extra_path_traversal = [
        {
            "description": "Symlink attack in temporary directory allows writing to arbitrary locations",
            "threat_type": "Path Traversal",
            "cvss_score": 7.2,
            "severity": "High",
            "exploitability": 7.8,
            "asset_type": "Unix System",
        },
        {
            "description": "Relative path traversal in compressed archive extraction",
            "threat_type": "Path Traversal",
            "cvss_score": 7.0,
            "severity": "High",
            "exploitability": 8.2,
            "asset_type": "Archive Handler",
        },
        {
            "description": "Unicode normalization bypass escapes path restrictions",
            "threat_type": "Path Traversal",
            "cvss_score": 6.8,
            "severity": "High",
            "exploitability": 7.5,
            "asset_type": "Web App",
        },
    ]

    extra_sqli = [
        {
            "description": "SQL injection through API sorting parameter",
            "threat_type": "SQL Injection",
            "cvss_score": 7.8,
            "severity": "High",
            "exploitability": 7.2,
            "asset_type": "API Server",
        },
        {
            "description": "Second-order SQL injection via persistent user data",
            "threat_type": "SQL Injection",
            "cvss_score": 8.0,
            "severity": "High",
            "exploitability": 6.8,
            "asset_type": "Web App",
        },
        {
            "description": "Cassandra CQL injection in multi-tenant database",
            "threat_type": "SQL Injection",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 7.0,
            "asset_type": "NoSQL DB",
        },
    ]

    extra_auth = [
        {
            "description": "JWT algorithm confusion attack allows authentication bypass",
            "threat_type": "Authentication Bypass",
            "cvss_score": 8.8,
            "severity": "High",
            "exploitability": 8.2,
            "asset_type": "API Server",
        },
        {
            "description": "Weak token expiration allows session replay attacks",
            "threat_type": "Authentication Bypass",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 8.0,
            "asset_type": "Web App",
        },
        {
            "description": "Captcha bypass via automation enables account takeover",
            "threat_type": "Authentication Bypass",
            "cvss_score": 7.0,
            "severity": "High",
            "exploitability": 8.5,
            "asset_type": "Web App",
        },
    ]

    extra_xss = [
        {
            "description": "Data URI scheme XSS bypasses CSP restrictions",
            "threat_type": "Cross-Site Scripting",
            "cvss_score": 6.5,
            "severity": "Medium",
            "exploitability": 7.8,
            "asset_type": "Web App",
        },
        {
            "description": "JavaScript protocol handler in href attribute",
            "threat_type": "Cross-Site Scripting",
            "cvss_score": 6.2,
            "severity": "Medium",
            "exploitability": 8.0,
            "asset_type": "Web Browser",
        },
        {
            "description": "Meta tag refresh with JavaScript execution",
            "threat_type": "Cross-Site Scripting",
            "cvss_score": 6.0,
            "severity": "Medium",
            "exploitability": 7.5,
            "asset_type": "Web App",
        },
    ]

    extra_privesc = [
        {
            "description": "ALSR bypass enables ROP gadget chain for privilege escalation",
            "threat_type": "Privilege Escalation",
            "cvss_score": 8.5,
            "severity": "High",
            "exploitability": 7.5,
            "asset_type": "Linux System",
        },
        {
            "description": "UAC bypass via DLL proxy loading escalates to admin",
            "threat_type": "Privilege Escalation",
            "cvss_score": 8.5,
            "severity": "High",
            "exploitability": 8.0,
            "asset_type": "Windows System",
        },
        {
            "description": "Systemd service unit file manipulation enables root access",
            "threat_type": "Privilege Escalation",
            "cvss_score": 8.2,
            "severity": "High",
            "exploitability": 7.8,
            "asset_type": "Linux Server",
        },
    ]

    extra_dos = [
        {
            "description": "SYN flood attack exhausts server connection table",
            "threat_type": "Denial of Service",
            "cvss_score": 7.8,
            "severity": "High",
            "exploitability": 8.5,
            "asset_type": "Network Device",
        },
        {
            "description": "Ping of death fragmented ICMP packets crash system",
            "threat_type": "Denial of Service",
            "cvss_score": 7.2,
            "severity": "High",
            "exploitability": 7.8,
            "asset_type": "Network Device",
        },
        {
            "description": "Teardrop attack via overlapping IP fragments",
            "threat_type": "Denial of Service",
            "cvss_score": 7.0,
            "severity": "High",
            "exploitability": 7.5,
            "asset_type": "Server",
        },
        {
            "description": "HTTP/2 rapid reset floods backend worker pool and causes timeouts",
            "threat_type": "Denial of Service",
            "cvss_score": 7.8,
            "severity": "High",
            "exploitability": 8.4,
            "asset_type": "Web Server",
        },
        {
            "description": "Catastrophic regex backtracking in login validator blocks request processing",
            "threat_type": "Denial of Service",
            "cvss_score": 7.2,
            "severity": "High",
            "exploitability": 8.1,
            "asset_type": "Web Application",
        },
        {
            "description": "Botnet SYN flood exhausts firewall state table and drops legitimate sessions",
            "threat_type": "Denial of Service",
            "cvss_score": 8.1,
            "severity": "High",
            "exploitability": 8.7,
            "asset_type": "Network Device",
        },
    ]

    extra_ssrf = [
        {
            "description": "SSRF via PDF generation service accesses internal APIs",
            "threat_type": "Server-Side Request Forgery",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 7.8,
            "asset_type": "PDF Service",
        },
        {
            "description": "SSRF through email header injection fetches internal resources",
            "threat_type": "Server-Side Request Forgery",
            "cvss_score": 6.8,
            "severity": "High",
            "exploitability": 7.2,
            "asset_type": "Mail Service",
        },
        {
            "description": "SSRF via cloud metadata service compromise",
            "threat_type": "Server-Side Request Forgery",
            "cvss_score": 8.5,
            "severity": "High",
            "exploitability": 8.8,
            "asset_type": "Cloud Infrastructure",
        },
        {
            "description": "Avatar fetch endpoint requests localhost admin console through user-supplied URL",
            "threat_type": "Server-Side Request Forgery",
            "cvss_score": 7.7,
            "severity": "High",
            "exploitability": 8.0,
            "asset_type": "Web Application",
        },
        {
            "description": "Webhook callback validation bypass allows requests to internal Kubernetes API",
            "threat_type": "Server-Side Request Forgery",
            "cvss_score": 8.0,
            "severity": "High",
            "exploitability": 8.2,
            "asset_type": "API Server",
        },
    ]

    extra_idor = [
        {
            "description": "API endpoint ID enumeration retrieves all organization resources",
            "threat_type": "Insecure Direct Object Reference",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 9.0,
            "asset_type": "API Server",
        },
        {
            "description": "Predictable UUID generation enables resource enumeration",
            "threat_type": "Insecure Direct Object Reference",
            "cvss_score": 6.8,
            "severity": "High",
            "exploitability": 8.2,
            "asset_type": "Web App",
        },
        {
            "description": "Admin report endpoint exposes records when object IDs are changed without ownership checks",
            "threat_type": "Insecure Direct Object Reference",
            "cvss_score": 8.0,
            "severity": "High",
            "exploitability": 8.5,
            "asset_type": "Web App",
        },
        {
            "description": "Changing account_id in profile API reveals another tenant account details",
            "threat_type": "Insecure Direct Object Reference",
            "cvss_score": 7.3,
            "severity": "High",
            "exploitability": 8.7,
            "asset_type": "API Server",
        },
        {
            "description": "Invoice download endpoint accepts sequential IDs and returns other customer invoices",
            "threat_type": "Insecure Direct Object Reference",
            "cvss_score": 7.4,
            "severity": "High",
            "exploitability": 8.8,
            "asset_type": "Billing System",
        },
        {
            "description": "Order status endpoint lacks ownership check and exposes unrelated order records",
            "threat_type": "Insecure Direct Object Reference",
            "cvss_score": 7.1,
            "severity": "High",
            "exploitability": 8.6,
            "asset_type": "E-Commerce",
        },
        {
            "description": "Document export API uses predictable object IDs without authorization enforcement",
            "threat_type": "Insecure Direct Object Reference",
            "cvss_score": 7.6,
            "severity": "High",
            "exploitability": 8.5,
            "asset_type": "SaaS Platform",
        },
    ]

    extra_sensitive = [
        {
            "description": "TLS downgrade attack forces weak cipher usage",
            "threat_type": "Sensitive Data Exposure",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 7.8,
            "asset_type": "Web Server",
        },
        {
            "description": "Padding oracle attack decrypts encrypted sensitive data",
            "threat_type": "Sensitive Data Exposure",
            "cvss_score": 7.5,
            "severity": "High",
            "exploitability": 6.5,
            "asset_type": "Application",
        },
        {
            "description": "Heartbleed vulnerability leaks server memory containing secrets",
            "threat_type": "Sensitive Data Exposure",
            "cvss_score": 8.8,
            "severity": "High",
            "exploitability": 8.5,
            "asset_type": "TLS Implementation",
        },
        {
            "description": "Detailed stack traces expose database credentials and internal service tokens",
            "threat_type": "Sensitive Data Exposure",
            "cvss_score": 7.4,
            "severity": "High",
            "exploitability": 8.1,
            "asset_type": "Web Application",
        },
        {
            "description": "Misconfigured object storage bucket exposes encrypted backups with accessible keys",
            "threat_type": "Sensitive Data Exposure",
            "cvss_score": 8.2,
            "severity": "High",
            "exploitability": 8.4,
            "asset_type": "Cloud Storage",
        },
    ]

    # Combine all scenarios
    threats.extend(rce_scenarios)
    threats.extend(traversal_scenarios)
    threats.extend(sqli_scenarios)
    threats.extend(auth_scenarios)
    threats.extend(xss_scenarios)
    threats.extend(privesc_scenarios)
    threats.extend(dos_scenarios)
    threats.extend(ssrf_scenarios)
    threats.extend(deser_scenarios)
    threats.extend(idor_scenarios)
    threats.extend(sensitive_data_scenarios)
    # Add extra scenarios for expanded training
    threats.extend(extra_rce_scenarios)
    threats.extend(extra_path_traversal)
    threats.extend(extra_sqli)
    threats.extend(extra_auth)
    threats.extend(extra_xss)
    threats.extend(extra_privesc)
    threats.extend(extra_dos)
    threats.extend(extra_ssrf)
    threats.extend(extra_idor)
    threats.extend(extra_sensitive)

    # Augment each threat 2x via synonym replacement
    augmented = []
    synonyms = {
        "remote code execution": [
            "arbitrary code execution",
            "unauthorized command execution",
        ],
        "path traversal": ["directory traversal", "file path traversal"],
        "sql injection": ["database injection", "SQL query injection"],
        "authentication": ["access control", "user verification"],
        "bypass": ["circumvent", "evade"],
        "cross-site scripting": ["XSS attack", "client-side injection"],
        "privilege escalation": ["privilege elevation", "permission escalation"],
        "denial of service": ["service disruption", "resource exhaustion"],
        "server-side request forgery": [
            "internal request forgery",
            "local network attack",
        ],
        "insecure deserialization": [
            "unsafe deserialization",
            "object deserialization flaw",
        ],
        "sensitive data": ["confidential information", "private data"],
        "exposure": ["disclosure", "unauthorized access"],
    }

    for threat in threats:
        augmented.append(threat)

        # Create augmented version 1 with first synonym replacement
        desc = threat["description"].lower()
        replaced = False
        for word, replacements in synonyms.items():
            if word in desc:
                desc = desc.replace(word, replacements[0])
                replaced = True
                break

        if replaced:
            augmented.append({**threat, "description": desc.capitalize()})

        # Create augmented version 2 with different synonym (if available)
        desc = threat["description"].lower()
        for word, replacements in synonyms.items():
            if word in desc and len(replacements) > 1:
                desc = desc.replace(word, replacements[1])
                augmented.append({**threat, "description": desc.capitalize()})
                break

    return augmented


def get_diverse_threat_scenarios_full() -> List[Dict]:
    """
    Return complete dataset with 1200+ scenarios via augmentation.

    Base scenarios + targeted expansion + deterministic top-up
    Target: robust sample volume for Word2Vec and Gradient Boosting training
    """
    base = get_diverse_threat_scenarios()
    rng = random.Random(42)

    # Add 200 high-signal samples for historically weak classes.
    targeted_seed_templates = {
        "Insecure Direct Object Reference": [
            "Changing {id_field} in {endpoint} reveals another user's {resource}",
            "Missing ownership check on {endpoint} lets attacker read {resource} for a different account",
            "Sequential {id_field} enumeration in {endpoint} exposes private {resource}",
            "Tampering {id_field} parameter in {endpoint} returns unauthorized {resource}",
        ],
        "Sensitive Data Exposure": [
            "Application logs expose {secret} in {surface} without redaction",
            "Debug output in {surface} leaks {secret} to unauthorized users",
            "Misconfigured storage in {surface} exposes unencrypted {secret}",
            "Weak TLS setup in {surface} allows interception of {secret}",
        ],
        "Server-Side Request Forgery": [
            "URL fetch in {surface} allows SSRF to internal {target}",
            "Unvalidated callback URL in {surface} triggers SSRF against {target}",
            "Attacker-controlled URL in {surface} reaches metadata service {target}",
            "SSRF in {surface} allows access to internal {target}",
        ],
        "SQL Injection": [
            "Unsanitized input in {endpoint} enables SQL injection against {resource}",
            "Dynamic query building in {endpoint} allows SQLi to extract {resource}",
            "Error-based SQL injection in {endpoint} leaks {resource}",
            "Blind SQL injection in {endpoint} permits enumeration of {resource}",
        ],
        "Authentication Bypass": [
            "Token validation flaw in {surface} allows authentication bypass for {resource}",
            "Weak session checks in {surface} permit account takeover of {resource}",
            "Improper access checks in {surface} allow login bypass to {resource}",
            "Reset-token flaw in {surface} enables unauthorized access to {resource}",
        ],
    }

    id_fields = ["user_id", "invoice_id", "order_id", "account_id", "document_id"]
    endpoints = [
        "profile API",
        "billing endpoint",
        "order service",
        "document API",
        "admin report API",
    ]
    resources = [
        "account records",
        "billing documents",
        "order history",
        "private files",
        "customer profiles",
    ]
    secrets = [
        "API keys",
        "session tokens",
        "database credentials",
        "JWT signing secrets",
        "customer PII",
    ]
    surfaces = [
        "debug endpoint",
        "application logs",
        "error response",
        "object storage bucket",
        "metrics dashboard",
    ]
    ssrf_targets = [
        "metadata endpoint 169.254.169.254",
        "internal Redis admin port",
        "Kubernetes API server",
        "localhost admin service",
        "internal billing service",
    ]

    target_add_counts = {
        "Insecure Direct Object Reference": 70,
        "Sensitive Data Exposure": 60,
        "Server-Side Request Forgery": 35,
        "SQL Injection": 20,
        "Authentication Bypass": 15,
    }

    metadata_by_type = {
        "Insecure Direct Object Reference": {
            "cvss": (6.8, 8.3),
            "severity": "High",
            "exploitability": (8.1, 9.0),
            "asset": [
                "API Server",
                "Web Application",
                "Billing System",
                "SaaS Platform",
            ],
        },
        "Sensitive Data Exposure": {
            "cvss": (6.6, 8.6),
            "severity": "High",
            "exploitability": (7.2, 8.8),
            "asset": ["Web Server", "Logging System", "Cloud Storage", "Application"],
        },
        "Server-Side Request Forgery": {
            "cvss": (7.1, 8.6),
            "severity": "High",
            "exploitability": (7.4, 8.7),
            "asset": ["API Server", "Web Application", "Cloud Infrastructure"],
        },
        "SQL Injection": {
            "cvss": (7.4, 9.1),
            "severity": "High",
            "exploitability": (7.0, 8.7),
            "asset": ["Web Application", "API Server", "Database Application"],
        },
        "Authentication Bypass": {
            "cvss": (7.8, 9.3),
            "severity": "High",
            "exploitability": (7.5, 8.9),
            "asset": ["API Server", "Web Application", "Authentication Service"],
        },
    }

    targeted_expansion = []
    for threat_type, add_count in target_add_counts.items():
        templates = targeted_seed_templates[threat_type]
        md = metadata_by_type[threat_type]

        for idx in range(add_count):
            template = templates[idx % len(templates)]
            description = template.format(
                id_field=id_fields[idx % len(id_fields)],
                endpoint=endpoints[idx % len(endpoints)],
                resource=resources[idx % len(resources)],
                secret=secrets[idx % len(secrets)],
                surface=surfaces[idx % len(surfaces)],
                target=ssrf_targets[idx % len(ssrf_targets)],
            )

            targeted_expansion.append(
                {
                    "description": description,
                    "threat_type": threat_type,
                    "cvss_score": round(rng.uniform(md["cvss"][0], md["cvss"][1]), 1),
                    "severity": md["severity"],
                    "exploitability": round(
                        rng.uniform(md["exploitability"][0], md["exploitability"][1]),
                        1,
                    ),
                    "asset_type": md["asset"][idx % len(md["asset"])],
                }
            )

    base.extend(targeted_expansion)

    # Keep dataset size above prior runs and reduce class skew in top-up samples.
    min_total_samples = 1600
    if len(base) < min_total_samples:
        additional = []
        qualifiers = ["active", "potential", "confirmed", "detected", "observed"]

        threats_by_type = {}
        for threat in base:
            threats_by_type.setdefault(threat["threat_type"], []).append(threat)

        class_counts = {
            threat_type: len(threats)
            for threat_type, threats in threats_by_type.items()
        }
        threat_types = sorted(threats_by_type.keys())

        # First pass: top up each class toward a balanced target.
        per_class_target = max(1, min_total_samples // max(1, len(threat_types)))
        idx = 0
        for threat_type in threat_types:
            pool = threats_by_type[threat_type]
            while class_counts[threat_type] < per_class_target:
                threat = pool[idx % len(pool)]
                desc = threat["description"]
                words = desc.split()

                if len(words) > 4 and idx % 2 == 0:
                    varied_desc = " ".join(words[-3:] + words[:-3])
                else:
                    qualifier = qualifiers[idx % len(qualifiers)]
                    varied_desc = f"{qualifier.capitalize()}: {desc}"

                additional.append({**threat, "description": varied_desc})
                class_counts[threat_type] += 1
                idx += 1

        # Second pass: fill any remaining gap to min_total_samples round-robin by class.
        rr = 0
        while len(base) + len(additional) < min_total_samples:
            threat_type = threat_types[rr % len(threat_types)]
            pool = threats_by_type[threat_type]
            threat = pool[idx % len(pool)]
            desc = threat["description"]
            words = desc.split()

            if len(words) > 4 and idx % 2 == 0:
                varied_desc = " ".join(words[-3:] + words[:-3])
            else:
                qualifier = qualifiers[idx % len(qualifiers)]
                varied_desc = f"{qualifier.capitalize()}: {desc}"

            additional.append({**threat, "description": varied_desc})
            class_counts[threat_type] += 1
            idx += 1
            rr += 1

        base.extend(additional)

    # If we don't have enough samples, add more via random variations
    if len(base) < 450:
        additional = []

        # Create additional variations of each threat
        for threat in base[: len(base) // 2]:  # Augment first half again
            # Variation 1: Slight word reordering/paraphrasing
            desc = threat["description"]
            words = desc.split()
            if len(words) > 3:
                # Rotate words for variation
                varied_desc = " ".join(words[-2:] + words[:-2])
                additional.append({**threat, "description": varied_desc})

            # Variation 2: Add qualifier words
            qualifiers = ["active", "potential", "confirmed", "detected"]
            qualifier = rng.choice(qualifiers)
            additional.append(
                {**threat, "description": f"{qualifier.capitalize()}: {desc}"}
            )

        base.extend(additional)

    return base


if __name__ == "__main__":
    data = get_diverse_threat_scenarios_full()
    print(f"Generated {len(data)} diverse threat training scenarios")
    print(f"\nFirst 10 scenarios:")
    for i, threat in enumerate(data[:10], 1):
        print(f"{i}. [{threat['threat_type']}] {threat['description'][:60]}...")
    print(f"\nThreat type distribution:")
    threat_types = {}
    for threat in data:
        threat_type = threat["threat_type"]
        threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
    for threat_type, count in sorted(threat_types.items()):
        print(f"  {threat_type}: {count}")
