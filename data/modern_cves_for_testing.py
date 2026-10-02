# Modern CVE Dataset for Model Evaluation Testing
# Contains hand-crafted, realistic threat descriptions from recent security issues
# Used to test model generalization on unseen, modern threats
# Expanded dataset: 155+ examples covering all threat categories

MODERN_TEST_CVES = [
    # Injection Attacks (Modern variants)
    (
        "GraphQL injection vulnerability in API endpoint allows unauthorized data extraction",
        "Injection Attack",
    ),
    (
        "Command injection in Kubernetes manifest processing enables cluster takeover",
        "Injection Attack",
    ),
    (
        "YAML deserialization vulnerability leads to arbitrary code execution",
        "Injection Attack",
    ),
    (
        "Template injection in Jinja2 rendering engine exposes sensitive configuration",
        "Injection Attack",
    ),
    (
        "Log4Shell vulnerability enables remote code execution via log message injection",
        "Injection Attack",
    ),
    (
        "Prototype pollution in JavaScript libraries allows prototype chain manipulation",
        "Injection Attack",
    ),
    (
        "LDAP filter injection in authentication query allows unauthorized user enumeration",
        "Injection Attack",
    ),
    (
        "XPath injection in XML processing bypasses authorization checks",
        "Injection Attack",
    ),
    (
        "Expression language injection in Spring framework enables SSTI attacks",
        "Injection Attack",
    ),
    (
        "HCL injection in Terraform parsing allows malicious infrastructure definition",
        "Injection Attack",
    ),
    (
        "CSV injection in Excel export enables formula injection attacks",
        "Injection Attack",
    ),
    (
        "Server-side template injection in Handlebars allows code execution",
        "Injection Attack",
    ),
    # Cross-Site Scripting (Modern variants)
    (
        "DOM-based XSS in single-page application bypasses Content Security Policy",
        "Cross-Site Scripting",
    ),
    (
        "Stored XSS in comment system persists malicious payload across sessions",
        "Cross-Site Scripting",
    ),
    (
        "Blind XSS via User-Agent header exfiltrates session cookies to attacker server",
        "Cross-Site Scripting",
    ),
    (
        "SVG-based XSS attack vector bypasses naive XSS filters",
        "Cross-Site Scripting",
    ),
    (
        "Mutation-based XSS exploits parser differential handling between browsers",
        "Cross-Site Scripting",
    ),
    (
        "Self-XSS vulnerability combined with social engineering enables account takeover",
        "Cross-Site Scripting",
    ),
    (
        "Angular template injection leads to XSS in JavaScript framework",
        "Cross-Site Scripting",
    ),
    (
        "Vector graphics XSS through malicious SVG file upload",
        "Cross-Site Scripting",
    ),
    (
        "HTML5 data attribute XSS bypasses traditional sanitization",
        "Cross-Site Scripting",
    ),
    (
        "Jazz protocol XSS in WebSocket communication channel",
        "Cross-Site Scripting",
    ),
    (
        "Flash XSS vulnerability embedded in page via deprecated plugin",
        "Cross-Site Scripting",
    ),
    (
        "Callback parameter XSS in JSONP endpoint exposes sensitive data",
        "Cross-Site Scripting",
    ),
    (
        "Meta refresh XSS via malicious redirect URL in page metadata",
        "Cross-Site Scripting",
    ),
    # Authentication Bypass
    (
        "JWT secret key exposure allows forging valid authentication tokens",
        "Authentication Bypass",
    ),
    (
        "OAUTH redirect URI validation bypass enables authorization code interception",
        "Authentication Bypass",
    ),
    (
        "Multi-factor authentication bypass via race condition in token validation",
        "Authentication Bypass",
    ),
    (
        "Session fixation in OAuth flow allows attacker to hijack user sessions",
        "Authentication Bypass",
    ),
    (
        "Default credentials in cloud storage bucket enable unauthorized access",
        "Authentication Bypass",
    ),
    (
        "SAML authentication bypass through signature wrapping attack",
        "Authentication Bypass",
    ),
    (
        "Broken authentication in API allows user enumeration via timing attacks",
        "Authentication Bypass",
    ),
    (
        "Insufficient credential verification enables credential stuffing attacks",
        "Authentication Bypass",
    ),
    (
        "Biometric authentication bypass through spoofed fingerprint injection",
        "Authentication Bypass",
    ),
    (
        "API key exposure in mobile app binary enables unauthorized access",
        "Authentication Bypass",
    ),
    (
        "Two-factor authentication bypass via SMS interception on same device",
        "Authentication Bypass",
    ),
    (
        "Windows NTLM relay attack enables authentication without password knowledge",
        "Authentication Bypass",
    ),
    # Privilege Escalation
    (
        "Misconfigured IAM role policy allows Lambda function to assume admin role",
        "Privilege Escalation",
    ),
    (
        "SUID binary with unsafe library path enables local root escalation",
        "Privilege Escalation",
    ),
    (
        "Kubernetes service account token with cluster-admin binding exposed",
        "Privilege Escalation",
    ),
    (
        "Docker socket exposure on host filesystem allows container escape and root access",
        "Privilege Escalation",
    ),
    (
        "Sudo configuration allows wildcard matching in command restrictions",
        "Privilege Escalation",
    ),
    (
        "Insecure sudo binary substitution enables privilege escalation via PATH manipulation",
        "Privilege Escalation",
    ),
    (
        "Setuid misconfiguration in custom application allows unprivileged user to become root",
        "Privilege Escalation",
    ),
    (
        "Weak file permissions on privileged script allows unauthorized modification",
        "Privilege Escalation",
    ),
    (
        "Cron job misconfiguration with world-writable script enables privilege escalation",
        "Privilege Escalation",
    ),
    (
        "SELinux policy bypass enables unauthorized privilege elevation",
        "Privilege Escalation",
    ),
    (
        "AppArmor profile bypass allows restricted process to escape confinement",
        "Privilege Escalation",
    ),
    (
        "Systemd user service confusion leads to privilege escalation",
        "Privilege Escalation",
    ),
    # Buffer Overflow
    (
        "Stack buffer overflow in OpenSSL TLS record parsing enables remote code execution",
        "Buffer Overflow",
    ),
    (
        "Heap overflow in PHP serialization handler allows arbitrary code execution",
        "Buffer Overflow",
    ),
    (
        "Integer underflow in WebKit audio processing leads to memory corruption",
        "Memory Corruption",
    ),
    (
        "Format string vulnerability in syslog processing enables kernel memory read",
        "Memory Corruption",
    ),
    (
        "Use-after-free vulnerability in JavaScript engine allows code execution",
        "Memory Corruption",
    ),
    (
        "Off-by-one buffer overflow in network packet parsing enables DoS",
        "Buffer Overflow",
    ),
    (
        "Double-free vulnerability in memory management leads to heap corruption",
        "Memory Corruption",
    ),
    (
        "String format vulnerability in logging function enables arbitrary memory write",
        "Memory Corruption",
    ),
    (
        "Stack overflow vulnerability in recursive function allows return address overwrite",
        "Memory Corruption",
    ),
    (
        "Heap buffer overflow in XML parser allows arbitrary memory write and code execution",
        "Memory Corruption",
    ),
    (
        "Use-after-free in DOM element handling enables privilege escalation",
        "Memory Corruption",
    ),
    (
        "Heap spray vulnerability combined with use-after-free enables deterministic code execution",
        "Memory Corruption",
    ),
    (
        "Bounds checking error in image decoder allows buffer overrun",
        "Buffer Overflow",
    ),
    (
        "Return-oriented programming gadget chain enables execution in DEP environments",
        "Buffer Overflow",
    ),
    # Denial of Service
    (
        "Algorithmic complexity attack via ReDoS in email validation regex",
        "Denial of Service",
    ),
    (
        "Slowloris-style attack exploits connection pooling limits in web server",
        "Denial of Service",
    ),
    (
        "Memory leak in WebSocket implementation leads to gradual server exhaustion",
        "Denial of Service",
    ),
    (
        "XML External Entity (XXE) attack via billion laughs variant consumes all memory",
        "Denial of Service",
    ),
    (
        "BGP route hijacking attack redirects traffic causing network unavailability",
        "Denial of Service",
    ),
    (
        "Hash collision attack exploits weak hash function in lookups",
        "Denial of Service",
    ),
    (
        "Regular expression catastrophic backtracking causes CPU exhaustion",
        "Denial of Service",
    ),
    (
        "Decompression bomb attack via zip file causes disk space exhaustion",
        "Denial of Service",
    ),
    (
        "Distributed reflection attack using open DNS resolvers amplifies traffic",
        "Denial of Service",
    ),
    (
        "Asymmetric cryptographic operation forces expensive computation",
        "Denial of Service",
    ),
    (
        "CSS parsing complexity causes browser DoS via crafted stylesheet",
        "Denial of Service",
    ),
    (
        "JSON parsing attack via deeply nested structure causes stack overflow",
        "Denial of Service",
    ),
    (
        "Protocol negotiation confusion allows attacker to force downgrade",
        "Denial of Service",
    ),
    # Path Traversal
    (
        "Directory traversal via symbolic link following in file extraction utility",
        "Path Traversal",
    ),
    (
        "Zip slip vulnerability in archive extraction bypasses path validation",
        "Path Traversal",
    ),
    (
        "Insecure file upload with path traversal allows overwriting critical files",
        "Path Traversal",
    ),
    (
        "Case sensitivity bypass in Windows path checking enables file access",
        "Path Traversal",
    ),
    (
        "Double encoding in URL parser enables bypass of path restrictions",
        "Path Traversal",
    ),
    (
        "Null byte injection in file path validation bypasses checks",
        "Path Traversal",
    ),
    (
        "URL encoding bypass allows traversal in request path handling",
        "Path Traversal",
    ),
    (
        "Backslash normalization difference exploited for path traversal",
        "Path Traversal",
    ),
    (
        "Symlink race condition during file operations enables arbitrary file access",
        "Path Traversal",
    ),
    (
        "Unicode normalization bypass enables path traversal in internationalized systems",
        "Path Traversal",
    ),
    # Remote Code Execution - expanded
    (
        "Unsafe deserialization in Java RMI allows arbitrary object instantiation",
        "Remote Code Execution",
    ),
    (
        "Code injection through eval-like function in Python web framework",
        "Code Execution",
    ),
    (
        "PHAR deserialization vulnerability in PHP file upload processing",
        "Remote Code Execution",
    ),
    (
        "Gadget chain exploitation in Apache Commons Collections enables RCE",
        "Remote Code Execution",
    ),
    (
        "Pickle deserialization vulnerability in Django enables arbitrary code execution",
        "Remote Code Execution",
    ),
    (
        "Groovy script execution in Jenkins configuration allows RCE",
        "Remote Code Execution",
    ),
    (
        "Expression language endpoint injection enables remote code execution in JSP",
        "Remote Code Execution",
    ),
    (
        "Plugin system vulnerability allows loading and executing arbitrary plugins",
        "Remote Code Execution",
    ),
    (
        "Database stored procedure injection enables operating system command execution",
        "Remote Code Execution",
    ),
    (
        "Script engine abuse through JavaScript eval enables server-side code execution",
        "Code Execution",
    ),
    (
        "Ant build file injection allows arbitrary command execution",
        "Remote Code Execution",
    ),
    (
        "Python pickle module exploitation allows arbitrary object deserialization",
        "Code Execution",
    ),
    (
        "Ruby YAML parsing vulnerability enables code execution through deserialization",
        "Code Execution",
    ),
    (
        "Node.js child_process execution via require injection enables arbitrary command execution",
        "Code Execution",
    ),
    (
        "Server-side JavaScript eval vulnerability allows node.js code execution",
        "Remote Code Execution",
    ),
    (
        "Dynamic code loading vulnerability via require allows arbitrary file execution",
        "Remote Code Execution",
    ),
    # Information Disclosure
    (
        "Folder enumeration in AWS S3 bucket reveals sensitive backup files",
        "Information Disclosure",
    ),
    (
        "Source code exposure through misconfigured .git directory publicly accessible",
        "Information Disclosure",
    ),
    (
        "GitHub token leak in repository history enables API access to private resources",
        "Information Disclosure",
    ),
    (
        "API response includes unnecessary sensitive user data via information leakage",
        "Information Disclosure",
    ),
    (
        "Database error messages expose table structure and encryption key hints",
        "Information Disclosure",
    ),
    (
        "Cloud metadata service exposure reveals instance credentials and configuration",
        "Information Disclosure",
    ),
    (
        ".env file exposure in static file server reveals sensitive credentials",
        "Information Disclosure",
    ),
    (
        "Backup file disclosure through directory listing enables data extraction",
        "Information Disclosure",
    ),
    (
        "Server directory traversal reveals cached passwords and session tokens",
        "Information Disclosure",
    ),
    (
        "Debug endpoint exposure reveals sensitive application state information",
        "Information Disclosure",
    ),
    (
        "Timing attack in password comparison reveals password length and characters",
        "Information Disclosure",
    ),
    (
        "Browser cache poisoning reveals previously visited sites of other users",
        "Information Disclosure",
    ),
    (
        "DNS rebinding attack reveals internal network topology and services",
        "Information Disclosure",
    ),
    # Cross-Site Request Forgery
    (
        "CSRF attack via image tag triggers unvalidated state-changing operation",
        "Cross-Site Request Forgery",
    ),
    (
        "Cross-site request forgery in admin panel allows account takeover",
        "Cross-Site Request Forgery",
    ),
    (
        "CSRF vulnerability in password change endpoint allows unauthorized modification",
        "Cross-Site Request Forgery",
    ),
    (
        "CSRF token validation bypass via null token or token reuse",
        "Cross-Site Request Forgery",
    ),
    (
        "Same-site cookie policy bypass enables CSRF in modern browsers",
        "Cross-Site Request Forgery",
    ),
    (
        "CSRF vulnerability in API endpoint allows unauthorized data modification",
        "Cross-Site Request Forgery",
    ),
    (
        "CSRF in file upload endpoint via hidden form submission enables malware distribution",
        "Cross-Site Request Forgery",
    ),
    (
        "SameSite=Lax bypass via GET request redirect enables session hijacking",
        "Cross-Site Request Forgery",
    ),
    # Clickjacking - expanded
    (
        "ClickJacking attack via invisible button overlay tricks users into account deletion",
        "Clickjacking",
    ),
    (
        "UI redressing attack obscures confirm dialog to obtain user permissions",
        "Clickjacking",
    ),
    (
        "Malicious iframe overlay enables click hijacking of payment buttons",
        "Clickjacking",
    ),
    (
        "Likejacking attack tricks users into clicking malicious social media buttons",
        "Clickjacking",
    ),
    (
        "Cursorjacking attack replicates cursor position to confuse users",
        "Clickjacking",
    ),
    (
        "Keystroke interception via invisible form field captures user input",
        "Clickjacking",
    ),
    (
        "Clickjacking using opacity 0 styling makes clickable elements invisible while functional",
        "Clickjacking",
    ),
    (
        "Flash-based clickjacking exploits legacy plugin vulnerability",
        "Clickjacking",
    ),
    (
        "SVG-based clickjacking uses scalable vector graphics for UI spoofing",
        "Clickjacking",
    ),
    (
        "CSS overlay attack hides malicious buttons beneath legitimate interface elements",
        "Clickjacking",
    ),
    # Input Validation
    (
        "Insufficient email validation allows homograph attacks with lookalike domains",
        "Input Validation",
    ),
    (
        "URL validation bypass via unusual characters allows SSRF to internal endpoints",
        "Input Validation",
    ),
    (
        "IP address validation bypass via octal notation allows internal network access",
        "Input Validation",
    ),
    (
        "Type confusion in input validation enables arbitrary type coercion",
        "Input Validation",
    ),
    (
        "Unicode encoding bypass defeats input validation in security filters",
        "Input Validation",
    ),
    (
        "Regex bypass using null character traversal bypasses simple validation",
        "Input Validation",
    ),
    (
        "Polyglot file upload bypasses file type validation with dual format magic bytes",
        "Input Validation",
    ),
    (
        "Content-Type header mismatch allows execution of malicious script files",
        "Input Validation",
    ),
    (
        "MIME type confusion attack bypasses file upload restrictions",
        "Input Validation",
    ),
    # Cryptographic Weakness
    (
        "Weak TLS configuration allows downgrade attack to older cipher suites",
        "Cryptographic Weakness",
    ),
    (
        "Insufficient random number generation in token creation allows prediction",
        "Cryptographic Weakness",
    ),
    (
        "Improper key derivation function uses insufficient entropy for password hashing",
        "Cryptographic Weakness",
    ),
    (
        "RSA key reuse across different systems enables related-message attack",
        "Cryptographic Weakness",
    ),
    (
        "ECB mode encryption reveals plaintext patterns enabling frequency analysis",
        "Cryptographic Weakness",
    ),
    (
        "Hardcoded encryption key in application source code enables data decryption",
        "Cryptographic Weakness",
    ),
    (
        "Weak initialization vector in CBC mode enables plaintext recovery",
        "Cryptographic Weakness",
    ),
    (
        "Missing or weak message authentication enables tampering with encrypted data",
        "Cryptographic Weakness",
    ),
    (
        "Side-channel attack via timing measurement extracts cryptographic key bits",
        "Cryptographic Weakness",
    ),
    (
        "Padding oracle attack reveals plaintext through decryption error messages",
        "Cryptographic Weakness",
    ),
    # Server-Side Request Forgery
    (
        "SSRF vulnerability in image proxy URL parameter allows internal network scanning",
        "Server-Side Request Forgery",
    ),
    (
        "SSRF via URL redirect following enables access to metadata service endpoint",
        "Server-Side Request Forgery",
    ),
    (
        "SSRF in webhook implementation allows querying internal Kubernetes API",
        "Server-Side Request Forgery",
    ),
    (
        "SSRF bypass using Unicode encoding bypasses blacklist filters",
        "Server-Side Request Forgery",
    ),
    (
        "SSRF via localhost bypass using IPv6 loopback notation",
        "Server-Side Request Forgery",
    ),
    (
        "SSRF attack accesses internal file shares via SMB protocol handler",
        "Server-Side Request Forgery",
    ),
    (
        "SSRF vulnerability in PDF generator enables server-side file inclusion",
        "Server-Side Request Forgery",
    ),
    (
        "SSRF via data URL scheme allows reading local files directly",
        "Server-Side Request Forgery",
    ),
    (
        "SSRF in report generation endpoint reveals internal network topology",
        "Server-Side Request Forgery",
    ),
    # Needs Review (ambiguous or uncertain threats)
    (
        "Unusual amount of failed login attempts from geographic location mismatch",
        "Needs Review",
    ),
    (
        "Large data exfiltration detected but encryption makes payload unclear",
        "Needs Review",
    ),
    (
        "Suspicious process spawned by system service with unclear purpose",
        "Needs Review",
    ),
    (
        "Anomalous memory allocation pattern detected but application behavior unknown",
        "Needs Review",
    ),
    (
        "Network traffic to unfamiliar destination observed but traffic encrypted",
        "Needs Review",
    ),
    (
        "File system changes detected in critical directory but origin unclear",
        "Needs Review",
    ),
    (
        "CPU spike detected but workload source uncertain",
        "Needs Review",
    ),
    (
        "Permission escalation attempt detected but privilege level change unconfirmed",
        "Needs Review",
    ),
    (
        "Potential lateral movement detected but network segmentation status unknown",
        "Needs Review",
    ),
    # Additional Injection Attacks
    (
        "NoSQL injection in MongoDB query allows arbitrary document retrieval",
        "Injection Attack",
    ),
    (
        "Cassandra query injection bypasses authentication in distributed database",
        "Injection Attack",
    ),
    (
        "Perl regex injection in text processing enables arbitrary code execution",
        "Injection Attack",
    ),
    (
        "Ruby ERB template injection allows server-side code execution",
        "Injection Attack",
    ),
    (
        "Python Jinja template injection exposes application configuration",
        "Injection Attack",
    ),
    # Additional XSS Variants
    (
        "Stored XSS in user profile bypasses HTML sanitization via nested encoding",
        "Cross-Site Scripting",
    ),
    (
        "Reflected XSS in search parameter uses HTML5 data attributes",
        "Cross-Site Scripting",
    ),
    (
        "DOM-based XSS via location.hash manipulation in SPAs",
        "Cross-Site Scripting",
    ),
    (
        "XSS via event handler attributes in dynamically generated HTML",
        "Cross-Site Scripting",
    ),
    (
        "Polyglot attack combining SVG and JavaScript XSS vector",
        "Cross-Site Scripting",
    ),
    # Additional Auth Bypass
    (
        "LDAP injection in login form bypasses authentication",
        "Authentication Bypass",
    ),
    (
        "SQL injection in authentication query allows login without password",
        "Authentication Bypass",
    ),
    (
        "Race condition in 2FA validation window enables bypass",
        "Authentication Bypass",
    ),
    (
        "Weak password reset token generation allows token prediction",
        "Authentication Bypass",
    ),
    (
        "Session fixation in password reset flow compromises account",
        "Authentication Bypass",
    ),
    # Additional Privilege Escalation
    (
        "Insecure direct object reference in admin interface allows privilege escalation",
        "Privilege Escalation",
    ),
    (
        "File permissions confusion allows group member to access admin files",
        "Privilege Escalation",
    ),
    (
        "Kernel module loading vulnerability enables kernel privilege escalation",
        "Privilege Escalation",
    ),
    (
        "Insecure systemd service file allows user to escalate to system owner",
        "Privilege Escalation",
    ),
    (
        "Capability misconfiguration in container allows breakout",
        "Privilege Escalation",
    ),
    # Additional Memory Corruption
    (
        "Integer overflow in size calculation leads to heap buffer overflow",
        "Memory Corruption",
    ),
    (
        "Type confusion in object handling enables arbitrary memory write",
        "Memory Corruption",
    ),
    (
        "Use-after-free in event handler cleanup enables code execution",
        "Memory Corruption",
    ),
    (
        "Memory leak in parser accumulates objects until OOM",
        "Memory Corruption",
    ),
    (
        "Control flow attack via corrupted virtual method table pointer",
        "Memory Corruption",
    ),
    # Additional DoS Attacks
    (
        "Zip bomb with nested compression exhausts system resources",
        "Denial of Service",
    ),
    (
        "Gzip compression bomb depletes disk space during decompression",
        "Denial of Service",
    ),
    (
        "Malicious PDF with excessive page count causes parser hang",
        "Denial of Service",
    ),
    (
        "Regular expression with catastrophic backtracking freezes application",
        "Denial of Service",
    ),
    (
        "Billion laughs XML attack via recursive entity expansion",
        "Denial of Service",
    ),
    # Additional Path Traversal
    (
        "Case-insensitive filesystem traversal on Windows systems",
        "Path Traversal",
    ),
    (
        "TOCTOU race condition enables file access after validation",
        "Path Traversal",
    ),
    (
        "Alternate data stream access via colon notation on Windows",
        "Path Traversal",
    ),
    (
        "Mounted filesystem traversal via /proc filesystem",
        "Path Traversal",
    ),
    (
        "Symlink race window enables overwriting arbitrary files",
        "Path Traversal",
    ),
    # Additional RCE Vectors
    (
        "Insecure temporary file creation enables arbitrary file execution",
        "Remote Code Execution",
    ),
    (
        "ImageMagick command injection via image filename processing",
        "Remote Code Execution",
    ),
    (
        "FFmpeg command injection in video transcoding pipeline",
        "Remote Code Execution",
    ),
    (
        "Ghostscript command injection in PDF processing",
        "Remote Code Execution",
    ),
    (
        "Template engine code injection enables arbitrary code execution",
        "Code Execution",
    ),
    # Additional Information Disclosure
    (
        "HTTP response splitting reveals internal session tokens",
        "Information Disclosure",
    ),
    (
        "Verbose error pages expose system paths and library versions",
        "Information Disclosure",
    ),
    (
        "REST API response includes sensitive fields in bulk export",
        "Information Disclosure",
    ),
    (
        "Cache poisoning reveals user session data to other clients",
        "Information Disclosure",
    ),
    (
        "CORS misconfiguration allows cross-origin JavaScript access to sensitive data",
        "Information Disclosure",
    ),
    # Additional CSRF Variants
    (
        "CSRF in DELETE endpoint via image src attribute",
        "Cross-Site Request Forgery",
    ),
    (
        "CSRF token in URL query parameter instead of body enables bypass",
        "Cross-Site Request Forgery",
    ),
    (
        "CSRF protection disabled for certain endpoints",
        "Cross-Site Request Forgery",
    ),
    (
        "CSRF token validation only checks presence, not value",
        "Cross-Site Request Forgery",
    ),
    # Additional Clickjacking
    (
        "Frame-busting code bypass via double-frame nesting",
        "Clickjacking",
    ),
    (
        "Clickjacking combined with social engineering via fake warning",
        "Clickjacking",
    ),
    (
        "Touch-jacking attack on mobile enables unauthorized actions",
        "Clickjacking",
    ),
    # Additional Input Validation
    (
        "File upload validation bypass via polyglot PHP-GIF file",
        "Input Validation",
    ),
    (
        "MIME type confusion via Content-Type header mismatch",
        "Input Validation",
    ),
    (
        "Archive extraction without size validation enables decompression bomb",
        "Input Validation",
    ),
    (
        "Name resolution bypass via mixed case domain in certificate check",
        "Input Validation",
    ),
    # Additional Crypto Issues
    (
        "Phantom SSL certificate accepted due to improper validation",
        "Cryptographic Weakness",
    ),
    (
        "Weak random number generator seeds enable token prediction",
        "Cryptographic Weakness",
    ),
    (
        "Two-phase commit vulnerability in cryptographic operations",
        "Cryptographic Weakness",
    ),
    (
        "Insecure cryptographic salt reuse reduces password entropy",
        "Cryptographic Weakness",
    ),
    # Additional SSRF
    (
        "SSRF in background job processing accesses internal services",
        "Server-Side Request Forgery",
    ),
    (
        "SSRF via DNS rebinding bypasses IP-based blacklist",
        "Server-Side Request Forgery",
    ),
    (
        "SSRF in file inclusion via gopher protocol handler",
        "Server-Side Request Forgery",
    ),
]


def get_modern_test_cves():
    """Return list of (description, threat_type) tuples for testing.

    Contains 200+ modern threat examples for evaluating model generalization.
    Each example is (threat_description, threat_type_label).
    """
    return MODERN_TEST_CVES
