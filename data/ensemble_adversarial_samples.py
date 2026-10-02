"""Adversarial-style text samples for ensemble classifier evaluation."""

from typing import List, Tuple
import random
from nltk.corpus import wordnet
from nltk.tokenize import word_tokenize

THREAT_CLASS_CONSOLIDATION = {
    # Injection attacks
    "Injection Attack": [
        "Injection Attack",
        "SQL Injection",
        "LDAP Injection",
        "OS Command Injection",
    ],
    # XSS family
    "Cross-Site Scripting": [
        "Cross-Site Scripting",
        "Stored XSS",
        "Reflected XSS",
        "DOM XSS",
    ],
    # Authentication & Access Control
    "Authentication Bypass": [
        "Authentication Bypass",
        "Session Hijacking",
        "Token Spoofing",
        "Credential Theft",
    ],
    "Privilege Escalation": [
        "Privilege Escalation",
        "Vertical Privilege Escalation",
        "Horizontal Privilege Escalation",
    ],
    # Request forgery (CSRF + SSRF merged)
    "Request Forgery": [
        "Cross-Site Request Forgery",
        "Server-Side Request Forgery",
        "CSRF",
        "SSRF",
    ],
    # Path/traversal issues
    "Path Traversal": ["Path Traversal", "Directory Traversal", "Directory Escape"],
    # Information leaks
    "Information Disclosure": [
        "Information Disclosure",
        "Data Exposure",
        "Sensitive Data Exposure",
        "Metadata Leakage",
    ],
    # Availability
    "Denial of Service": ["Denial of Service", "DDoS", "Resource Exhaustion"],
    # Execution
    "Remote Code Execution": [
        "Remote Code Execution",
        "Arbitrary Code Execution",
        "Unserialize RCE",
    ],
    # Cryptography
    "Cryptographic Weakness": [
        "Cryptographic Weakness",
        "Weak Hashing",
        "Broken Cipher",
        "Weak Key Generation",
    ],
    # Input handling
    "Input Validation": [
        "Input Validation",
        "Improper Input Handling",
        "Type Confusion",
    ],
}


def normalize_threat_label(label):
    for canonical_label, variations in THREAT_CLASS_CONSOLIDATION.items():
        if label in variations:
            return canonical_label

    # If not found in mapping, return original
    print(f"Warning: Unrecognized label '{label}' - using as-is")
    return label


def get_extended_adversarial_samples() -> List[Tuple[str, str]]:
    """Return 84 adversarial/paraphrased threat samples for robust eval training."""
    return [
        # Injection Attack (7)
        (
            "User-controlled SQL fragment appended to backend query string",
            "Injection Attack",
        ),
        ("Unsanitized database clause in account lookup endpoint", "Injection Attack"),
        (
            "Command argument passed from form input into shell execution",
            "Injection Attack",
        ),
        ("NoSQL operator injection through crafted JSON filter", "Injection Attack"),
        (
            "Template expression injection through unescaped render context",
            "Injection Attack",
        ),
        (
            "LDAP filter manipulation bypasses intended query constraints",
            "Injection Attack",
        ),
        (
            "XPath query pieces built directly from request parameters",
            "Injection Attack",
        ),
        # Cross-Site Scripting (7)
        (
            "Stored script payload rendered in comment preview panel",
            "Cross-Site Scripting",
        ),
        ("DOM sink receives attacker input via hash fragment", "Cross-Site Scripting"),
        ("Reflected payload executes from search query output", "Cross-Site Scripting"),
        (
            "Rich text editor allows event handler attribute injection",
            "Cross-Site Scripting",
        ),
        (
            "Profile field HTML not sanitized before rendering to users",
            "Cross-Site Scripting",
        ),
        (
            "SVG upload executes embedded script in browser context",
            "Cross-Site Scripting",
        ),
        (
            "Client-side template output exposes script execution vector",
            "Cross-Site Scripting",
        ),
        # Authentication Bypass (7)
        (
            "JWT token accepted with invalid signature verification",
            "Authentication Bypass",
        ),
        (
            "OAuth redirect validation flaw allows auth code theft",
            "Authentication Bypass",
        ),
        (
            "Session fixation lets attacker reuse known session identifier",
            "Authentication Bypass",
        ),
        (
            "MFA workflow can be skipped by replaying stale state",
            "Authentication Bypass",
        ),
        (
            "Default admin credentials still active in production service",
            "Authentication Bypass",
        ),
        (
            "Password reset token accepted beyond expiration window",
            "Authentication Bypass",
        ),
        (
            "API endpoint trusts client role claim without server validation",
            "Authentication Bypass",
        ),
        # Privilege Escalation (7)
        (
            "Sudo rule wildcard permits execution of arbitrary root command",
            "Privilege Escalation",
        ),
        (
            "Service account bound to cluster-admin can be impersonated",
            "Privilege Escalation",
        ),
        (
            "Setuid helper loads attacker-controlled library from writable path",
            "Privilege Escalation",
        ),
        (
            "Container runtime socket exposed enabling host privilege access",
            "Privilege Escalation",
        ),
        (
            "Weak ACL on privileged script allows local privilege gain",
            "Privilege Escalation",
        ),
        (
            "Kernel capability misconfiguration grants unauthorized admin actions",
            "Privilege Escalation",
        ),
        (
            "Scheduled root task executes world-writable script content",
            "Privilege Escalation",
        ),
        # Denial of Service (7)
        (
            "Regex backtracking payload spikes CPU to full utilization",
            "Denial of Service",
        ),
        ("Slow HTTP connection flood exhausts worker thread pool", "Denial of Service"),
        (
            "Deeply nested JSON body causes parser resource exhaustion",
            "Denial of Service",
        ),
        (
            "Zip bomb decompression consumes storage and memory capacity",
            "Denial of Service",
        ),
        (
            "Hash collision set degrades hash map performance severely",
            "Denial of Service",
        ),
        (
            "Algorithmic complexity attack overwhelms validation routine",
            "Denial of Service",
        ),
        (
            "Amplified reflected traffic saturates ingress bandwidth",
            "Denial of Service",
        ),
        # Path Traversal (7)
        (
            "Archive extraction writes files outside intended destination path",
            "Path Traversal",
        ),
        ("Double-encoded dot-dot slash bypasses upload path filter", "Path Traversal"),
        (
            "Backslash normalization bug allows directory traversal on Windows",
            "Path Traversal",
        ),
        (
            "Symbolic link in temp directory redirects protected file write",
            "Path Traversal",
        ),
        (
            "Null byte terminator bypasses file extension path validation",
            "Path Traversal",
        ),
        ("Relative path segments read arbitrary server-side files", "Path Traversal"),
        (
            "Case-folding mismatch enables traversal past restricted base path",
            "Path Traversal",
        ),
        # Remote Code Execution (7)
        (
            "Unsafe deserialization instantiates attacker-controlled gadget chain",
            "Remote Code Execution",
        ),
        (
            "Template sandbox escape leads to server-side command execution",
            "Remote Code Execution",
        ),
        (
            "Eval-like function executes untrusted expression from request",
            "Remote Code Execution",
        ),
        (
            "Plugin loader accepts unsigned remote package with executable hooks",
            "Remote Code Execution",
        ),
        (
            "Child process command composed from untrusted payload",
            "Remote Code Execution",
        ),
        (
            "Memory corruption exploit pivots execution to attacker shellcode",
            "Remote Code Execution",
        ),
        (
            "Insecure script engine endpoint executes arbitrary server code",
            "Remote Code Execution",
        ),
        # Information Disclosure (7)
        (
            "Publicly exposed backup archive contains customer records",
            "Information Disclosure",
        ),
        (
            "Verbose stack trace leaks internal paths and secret names",
            "Information Disclosure",
        ),
        (
            "Metadata endpoint reveals temporary cloud access credentials",
            "Information Disclosure",
        ),
        ("Git repository artifacts published under web root", "Information Disclosure"),
        (
            "Debug API returns sensitive fields not required by clients",
            "Information Disclosure",
        ),
        (
            "Directory listing enabled exposes private configuration files",
            "Information Disclosure",
        ),
        (
            "Timing side channel reveals valid username and token patterns",
            "Information Disclosure",
        ),
        # Cross-Site Request Forgery (7)
        (
            "State-changing endpoint accepts cross-origin form submission",
            "Cross-Site Request Forgery",
        ),
        (
            "Missing CSRF token allows unauthorized password update requests",
            "Cross-Site Request Forgery",
        ),
        (
            "SameSite bypass enables forged banking transfer request",
            "Cross-Site Request Forgery",
        ),
        (
            "Admin action triggered through hidden auto-submitted form",
            "Cross-Site Request Forgery",
        ),
        (
            "Token not bound to session allows replayed forged actions",
            "Cross-Site Request Forgery",
        ),
        (
            "GET endpoint performs destructive action without anti-CSRF control",
            "Cross-Site Request Forgery",
        ),
        (
            "Embedded image tag triggers authenticated delete request",
            "Cross-Site Request Forgery",
        ),
        # Server-Side Request Forgery (7)
        (
            "Image fetch service requests attacker-controlled internal URL",
            "Server-Side Request Forgery",
        ),
        (
            "Webhook callback follows redirect into internal network target",
            "Server-Side Request Forgery",
        ),
        (
            "PDF renderer loads file URI and exposes local system content",
            "Server-Side Request Forgery",
        ),
        (
            "IPv6 loopback notation bypasses localhost SSRF denylist",
            "Server-Side Request Forgery",
        ),
        (
            "Cloud metadata endpoint accessed through URL parser confusion",
            "Server-Side Request Forgery",
        ),
        (
            "Custom protocol handler allows internal service probing",
            "Server-Side Request Forgery",
        ),
        (
            "Report generator makes arbitrary backend requests from user input",
            "Server-Side Request Forgery",
        ),
        # Cryptographic Weakness (7)
        (
            "Static encryption key hardcoded in mobile application binary",
            "Cryptographic Weakness",
        ),
        (
            "TLS configuration permits deprecated cipher downgrade",
            "Cryptographic Weakness",
        ),
        (
            "Predictable random seed used for security token generation",
            "Cryptographic Weakness",
        ),
        (
            "Weak key derivation parameters enable fast brute-force",
            "Cryptographic Weakness",
        ),
        ("ECB mode leaks repeating plaintext block patterns", "Cryptographic Weakness"),
        (
            "Missing integrity check allows tampering of encrypted payload",
            "Cryptographic Weakness",
        ),
        (
            "Padding oracle behavior reveals decrypted plaintext bytes",
            "Cryptographic Weakness",
        ),
        # Input Validation (7)
        (
            "File upload filter accepts polyglot payload disguised as image",
            "Input Validation",
        ),
        (
            "Unicode normalization bypass evades blacklist-based checks",
            "Input Validation",
        ),
        (
            "Numeric parser accepts octal IP form to reach internal hosts",
            "Input Validation",
        ),
        (
            "Type coercion bug permits invalid object in trusted code path",
            "Input Validation",
        ),
        ("MIME sniffing mismatch allows executable content upload", "Input Validation"),
        (
            "Length validation omitted causing oversized payload handling faults",
            "Input Validation",
        ),
        ("URL validator accepts dangerous scheme due to regex gap", "Input Validation"),
    ]


def get_extended_adversarial_samples_normalized():
    """Extended threat samples with normalized (consolidated) class labels."""
    original_samples = get_extended_adversarial_samples()
    normalized = [
        (text, normalize_threat_label(label)) for text, label in original_samples
    ]
    return normalized


def generate_synthetic_samples_from_templates():
    """Generate synthetic threat samples using domain-specific templates"""

    # Define templates for each threat type
    # Each template is a sentence with {attack}, {location}, {method} placeholders
    threat_templates = {
        "Injection Attack": [
            "SQL {attack} detected in {location} parameter",
            "{method} injection bypassing input validation at {location}",
            "Malicious {attack} in database query from {location}",
            "Attempted {attack} through {location} endpoint",
            "{attack} payload detected in {location} field",
            "Database {attack} from user {location} input",
            "{method} {attack} attempting data extraction via {location}",
        ],
        "Cross-Site Scripting": [
            "XSS payload {attack} found in {location} DOM",
            "Malicious JavaScript {attack} executed in {location} context",
            "{method} XSS attempting {location} access",
            "{attack} script injection in {location} content",
            "Stored {attack} detected in {location} rendering",
            "Reflected {attack} in {location} parameter",
        ],
        "Authentication Bypass": [
            "Session token {attack} bypassing {location} authentication",
            "Authentication {method} at {location} endpoint",
            "Credential bypass {attack} detected in {location}",
            "Authentication logic {attack} at {location} layer",
            "{attack} bypassing {location} access control",
        ],
        "Privilege Escalation": [
            "Privilege escalation {attack} from {location} context",
            "User {method} escalation to admin via {location}",
            "Role-based {attack} bypass at {location} checkpoint",
            "Unauthorized privilege {attack} in {location} function",
            "Elevation {method} detected at {location} boundary",
        ],
        "Denial of Service": [
            "{attack} flood attack on {location} resource",
            "DoS {method} consuming {location} capacity",
            "Resource exhaustion {attack} at {location} service",
            "{method} attack targeting {location} availability",
            "Service {attack} detected at {location} endpoint",
        ],
        "Path Traversal": [
            "Directory traversal {attack} attempting {location} access",
            "Path {method} crossing security boundary at {location}",
            "{attack} accessing unauthorized {location} directory",
            "File system {attack} via {location} parameter",
            "Path escape {method} in {location} handler",
        ],
        "Remote Code Execution": [
            "Arbitrary code {attack} detected in {location} endpoint",
            "RCE {method} executing commands via {location}",
            "Code execution {attack} at {location} processor",
            "Unserialize {attack} leading to RCE at {location}",
            "Command {method} injection in {location} function",
        ],
        "Information Disclosure": [
            "Sensitive data {attack} exposed via {location} response",
            "Information leak {method} in {location} logging",
            "Confidential {attack} revealed through {location} error",
            "Data exposure {method} at {location} boundary",
            "{attack} disclosure through {location} debugging output",
        ],
        "Cross-Site Request Forgery": [
            "CSRF {attack} bypassing {location} token validation",
            "Forged request {method} to {location} endpoint",
            "State-changing {attack} via {location} link",
            "CSRF {method} exploiting {location} trust",
            "Anti-CSRF {attack} bypass at {location} handler",
        ],
        "Server-Side Request Forgery": [
            "SSRF {attack} to internal {location} service",
            "Server request {method} targeting {location} resource",
            "Internal network {attack} via {location} proxy",
            "SSRF {method} accessing {location} metadata service",
        ],
        "Cryptographic Weakness": [
            "Weak crypto {attack} at {location} encryption layer",
            "Broken {method} implementation in {location} cipher",
            "Insufficient key {attack} in {location} setup",
            "Deprecated {attack} algorithm at {location} endpoint",
            "Crypto {method} vulnerability in {location} module",
        ],
        "Input Validation": [
            "Input validation {attack} allowing {location} bypass",
            "Insufficient sanitization {method} in {location} handler",
            "Type confusion {attack} in {location} parser",
            "Validation logic {method} at {location} boundary",
            "Input {attack} propagating to {location} processing",
        ],
    }

    # Placeholder variations for each template parameter
    attack_variations = {
        "Injection Attack": [
            "payload",
            "query",
            "command",
            "statement",
            "string",
            "vector",
            "exploit",
            "injection",
            "input",
            "breach",
        ],
        "Cross-Site Scripting": [
            "payload",
            "script",
            "event handler",
            "code",
            "markup",
            "injection",
            "vector",
            "attack",
            "fragment",
            "execution",
        ],
        "Authentication Bypass": [
            "token",
            "bypass",
            "forging",
            "hijacking",
            "spoofing",
            "manipulation",
            "weakness",
            "flaw",
            "exploit",
            "breach",
        ],
        # Add more as needed for each type
    }

    location_variations = [
        "request",
        "response",
        "parameter",
        "header",
        "cookie",
        "session",
        "payload",
        "endpoint",
        "API gateway",
        "microservice",
        "database",
        "cache",
        "queue",
        "storage",
        "queue",
    ]

    method_variations = [
        "attempted",
        "detected",
        "exploiting",
        "leveraging",
        "abusing",
        "utilizing",
        "employing",
        "crafting",
        "constructing",
        "launching",
    ]

    synthetic_samples = []

    # Generate variations for each threat type
    for threat_type, templates in threat_templates.items():
        for template in templates:
            # Generate 3 variations per template by randomizing placeholders
            for _ in range(3):
                description = template

                # Replace {attack} with random variation
                if "{attack}" in description:
                    attack_var = attack_variations.get(
                        threat_type, attack_variations["Injection Attack"]  # Default
                    )
                    description = description.replace(
                        "{attack}", random.choice(attack_var)
                    )

                # Replace {location} with random variation
                if "{location}" in description:
                    description = description.replace(
                        "{location}", random.choice(location_variations)
                    )

                # Replace {method} with random variation
                if "{method}" in description:
                    description = description.replace(
                        "{method}", random.choice(method_variations)
                    )

                # Add to samples
                synthetic_samples.append((description, threat_type))

    return synthetic_samples


def get_extended_adversarial_samples_with_synthetic():
    """Combines original 84 samples with 300+ synthetic samples."""
    original = get_extended_adversarial_samples()
    synthetic = generate_synthetic_samples_from_templates()

    return original + synthetic


def augment_text_via_synonym_replacement(text, synonym_replacement_rate=0.25):
    """Augment a text sample by replacing words with synonyms."""
    words = text.split()  # Simple word splitting
    augmented = []

    for word in words:
        # Randomly decide whether to augment this word
        if random.random() < synonym_replacement_rate:
            # Get synonyms from WordNet
            synsets = wordnet.synsets(word)

            if synsets:
                # Get all lemmas (word variations) from first synset
                lemmas = synsets[0].lemmas()

                if lemmas:
                    # Pick a random synonym
                    synonym = random.choice(lemmas).name()
                    # Replace underscores with spaces (WordNet format)
                    augmented.append(synonym.replace("_", " "))
                else:
                    augmented.append(word)
            else:
                augmented.append(word)
        else:
            # Keep original word
            augmented.append(word)

    return " ".join(augmented)


def augment_dataset(samples, num_augmentations_per_sample=2, replacement_rate=0.25):
    """Augment entire dataset by creating paraphrased variations."""
    augmented_samples = list(samples)  # Start with originals

    for text, label in samples:
        for _ in range(num_augmentations_per_sample):
            aug_text = augment_text_via_synonym_replacement(
                text, synonym_replacement_rate=replacement_rate
            )
            augmented_samples.append((aug_text, label))

    return augmented_samples
