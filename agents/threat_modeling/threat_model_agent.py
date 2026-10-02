# Vigilon Atlas: Threat Modeling & Attack Paths
# Builds dynamic threat models and maps attack paths


import json
from datetime import datetime, timezone
from typing import Dict, List, Optional

try:
    from mitreattack.stix20 import MitreAttackData

    MITRE_AVAILABLE = True
except ImportError:
    MITRE_AVAILABLE = False


import sys
import os
from agents.log_ingestor.log_ingestor_agent1 import Agent1LogIngestion

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))
from shared.communication.message_bus import message_bus
from neo4j import GraphDatabase
from data.models.models import (
    Base,
    Asset,
    Vulnerability,
    AssetVulnerability,
    AttackEdge,
    ThreatScenario,
    AttackPath,
    ScenarioAsset,
    get_session,
    engine,
    Session,
)
from vulnerability_enrichment.cve_fetcher import CVEFetcher
from agents.threat_modeling.attack_path_ranker import AttackPathRanker
import time
from dotenv import load_dotenv
import logging
from shared.logging_config import setup_agent_logger
from shared.agent_names import agent_name, agent_full_name
import re
from opentelemetry import trace, metrics

# Create tables if the don't exist (run once)
Base.metadata.create_all(engine)

load_dotenv()  # Load environment variables from .env file

ATTACK_CHAIN_MAP = {
    # keyword in description -> ordered list of attack steps
    "rce": [
        "Initial reconnaissance",
        "Exploit delivery",
        "Remote code execution",
        "Post-exploitation",
    ],
    "remote code": [
        "Initial reconnaissance",
        "Exploit delivery",
        "Remote code execution",
        "Post-exploitation",
    ],
    "auth bypass": [
        "Unauthenticated access attempt",
        "Authentication bypass",
        "Unauthorized resource access",
    ],
    "privilege esc": [
        "Initial access",
        "Exploit privilege escalation vulnerability",
        "Obtain elevated privileges",
        "Persistence",
    ],
    "sql inject": [
        "Reconnaissance of input fields",
        "Craft SQL payload",
        "Database query injection",
        "Data extraction",
    ],
    "xss": [
        "Identify reflected/stored input",
        "Inject malicious script",
        "User session targeted",
        "Credential or token theft",
    ],
    "buffer overflow": [
        "Craft malformed input",
        "Trigger buffer overflow",
        "Control instruction pointer",
        "Arbitrary code execution",
    ],
    "denial": [
        "Identify target service",
        "Send malformed/flood packets",
        "Service becomes unavailable",
    ],
    "path traversal": [
        "Enumerate directory structure",
        "Craft traversal payload",
        "Access restricted files",
    ],
    "deserialization": [
        "Supply malicious serialised object",
        "Trigger deserialisation",
        "Arbitrary object instantiation",
        "Code execution",
    ],
    "ssrf": [
        "Identify SSRF-vulnerable endpoint",
        "Craft internal request",
        "Access internal metadata/services",
    ],
    "open redirect": [
        "Identify redirect parameter",
        "Craft phishing URL",
        "Redirect victim to attacker-controlled page",
    ],
    "ldap inject": [
        "Identify LDAP input",
        "Inject LDAP filter",
        "Bypass authentication or extract directory data",
    ],
    "xxe": [
        "Supply external entity XML",
        "Server parses malicious XML",
        "File read or SSRF via XXE",
    ],
}


def _derive_attack_chain(description: str) -> List[str]:
    """Derive attack chain steps from vulnerability description using keyword mapping."""
    desc_lower = description.lower()
    for keyword, chain in ATTACK_CHAIN_MAP.items():
        if keyword in desc_lower:
            return chain

    # Generic fallback
    return [
        "Reconnaissance and target identification",
        "Exploitaion of vulnerability",
        "Establish foothold",
        "Exfiltration or impact",
    ]


def _derive_likelihood(cvss_vector: str, cvss_score: float) -> str:
    """Derive likelihood from CVSS vector and score."""
    if not cvss_vector:
        return "medium" if cvss_score >= 7.0 else "low"
    if "AV:N" in cvss_vector:  # Network-exploitable
        return "high"
    if "AV:A" in cvss_vector:  # Adjacent network
        return "medium"
    return "low"  # Local / Physical


class ThreatModelAgent:

    def __init__(
        self,
        agent_id: str = "threat_model_001",
        log_dir: str = "test_logs",
        verbose: bool = True,
    ):
        self.agent_id = agent_id
        self.verbose = (
            verbose  # Demo mode (True) shows DEBUG, Listen mode (False) shows only INFO
        )
        self.logger = setup_agent_logger(
            agent_id, verbose
        )  # Initialize logger with verbose control
        self.status = "initialized"
        self.threat_models = {}
        self.attack_graphs = []
        self.log_dir = log_dir
        self._known_log_files = set()  # Track already-processed log files
        self._new_logs_detected = False  # Flag: set True when new logs arrive
        # Ingest logs on agent initialization
        self.ingest_all_logs()
        self._last_analyzed_log_id = (
            0  # Track last analyzed log entry ID for incremental analysis
        )
        self.cve_min_year = int(os.getenv("CVE_MIN_YEAR", "2018"))
        self.tracer = trace.get_tracer(self.agent_id)
        self.meter = metrics.get_meter(self.agent_id)
        self.model_time = self.meter.create_histogram("model_latency_ms")
        self.modeled_count = self.meter.create_counter("threats_modeled")
        self.graph_time = self.meter.create_histogram("graph_latency_ms")
        self.graph_nodes = self.meter.create_counter("attack_graph_nodes")
        self.scenarios_time = self.meter.create_histogram("scenarios_latency_ms")
        self.scenarios_count = self.meter.create_counter("threat_scenarios")

    def ingest_all_logs(self):
        """Ingest all log files in the log directory."""
        if not os.path.exists(self.log_dir):
            self.logger.warning("Log directory '%s' does not exist.", self.log_dir)
            return
        log_files = [
            f
            for f in os.listdir(self.log_dir)
            if f.endswith((".log", ".txt", ".json", ".csv"))
        ]
        log_sources = [
            {"type": "file", "path": os.path.join(self.log_dir, f)} for f in log_files
        ]
        if log_sources:
            self.logger.info("Ingesting %d log files...", len(log_sources))
            Agent1LogIngestion(log_sources).run()
            self._known_log_files.update(log_files)
            self.logger.info("Tracking %d known log files", len(self._known_log_files))
        else:
            self.logger.info("No log files found to ingest.")

        # Mapping of vulnerabilities to MITRE tactics
        # Map vulnerabilities to MITRE ATT&CK tactic IDs
        self.vuln_to_mitre = {
            "SQL Injection": ["TA0001", "TA0002"],
            "XSS": ["TA0001", "TA0002"],
            "Broken Authentication": ["TA0001", "TA0006"],
            "API Rate Limiting Issues": ["TA0040"],
            "Unencrypted Traffic": ["TA0009", "TA0010"],
            "Weak Protocols": ["TA0009"],
        }

        # Expanded mapping for better MITRE coverage
        self.vuln_to_mitre_keyword = {
            "SQL Injection": [
                "sql injection",
                "injection",
                "input validation",
                "database",
            ],
            "XSS": [
                "cross-site scripting",
                "xss",
                "scripting",
                "input validation",
                "web application",
            ],
            "Broken Authentication": [
                "credential access",
                "valid accounts",
                "authentication",
                "brute force",
                "login",
                "session",
            ],
            "API Rate Limiting Issues": [
                "abuse",
                "resource hijacking",
                "denial of service",
                "dos",
                "brute force",
                "api",
                "rate limiting",
            ],
            "Unencrypted Traffic": [
                "network sniffing",
                "traffic capture",
                "plaintext",
                "unencrypted",
                "network monitoring",
                "network service",
            ],
            "Weak Protocols": [
                "plaintext",
                "unencrypted",
                "weak protocol",
                "protocol",
                "network service",
            ],
            # Fallbacks for node types
            "web_interface": ["web application", "web server", "web"],
            "api_endpoint": ["api", "application programming interface", "endpoint"],
            "network_service": ["network service", "service", "protocol"],
        }

        if MITRE_AVAILABLE:
            self.mitre_data = MitreAttackData("data/mitre/enterprise-attack.json")
        else:
            self.mitre_data = None

        neo4j_uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        neo4j_username = os.getenv("NEO4J_USERNAME", "neo4j")
        neo4j_password = os.getenv("NEO4J_PASSWORD", "neo4j")
        self.neo4j_driver = GraphDatabase.driver(
            neo4j_uri,
            auth=(neo4j_username, neo4j_password),
        )

        self.cve_fetcher = CVEFetcher(api_key=os.getenv("VULNERS_API_KEY"))

        # Subscribe to relevant channels
        # message_bus.subscribe("system_events", self.handle_system_event)
        message_bus.subscribe("threat_updates", self.handle_threat_update)
        # Subscribe to log upload events for event-driven ingestion
        message_bus.subscribe("log_uploaded", self.handle_log_uploaded)

    def handle_log_uploaded(self, message: Dict):
        """Handle log upload event and ingest the new log file."""
        log_path = message.get("path")
        if log_path and os.path.exists(log_path):
            self.logger.info("Detected new log upload: %s. Ingesting...", log_path)
            Agent1LogIngestion([{"type": "file", "path": log_path}]).run()
            self._known_log_files.add(os.path.basename(log_path))
            self._new_logs_detected = True
            self.logger.info(
                "✅ New log ingested — will re-run threat modeling on next cycle"
            )
        else:
            self.logger.warning(
                "Log upload event received but file not found: %s", log_path
            )

    def _check_for_new_log_files(self):
        """Scan the log directory for new files not yet processed."""
        if not os.path.exists(self.log_dir):
            return
        current_files = set(
            f
            for f in os.listdir(self.log_dir)
            if f.endswith((".log", ".txt", ".json", ".csv"))
        )
        new_files = current_files - self._known_log_files
        if new_files:
            self.logger.info(
                "📁 Detected %d new log file(s): %s",
                len(new_files),
                ", ".join(new_files),
            )
            log_sources = [
                {"type": "file", "path": os.path.join(self.log_dir, f)}
                for f in new_files
            ]
            Agent1LogIngestion(log_sources).run()
            self._known_log_files.update(new_files)
            self._new_logs_detected = True
            self.logger.info("✅ New log(s) ingested — will re-run threat modeling")

    # TODO: Add system event handling

    def publish_threat_model(self, threat_data: Dict):
        # Publish updated threat model to message bus
        message_bus.publish(
            "threat_intelligence",
            {
                "type": "threat_model_update",
                "source": self.agent_id,
                "data": threat_data,
            },
        )

    # Autonomous agent for building and maintaining threat models

    def analyze_logs_for_system_architecture(self) -> Dict:
        """Analyze ingested logs to discover system architecture and build attack surfaces"""
        with self.tracer.start_as_current_span(
            "analyze_logs_for_system_architecture"
        ) as span:
            span.set_attribute("log_dir", self.log_dir)

            start = time.time()

            self.logger.info(
                "Analyzing ingested logs for system architecture and attack surfaces..."
            )

            from data.models.models import LogEvent, get_session
            import json

            session = get_session()
            discovered_config = {
                "web_apps": [],
                "apis": [],
                "services": [],
                "databases": [],
                "network_devices": [],
            }

            try:
                # Get recent logs to analyze
                logs = (
                    session.query(LogEvent)
                    .filter(LogEvent.id > self._last_analyzed_log_id)
                    .order_by(LogEvent.id.asc())
                    .all()
                )
                self.logger.info("Analyzing %d recent log entries...", len(logs))
                if logs:
                    self._last_analyzed_log_id = max(
                        log.id for log in logs
                    )  # Update last analyzed log ID
                discovered_services = set()
                discovered_apis = set()
                discovered_web_apps = set()
                discovered_databases = set()
                error_patterns = []
                # Track specific software names so CVE queries are targeted
                discovered_web_software: set = set()
                discovered_network_software: set = set()
                discovered_db_software: set = set()
                # Explicit CVE IDs found directly in log entries
                discovered_explicit_cve_ids: set = set()

                for log in logs:
                    # Parse the JSON data if available
                    parsed_data = {}
                    if log.data:
                        try:
                            parsed_data = json.loads(log.data)
                        except:
                            pass

                    # Use parsed data or fall back to message
                    message = (log.message or "").lower()
                    service = parsed_data.get("service", "").lower()
                    level = (log.level or parsed_data.get("level", "")).upper()

                    if not message and not service:
                        continue

                    # Pick up explicit CVE IDs embedded in structured log data
                    raw_cve = parsed_data.get("cve_id") or parsed_data.get("cve")
                    if (
                        raw_cve
                        and isinstance(raw_cve, str)
                        and raw_cve.upper().startswith("CVE-")
                    ):
                        discovered_explicit_cve_ids.add(raw_cve.upper())

                    # Extract software name from service field or message
                    _WEB_ANCHORS = {
                        "nginx",
                        "apache",
                        "httpd",
                        "iis",
                        "tomcat",
                        "lighttpd",
                        "caddy",
                    }
                    _DB_ANCHORS = {
                        "mysql",
                        "postgres",
                        "postgresql",
                        "mongodb",
                        "redis",
                        "oracle",
                        "mssql",
                        "sqlite",
                        "mariadb",
                        "cassandra",
                        "elasticsearch",
                    }
                    # Noise words that can appear before a colon in syslog messages
                    # but are not process names.
                    _SKIP_WORDS = {
                        "error",
                        "warning",
                        "warn",
                        "info",
                        "debug",
                        "notice",
                        "critical",
                        "failed",
                        "the",
                        "for",
                        "from",
                        "to",
                        "at",
                        "in",
                        "on",
                    }
                    _PROC_RE = re.compile(
                        r"\b([a-z][a-z0-9_-]{1,24})(?:\[\d+\])?:", re.I
                    )

                    sw_name = (
                        service  # already lowercase from parsed_data.get("service")
                    )

                    if not sw_name and message:
                        m_proc = _PROC_RE.search(message)
                        if m_proc:
                            candidate = m_proc.group(1).lower()
                            if candidate not in _SKIP_WORDS:
                                sw_name = candidate

                    # Strip trailing version digits (apache2 → apache, openssl3 → openssl)
                    if sw_name:
                        sw_name = re.sub(r"\d+$", "", sw_name).strip("-_")

                    if sw_name:
                        if sw_name in _WEB_ANCHORS:
                            discovered_web_software.add(sw_name)
                        elif sw_name in _DB_ANCHORS:
                            discovered_db_software.add(sw_name)
                        else:
                            discovered_network_software.add(sw_name)

                    # Enhanced service detection using structured data
                    if service or any(
                        svc in message
                        for svc in ["apache", "nginx", "iis", "httpd", "tomcat"]
                    ):
                        # Detect web applications
                        if (
                            "portal" in message
                            or parsed_data.get("url", "").find("portal") != -1
                        ):
                            discovered_web_apps.add(
                                ("Customer Portal", True, False)
                            )  # public, no input validation
                        elif "admin" in message or "dashboard" in message:
                            discovered_web_apps.add(
                                ("Admin Dashboard", False, True)
                            )  # internal, has input validation
                        elif service in ["apache2", "nginx", "httpd", "iis", "tomcat"]:
                            discovered_web_apps.add(
                                (f"{service.title()} Web Server", True, False)
                            )

                    # Detect APIs
                    if any(
                        pattern in message
                        for pattern in ["api", "rest", "endpoint", "json"]
                    ):
                        if "external" in message or "public" in message:
                            discovered_apis.add(
                                ("REST API", True, True)
                            )  # public, authenticated
                        else:
                            discovered_apis.add(
                                ("Internal API", False, True)
                            )  # internal, authenticated

                    # Detect databases
                    if any(
                        pattern in message
                        for pattern in [
                            "mysql",
                            "postgresql",
                            "mongodb",
                            "redis",
                            "database",
                            "db",
                        ]
                    ):
                        if "error" in message or "failed" in message:
                            discovered_databases.add(
                                ("Database Server", False, False)
                            )  # internal, has issues
                        else:
                            discovered_databases.add(
                                ("Database Server", False, True)
                            )  # internal, secure

                    # Detect other services (network layer)
                    if any(
                        pattern in message
                        for pattern in [
                            "ssh",
                            "ftp",
                            "smtp",
                            "dns",
                            "haproxy",
                            "openssl",
                            "snmp",
                        ]
                    ):
                        service_name = next(
                            (
                                s
                                for s in [
                                    "ssh",
                                    "ftp",
                                    "smtp",
                                    "dns",
                                    "haproxy",
                                    "openssl",
                                    "snmp",
                                ]
                                if s in message
                            ),
                            "Unknown Service",
                        )
                        discovered_services.add(
                            (f"{service_name.upper()} Service", False, True)
                        )

                    # Collect error patterns for vulnerability analysis
                    if any(
                        pattern in message
                        for pattern in ["error", "failed", "exception", "denied"]
                    ):
                        error_patterns.append(message)

                if discovered_explicit_cve_ids:
                    self.logger.info(
                        "Detected %d explicit CVE IDs in log entries: %s",
                        len(discovered_explicit_cve_ids),
                        ", ".join(sorted(discovered_explicit_cve_ids)),
                    )
                if discovered_network_software:
                    self.logger.info(
                        "Detected network software: %s",
                        ", ".join(sorted(discovered_network_software)),
                    )

                # Convert discovered items to config format, carrying software names
                # through so CVE queries can be targeted to actual detected software.
                _web_sw_list = sorted(discovered_web_software)
                _net_sw_list = sorted(discovered_network_software)
                _db_sw_list = sorted(discovered_db_software)
                _explicit_cves = sorted(discovered_explicit_cve_ids)

                discovered_config["web_apps"] = [
                    {
                        "name": name,
                        "public_facing": public,
                        "input_validation": validation,
                        "auth_implemented": True,
                        "software_names": _web_sw_list,
                        "explicit_cve_ids": _explicit_cves,
                    }
                    for name, public, validation in discovered_web_apps
                ]

                discovered_config["apis"] = [
                    {
                        "name": name,
                        "public_facing": public,
                        "authenticated": auth,
                        "software_names": _web_sw_list + _net_sw_list,
                        "explicit_cve_ids": _explicit_cves,
                    }
                    for name, public, auth in discovered_apis
                ]

                discovered_config["services"] = [
                    {
                        "name": name,
                        "public_facing": public,
                        "encrypted": encrypted,
                        "software_names": _net_sw_list,
                        "explicit_cve_ids": _explicit_cves,
                    }
                    for name, public, encrypted in discovered_services
                ]

                discovered_config["databases"] = [
                    {
                        "name": name,
                        "public_facing": public,
                        "encrypted": encrypted,
                        "software_names": _db_sw_list,
                        "explicit_cve_ids": _explicit_cves,
                    }
                    for name, public, encrypted in discovered_databases
                ]

                # Add default components if none discovered
                if not any(
                    [
                        discovered_web_apps,
                        discovered_apis,
                        discovered_services,
                        discovered_databases,
                    ]
                ):
                    self.logger.info(
                        "No specific components detected, using inferred architecture..."
                    )
                    discovered_config = {
                        "web_apps": [
                            {
                                "name": "Inferred Web Application",
                                "public_facing": True,
                                "input_validation": False,
                                "auth_implemented": True,
                            }
                        ],
                        "apis": [
                            {
                                "name": "Inferred API Endpoint",
                                "public_facing": True,
                                "authenticated": True,
                            }
                        ],
                        "services": [
                            {
                                "name": "Inferred Backend Service",
                                "public_facing": False,
                                "encrypted": True,
                            }
                        ],
                        "databases": [],
                    }

                self.logger.info("Discovered architecture:")
                self.logger.info("  - Web Apps: %d", len(discovered_config["web_apps"]))
                self.logger.info("  - APIs: %d", len(discovered_config["apis"]))
                self.logger.info("  - Services: %d", len(discovered_config["services"]))
                self.logger.info(
                    "  - Databases: %d", len(discovered_config["databases"])
                )
                self.logger.info("  - Error patterns found: %d", len(error_patterns))

                # Now analyze the discovered config to build attack surfaces
                self.logger.info(
                    "Building attack surfaces from discovered architecture..."
                )
                attack_surfaces = self.analyze_system_architecture(discovered_config)

                latency_ms = (time.time() - start) * 1000
                self.model_time.record(latency_ms)
                self.modeled_count.add(1)

                return attack_surfaces

            except Exception as e:
                self.logger.error("Error analyzing logs: %s", e)
                # Fallback to basic inferred architecture
                fallback_config = {
                    "web_apps": [
                        {
                            "name": "Unknown Web Application",
                            "public_facing": True,
                            "input_validation": False,
                            "auth_implemented": True,
                        }
                    ],
                    "apis": [
                        {
                            "name": "Unknown API",
                            "public_facing": True,
                            "authenticated": True,
                        }
                    ],
                    "services": [
                        {
                            "name": "Unknown Service",
                            "public_facing": False,
                            "encrypted": True,
                        }
                    ],
                    "databases": [],
                }

                latency_ms = (time.time() - start) * 1000
                self.model_time.record(latency_ms)
                self.modeled_count.add(1)

                return self.analyze_system_architecture(fallback_config)
            finally:
                session.close()

    def analyze_system_architecture(self, system_config: Dict) -> Dict:
        # Analyze system architecture and identify attack surfaces
        attack_surfaces = {
            "web_interfaces": [],
            "api_endpoints": [],
            "network_services": [],
            "databases": [],
            "external_integrations": [],
        }

        # Analyze different components
        for component_type, components in system_config.items():
            if component_type == "web_apps":
                attack_surfaces["web_interfaces"].extend(
                    self._analyze_web_components(components)
                )
            elif component_type == "apis":
                attack_surfaces["api_endpoints"].extend(
                    self._analyze_api_components(components)
                )
            elif component_type == "services":
                attack_surfaces["network_services"].extend(
                    self._analyze_network_services(components)
                )

        self.logger.info(
            "Identified %d attack surface categories", len(attack_surfaces)
        )
        return attack_surfaces

    def handle_threat_update(self, message: Dict):
        # Print what received
        self.logger.info("Received threat update")
        self.logger.info("Message type: %s", message.get("type"))
        self.logger.info("New CVEs found: %d", message.get("new_cves_count"))

        # Get the list of new CVE IDs
        new_cve_ids = message.get("cve_ids", [])

        if not new_cve_ids:
            self.logger.info("No new CVE IDs to process.")
            return

        self.logger.info("Processing %d new CVEs...", len(new_cve_ids))
        for cve_id in new_cve_ids:
            self.logger.info("  - %s", cve_id)

        # Query database to get full details of new CVEs
        session = Session()
        try:
            new_vulns = (
                session.query(Vulnerability)
                .filter(Vulnerability.cve_id.in_(new_cve_ids))
                .all()
            )

            self.logger.info(
                "Retrieved %d vulnerabilities from database.", len(new_vulns)
            )
        finally:
            session.close()

        # Publish notification to Vigilon Triage
        threat_intel = {
            "type": "new_vulnerabilities_detected",
            "source": self.agent_id,
            "timestamp": datetime.now().isoformat(),
            "new_cve_count": len(new_cve_ids),
            "cve_ids": new_cve_ids,
        }

        message_bus.publish("threat_intelligence", threat_intel)
        self.logger.info(f"Notified {agent_name('classifier')} of new vulnerabilities")

    def add_asset_neo4j(self, asset_id, asset_type):
        # Add asset node to Neo4j database
        with self.neo4j_driver.session() as session:
            session.run(
                "MERGE (a:Asset {id: $id, type: $type})",
                id=asset_id,
                type=asset_type,
            )

    def add_vuln_neo4j(self, asset_id, vuln_name):
        # Add vulnerability node and relationship to asset in Neo4j
        with self.neo4j_driver.session() as session:
            session.run(
                """
                MATCH (a:Asset {id: $id})
                MERGE (v:Vulnerability {name: $vuln_name})
                MERGE (a)-[:HAS_VULNERABILITY]->(v)
                """,
                id=asset_id,
                vuln_name=vuln_name,
            )

    def reset_neo4j(self):
        # Clear all nodes and relationships in Neo4j database
        with self.neo4j_driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")
        self.logger.debug("Neo4j database reset completed.")

    def run_cypher_query(self, query, parameters=None):
        # Run a cypher query and print the results
        with self.neo4j_driver.session() as session:
            result = session.run(query, parameters or {})
            records = list(result)
            self.logger.debug("Cypher Query Results:")
            for record in records:
                self.logger.debug("  - %s", dict(record))
            return records

    # Database interaction methods

    def add_asset_db(self, name, type, risk_level):
        session = get_session()
        try:
            # Check if asset already exists
            existing = session.query(Asset).filter_by(name=name, type=type).first()
            if existing:
                return existing
            # Add asset to relational database
            asset = Asset(name=name, type=type, risk_level=risk_level)
            session.add(asset)
            session.commit()
            return asset
        except Exception as e:
            session.rollback()
            self.logger.error("Error adding asset: %s", str(e))
            return None
        finally:
            session.close()

    def add_vuln_db(self, name, description, severity):
        session = get_session()
        try:
            # Check if vulnerability already exists
            existing = (
                session.query(Vulnerability)
                .filter_by(name=name, description=description)
                .first()
            )
            if existing:
                return existing
            # Add vulnerability to relational database
            vuln = Vulnerability(name=name, description=description, severity=severity)
            session.add(vuln)
            session.commit()
            return vuln
        except Exception as e:
            session.rollback()
            self.logger.error("Error adding vulnerability: %s", str(e))
            return None
        finally:
            session.close()

    def link_asset_vuln_db(self, asset: Asset, vuln: Vulnerability):
        session = get_session()
        try:
            # Check if link already exists
            existing = (
                session.query(AssetVulnerability)
                .filter_by(asset_id=asset.id, vulnerability_id=vuln.id)
                .first()
            )
            if existing:
                return existing

            # Link asset and vulnerability in relational database
            link = AssetVulnerability(
                asset_id=asset.id,
                vulnerability_id=vuln.id,
            )
            session.add(link)
            session.commit()
            return link
        except Exception as e:
            session.rollback()
            self.logger.error("Error linking asset and vulnerability: %s", str(e))
            return None
        finally:
            session.close()

    def add_attack_edge_db(
        self, from_asset: Asset, to_asset: Asset, attack_technique: str, difficulty: str
    ):
        # Add attack edge to relational database
        session = get_session()
        try:
            edge = AttackEdge(
                from_asset_id=from_asset.id,
                to_asset_id=to_asset.id,
                attack_technique=attack_technique,
                difficulty=difficulty,
            )
            session.add(edge)
            session.commit()
            return edge
        except Exception as e:
            session.rollback()
            self.logger.error("Error adding attack edge: %s", str(e))
            return None
        finally:
            session.close()

    def add_threat_scenario_db(
        self, name: str, likelihood: str, impact: str, description: str
    ):
        session = get_session()
        try:
            # Add threat scenario to relational database
            scenario = ThreatScenario(
                name=name,
                likelihood=likelihood,
                impact=impact,
                description=description,
            )
            session.add(scenario)
            session.commit()
            return scenario
        except Exception as e:
            session.rollback()
            self.logger.error("Error adding threat scenario: %s", str(e))
            return None
        finally:
            session.close()

    def link_scenario_asset_db(self, scenario: ThreatScenario, asset: Asset):
        session = get_session()
        try:
            # Check if link already exists
            existing = (
                session.query(ScenarioAsset)
                .filter_by(scenario_id=scenario.id, asset_id=asset.id)
                .first()
            )
            if existing:
                return existing
            # Link scenario and asset in relational database
            link = ScenarioAsset(
                scenario_id=scenario.id,
                asset_id=asset.id,
            )
            session.add(link)
            session.commit()
            return link
        except Exception as e:
            session.rollback()
            self.logger.error("Error linking scenario and asset: %s", str(e))
            return None
        finally:
            session.close()

    def add_assets_batch_db(self, asset_data_list):
        # Batch upsert assets to database
        session = get_session()
        try:
            result = []
            for data in asset_data_list:
                existing = session.query(Asset).filter_by(name=data["name"]).first()
                if existing:
                    result.append(existing)
                else:
                    asset = Asset(**data)
                    session.add(asset)
                    session.flush()
                    result.append(asset)
            session.commit()
            return result
        except Exception as e:
            session.rollback()
            self.logger.error("Error in batch asset insert: %s", str(e))
            return []
        finally:
            session.close()

    def add_vulns_batch_db(self, vuln_data_list):
        # Batch upsert vulnerabilities to database
        session = get_session()
        try:
            result = []
            for data in vuln_data_list:
                existing = (
                    session.query(Vulnerability).filter_by(name=data["name"]).first()
                )
                if existing:
                    result.append(existing)
                else:
                    vuln = Vulnerability(**data)
                    session.add(vuln)
                    session.flush()
                    result.append(vuln)
            session.commit()
            return result
        except Exception as e:
            session.rollback()
            self.logger.error("Error in batch vulnerability insert: %s", str(e))
            return []
        finally:
            session.close()

    # Builds attack graph from attack surfaces

    def build_attack_graph(self, attack_surfaces: Dict) -> Dict:
        # Build attack graph from identified attack surfaces
        with self.tracer.start_as_current_span("build_attack_graph") as span:
            span.set_attribute("surface_count", len(attack_surfaces))

            start = time.time()

            self.logger.info("Building attack graph")

            attack_graph = {"nodes": [], "edges": [], "critical_paths": []}

            node_id = 0
            for surface_type, surfaces in attack_surfaces.items():
                for surface in surfaces:
                    node_identifier = f"node_{node_id}"
                    node = {
                        "id": node_identifier,
                        "type": surface_type,
                        "name": surface.get("name"),
                        "risk_level": surface.get("risk_level", "medium"),
                        "vulnerabilities": surface.get("vulnerabilities", []),
                    }
                    attack_graph["nodes"].append(node)

                    # Persist asset node to Neo4j
                    self.add_asset_neo4j(node_identifier, surface_type)
                    # Persist vulnerabilities and relationships to Neo4j
                    for vuln in node["vulnerabilities"]:
                        # Extract CVE ID if it's a dictionary
                        vuln_name = (
                            vuln.get("cve_id") if isinstance(vuln, dict) else vuln
                        )
                        self.add_vuln_neo4j(node_identifier, vuln_name)

                    node_id += 1
            # Create edges (attack paths)
            attack_graph["edges"] = self._generate_attack_paths(attack_graph["nodes"])

            self.logger.info(
                "Attack graph created with %d nodes", len(attack_graph["nodes"])
            )

            latency_ms = (time.time() - start) * 1000
            self.graph_time.record(latency_ms)
            self.graph_nodes.add(len(attack_graph["nodes"]))

            return attack_graph

    def _get_mitre_tactics(self, vulnerabilities: list) -> list:
        # Get MITRE tactics for a list of vulnerabilities.
        tactics = set()
        for vuln in vulnerabilities:
            tactics.update(self.vuln_to_mitre.get(vuln, []))
        return list(tactics)

    def generate_threat_scenarios(
        self, attack_graph: Dict, system_config: Dict = None
    ) -> List[Dict]:
        # Generate threat scenarios from attack graph
        with self.tracer.start_as_current_span("generate_threat_scenarios") as span:
            span.set_attribute("graph_nodes", len(attack_graph.get("nodes", [])))

            start = time.time()

            self.logger.info(
                "Generating threat scenarios from actual attack graph data..."
            )
            scenarios = []
            seen_cves = set()

            for node_idx, node in enumerate(attack_graph.get("nodes", [])):
                asset_name = node.get("name", "Unknown Asset")
                asset_type = node.get("type", "unknown")

                for vuln_dict in node.get("vulnerabilities", []):
                    # Normalise: vulns may be strings or dicts depending on code path
                    if isinstance(vuln_dict, str):
                        cve_id = vuln_dict
                        description = vuln_dict
                        cvss_score = 5.0
                        cvss_vector = ""
                        severity = "medium"
                    else:
                        cve_id = vuln_dict.get("cve_id", "Unknown")
                        description = vuln_dict.get("description", cve_id)
                        cvss_score = float(vuln_dict.get("cvss_score") or 5.0)
                        cvss_vector = vuln_dict.get("cvss_vector", "")
                        severity = vuln_dict.get("severity", "medium")

                    if cve_id in seen_cves:
                        continue
                    seen_cves.add(cve_id)

                    attack_chain = _derive_attack_chain(description)
                    likelihood = _derive_likelihood(cvss_vector, cvss_score)
                    impact = (
                        "critical"
                        if cvss_score >= 9.0
                        else (
                            "high"
                            if cvss_score >= 7.0
                            else "medium" if cvss_score >= 4.0 else "low"
                        )
                    )
                    techniques = self.get_techniques_for_vuln(cve_id, asset_type)

                    # Use first sentence of description as scenario name cap
                    short_desc = description.split(".")[0][:80]
                    scenario_name = f"{cve_id}: {short_desc}"

                    scenarios.append(
                        {
                            "id": f"scenario_{cve_id.replace('-','_').lower()}",
                            "name": scenario_name,
                            "asset": asset_name,
                            "attack_chain": attack_chain,
                            "likelihood": likelihood,
                            "impact": impact,
                            "mitre_techniques": techniques,
                            "vulnerabilities_exploited": [cve_id],
                            "cvss_score": cvss_score,
                        }
                    )

            # Fallback if no CVEs were found in graph
            if not scenarios:
                self.logger.warning(
                    "No CVEs in attack graph — using generic fallback scenario"
                )
                scenarios.append(
                    {
                        "id": "scenario_generic_001",
                        "name": "Generic Threat: Unidentified Attack Surface",
                        "asset": "Unknown",
                        "attack_chain": ["Reconnaissance", "Exploitation", "Impact"],
                        "likelihood": "medium",
                        "impact": "medium",
                        "mitre_techniques": [],
                        "vulnerabilities_exploited": [],
                    }
                )

            self.logger.info(
                "Generated %d dynamic threat scenarios from %d unique CVEs",
                len(scenarios),
                len(seen_cves),
            )

            latency_ms = (time.time() - start) * 1000
            self.scenarios_time.record(latency_ms)
            self.scenarios_count.add(len(scenarios))

            return scenarios

    def display_attack_paths(self):
        """Display ranked attack paths to analyst in logs."""
        session = get_session()
        paths = session.query(AttackPath).all()

        if not paths:
            self.logger.info("No attack paths found in database")
            session.close()
            return

        ranker = AttackPathRanker()
        ranked = ranker.rank_paths_by_risk([p.__dict__ for p in paths])

        self.logger.info("\n🎯 Top-Risk Attack Paths (Ranked):")
        for i, path in enumerate(ranked[:10], 1):  # Top 10
            # Get asset names if they exist
            source_asset = (
                session.query(Asset).filter_by(id=path.source_asset_id).first()
            )
            target_asset = (
                session.query(Asset).filter_by(id=path.target_asset_id).first()
            )
            source_name = source_asset.name if source_asset else "Unknown"
            target_name = target_asset.name if target_asset else "Unknown"

            self.logger.info(
                f"\n{i}. Risk: {path.risk_score:.2f} | Difficulty: {path.difficulty_score:.1f}/10"
            )
            self.logger.info(f"   Path: {source_name} → {target_name}")
            self.logger.info(f"   Time to Exploit: {path.time_to_exploit} minutes")
            self.logger.info(f"   Success Probability: {path.success_probability:.1%}")
            if path.threat_actor_profile:
                self.logger.info(f"   Threat Actor: {path.threat_actor_profile}")

        session.close()

    def share_intelligence(self, data: Dict) -> Dict:
        # Share threat intelligence with other agents
        # Calculate confidence based on data completeness
        confidence = 0.5  # Base confidence
        assets = data.get("assets", 0)
        if (len(assets) if isinstance(assets, (list, dict)) else assets) > 0:
            confidence += 0.15
        vulns = data.get("vulnerabilities", 0)
        if (len(vulns) if isinstance(vulns, (list, dict)) else vulns) > 0:
            confidence += 0.2
        scenarios = data.get("threat_scenarios", 0)
        if (len(scenarios) if isinstance(scenarios, (list, dict)) else scenarios) > 0:
            confidence += 0.15
        confidence = min(confidence, 1.0)  # Cap at 1.0

        intel_package = {
            "source_agent": self.agent_id,
            "timestamp": datetime.now().isoformat(),
            "intel_type": "threat_model",
            "data": data,
            "confidence": confidence,
        }

        self.logger.debug("Sharing intelligence package")

        # Publish to message bus to trigger other agents
        threat_intel_msg = {
            "type": "threat_model_update",
            "source": self.agent_id,
            "data": intel_package,
            "assets_count": data.get("assets", 0),
            "vulnerabilities_count": data.get("vulnerabilities", 0),
            "scenarios_count": data.get("threat_scenarios", 0),
        }
        self.logger.debug("Published to 'threat_intelligence': threat_model_update")
        self.logger.debug("Full message content: %s", threat_intel_msg)
        message_bus.publish("threat_intelligence", threat_intel_msg)

        # Also notify Vigilon Triage for classification
        classified_msg = {
            "type": "new_threats_available",
            "source": self.agent_id,
            "threat_count": data.get("threat_scenarios", 0),
            "asset_count": data.get("assets", 0),
        }
        self.logger.debug("Published to 'classified_threats': new_threats_available")
        self.logger.debug("Full message content: %s", classified_msg)
        message_bus.publish("classified_threats", classified_msg)

        return intel_package

    def get_techniques_for_vuln(self, vuln_keyword: str, node_type: str = None):
        """Return the most relevant MITRE techniques for a vulnerability using loose, relevant matching."""
        if not self.mitre_data:
            return []
        # Use mapped keywords if available, else just the vuln_keyword
        keywords = self.vuln_to_mitre_keyword.get(vuln_keyword, [vuln_keyword])
        matches = []
        for tech in self.mitre_data.get_techniques():
            name = tech.get("name", "").lower()
            desc = tech.get("description", "").lower()
            # Match if ANY keyword is present in name or description
            if any(kw.lower() in name or kw.lower() in desc for kw in keywords):
                matches.append(
                    {
                        "id": tech["external_references"][0]["external_id"],
                        "name": tech["name"],
                        "tactics": [
                            t["phase_name"] for t in tech.get("kill_chain_phases", [])
                        ],
                        "url": tech["external_references"][0]["url"],
                    }
                )
        # Fallback: if no matches and node_type is provided, try node type keywords
        if not matches and node_type and node_type in self.vuln_to_mitre_keyword:
            fallback_keywords = self.vuln_to_mitre_keyword[node_type]
            for tech in self.mitre_data.get_techniques():
                name = tech.get("name", "").lower()
                desc = tech.get("description", "").lower()
                if any(
                    kw.lower() in name or kw.lower() in desc for kw in fallback_keywords
                ):
                    matches.append(
                        {
                            "id": tech["external_references"][0]["external_id"],
                            "name": tech["name"],
                            "tactics": [
                                t["phase_name"]
                                for t in tech.get("kill_chain_phases", [])
                            ],
                            "url": tech["external_references"][0]["url"],
                        }
                    )
                if len(matches) >= 3:
                    break
        return matches[:3]

    # Helper methods

    def _log_attack_surfaces_debug(self, attack_surfaces: Dict) -> None:
        """Log detailed attack surface information to file as DEBUG level."""
        self.logger.debug("MITRE ATT&CK techniques for attack surfaces...")
        for surface_type, surfaces in attack_surfaces.items():
            self.logger.debug(f"Attack Surface: {surface_type}")
            for surface in surfaces:
                vulns = surface.get("vulnerabilities", [])
                self.logger.debug(f"  {surface.get('name', 'Unknown')}: {vulns}")
                found_any = False
                for vuln in vulns:
                    vuln_id = vuln.get("cve_id") if isinstance(vuln, dict) else vuln
                    techniques = self.get_techniques_for_vuln(vuln_id, surface_type)
                    if techniques:
                        found_any = True
                        self.logger.debug(f"    {vuln_id} → MITRE Techniques:")
                    else:
                        self.logger.debug(
                            f"    {vuln_id} → No direct MITRE technique match found."
                        )
                if not vulns or not found_any:
                    techniques = self.get_techniques_for_vuln(
                        surface_type, surface_type
                    )
                    if techniques:
                        self.logger.debug(
                            "[Fallback: %s] → MITRE Techniques:", surface_type
                        )
                        for tech in techniques:
                            self.logger.debug(
                                f"      - {tech['id']}: {tech['name']} (Tactics: {', '.join(tech['tactics'])})"
                            )
                    elif not vulns:
                        self.logger.debug(
                            "[Fallback: %s] → No MITRE technique match found.",
                            surface_type,
                        )

    def _log_attack_surfaces_info(self, attack_surfaces: Dict) -> None:
        """Log detailed attack surface information with INFO level (for demo console output)."""
        self.logger.info("MITRE ATT&CK techniques for attack surfaces (demo)...")
        for surface_type, surfaces in attack_surfaces.items():
            self.logger.info(f"Attack Surface: {surface_type}")
            for surface in surfaces:
                vulns = surface.get("vulnerabilities", [])
                self.logger.info(f"  {surface.get('name', 'Unknown')}: {vulns}")
                found_any = False
                for vuln in vulns:
                    vuln_id = vuln.get("cve_id") if isinstance(vuln, dict) else vuln
                    techniques = self.get_techniques_for_vuln(vuln_id, surface_type)
                    if techniques:
                        found_any = True
                        self.logger.info(f"    {vuln_id} → MITRE Techniques:")
                    else:
                        self.logger.info(
                            f"    {vuln_id} → No direct MITRE technique match found."
                        )
                if not vulns or not found_any:
                    techniques = self.get_techniques_for_vuln(
                        surface_type, surface_type
                    )
                    if techniques:
                        self.logger.debug(
                            "[Fallback: %s] → MITRE Techniques:", surface_type
                        )
                        for tech in techniques:
                            self.logger.debug(
                                f"      - {tech['id']}: {tech['name']} (Tactics: {', '.join(tech['tactics'])})"
                            )
                    elif not vulns:
                        self.logger.debug(
                            "[Fallback: %s] → No MITRE technique match found.",
                            surface_type,
                        )

    def _add_assets_and_vulns_db(self, attack_graph: Dict):
        """Add assets and vulnerabilities from attack graph to databases. Returns (asset_data, db_assets, vuln_data, db_vulns)."""
        asset_data = []
        for node in attack_graph["nodes"]:
            asset_data.append(
                {
                    "name": node["name"],
                    "type": node["type"],
                    "risk_level": node["risk_level"],
                }
            )

        db_assets = self.add_assets_batch_db(asset_data) if asset_data else []

        vuln_data = []
        vuln_names = set()
        for node in attack_graph["nodes"]:
            for vuln_dict in node.get("vulnerabilities", []):
                if isinstance(vuln_dict, dict):
                    cve_id = vuln_dict.get("cve_id", "Unknown")
                    if cve_id not in vuln_names:
                        vuln_names.add(cve_id)
                        vuln_data.append(
                            {
                                "name": cve_id,
                                "description": vuln_dict.get(
                                    "description", "No description"
                                ),
                                "severity": vuln_dict.get("severity", "medium"),
                                "cve_id": cve_id,
                                "cvss_base_score": vuln_dict.get("cvss_score"),
                                "cvss_vector": vuln_dict.get("cvss_vector"),
                            }
                        )

        db_vulns = self.add_vulns_batch_db(vuln_data) if vuln_data else []
        return asset_data, db_assets, vuln_data, db_vulns

    def _link_assets_vulns_db(
        self, attack_graph: Dict, db_assets: list, db_vulns: list
    ) -> int:
        """Link assets and vulnerabilities in database. Returns link count."""
        link_count = 0
        for i, node in enumerate(attack_graph["nodes"]):
            if i < len(db_assets) and db_assets[i]:
                self.logger.debug("Processing asset: %s", db_assets[i].name)
                for vuln_dict in node.get("vulnerabilities", []):
                    vuln_name = (
                        vuln_dict.get("cve_id")
                        if isinstance(vuln_dict, dict)
                        else vuln_dict
                    )
                    vuln_obj = next(
                        (v for v in db_vulns if v and v.name == vuln_name), None
                    )
                    if vuln_obj:
                        self.logger.debug("Linking to vulnerability: %s", vuln_name)
                        result = self.link_asset_vuln_db(db_assets[i], vuln_obj)
                        if result:
                            link_count += 1
                        else:
                            self.logger.warning(
                                "Failed to link %s to %s", db_assets[i].name, vuln_name
                            )
                    else:
                        self.logger.warning(
                            "Vulnerability '%s' not found in db_vulns", vuln_name
                        )
        return link_count

    def _add_attack_edges_db(self, attack_graph: Dict, db_assets: list) -> int:
        """Add attack edges from attack graph to database. Returns edge count."""
        edge_count = 0
        for edge in attack_graph["edges"]:
            # Handle both dict and object formats
            from_node_id = (
                edge.get("from")
                if isinstance(edge, dict)
                else getattr(edge, "source_asset_id", None)
            )
            to_node_id = (
                edge.get("to")
                if isinstance(edge, dict)
                else getattr(edge, "target_asset_id", None)
            )

            # Skip if we can't get node IDs
            if not from_node_id or not to_node_id:
                continue

            from_asset = next(
                (
                    a
                    for i, a in enumerate(db_assets)
                    if a and attack_graph["nodes"][i]["id"] == from_node_id
                ),
                None,
            )
            to_asset = next(
                (
                    a
                    for i, a in enumerate(db_assets)
                    if a and attack_graph["nodes"][i]["id"] == to_node_id
                ),
                None,
            )
            if from_asset and to_asset:
                attack_technique = (
                    edge.get("attack_technique")
                    if isinstance(edge, dict)
                    else getattr(edge, "attack_technique", "exploitation")
                )
                difficulty = (
                    edge.get("difficulty")
                    if isinstance(edge, dict)
                    else getattr(edge, "difficulty", "medium")
                )
                self.add_attack_edge_db(
                    from_asset, to_asset, attack_technique, difficulty
                )
                edge_count += 1
        return edge_count

    def _add_and_link_scenarios_db(self, scenarios: List[Dict], db_assets: list):
        """Add threat scenarios and link to assets. Returns (db_scenarios, scenario_count, scenario_asset_count)."""
        scenario_count = 0
        db_scenarios = []
        for scenario in scenarios:
            self.logger.debug(
                "Processing scenario: %s (Likelihood: %s, Impact: %s)",
                scenario["name"],
                scenario.get("likelihood", "unknown"),
                scenario.get("impact", "unknown"),
            )
            result = self.add_threat_scenario_db(
                name=scenario["name"],
                likelihood=scenario.get("likelihood", "unknown"),
                impact=scenario.get("impact", "unknown"),
                description=", ".join(scenario.get("attack_chain", [])),
            )
            if result:
                db_scenarios.append(result)
                scenario_count += 1

        scenario_asset_count = 0
        for scenario_obj in db_scenarios:
            if db_assets:
                self.logger.debug(
                    "Linking scenario '%s' to asset '%s'",
                    scenario_obj.name,
                    db_assets[0].name,
                )
                result = self.link_scenario_asset_db(scenario_obj, db_assets[0])
                if result:
                    scenario_asset_count += 1

        return db_scenarios, scenario_count, scenario_asset_count

    def enrich_with_mitre_dynamic(self, attack_surfaces):
        # Dynamically enrich attack surfaces with MITRE ATT&CK techniques by matching
        # vulnerabilities and names to technique names/descriptions.
        for surface_type, surfaces in attack_surfaces.items():
            for surface in surfaces:
                keywords = []
                # Use vulnerabilities and name as keywords
                if "vulnerabilities" in surface:
                    for vuln in surface["vulnerabilities"]:
                        keywords.append(vuln)
                        # Add generic forms for better matching
                        if "Injection" in vuln:
                            keywords.append("Injection")
                        if "Authentication" in vuln:
                            keywords.append("Authentication")
                        if "XSS" in vuln:
                            keywords.append("Cross-Site Scripting")
                        if "Rate Limiting" in vuln:
                            keywords.append("Rate Limiting")
                if "name" in surface:
                    keywords.append(surface["name"])
                matched_techniques = []
                for tid, t in self.mitre_techniques.items():
                    for kw in keywords:
                        if (
                            kw.lower() in t["name"].lower()
                            or kw.lower() in t.get("description", "").lower()
                        ):
                            matched_techniques.append(
                                {
                                    "id": tid,
                                    "name": t["name"],
                                    "url": t["external_references"][0]["url"],
                                }
                            )
                            break  # Avoid duplicates for this technique
                surface["mitre_techniques"] = matched_techniques
        return attack_surfaces

    def _analyze_web_components(self, components: List) -> List[Dict]:
        # Analyze web components for vulnerabilities
        results = []
        for component in components:
            results.append(
                {
                    "name": component.get("name"),
                    "type": "web_interface",
                    "risk_level": self._assess_risk(component),
                    "vulnerabilities": self._identify_common_web_vulns(component),
                }
            )
        return results

    def _analyze_api_components(self, components: List) -> List[Dict]:
        # Analyze API components
        results = []
        for component in components:
            results.append(
                {
                    "name": component.get("name"),
                    "type": "api_endpoint",
                    "risk_level": self._assess_risk(component),
                    "vulnerabilities": self._identify_api_vulns(component),
                }
            )
        return results

    def _analyze_network_services(self, components: List) -> List[Dict]:
        # Analyze network services
        results = []
        for component in components:
            results.append(
                {
                    "name": component.get("name"),
                    "type": "network_service",
                    "risk_level": self._assess_risk(component),
                    "vulnerabilities": self._identify_network_vulns(component),
                }
            )
        return results

    def _assess_risk(self, component: Dict) -> str:
        # Simple risk assessment
        # This would be more sophisticated in production
        if component.get("public_facing"):
            return "high"
        elif component.get("authenticated"):
            return "medium"
        else:
            return "low"

    def _fetch_targeted_cves(
        self, software_names: list, results_per_name: int = 2, min_year: int = 2018
    ) -> list:
        """Query Vulners for each specific software name, return deduplicated CVE list."""
        seen_ids: set = set()
        results: list = []
        for sw in software_names[:4]:  # cap at 4 names to stay within rate-limit budget
            for cve in self.cve_fetcher.fetch_cves(
                sw,
                results_per_page=results_per_name,
                min_year=min_year,
                post_filter=True,
            ):
                cve_id = cve.get("cve_id", "")
                if cve_id and cve_id not in seen_ids:
                    seen_ids.add(cve_id)
                    results.append(cve)
        return results

    def _filter_cves_by_min_year(self, cves: list, min_year: int) -> list:
        """Filter CVE dicts using CVE ID year (CVE-YYYY-XXXX)."""
        filtered = []
        dropped = 0

        for cve in cves:
            cve_id = str(cve.get("cve_id", ""))
            year = None

            if cve_id.startswith("CVE-"):
                parts = cve_id.split("-")
                if len(parts) >= 3:
                    try:
                        year = int(parts[1])
                    except Exception:
                        year = None

            # Fail-open on unknown year so we don't drop potentially relevant CVEs
            if year is None or year >= min_year:
                filtered.append(cve)
            else:
                dropped += 1

        if dropped > 0:
            self.logger.info(
                "Applied fallback CVE year filter: kept=%d dropped_old=%d min_year=%d",
                len(filtered),
                dropped,
                min_year,
            )

        return filtered

    def _identify_common_web_vulns(self, component: Dict) -> List[str]:
        """Identify web vulnerabilities using targeted software queries where available."""
        vulns = []
        software_names = component.get("software_names", [])

        if software_names:
            # Query Vulners for each detected web server software specifically
            self.logger.debug("Querying Vulners for web software: %s", software_names)
            vulns = self._fetch_targeted_cves(
                software_names, results_per_name=3, min_year=self.cve_min_year
            )

        # Also run the generic keyword queries so we always get sql/xss coverage
        if not component.get("input_validation"):
            for keyword in ["sql injection", "cross-site scripting"]:
                for cve in self.cve_fetcher.fetch_cves(
                    keyword,
                    results_per_page=2,
                    min_year=self.cve_min_year,
                    post_filter=True,
                ):
                    if not any(v.get("cve_id") == cve.get("cve_id") for v in vulns):
                        vulns.append(cve)

        if not component.get("auth_implemented"):
            for cve in self.cve_fetcher.fetch_cves(
                "authentication bypass",
                results_per_page=2,
                min_year=self.cve_min_year,
                post_filter=True,
            ):
                if not any(v.get("cve_id") == cve.get("cve_id") for v in vulns):
                    vulns.append(cve)

        if not vulns:
            # Vulners API unavailable — use well-known static CVEs as fallback
            vulns = [
                {
                    "cve_id": "CVE-2021-44228",
                    "description": "Log4Shell remote code execution via JNDI injection",
                    "severity": "critical",
                    "cvss_score": 10.0,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                },
                {
                    "cve_id": "CVE-2022-22965",
                    "description": "Spring4Shell: RCE via data binding in Spring Framework",
                    "severity": "critical",
                    "cvss_score": 9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                },
                {
                    "cve_id": "CVE-2021-26855",
                    "description": "Microsoft Exchange Server SSRF allowing pre-auth RCE (ProxyLogon)",
                    "severity": "critical",
                    "cvss_score": 9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                },
                {
                    "cve_id": "CVE-2019-11043",
                    "description": "PHP-FPM buffer underflow allowing RCE in nginx configurations",
                    "severity": "critical",
                    "cvss_score": 9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                },
                {
                    "cve_id": "CVE-2017-5638",
                    "description": "Apache Struts2 RCE via Content-Type header (Equifax breach vector)",
                    "severity": "critical",
                    "cvss_score": 10.0,
                    "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                },
            ]
            vulns = self._filter_cves_by_min_year(vulns, self.cve_min_year)
        return vulns

    def _identify_api_vulns(self, component: Dict) -> List[str]:
        """Identify API vulnerabilities using targeted software queries where available."""
        software_names = component.get("software_names", [])
        vuln_list = []

        if software_names:
            self.logger.debug("Querying Vulners for API software: %s", software_names)
            vuln_list = self._fetch_targeted_cves(
                software_names, results_per_name=2, min_year=self.cve_min_year
            )

        if not vuln_list:
            vuln_list = [
                cve
                for cve in self.cve_fetcher.fetch_cves(
                    "api vulnerability",
                    results_per_page=3,
                    min_year=self.cve_min_year,
                    post_filter=True,
                )
            ]

        if not vuln_list:
            vuln_list = [
                {
                    "cve_id": "CVE-2023-44487",
                    "description": "HTTP/2 Rapid Reset Attack causing DoS on API servers",
                    "severity": "high",
                    "cvss_score": 7.5,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                {
                    "cve_id": "CVE-2021-41773",
                    "description": "Apache HTTP Server path traversal and RCE via crafted requests",
                    "severity": "critical",
                    "cvss_score": 9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                },
                {
                    "cve_id": "CVE-2020-11651",
                    "description": "SaltStack authentication bypass allowing arbitrary command execution",
                    "severity": "critical",
                    "cvss_score": 9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                },
            ]
            vuln_list = self._filter_cves_by_min_year(vuln_list, self.cve_min_year)
        return vuln_list

    def _identify_network_vulns(self, component: Dict) -> List[str]:
        """Identify network vulnerabilities using targeted software queries where available."""
        software_names = component.get("software_names", [])
        vuln_list = []

        if software_names:
            self.logger.debug(
                "Querying Vulners for network software: %s", software_names
            )
            vuln_list = self._fetch_targeted_cves(
                software_names, results_per_name=2, min_year=self.cve_min_year
            )

        if not vuln_list:
            vuln_list = [
                cve
                for cve in self.cve_fetcher.fetch_cves(
                    "network protocol",
                    results_per_page=3,
                    min_year=self.cve_min_year,
                    post_filter=True,
                )
            ]

        if not vuln_list:
            vuln_list = [
                {
                    "cve_id": "CVE-2022-0778",
                    "description": "OpenSSL infinite loop via malformed certificate causing DoS",
                    "severity": "high",
                    "cvss_score": 7.5,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                {
                    "cve_id": "CVE-2021-3449",
                    "description": "OpenSSL NULL ptr deref via malicious ClientHello renegotiation",
                    "severity": "medium",
                    "cvss_score": 5.9,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
                },
                {
                    "cve_id": "CVE-2019-0708",
                    "description": "BlueKee minp: RCE in Windows RDP service, no authentication required",
                    "severity": "critical",
                    "cvss_score": 9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                },
            ]
            vuln_list = self._filter_cves_by_min_year(vuln_list, self.cve_min_year)
        return vuln_list

    def _generate_attack_paths(self, nodes: List[Dict]) -> List[Dict]:
        # Generate attack paths between nodes
        edges = []
        for i, node in enumerate(nodes):
            if i < len(nodes) - 1:
                edges.append(
                    {
                        "from": node["id"],
                        "to": nodes[i + 1]["id"],
                        "attack_technique": "exploitation",
                        "difficulty": "medium",
                    }
                )

        if edges:
            ranker = AttackPathRanker()
            ranked_edges = ranker.rank_paths_by_risk(edges)
            self.logger.info(f"📊 Ranked {len(ranked_edges)} attack paths by risk")

            # Store attack paths in database
            self._store_attack_paths_to_db(ranked_edges, nodes)

            # Convert AttackPath objects back to dictionaries for JSON serialization
            edges_dicts = []
            for edge in ranked_edges:
                if isinstance(edge, dict):
                    edges_dicts.append(edge)
                else:
                    # Convert AttackPath ORM object to dictionary
                    edges_dicts.append(
                        {
                            "from": getattr(edge, "source_asset_id", None),
                            "to": getattr(edge, "target_asset_id", None),
                            "attack_technique": getattr(
                                edge, "attack_technique", "exploitation"
                            ),
                            "difficulty": getattr(edge, "difficulty", "medium"),
                            "risk_score": getattr(edge, "risk_score", 0.0),
                        }
                    )

            return edges_dicts
        return edges

    def _store_attack_paths_to_db(self, ranked_edges: List, nodes: List[Dict]):
        """Store ranked attack paths to database for dashboard display."""
        try:
            session = get_session()

            # Clear existing paths to avoid duplicates
            session.query(AttackPath).delete()

            for edge in ranked_edges:
                # Handle both dict and object formats
                from_node_id = (
                    edge.get("from")
                    if isinstance(edge, dict)
                    else getattr(edge, "from", None)
                )
                to_node_id = (
                    edge.get("to")
                    if isinstance(edge, dict)
                    else getattr(edge, "to", None)
                )

                # Get source and target nodes
                source_node = next(
                    (n for n in nodes if n.get("id") == from_node_id), None
                )
                target_node = next(
                    (n for n in nodes if n.get("id") == to_node_id), None
                )

                if not source_node or not target_node:
                    continue

                # Get or create assets
                source_asset = (
                    session.query(Asset).filter_by(name=source_node.get("name")).first()
                )
                target_asset = (
                    session.query(Asset).filter_by(name=target_node.get("name")).first()
                )

                if not source_asset or not target_asset:
                    continue

                # Create attack path record
                attack_path = AttackPath(
                    source_asset_id=source_asset.id,
                    target_asset_id=target_asset.id,
                    attack_steps=(
                        edge.get("attack_technique")
                        if isinstance(edge, dict)
                        else getattr(edge, "attack_technique", None)
                    ),
                    difficulty_score=(
                        float(edge.difficulty_score)
                        if hasattr(edge, "difficulty_score")
                        else 5.0
                    ),
                    time_to_exploit=(
                        edge.time_to_exploit if hasattr(edge, "time_to_exploit") else 0
                    ),
                    success_probability=(
                        float(edge.success_probability)
                        if hasattr(edge, "success_probability")
                        else 0.5
                    ),
                    risk_score=(
                        float(edge.risk_score) if hasattr(edge, "risk_score") else 0.0
                    ),
                    created_at=datetime.now(timezone.utc),
                    threat_actor_profile="equipped",
                )
                session.add(attack_path)

            session.commit()
            self.logger.info(f"✅ Stored {len(ranked_edges)} attack paths to database")
        except Exception as e:
            self.logger.error(f"❌ Error storing attack paths: {str(e)}")
        finally:
            session.close()


# Example usage and testing
if __name__ == "__main__":
    import argparse

    # Parse command line arguments
    parser = argparse.ArgumentParser(description=agent_full_name("threat_model"))
    parser.add_argument(
        "--mode",
        choices=["listen", "demo"],
        default="demo",
        help="Run in listening mode or demo mode (default: demo)",
    )
    args = parser.parse_args()

    # Determine verbose mode: True for demo, False for listen
    verbose = args.mode == "demo"  # demo=True (verbose), listen=False (quiet)

    # Send heartbeat so dashboard shows agent running before initialization
    if args.mode == "listen":
        message_bus.heartbeat("threat_model_001")

    # Initialize agent with verbose flag
    agent = ThreatModelAgent(verbose=verbose)

    # LISTENING MODE - Active threat modeling with message handling
    if args.mode == "listen":
        print("\n" + "=" * 80)
        print("THREAT MODELING AGENT - ACTIVE LISTENING MODE")
        print("=" * 80 + "\n")

        agent.logger.info("Agent initialized and ready")
        agent.logger.info("Subscribed to 'threat_updates' and 'log_uploaded' channels")
        agent.logger.info("Starting continuous threat modeling...")
        agent.logger.info("Press Ctrl+C to exit")
        print("=" * 80 + "\n")

        # Send heartbeat immediately so dashboard shows agent as running
        message_bus.heartbeat(agent.agent_id)

        # Initial threat modeling run
        agent.logger.info("Running initial threat modeling...")

        # Analyze logs to discover system architecture and attack surfaces (no hardcoded data!)
        agent.logger.info(
            "Discovering system architecture and attack surfaces from ingested logs..."
        )
        attack_surfaces = agent.analyze_logs_for_system_architecture()

        # Log detailed attack surface information to file as DEBUG
        agent._log_attack_surfaces_debug(attack_surfaces)

        agent.logger.info("Building attack graph...")
        attack_graph = agent.build_attack_graph(attack_surfaces)

        agent.logger.info("Adding assets and vulnerabilities to databases...")
        asset_data, db_assets, vuln_data, db_vulns = agent._add_assets_and_vulns_db(
            attack_graph
        )
        agent.logger.info("Added %d assets to PostgreSQL", len(db_assets))
        agent.logger.info("Added %d vulnerabilities to PostgreSQL", len(db_vulns))

        # Add sample assets/vulns to Neo4j as well
        for node in attack_graph["nodes"][:3]:
            agent.add_asset_neo4j(node["name"], node["type"])
        for vuln in vuln_data[:3]:
            agent.add_vuln_neo4j("webserver1", vuln["name"])

        agent.logger.info("Generating threat scenarios...")
        scenarios = agent.generate_threat_scenarios(attack_graph)
        agent.logger.info("Generated %d threat scenarios", len(scenarios))

        # Link assets and vulnerabilities in PostgreSQL
        agent.logger.info("Linking assets and vulnerabilities...")
        link_count = agent._link_assets_vulns_db(attack_graph, db_assets, db_vulns)
        agent.logger.info("Created %d asset-vulnerability links", link_count)

        # Add attack edges from attack graph to PostgreSQL
        agent.logger.info("Adding attack edges...")
        edge_count = agent._add_attack_edges_db(attack_graph, db_assets)
        agent.logger.info("Added %d attack edges", edge_count)

        # Add threat scenarios to PostgreSQL
        agent.logger.info("Adding threat scenarios to database...")
        db_scenarios, scenario_count, scenario_asset_count = (
            agent._add_and_link_scenarios_db(scenarios, db_assets)
        )
        agent.logger.info("Added %d threat scenarios", scenario_count)
        agent.logger.info("Created %d scenario-asset links", scenario_asset_count)
        rankedPaths = agent._generate_attack_paths(attack_graph["nodes"])

        # Display ranked attack paths to logs (analysts can review if needed)
        agent.display_attack_paths()

        # Notify other agents
        intelligence_package = {
            "assets": len(asset_data),
            "vulnerabilities": len(vuln_data),
            "attack_paths": len(attack_graph["edges"]),
            "threat_scenarios": len(scenarios),
            "timestamp": datetime.now().isoformat(),
        }

        agent.share_intelligence(intelligence_package)
        agent.logger.info("Shared intelligence package with other agents")
        agent.logger.debug(
            "Intelligence package created at %s", intelligence_package["timestamp"]
        )

        agent.logger.info("✅ Initial threat modeling completed!")
        agent.logger.info("Now monitoring for new logs and threat updates...")

        # Send heartbeat immediately so dashboard shows agent as running
        message_bus.heartbeat(agent.agent_id)

        try:
            heartbeat_counter = 0
            threat_modeling_cycle = 0
            while True:
                time.sleep(1)
                heartbeat_counter += 1

                # Send heartbeat every second to dashboard
                message_bus.heartbeat(agent.agent_id)

                # Scan the log directory for new files every 10 seconds
                if heartbeat_counter % 10 == 0:
                    agent._check_for_new_log_files()

                # Only re-run threat modeling when new logs have been detected
                # (either via dashboard upload → handle_log_uploaded, or new file in folder → _check_for_new_log_files)
                if agent._new_logs_detected:
                    agent._new_logs_detected = False
                    threat_modeling_cycle += 1
                    agent.logger.info(
                        "🔄 New logs detected! Running threat modeling cycle #%d...",
                        threat_modeling_cycle,
                    )

                    # Re-analyze logs for new system components and attack surfaces
                    attack_surfaces = agent.analyze_logs_for_system_architecture()

                    # Log detailed attack surface information to file as DEBUG
                    agent._log_attack_surfaces_debug(attack_surfaces)

                    attack_graph = agent.build_attack_graph(attack_surfaces)

                    # Persist assets and vulnerabilities to database
                    asset_data, db_assets, vuln_data, db_vulns = (
                        agent._add_assets_and_vulns_db(attack_graph)
                    )
                    link_count = agent._link_assets_vulns_db(
                        attack_graph, db_assets, db_vulns
                    )
                    agent.logger.info(
                        "💾 Saved %d assets, %d vulns, %d links to Database",
                        len(db_assets),
                        len(db_vulns),
                        link_count,
                    )

                    scenarios = agent.generate_threat_scenarios(attack_graph)

                    # Persist attack edges and scenarios so Vigilon Warden has up-to-date data
                    edge_count = agent._add_attack_edges_db(attack_graph, db_assets)
                    agent._add_and_link_scenarios_db(scenarios, db_assets)
                    agent.logger.info(
                        "💾 Saved %d attack edges and %d scenarios to database",
                        edge_count,
                        len(scenarios),
                    )

                    # Create updated intelligence package with current cycle data
                    current_intelligence = {
                        "attack_surfaces": attack_surfaces,
                        "attack_graph": attack_graph,
                        "threat_scenarios": scenarios,
                        "assets": (
                            len(attack_graph["nodes"])
                            if attack_graph and "nodes" in attack_graph
                            else 0
                        ),
                        "vulnerabilities": (
                            sum(
                                len(node.get("vulnerabilities", []))
                                for node in attack_graph.get("nodes", [])
                            )
                            if attack_graph
                            else 0
                        ),
                        "attack_paths": (
                            len(attack_graph["edges"])
                            if attack_graph and "edges" in attack_graph
                            else 0
                        ),
                        "scenarios_count": len(scenarios),
                        "cycle": threat_modeling_cycle,
                        "timestamp": datetime.now().isoformat(),
                    }

                    # Share updated intelligence with actual threat data
                    agent.share_intelligence(current_intelligence)

                    agent.logger.info(
                        "✅ Completed cycle #%d — other agents will now process new intel",
                        threat_modeling_cycle,
                    )

        except KeyboardInterrupt:
            agent.logger.info("Shutting down...")
            sys.exit(0)
    else:
        # DEMO MODE - Run full demo
        print("=" * 80)
        print(f"{agent_full_name('threat_model')} - Demo")
        print("=" * 80)

        # Reset Neo4j database for clean demo
        agent.reset_neo4j()

        # Example system configuration
        system_config = {
            "web_apps": [
                {
                    "name": "Customer Portal",
                    "public_facing": True,
                    "input_validation": False,
                    "auth_implemented": True,
                },
                {
                    "name": "Admin Dashboard",
                    "public_facing": False,
                    "input_validation": True,
                    "auth_implemented": True,
                },
            ],
            "apis": [
                {"name": "REST API v1", "public_facing": True, "authenticated": True}
            ],
            "services": [
                {"name": "Database Server", "public_facing": False, "encrypted": True}
            ],
        }

        # Run threat modeling workflow
        agent.logger.info("Loading MITRE ATT&CK techniques...")

        agent.logger.info("Analyzing system architecture...")
        attack_surfaces = agent.analyze_system_architecture(system_config)

        # Log detailed attack surface information for demo console output
        agent._log_attack_surfaces_info(attack_surfaces)

        agent.logger.info("Building attack graph...")
        attack_graph = agent.build_attack_graph(attack_surfaces)
        agent.add_asset_neo4j("webserver1", "WebServer")
        agent.add_vuln_neo4j("webserver1", "SQL Injection")
        agent.logger.info("Attack Graph Summary:")
        agent.logger.info("Added asset and vulnerability to Neo4j database.")
        agent.logger.info(
            "Nodes: %d, Edges: %d",
            len(attack_graph["nodes"]),
            len(attack_graph["edges"]),
        )

        agent.logger.info("Running sample Cypher query to verify Neo4j data...")
        agent.run_cypher_query(
            "MATCH (a:Asset)-[r:HAS_VULNERABILITY]->(v:Vulnerability) RETURN a, r, v"
        )

        agent.logger.info("Adding data to PostgreSQL database...")
        asset_data, db_assets, vuln_data, db_vulns = agent._add_assets_and_vulns_db(
            attack_graph
        )
        agent.logger.info("Added %d assets to PostgreSQL database.", len(db_assets))
        agent.logger.info(
            "Added %d vulnerabilities to PostgreSQL database.", len(db_vulns)
        )

        # Link assets and vulnerabilities in PostgreSQL
        agent.logger.info("Linking assets and vulnerabilities...")
        link_count = agent._link_assets_vulns_db(attack_graph, db_assets, db_vulns)
        agent.logger.info("Created %d asset-vulnerability links", link_count)

        # Add attack edges from attack graph to PostgreSQL
        edge_count = agent._add_attack_edges_db(attack_graph, db_assets)
        agent.logger.info("Added %d attack edges", edge_count)

        agent.logger.info("Generating threat scenarios...")
        scenarios = agent.generate_threat_scenarios(attack_graph)
        for scenario in scenarios:
            agent.logger.debug(
                "Scenario: %s (Likelihood: %s, Impact: %s)",
                scenario["name"],
                scenario.get("likelihood", "unknown"),
                scenario.get("impact", "unknown"),
            )

        # Add threat scenarios to PostgreSQL and link to assets
        agent.logger.info("Adding threat scenarios to database...")
        db_scenarios, scenario_count, scenario_asset_count = (
            agent._add_and_link_scenarios_db(scenarios, db_assets)
        )
        agent.logger.info("Added %d threat scenarios", scenario_count)
        agent.logger.info("Created %d scenario-asset links", scenario_asset_count)

        agent.logger.info("Sharing intelligence package...")
        intel_package = agent.share_intelligence(
            {
                "attack_surfaces": attack_surfaces,
                "attack_graph": attack_graph,
                "scenarios": scenarios,
            }
        )
        agent.logger.debug(
            "Intelligence package created at %s", intel_package["timestamp"]
        )

        # --- Message Bus Demo ---
        print(
            "\nMessage Bus Demo: Publishing test message to 'threat_intelligence' channel..."
        )
        model_message = {
            "type": "threat_model_update",
            "source": agent.agent_id,
            "data": attack_graph,
        }
        message_bus.publish("threat_intelligence", model_message)
        print(
            "Test message published! If the classifier agent is running, it should print the received message."
        )

        print("\n" + "=" * 80)
        print("Demo complete! Agent is operational.")
        print("=" * 80)
