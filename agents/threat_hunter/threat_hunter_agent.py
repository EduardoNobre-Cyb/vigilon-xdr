# Vigilon Sentinel: Threat Hunting
# Identifies and investigates potential threats

import time
from shared.communication.message_bus import message_bus
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple
import logging
from sqlalchemy import select
from shared.logging_config import setup_agent_logger
from shared.agent_names import agent_name, agent_full_name
import pickle
import os
from .threat_intel import ThreatIntelClient
from data.models.models import ExternalIOC, get_session
from opentelemetry import trace, metrics


IOCS = [
    {"type": "ip", "value": "192.168.1.100"},
    {"type": "domain", "value": "malicious.com"},
    {"type": "hash", "value": "e99a18c428cb38d5f260853678922e03"},
    {"type": "process", "value": "mimikatz.exe"},
    {"type": "keyword", "value": "CVE-2023-1234"},
    # Test IOCs that match your sample classified threats
    {"type": "keyword", "value": "CVE-1999-1167"},
    {"type": "keyword", "value": "CVE-2000-1082"},
    {"type": "keyword", "value": "CVE-2000-0817"},
    {"type": "asset", "value": "Customer Portal"},
    {"type": "asset", "value": "Admin Dashboard"},
    {"type": "asset", "value": "REST API v1"},
    {"type": "asset", "value": "Database Server"},
]

# MITRE ATT&CK tactic normalisation mapping
TACTIC_NORMALISER = {
    "ta0001": "Reconnaissance",
    "ta0002": "Initial Access",
    "ta0003": "Execution",
    "ta0004": "Persistence",
    "ta0005": "Privilege Escalation",
    "ta0006": "Defense Evasion",
    "ta0007": "Credential Access",
    "ta0008": "Discovery",
    "ta0009": "Lateral Movement",
    "ta0010": "Collection",
    "ta0011": "Exfiltration",
    "ta0012": "Command and Control",
    "ta0040": "Impact",
    "ta0043": "Reconnaissance",
    "reconnaissance": "Reconnaissance",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "privilege escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "defense evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "credential access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "lateral movement": "Lateral Movement",
    "collection": "Collection",
    "exfiltration": "Exfiltration",
    "command-and-control": "Command and Control",
    "command and control": "Command and Control",
    "impact": "Impact",
}


def normalise_tactic(tactic: str) -> str:
    """Normalize a MITRE tactic string to canonical form."""
    if not tactic:
        return "Unknown"
    t = tactic.strip().lower().replace(" ", "-")
    return TACTIC_NORMALISER.get(t, tactic.title())


class ThreatHunterAgent:
    def __init__(self, agent_id: str = "hunter_001", verbose: bool = True):
        self.agent_id = agent_id
        self.intel_client = ThreatIntelClient()
        self.recent_threats = []  # Stores (timestamp, classification) tuples
        self.correlation_window = 300  # seconds (5 minutes)
        self.anomaly_detector = AnomalyDetector(
            window_size=100, zscore_threshold=2.5, min_samples=5
        )
        self.pattern_matcher = PatternMatcher()
        self.verbose = verbose  # Set to False in listen mode for minimal output
        self.vectorizer = TfidfVectorizer()  # For ML-based correlation
        self.logger = setup_agent_logger(agent_id, verbose)
        # In-memory set of already-processed threat IDs to prevent duplicate handling
        self._processed_threat_ids: set = set()
        self.pattern_model = None
        self.pattern_scaler = None
        self.load_pattern_model()  # Attempt to load trained pattern detection model

        # Fetch and store threat intelligence indicators on startup
        self.logger.info(
            "Fetching threat intelligence indicators from external APIs..."
        )
        try:
            stored = self.intel_client.fetch_and_store_indicators()
            if stored > 0:
                self.logger.info(
                    f"✅ Threat intelligence ready with {stored} indicators"
                )
        except Exception as e:
            self.logger.warning(f"Could not fetch threat intel on startup: {e}")

        # Initialize OpenTelemetry tracing
        self.tracer = trace.get_tracer(self.agent_id)
        self.meter = metrics.get_meter(self.agent_id)
        self.hunt_time = self.meter.create_histogram("hunt_latency_ms")
        self.hunted_threats = self.meter.create_counter("threats_hunted")
        self.correlations_found = self.meter.create_counter("correlations_detected")

    def load_pattern_model(self):
        """Load trained pattern detection model if available"""

        # Try multiple path locations
        possible_paths = [
            os.getenv("PATTERN_MODEL_PATH", "data/models/threat_hunter.pkl"),
            "threat-defense-system/data/models/threat_hunter.pkl",
            os.path.join(
                os.path.dirname(__file__),
                "..",
                "..",
                "data",
                "models",
                "threat_hunter.pkl",
            ),
        ]

        for model_path in possible_paths:
            try:
                if os.path.exists(model_path):
                    with open(model_path, "rb") as f:
                        data = pickle.load(f)
                        self.pattern_model = data.get("model")
                        self.pattern_scaler = data.get("scaler")
                    self.logger.info(
                        f"✓ Loaded pattern detection model from {model_path}"
                    )
                    return
            except Exception as e:
                self.logger.debug(f"Failed to load from {model_path}: {e}")
                continue

        self.logger.warning(
            "Pattern model not found in any location - Using rule-based patterns only."
        )

    def load_model(self, model_path: str) -> None:
        """Hot-reload the pattern detection model from a new path."""

        try:
            self.logger.info(f"🔄 Hot-reloading pattern model from {model_path}")
            if os.path.exists(model_path):
                with open(model_path, "rb") as f:
                    data = pickle.load(f)
                    self.pattern_model = data.get("model")
                    self.pattern_scaler = data.get("scaler")
                self.logger.info("✅ Pattern model reloaded successfully")
            else:
                self.logger.error(f"Model file not found: {model_path}")
                raise FileNotFoundError(f"Model file not found: {model_path}")
        except Exception as e:
            self.logger.error(f"❌ Failed to reload pattern model: {e}")
            # Don't clear the pattern model on failure - keep using the old one
            raise

    def _extract_sequence_features(self, threat_sequence):
        """Extract numeric features from threat sequence for ML prediction"""

        severity_map = {"critical": 10, "high": 7.5, "medium": 5, "low": 2.5}

        num_threats = len(threat_sequence)
        severities = [
            severity_map.get(t.get("severity", "medium").lower(), 5)
            for t in threat_sequence
        ]
        severity_mean = np.mean(severities) if severities else 0
        severity_max = np.max(severities) if severities else 0

        risk_scores = [t.get("risk_score", 5.0) for t in threat_sequence]
        risk_mean = np.mean(risk_scores) if risk_scores else 0
        risk_max = np.max(risk_scores) if risk_scores else 0

        time_deltas = [t.get("time_delta", 0) for t in threat_sequence]
        time_sum = np.sum(time_deltas) if time_deltas else 0
        time_mean = np.mean(time_deltas) if time_deltas else 0

        all_tactics = []
        for threat in threat_sequence:
            all_tactics.extend(threat.get("mitre_tactics", []))
        tactic_diversity = len(set(all_tactics)) / max(len(all_tactics), 1)

        threat_types = [t.get("threat_type") for t in threat_sequence]
        threat_diversity = (
            len(set(threat_types)) / len(threat_types) if threat_types else 0
        )

        features = np.array(
            [
                num_threats,
                severity_mean,
                severity_max,
                risk_mean,
                risk_max,
                time_sum,
                time_mean,
                tactic_diversity,
                threat_diversity,
            ]
        ).reshape(1, -1)

        return features

    def start_listening(self):
        """Subscribe to classified_threats channel.
        Must only be called once from listen mode — never from dashboard endpoints."""
        message_bus.subscribe("classified_threats", self.handle_classified_threat)

    def handle_classified_threat(self, message, print_results=True):
        """Handle individual classified threat: dedup, correlate, hunt, save to DB, publish"""
        with self.tracer.start_as_current_span("handle_classified_threat") as span:
            start = time.time()

            # Support both single and multiple classified threats
            classifications = message.get("classification", {})
        # If it's a dict, wrap in a list for uniform processing
        if isinstance(classifications, dict):
            classifications = [classifications]
        elif not isinstance(classifications, list):
            self.logger.error(f"Invalid classification format: {classifications}")
            return

        for classification in classifications:
            # Skip threats already processed in this session (dedup guard)
            threat_id = classification.get("id")
            if threat_id and threat_id in self._processed_threat_ids:
                continue
            if threat_id:
                self._processed_threat_ids.add(threat_id)
            now = time.time()
            self.recent_threats.append((now, classification))

            # Prune old threats
            self.recent_threats = [
                (ts, threat)
                for ts, threat in self.recent_threats
                if now - ts <= self.correlation_window
            ]

            correlated_events = []
            for ts, past_threat in self.recent_threats:
                # Skip if its the same object (just added)
                if past_threat is classification:
                    continue
                if classification.get("asset_name") == past_threat.get(
                    "asset_name"
                ) or classification.get("vulnerability_name") == past_threat.get(
                    "vulnerability_name"
                ):
                    correlated_events.append(past_threat)

            texts = [self.get_threat_text(classification)] + [
                self.get_threat_text(t)
                for _, t in self.recent_threats
                if t is not classification
            ]
            if len(texts) > 1:
                tfidf = self.vectorizer.fit_transform(texts)
                similarities = cosine_similarity(tfidf[0:1], tfidf[1:]).flatten()
                ml_correlated = [
                    t
                    for (sim, (_, t)) in zip(similarities, self.recent_threats)
                    if sim > 0.5 and t is not classification
                ]
            else:
                ml_correlated = []

            threat_type = classification.get("threat_type", "unknown")
            severity = classification.get("severity", "unknown")
            mitre = classification.get("mitre_tactics", [])
            risk_score = classification.get("risk_score", 0)
            prediction_confidence = classification.get("prediction_confidence")

            self.logger.debug(f"Received classified threat: {classification}")

            # Call match_iocs to find matching IOCs
            ioc_matches = self.match_iocs(classification)

            # External threat intel matching
            external_ioc_matches = self.intel_client.hunt_with_external_iocs(
                classification
            )
            if external_ioc_matches:
                self.logger.warning(
                    f"🔗 External IOC matches found: {len(external_ioc_matches)}"
                )
                for match in external_ioc_matches:
                    self.logger.warning(
                        f"  - {match.get('type', 'unknown')}: {match['ioc']} "
                        f"(Actor: {match.get('threat_actor', 'Unknown')}) "
                        f"(Source: {match.get('source', 'unknown')})"
                    )
                # Merge external IOCs with existing matches
                ioc_matches.extend(external_ioc_matches)
            else:
                self.logger.debug(f"  No external IOC matches for this threat")

            # Identifying threat actor if IOCs found
            if external_ioc_matches:
                all_iocs = [m["ioc"] for m in external_ioc_matches]
                threat_actors = self.intel_client.identify_threat_actor(all_iocs)
                if threat_actors:
                    self.logger.info(
                        "🎭 Potential threat actors identified: "
                        + ", ".join(threat_actors)
                    )
                    classification["identified_actors"] = threat_actors

            hunting_result = {
                "threat_id": classification.get("id"),
                "threat_type": threat_type,
                "asset_name": classification.get("asset_name", "Unknown"),
                "vulnerability_name": classification.get(
                    "vulnerability_name", "Unknown"
                ),
                "ioc_matches": ioc_matches,  # List of matching IOCs
                "threat_level": severity,
                "mitre_tactics": mitre,
                "risk_score": risk_score,
                "ensemble_confidence": prediction_confidence,  # Include confidence from Vigilon Triage
                "details": f"Hunting for {threat_type} threats with severity {severity} and risk score {risk_score}",
                "correlated_events": correlated_events,
                "ml_correlated_events": ml_correlated,
            }
            if self.verbose:
                self.logger.debug(f"[DEMO] Hunting result to {agent_name('response')}: {hunting_result}")
            else:
                self.logger.debug(
                    f" ✅ Hunted threat | Type: {threat_type}"
                    f" | Severity: {severity} | IOCs: {len(ioc_matches)}"
                    f" | Correlated: {len(correlated_events)}"
                )
            self.publish_hunting_results(hunting_result)

            # Save individual hunting result to database
            threat_id = classification.get("id")
            if threat_id:
                self._save_single_hunting_result(threat_id, hunting_result)

    def _save_single_hunting_result(self, threat_id: int, hunting_result: Dict) -> None:
        """Save a single hunting result to database (used in listen mode per-threat processing)"""
        from data.models.models import get_session, HuntingResult

        session = get_session()
        try:
            ioc_matches = hunting_result.get("ioc_matches", [])
            correlated = hunting_result.get("correlated_events", [])
            ml_correlated = hunting_result.get("ml_correlated_events", [])

            hunting_record = HuntingResult(
                threat_id=threat_id,
                ioc_matches=ioc_matches,
                ioc_match_count=len(ioc_matches),
                entity_correlations=correlated,
                ml_correlations=ml_correlated,
                anomaly_detected=False,
                anomaly_score=0.0,
                patterns_detected=[],
                hunting_confidence=(
                    len(ioc_matches) * 0.2
                    + len(correlated) * 0.3
                    + len(ml_correlated) * 0.3
                ),
                agent_id=self.agent_id,
            )

            session.add(hunting_record)
            session.commit()
            self.logger.debug(
                f"Saved hunting result for threat #{threat_id} to database"
            )

        except Exception as e:
            session.rollback()
            self.logger.error(f"ERROR saving hunting result: {e}")
        finally:
            session.close()

    def publish_hunting_results(self, results):
        # Publish hunting results to other agents
        message_bus.publish(
            "hunting_results",
            {"type": "hunting_result", "agent": self.agent_id, "results": results},
        )

    def save_hunting_results_to_database(self, hunting_results: Dict) -> None:
        """Save hunting results to database for persistence and audit trail"""
        from data.models.models import get_session, HuntingResult

        session = get_session()
        try:
            # Save each threat's hunting result
            for threat in hunting_results.get("threats", []):
                threat_id = threat.get("threat_id")

                hunting_record = HuntingResult(
                    threat_id=threat_id,
                    ioc_matches=threat.get("ioc_matches", []),
                    ioc_match_count=len(threat.get("ioc_matches", [])),
                    entity_correlations=threat.get("entity_correlations", []),
                    ml_correlations=threat.get("ml_correlations", []),
                    anomaly_detected=threat.get("anomaly_detected", False),
                    anomaly_score=threat.get("anomaly_score", 0.0),
                    patterns_detected=hunting_results.get("patterns_detected", []),
                    hunting_confidence=(
                        len(threat.get("ioc_matches", [])) * 0.2
                        + len(threat.get("entity_correlations", [])) * 0.3
                        + len(threat.get("ml_correlations", [])) * 0.3
                        + (0.2 if threat.get("anomaly_detected") else 0)
                    ),
                    agent_id=self.agent_id,
                )

                session.add(hunting_record)

            session.commit()
            self.logger.debug(
                f"Saved {len(hunting_results.get('threats', []))} hunting results to database"
            )

        except Exception as e:
            session.rollback()
            self.logger.error(f"saving hunting results: {e}")
        finally:
            session.close()

    @staticmethod
    def match_iocs(classification):
        # Checks if any IOC matches the threat classification.
        # Returns a list of matches IOCs (can be empty).
        matches = []
        # Combine all relevant fields into a single string for matching
        threat_text = " ".join(
            [
                str(classification.get("threat_type", "")),
                str(classification.get("severity", "")),
                str(classification.get("mitre_tactics", "")),
                str(classification.get("risk_score", "")),
                str(classification.get("details", "")),
                str(classification.get("asset_name", "")),
                str(classification.get("vulnerability_name", "")),
            ]
        ).lower()
        for ioc in IOCS:
            if ioc["value"].lower() in threat_text:
                matches.append(ioc)
        return matches

    # Helper function to vectorize threat text for comparisson
    @staticmethod
    def get_threat_text(threat):
        return " ".join(
            [
                str(threat.get("threat_type", "")),
                str(threat.get("severity", "")),
                str(threat.get("mitre_tactics", "")),
                str(threat.get("risk_score", "")),
                str(threat.get("details", "")),
                str(threat.get("asset_name", "")),
                str(threat.get("vulnerability_name", "")),
            ]
        )

    def correlate_by_entity(self, threat):
        """Correlate threats by entity (asset, user, IP, etc.)"""
        correlations = []

        # Look for similar threats affecting the same asset
        asset_name = threat.get("asset_name", "")
        if asset_name:
            correlations.append(
                {
                    "type": "asset_correlation",
                    "entity": asset_name,
                    "description": f"Threat affects asset: {asset_name}",
                    "confidence": 0.8,
                }
            )

        # Look for IP-based correlations
        threat_text = self.get_threat_text(threat).lower()
        if "192.168." in threat_text or "10.0." in threat_text or "172." in threat_text:
            correlations.append(
                {
                    "type": "network_correlation",
                    "entity": "internal_network",
                    "description": "Internal network threat detected",
                    "confidence": 0.7,
                }
            )

        return correlations

    def correlate_by_ml(self, threat):
        """Use ML-based correlation techniques"""
        correlations = []

        # Simple ML-based correlation using threat characteristics
        severity = threat.get("severity", "").lower()
        risk_score = threat.get("risk_score", 0)

        # High-risk correlation
        if severity in ["critical", "high"] or risk_score > 7.0:
            correlations.append(
                {
                    "type": "risk_correlation",
                    "ml_confidence": 0.85,
                    "description": f"High-risk threat: {severity} severity, score {risk_score}",
                    "threat_cluster": "high_priority",
                }
            )

        # MITRE tactic correlation
        mitre_tactics = threat.get("mitre_tactics", [])
        if mitre_tactics:
            correlations.append(
                {
                    "type": "mitre_correlation",
                    "ml_confidence": 0.75,
                    "description": f"MITRE tactics detected: {mitre_tactics}",
                    "threat_cluster": "mitre_mapped",
                }
            )

        return correlations

    def hunt_threats(self, classified_threats: List[Dict]) -> Dict:
        """
        Enhanced threat hunting with anomaly detection and pattern matching.
        """
        with self.tracer.start_as_current_span("hunt_threats") as span:
            span.set_attribute("threat_count", len(classified_threats))
            start = time.time()

            hunting_results = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "threats_analyzed": len(classified_threats),
                "threats": [],
                "anomalies_detected": [],
                "patterns_detected": [],
                "ml_detected_patterns": [],
            }

            # Pre-warm anomaly detector with full batch
            for threat in classified_threats:
                pre_sev = self._severity_to_numeric(threat.get("severity", "Medium"))
                pre_risk = float(threat.get("risk_score", 5.0))
                self.anomaly_detector.add_threat(pre_sev, pre_risk)

            for threat in classified_threats:
                # Extract threat data
                threat_id = threat.get("id")
                threat_type = threat.get("threat_type")
                severity = threat.get("severity", "Medium")
                risk_score = threat.get("risk_score", 5.0)
                mitre_tactics = threat.get("mitre_tactics", [])

                self.logger.debug(
                    "Hunting threat #%s | Type: %s | Severity: %s | Risk: %.2f",
                    threat_id,
                    threat_type,
                    severity,
                    risk_score,
                )

                # Convert severity string to numeric
                severity_score = self._severity_to_numeric(severity)

                # Traditional hunting (IOC matching + correlation)
                ioc_matches = self.match_iocs(threat)
                entity_correlations = self.correlate_by_entity(threat)
                ml_correlations = self.correlate_by_ml(threat)

                self.logger.debug(
                    "  IOC matches: %d | Entity correlations: %d | ML correlations: %d",
                    len(ioc_matches),
                    len(entity_correlations),
                    len(ml_correlations),
                )

                # Anomaly detection
                self.anomaly_detector.add_threat(severity_score, risk_score)
                anomaly_result = self.anomaly_detector.detect_anomalies(
                    severity_score=severity_score,
                    risk_score=risk_score,
                    threat_count_increase=len(
                        classified_threats
                    ),  # How many threats came in batch
                )

                if anomaly_result["is_anomalous"]:
                    self.logger.debug(
                        "  ⚠️  Anomaly detected (score: %.2f) — %s",
                        anomaly_result["anomaly_score"],
                        "; ".join(anomaly_result.get("reasons", [])),
                    )
                    hunting_results["anomalies_detected"].append(
                        {
                            "threat_id": threat_id,
                            "threat_type": threat_type,
                            "anomaly_score": anomaly_result["anomaly_score"],
                            "reasons": anomaly_result["reasons"],
                            "details": anomaly_result["details"],
                        }
                    )

                self.pattern_matcher.add_threat_to_sequence(
                    threat_type=threat_type,
                    severity=severity_score,
                    mitre_tactics=mitre_tactics,
                    threat_id=threat_id,
                )

                # Compile threat hunting record
                threat_record = {
                    "threat_id": threat_id,
                    "threat_type": threat_type,
                    "severity": severity,
                    "risk_score": risk_score,
                    "mitre_tactics": mitre_tactics,
                    "ioc_matches": ioc_matches,
                    "entity_correlations": entity_correlations,
                    "ml_correlations": ml_correlations,
                    "anomaly_detected": anomaly_result["is_anomalous"],
                    "anomaly_score": anomaly_result["anomaly_score"],
                }

                hunting_results["threats"].append(threat_record)

            # Check for surge of critical threats in batch
            critical_in_batch = sum(
                1
                for t in classified_threats
                if self._severity_to_numeric(t.get("severity", "Medium")) >= 9.0
            )
            if critical_in_batch >= self.anomaly_detector.min_samples:
                surge_score = round(
                    min(0.5 + critical_in_batch / (len(classified_threats) * 2), 0.95),
                    2,
                )
                hunting_results["anomalies_detected"].append(
                    {
                        "threat_id": None,
                        "threat_type": "Threat Surge",
                        "anomaly_score": surge_score,
                        "reasons": [
                            f"Surge of {critical_in_batch} critical-severity threats in a single batch",
                            f"{critical_in_batch}/{len(classified_threats)} threats rated Critical — sustained high-severity activity",
                        ],
                        "details": {
                            "critical_count": critical_in_batch,
                            "total_batch": len(classified_threats),
                            "baseline_available": True,
                        },
                    }
                )

            # ML-based pattern detection (if model available) - runs once per hunt batch
            if (
                self.pattern_model
                and self.pattern_scaler
                and len(classified_threats) >= 2
            ):
                try:
                    # Get recent threats as sequence
                    recent_threats = [
                        {
                            "threat_type": t.get("threat_type"),
                            "severity": t.get("severity"),
                            "mitre_tactics": t.get("mitre_tactics", []),
                            "risk_score": t.get("risk_score", 5.0),
                            "time_delta": 0,
                        }
                        for t in classified_threats[-10:]
                    ]

                    if len(recent_threats) >= 2:
                        features = self._extract_sequence_features(recent_threats)
                        features_scaled = self.pattern_scaler.transform(features)
                        is_pattern = self.pattern_model.predict(features_scaled)[0]
                        pattern_confidence = np.max(
                            self.pattern_model.predict_proba(features_scaled)
                        )

                        if is_pattern and pattern_confidence >= 0.65:
                            # Build detailed description with actual threat data
                            threat_types = [
                                t.get("threat_type", "Unknown") for t in recent_threats
                            ]
                            threat_types_unique = ", ".join(dict.fromkeys(threat_types))

                            severities = [
                                t.get("severity", "Unknown") for t in recent_threats
                            ]
                            avg_severity = sum(s == "Critical" for s in severities)

                            all_tactics = []
                            for t in recent_threats:
                                all_tactics.extend(t.get("mitre_tactics", []))
                            tactics_str = (
                                ", ".join(list(set(all_tactics))[:3])
                                if all_tactics
                                else "Unknown"
                            )

                            avg_risk = (
                                sum(t.get("risk_score", 0) for t in recent_threats)
                                / len(recent_threats)
                                if recent_threats
                                else 0
                            )

                            detailed_description = (
                                f"Coordinated attack sequence ({len(recent_threats)} threats): {threat_types_unique}. "
                                f"Severity distribution: {', '.join(severities)}. "
                                f"MITRE tactics: {tactics_str}. "
                                f"Average risk score: {avg_risk:.1f}/10. "
                                f"ML confidence: {pattern_confidence:.1%}"
                            )

                            hunting_results["ml_detected_patterns"].append(
                                {
                                    "pattern": "Coordinated Attack Sequence",
                                    "description": detailed_description,
                                    "confidence": float(pattern_confidence),
                                }
                            )
                            self.logger.debug(
                                "  🎯 ML pattern detected with confidence %.2f: %s",
                                pattern_confidence,
                                detailed_description,
                            )
                except Exception as e:
                    self.logger.error(f"Pattern detection failed: {e}", exc_info=True)

            self.logger.debug(
                "Hunt complete | Threats: %d | Anomalies: %d | Patterns: %d",
                len(hunting_results["threats"]),
                len(hunting_results["anomalies_detected"]),
                len(hunting_results["ml_detected_patterns"]),
            )

            latency_ms = (time.time() - start) * 1000
            self.hunt_time.record(latency_ms)
            self.hunted_threats.add(len(classified_threats))

            return hunting_results

    @staticmethod
    def _severity_to_numeric(severity: str) -> float:
        """Convert severity string to numeric score (0-10)."""
        severity_map = {
            "Critical": 10.0,
            "High": 8.0,
            "Medium": 5.0,
            "Low": 2.0,
            "Info": 1.0,
        }
        return severity_map.get(severity, 5.0)


class AnomalyDetector:
    """Detects anomalous threat behaviour using statistical analysis."""

    def __init__(
        self,
        window_size: int = 100,  # How many threats to analyze
        zscore_threshold: float = 2.5,  # How far from normal it is
        min_samples: int = 5,
    ):

        self.window_size = window_size
        self.zscore_threshold = zscore_threshold
        self.min_samples = min_samples

        # Store recent threat data (severity_score, risk_score, threat_count_per_hour)
        self.threat_history = deque(maxlen=window_size)
        self.hourly_threat_counts = deque(maxlen=24)  # Track threats per hour
        self.last_hour = datetime.now(timezone.utc).replace(
            minute=0, second=0, microsecond=0
        )
        self.current_hour_count = 0

    def add_threat(self, severity_score: float, risk_score: float) -> None:
        # Add a threat to history for baseline calculation

        self.threat_history.append(
            {
                "severity": severity_score,
                "risk": risk_score,
                "timestamp": datetime.now(timezone.utc),
            }
        )

        # Track threats per hour
        now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        if now != self.last_hour:
            self.hourly_threat_counts.append(self.current_hour_count)
            self.current_hour_count = 0
            self.last_hour = now
        self.current_hour_count += 1

    def calculate_baseline_stats(self) -> Dict[str, float]:
        # Calculate baseline statistics from threat history
        if len(self.threat_history) < self.min_samples:
            return None  # Not enough data yet

        severities = [t["severity"] for t in self.threat_history]
        risks = [t["risk"] for t in self.threat_history]

        return {
            "severity_mean": float(np.mean(severities)),
            "severity_std": float(np.std(severities)),
            "severity_q75": float(np.percentile(severities, 75)),
            "risk_mean": float(np.mean(risks)),
            "risk_std": float(np.std(risks)),
            "threat_frequency_mean": float(
                np.mean(self.hourly_threat_counts) if self.hourly_threat_counts else 0
            ),
            "threat_frequency_std": float(
                np.std(self.hourly_threat_counts)
                if len(self.hourly_threat_counts) > 1
                else 0
            ),
        }

    def warmup_from_db(self, limit: int = 100) -> int:
        """Seed threat_history from existing ThreatClassification data"""

        session = get_session()
        try:
            rows = (
                session.query(ThreatClassification)
                .order_by(ThreatClassification.id.desc())
                .limit(limit)
                .all()
            )
            for row in rows:
                severity_numeric = {
                    "critical": 10.0,
                    "high": 7.5,
                    "medium": 5.0,
                    "low": 2.5,
                }.get((row.severity or "medium").lower(), 5.0)
                self.threat_history.appendleft(
                    {
                        "severity": severity_numeric,
                        "risk": float(row.risk_score or 5.0),
                        "timestamp": row.timestamp or datetime.now(timezone.utc),
                    }
                )
            return len(rows)
        except Exception as e:
            print(f"[AnomalyDetector] Error warming up from DB: {e}")
            return 0
        finally:
            session.close()

    def detect_anomalies(
        self, severity_score: float, risk_score: float, threat_count_increase: int = 0
    ) -> Dict[str, any]:
        # Detect if threat is anomalous
        baseline = self.calculate_baseline_stats()
        if baseline is None:
            # Insufficient baseline — wait for more samples
            return {
                "is_anomalous": False,
                "anomaly_score": 0.0,
                "reasons": ["Insufficient baseline data — waiting for more samples"],
                "details": {
                    "severity_score": severity_score,
                    "risk_score": risk_score,
                    "baseline_available": False,
                },
            }
        anomalies = []
        anomaly_scores = []

        # Check 1: Severity Anomaly
        if baseline["severity_std"] > 0:
            severity_zscore = abs(
                (severity_score - baseline["severity_mean"]) / baseline["severity_std"]
            )
            if severity_zscore > self.zscore_threshold:
                anomalies.append(
                    f"High severity anomaly (Z-score: {severity_zscore:.2f})"
                )
                anomaly_scores.append(min(severity_zscore / 5, 1.0))  # Normalize to 0-1

        # Check 2: Risk Score Anomaly
        if baseline["risk_std"] > 0:
            risk_zscore = abs(
                (risk_score - baseline["risk_mean"]) / baseline["risk_std"]
            )
            if risk_zscore > self.zscore_threshold:
                anomalies.append(
                    f"Unusual risk score anomaly (Z-score: {risk_zscore:.2f})"
                )
                anomaly_scores.append(min(risk_zscore / 5, 1.0))

        # Check 3: Threat Frequency Spike
        if baseline["threat_frequency_std"] > 0 and threat_count_increase > 0:
            freq_zscore = abs(
                (threat_count_increase - baseline["threat_frequency_mean"])
                / (baseline["threat_frequency_std"] + 0.1)
            )
            if freq_zscore > self.zscore_threshold:
                anomalies.append(f"Threat frequency spike (Z-score: {freq_zscore:.2f})")
                anomaly_scores.append(min(freq_zscore / 5, 1.0))

        # Calculate overall anomaly score (average of all anomalies)
        overall_score = float(np.mean(anomaly_scores)) if anomaly_scores else 0.0

        return {
            "is_anomalous": len(anomalies) > 0,
            "anomaly_score": float(overall_score),
            "reasons": anomalies,
            "details": {
                "severity_zscore": float(
                    abs(
                        (severity_score - baseline["severity_mean"])
                        / (baseline["severity_std"] + 1e-6)
                    )
                ),
                "risk_zscore": float(
                    abs(
                        (risk_score - baseline["risk_mean"])
                        / (baseline["risk_std"] + 1e-6)
                    )
                ),
                "baseline_severity_mean": float(baseline["severity_mean"]),
                "baseline_risk_mean": float(baseline["risk_mean"]),
                "baseline_threat_frequency": float(baseline["threat_frequency_mean"]),
            },
        }


class PatternMatcher:
    """Detects multi-stage attack patterns and threat sequences."""

    # Known attack chain patterns (MITRE ATT&CK based)
    ATTACK_PATTERNS = {
        "network_recon_to_exploit": {
            "description": "Network reconnaissance followed by exploitation",
            "sequence": ["Reconnaissance", "Initial Access", "Execution"],
            "window_minutes": 60,
            "severity_threshold": 6,  # Pattern only matters if total severity > 6
        },
        "vulnerability_exploitation_campaign": {
            "description": "Multiple vulnerability exploitations indicating coordinated attack",
            "sequence": [
                "Vulnerability Exploitation",
                "Vulnerability Exploitation",
                "Vulnerability Exploitation",
            ],
            "window_minutes": 30,
            "severity_threshold": 15,  # Lower threshold for vuln campaigns
        },
        "injection_attack_campaign": {
            "description": "Multiple injection attacks indicating coordinated campaign",
            "sequence": [
                "Injection Attack",
                "Injection Attack",
                "Injection Attack",
            ],
            "window_minutes": 60,
            "severity_threshold": 12,  # Matches current threat types
        },
        "xss_attack_campaign": {
            "description": "Cross-site scripting attack campaign targeting web applications",
            "sequence": [
                "Cross-Site Scripting",
                "Cross-Site Scripting",
                "Cross-Site Scripting",
            ],
            "window_minutes": 45,
            "severity_threshold": 10,  # 6 medium threats = 6*5 = 30, so 3 threats = 15
        },
        "denial_of_service_attack": {
            "description": "Denial of Service attack targeting availability",
            "sequence": [
                "Denial of Service",
                "Denial of Service",
            ],
            "window_minutes": 30,
            "severity_threshold": 12,  # 2 high = 2*8 = 16, threshold 12
        },
        "web_infrastructure_assault": {
            "description": "Coordinated attack targeting web infrastructure components",
            "sequence": [
                "Web Application Attack",
                "Web Server Attack",
                "Infrastructure Attack",
            ],
            "window_minutes": 90,
            "severity_threshold": 18,  # Mix of critical/high threats
        },
        "initial_access_to_execution": {
            "description": "Exploit delivery leading to code execution on target",
            "sequence": ["Initial Access", "Execution"],
            "window_minutes": 30,
            "severity_threshold": 7,
        },
        "reconnaissance_to_exploit": {
            "description": "Active reconnaissance immediately preceding exploitation",
            "sequence": ["Reconnaissance", "Initial Access", "Execution"],
            "window_minutes": 60,
            "severity_threshold": 6,
        },
        "defense_evasion_then_impact": {
            "description": "Defense evasion followed by destructive or disruptive impact",
            "sequence": ["Defense Evasion", "Impact"],
            "window_minutes": 60,
            "severity_threshold": 8,
        },
        "credential_attack_chain": {
            "description": "Credential theft followed by account compromise",
            "sequence": ["Credential Access", "Lateral Movement", "Persistence"],
            "window_minutes": 120,
            "severity_threshold": 5,
        },
        "data_exfiltration_chain": {
            "description": "Data discovery followed by exfiltration attempt",
            "sequence": ["Discovery", "Collection", "Exfiltration"],
            "window_minutes": 90,
            "severity_threshold": 7,
        },
        "privilege_escalation_chain": {
            "description": "Initial access followed by privilege escalation and persistence",
            "sequence": ["Initial Access", "Privilege Escalation", "Persistence"],
            "window_minutes": 180,
            "severity_threshold": 5,
        },
    }

    def __init__(self):
        self.threat_sequence_buffer = (
            deque()
        )  # Store (timestamp, threat_type, severity, mitre_tactics)
        self.detected_patterns = []  # Store detected patterns for reporting

    def add_threat_to_sequence(
        self,
        threat_type: str,
        severity: float,
        mitre_tactics: List[str],
        threat_id: int,
    ) -> None:
        # Add a threat to the sequence buffer for pattern matching
        self.threat_sequence_buffer.append(
            {
                "timestamp": datetime.now(timezone.utc),
                "threat_type": threat_type,
                "severity": severity,
                "mitre_tactics": mitre_tactics,
                "threat_id": threat_id,
            }
        )

    @staticmethod
    def extract_primary_tactic(mitre_tactics: List[str]) -> str:
        # Extract primary MITRE tactic from list.
        # Maps threat activities to MITRE tactics

        if not mitre_tactics:
            return "Unknown"

        # Return first/primary tactic
        return mitre_tactics[0] if isinstance(mitre_tactics[0], str) else "Unknown"

    def match_pattern(self, pattern_name: str) -> List[Dict]:
        # CHeck if a specific attack pattern is occuring
        # Returns: List of matches pattern occurences with details

        pattern = self.ATTACK_PATTERNS.get(pattern_name)
        if not pattern:
            return []

        matches = []
        sequence = pattern["sequence"]
        window_minutes = pattern["window_minutes"]
        severity_threshold = pattern["severity_threshold"]

        # Clean old threats outside the time window
        cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        while (
            self.threat_sequence_buffer
            and self.threat_sequence_buffer[0]["timestamp"] < cutoff_time
        ):
            self.threat_sequence_buffer.popleft()

        # Try to find the pattern in our buffer
        buffer_list = list(self.threat_sequence_buffer)

        for i in range(len(buffer_list) - len(sequence) + 1):
            # Ceck if next N threats match the pattern sequence
            potential_match = buffer_list[i : i + len(sequence)]

            # Extract primary tactic from each threat OR use threat type/severity for special patterns
            threat_characteristics = []
            for t in potential_match:
                if pattern_name in [
                    "vulnerability_exploitation_campaign",
                    "injection_attack_campaign",
                    "xss_attack_campaign",
                    "denial_of_service_attack",
                ]:
                    # For threat-type-based campaigns, look at threat type
                    threat_characteristics.append(str(t.get("threat_type", "Unknown")))
                elif pattern_name in ["web_infrastructure_assault"]:
                    # For infrastructure attacks, categorize by threat type
                    threat_type = str(t.get("threat_type", "Unknown"))
                    if (
                        "Cross-Site Scripting" in threat_type
                        or "Injection" in threat_type
                    ):
                        threat_characteristics.append("Web Application Attack")
                    elif (
                        "Apache" in threat_type
                        or "Nginx" in threat_type
                        or "Web Server" in threat_type
                    ):
                        threat_characteristics.append("Web Server Attack")
                    else:
                        threat_characteristics.append("Infrastructure Attack")
                elif pattern_name in ["critical_service_compromise"]:
                    # For service-based patterns, categorize by service
                    threat_type = str(t.get("threat_type", "Unknown"))
                    if t.get("severity", 0) >= 9.0:  # Critical threats only
                        threat_characteristics.append("Critical Service")
                    else:
                        threat_characteristics.append("Non-Critical Service")
                elif pattern_name in [
                    "credential_attack_chain",
                    "data_exfiltration_chain",
                    "privilege_escalation_chain",
                    "initial_access_to_execution",
                    "reconnaissance_to_exploit",
                    "defense_evasion_then_impact",
                ]:
                    # For tactic-based patterns, extract and normalize the primary MITRE tactic
                    tactic = self.extract_primary_tactic(t.get("mitre_tactics", []))
                    tactic_normalized = normalise_tactic(str(tactic))
                    threat_characteristics.append(tactic_normalized)
                else:
                    # Default behavior: use MITRE tactics
                    tactic = self.extract_primary_tactic(t["mitre_tactics"])
                    threat_characteristics.append(str(tactic))

            # Check if characteristics match sequence (fuzzy match - allow some variation)
            if self._fuzzy_match_sequence(threat_characteristics, sequence):
                # Check total severity
                total_severity = sum(t["severity"] for t in potential_match)

                if total_severity >= severity_threshold:
                    matches.append(
                        {
                            "pattern": pattern_name,
                            "description": pattern["description"],
                            "matched_threats": [
                                t["threat_id"] for t in potential_match
                            ],
                            "threat_types": [t["threat_type"] for t in potential_match],
                            "characteristics_sequence": threat_characteristics,
                            "time_span_minutes": (
                                potential_match[-1]["timestamp"]
                                - potential_match[0]["timestamp"]
                            ).total_seconds()
                            / 60,
                            "total_severity": total_severity,
                            "confidence": self._calculate_pattern_confidence(
                                threat_characteristics, sequence
                            ),
                        }
                    )
        return matches

    @staticmethod
    def _fuzzy_match_sequence(observed: List[str], expected: List[str]) -> bool:
        # Fuzzy match observed tactic sequence against expected pattern.
        # Allows for clsoe matches (e.g., "Lateral Movement" vs "lateral_movement")

        if len(observed) != len(expected):
            return False

        for obs, exp in zip(observed, expected):
            # Normalize and compare
            obs_normalized = obs.lower().replace(" ", "_").replace("-", "_")
            exp_normalized = exp.lower().replace(" ", "_").replace("-", "_")

            # Exact match or partial match (first 10 chars)
            if not (
                obs_normalized == exp_normalized
                or obs_normalized.startswith(exp_normalized[:10])
            ):
                return False

        return True

    @staticmethod
    def _calculate_pattern_confidence(
        observed: List[str], expected: List[str]
    ) -> float:
        # Calculate confidence score (0-1) for pattern match.
        # Higher score = better match between observed and expected.

        if not observed or not expected:
            return 0.0

        matches = 0
        for obs, exp in zip(observed, expected):
            obs_normalized = obs.lower().replace(" ", "_").replace("-", "_")
            exp_normalized = exp.lower().replace(" ", "_").replace("-", "_")
            if obs_normalized == exp_normalized:
                matches += 1

        return matches / len(expected)

    def detect_all_patterns(self) -> List[Dict]:
        # Run all pattern matching algorithms and return all detected patterns.

        all_matches = []

        for pattern_name in self.ATTACK_PATTERNS.keys():
            matches = self.match_pattern(pattern_name)
            all_matches.extend(matches)

        return all_matches


if __name__ == "__main__":
    import argparse
    import sys

    # Parse command line arguments
    parser = argparse.ArgumentParser(description=agent_full_name("threat_hunter"))
    parser.add_argument(
        "--mode",
        choices=["listen", "demo"],
        default="demo",
        help="Run in listening mode or demo mode (default: demo)",
    )
    args = parser.parse_args()

    verbose = args.mode == "demo"

    agent = ThreatHunterAgent(verbose=verbose)

    if args.mode == "demo":
        # DEMO MODE - Hunt threats from Vigilon Triage's classifications
        print("=" * 80)
        print(f"{agent_full_name('threat_hunter')} - Demo Mode")
        print("=" * 80)

        agent.logger.debug("Initialized successfully")
        agent.logger.debug(
            f"Running threat hunting on classified threats from {agent_name('classifier')}..."
        )

        print("\n" + "=" * 80)
        print("DEMO: Threat Hunting Workflow")
        print("=" * 80)

        # Get real classified threats from database
        from data.models.models import (
            get_session,
            ThreatClassification,
            Asset,
            Vulnerability,
        )

        session = get_session()
        classified_threats = session.query(ThreatClassification).limit(5).all()

        threat_count = len(classified_threats)
        agent.logger.info(f"Hunting {threat_count} classified threats from database...")

        if threat_count == 0:
            agent.logger.info(f"No classified threats in database.")
        else:
            # Convert ORM objects to dictionaries for processing (resolve asset/vuln names)
            threats_data = []
            for t in classified_threats:
                asset = (
                    session.query(Asset).filter_by(id=t.asset_id).first()
                    if t.asset_id
                    else None
                )
                vuln = (
                    session.query(Vulnerability)
                    .filter_by(id=t.vulnerability_id)
                    .first()
                    if t.vulnerability_id
                    else None
                )
                threats_data.append(
                    {
                        "id": t.id,
                        "threat_type": t.threat_type,
                        "severity": t.severity,
                        "risk_score": t.risk_score,
                        "mitre_tactics": t.mitre_tactic,
                        "asset_name": asset.name if asset else "Unknown",
                        "vulnerability_name": vuln.name if vuln else "Unknown",
                        "details": f"Threat classification for {t.threat_type}",
                    }
                )
            session.close()

            # Run threat hunting
            hunting_results = agent.hunt_threats(threats_data)

            # Save hunting results to database
            agent.save_hunting_results_to_database(hunting_results)

            # Publish to message bus for Vigilon Warden
            agent.publish_hunting_results(hunting_results)

            # Display results
            agent.logger.debug("\n[HUNTING RESULTS]")
            for i, threat in enumerate(hunting_results.get("threats", []), 1):
                agent.logger.debug(
                    f" [{i}] Threat: {threat.get('threat_type')} ({threat.get('severity')})"
                )
                agent.logger.debug(
                    f"      Risk Score: {threat.get('risk_score'):.2f}/10"
                )
                agent.logger.debug(
                    f"      ✓ IOC Matches: {len(threat.get('ioc_matches', []))}"
                )
                agent.logger.debug(
                    f"      ✓ Entity Correlations: {len(threat.get('entity_correlations', []))}"
                )
                agent.logger.debug(
                    f"      ✓ ML Correlations: {len(threat.get('ml_correlations', []))}"
                )
                agent.logger.debug(
                    f"      ✓ Anomaly Detected: {threat.get('anomaly_detected', False)}"
                )
                if threat.get("anomaly_detected"):
                    agent.logger.debug(
                        f"      ✓ Anomaly Score: {threat.get('anomaly_score', 0):.2f}/10"
                    )

            print("\n" + "=" * 80)
            agent.logger.debug("[HUNTING SUMMARY]")
            agent.logger.debug(
                f"  ✓ Threats Hunted: {hunting_results.get('threats_analyzed', 0)}"
            )
            agent.logger.debug(
                f"  ✓ Anomalies Found: {len(hunting_results.get('anomalies_detected', []))}"
            )
            agent.logger.debug(
                f"  ✓ Patterns Detected: {len(hunting_results.get('patterns_detected', []))}"
            )
            agent.logger.debug(f"  ✓ Results Saved to Database")
            agent.logger.debug(f"  ✓ Results Published to Message Bus for {agent_name('response')}")
            print("\n" + "=" * 80)
            print("Demo complete!")
            print("=" * 80)

    else:
        # LISTEN MODE - Continuous operation
        agent.verbose = False  # Minimal output in listen mode
        print("=" * 80)
        print(f"{agent_full_name('threat_hunter')} - Listen Mode")
        print("=" * 80)
        agent.logger.info("Initialized and ready")
        agent.logger.debug("Press Ctrl+C to exit")
        print("=" * 80 + "\n")

        # Send heartbeat immediately so dashboard shows agent as running
        message_bus.heartbeat(agent.agent_id)

        # Initial hunting run on existing classified threats
        from data.models.models import (
            get_session,
            ThreatClassification,
            Asset,
            Vulnerability,
        )

        agent.logger.info("Running initial hunt on existing classified threats...")
        session = get_session()
        # Only hunt threats that don't already have a HuntingResult (watermark)
        from data.models.models import HuntingResult as HuntingResultModel

        # Pre-populate the in-memory dedup set with all already-hunted IDs so
        # the subscription thread won't re-process them when Redis messages arrive
        existing_hunted_ids = session.query(HuntingResultModel.threat_id).all()
        agent._processed_threat_ids = {row[0] for row in existing_hunted_ids}

        already_hunted = select(HuntingResultModel.threat_id)
        classified_threats = (
            session.query(ThreatClassification)
            .filter(~ThreatClassification.id.in_(already_hunted))
            .order_by(ThreatClassification.id.asc())
            .limit(20)
            .all()
        )

        if classified_threats:
            threats_data = []
            for t in classified_threats:
                asset = (
                    session.query(Asset).filter_by(id=t.asset_id).first()
                    if t.asset_id
                    else None
                )
                vuln = (
                    session.query(Vulnerability)
                    .filter_by(id=t.vulnerability_id)
                    .first()
                    if t.vulnerability_id
                    else None
                )
                threats_data.append(
                    {
                        "id": t.id,
                        "threat_type": t.threat_type,
                        "severity": t.severity,
                        "risk_score": t.risk_score,
                        "mitre_tactics": t.mitre_tactic,
                        "asset_name": asset.name if asset else "Unknown",
                        "vulnerability_name": vuln.name if vuln else "Unknown",
                        "details": f"Threat classification for {t.threat_type}",
                    }
                )
            # Mark these IDs as processed before saving so subscription thread
            # won't double-process them if a Redis message arrives during the hunt
            for t in classified_threats:
                agent._processed_threat_ids.add(t.id)
            session.close()

            hunting_results = agent.hunt_threats(threats_data)
            agent.save_hunting_results_to_database(hunting_results)
            # Publish hunted threats to channel for Vigilon Warden
            for threat_input, threat_record in zip(
                threats_data, hunting_results.get("threats", [])
            ):
                agent.publish_hunting_results(
                    {
                        "threat_id": threat_record["threat_id"],
                        "threat_type": threat_record["threat_type"],
                        "asset_name": threat_input.get("asset_name", "Unknown"),
                        "vulnerability_name": threat_input.get(
                            "vulnerability_name", "Unknown"
                        ),
                        "ioc_matches": threat_record.get("ioc_matches", []),
                        "threat_level": threat_record.get("severity"),
                        "mitre_tactics": threat_record.get("mitre_tactics", []),
                        "risk_score": threat_record.get("risk_score"),
                        "correlated_events": threat_record.get(
                            "entity_correlations", []
                        ),
                        "ml_correlated_events": threat_record.get(
                            "ml_correlations", []
                        ),
                        "anomaly_detected": threat_record.get(
                            "anomaly_detected", False
                        ),
                        "anomaly_score": threat_record.get("anomaly_score", 0.0),
                        "details": threat_input.get("details", ""),
                    }
                )
            agent.logger.info(
                f"✅ Initial hunt complete: {len(threats_data)} threats saved to DB"
            )
        else:
            session.close()
            agent.logger.info(f"No classified threats yet. Waiting for {agent_name('classifier')}...")

        # Subscribe after initial hunt completes to prevent duplicates
        agent.start_listening()
        agent.logger.info(f"Subscribed to 'classified_threats' channel from {agent_name('classifier')}")

        # Send heartbeat immediately so dashboard shows agent as running
        message_bus.heartbeat(agent.agent_id)

        # Warm up anomaly detector baseline with existing data
        loaded = agent.anomaly_detector.warmup_from_db(limit=200)
        agent.logger.info(
            f"Anomaly detector warmup complete with {loaded} historical threats"
        )

        try:
            while True:
                time.sleep(1)
                message_bus.heartbeat(agent.agent_id)

        except KeyboardInterrupt:
            agent.logger.debug("Shutting down...")
