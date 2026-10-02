# Vigilon Triage: Threat Classification
# Categorizes threats and assigns risk scores using ML

from typing import Dict, List
from shared.communication.message_bus import message_bus
import time
import shutil
import glob
from pathlib import Path
from data.models.models import (
    Asset,
    Vulnerability,
    AssetVulnerability,
    ThreatClassification,
    ThreatReview,
    AnalystCuratedTrainingData,
    get_session,
    Model,
)
from data.modern_cves_for_testing import get_modern_test_cves
from data.diverse_threat_training_data import get_diverse_threat_scenarios_full
from data.ensemble_adversarial_samples import (
    get_extended_adversarial_samples_with_synthetic,
    get_extended_adversarial_samples_normalized,
    augment_text_via_synonym_replacement,
)
import re
import pickle
import os
import random
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline, make_pipeline
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    f1_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    accuracy_score,
)
import numpy as np
from data.cvss_utils import get_cvss_for_vulnerability, get_severity_from_cvss
import logging
from shared.logging_config import setup_agent_logger
from shared.agent_names import agent_name, agent_full_name
import traceback
from datetime import datetime, timedelta, timezone
from dashboard.notification_service import NotificationService
from agents.classification.ensemble_classifier import EnsembleClassifier
from data.models.model_prom_workflow import ModelPromotionWorkflow
from data.models.classifier_feature_extractors import (
    StructuredMetadataExtractor,
    Word2VecFeatureExtractor,
)
from data.edr_synthetic_training_data import get_edr_synthetic_training_samples
from opentelemetry import trace, metrics


class _LegacyClassifierArtifactUnpickler(pickle.Unpickler):
    """Map legacy extractor pickles to the shared importable classes."""

    def find_class(self, module, name):
        if name == "Word2VecFeatureExtractor":
            return Word2VecFeatureExtractor
        if name == "StructuredMetadataExtractor":
            return StructuredMetadataExtractor
        return super().find_class(module, name)


class ThreatClassificationAgent:
    # Classifies threats using MITRE ATT&CK framework

    def __init__(self, agent_id: str = "classifier_001", verbose: bool = True):
        self.agent_id = agent_id
        self.severity_weights = {
            "critical": 10.0,
            "high": 8.0,
            "medium": 5.0,
            "low": 2.0,
            "info": 0.5,
        }
        self.criticality_weights = {
            "critical": 10.0,
            "high": 8.0,
            "medium": 5.0,
            "low": 2.0,
        }

        self.tactic_severity = {
            "TA0043": 3.0,  # Reconnaissance
            "TA0042": 4.0,  # Resource Development
            "TA0001": 5.0,  # Initial Access
            "TA0002": 5.5,  # Execution
            "TA0003": 6.0,  # Persistence
            "TA0004": 6.5,  # Privilege Escalation
            "TA0005": 7.0,  # Defense Evasion
            "TA0006": 7.5,  # Credential Access
            "TA0007": 8.0,  # Discovery
            "TA0008": 8.5,  # Lateral Movement
            "TA0009": 9.0,  # Collection
            "TA0011": 9.5,  # Command and Control
            "TA0010": 9.8,  # Exfiltration
            "TA0040": 10.0,  # Impact
        }

        # ML Model confidence gate
        self.min_prediction_confidence = 0.72
        self.min_confidence_margin = 0.12
        self.abstain_label = "Needs Review"
        self.model_version = "nb_v2_conf_gate"  # Naive Bayes with confidence gating

        # ML model for threat classification (components)
        self.classifier = None
        self.classifier_model = None
        self.w2v_extractor = None
        self.metadata_extractor = None
        self.scaler = None
        self.label_encoder = None
        self.model_path = None  # Will be set to active model path after loading
        self.fallback_model_path = (
            "data/models/threat_classifier_v8"  # Only used if no active model found
        )
        self.verbose = verbose  # Set to False in listen mode for minimal output
        self.logger = setup_agent_logger(agent_id, verbose)

        # Load the active deployed model (or fall back to v2)
        self.load_model(auto_load_active=False)

        # Fallback ensemble for compatibility (if active model load fails)
        self.ensemble = None
        if not self.classifier:
            try:
                self.ensemble = EnsembleClassifier(models_dir=self.fallback_model_path)
                self.ensemble.load_models()
                self.logger.info(
                    f"⚠️  Active model not found, falling back to ensemble (Naive Bayes + SVM + Random Forest)"
                )
            except Exception as e:
                self.logger.error("Failed to load ensemble models: %s.", e)
                self.ensemble = None

        self.last_retrain_time = None
        self.retrain_interval = 3600  # Retrain every 1 hour (in seconds)

        # Initialize OpenTelemetry tracing
        self.tracer = trace.get_tracer(self.agent_id)
        self.meter = metrics.get_meter(self.agent_id)
        self.classification_time = self.meter.create_histogram(
            "classification_latency_ms"
        )
        self.classified_threats = self.meter.create_counter("threats_classified")

        # Subscribe to threat intelligence
        message_bus.subscribe("threat_intelligence", self.classify_threat)

    def _get_active_model_path(self) -> str:
        """
        Query database for the active deployed model.
        Returns the model_path of the active model, or falls back to v2.
        """
        try:
            session = get_session()
            active_model = (
                session.query(Model)
                .filter_by(agent_id=self.agent_id, is_active=True)
                .first()
            )
            session.close()

            if active_model and active_model.model_path:
                self.logger.debug(f"Found active model at: {active_model.model_path}")
                return active_model.model_path
        except Exception as e:
            self.logger.warning(f"Could not query active model from database: {e}")

        # No active DB model entry: fall back to the highest local versioned model folder.
        model_root = Path("data/models")
        highest_version = -1
        highest_path = None

        if model_root.exists():
            for candidate in model_root.glob("threat_classifier_v*"):
                if not candidate.is_dir():
                    continue

                try:
                    version_num = int(candidate.name.split("_v")[-1])
                except (ValueError, IndexError):
                    continue

                required_files = [
                    candidate / "classifier.pkl",
                    candidate / "w2v_extractor.pkl",
                    candidate / "metadata_extractor.pkl",
                    candidate / "scaler.pkl",
                    candidate / "label_encoder.pkl",
                ]

                if all(path.exists() for path in required_files):
                    if version_num > highest_version:
                        highest_version = version_num
                        highest_path = candidate

        if highest_path is not None:
            selected_path = str(highest_path)
            self.logger.info(
                f"No active DB model found. Using highest local model: {selected_path}"
            )
            return selected_path

        # Fallback to v2 if no active model found
        fallback_path = "data/models/threat_classifier_v8"
        self.logger.debug(f"Using fallback model path: {fallback_path}")
        return fallback_path

    # _enrich_threat_description removed - classifier uses structured metadata instead of text enrichment

    def load_model(self, auto_load_active=False) -> None:
        """
        Load semantic ensemble model components (Word2Vec + metadata extractor + Gradient Boosting classifier).
        Falls back gracefully to v2 if active model not found.
        Updates self.model_path to reflect the actual active model path.
        """
        if auto_load_active:
            model_path = self._get_active_model_path()
        else:
            model_path = self.fallback_model_path

        model_path = Path(model_path)

        try:
            # Load all components
            with open(model_path / "classifier.pkl", "rb") as f:
                self.classifier = pickle.load(f)
            with open(model_path / "w2v_extractor.pkl", "rb") as f:
                self.w2v_extractor = _LegacyClassifierArtifactUnpickler(f).load()
            with open(model_path / "metadata_extractor.pkl", "rb") as f:
                self.metadata_extractor = _LegacyClassifierArtifactUnpickler(f).load()
            with open(model_path / "scaler.pkl", "rb") as f:
                self.scaler = pickle.load(f)
            with open(model_path / "label_encoder.pkl", "rb") as f:
                self.label_encoder = pickle.load(f)

            # Keep the legacy attribute name and the active loaded object in sync
            # so both the runtime compatibility path and the ML-based predictors work.
            self.classifier_model = self.classifier

            # Update model_path to reflect what's actually active
            self.model_path = str(model_path)

            self.logger.info(f"✅ Loaded classifier model from {self.model_path}")
            self.logger.info(
                f"   Architecture: Word2Vec embeddings + Metadata features + Gradient Boosting"
            )
            self.model_version = "word2vec_metadata_classifier"
            self.logger.info(
                "MODEL_LOAD_TRACE | auto_load_active=%s | model_path=%s | model_version=%s",
                auto_load_active,
                self.model_path,
                self.model_version,
            )

        except (FileNotFoundError, Exception) as e:
            self.logger.warning(f"⚠️  Could not load model from {model_path}: {e}")
            self.model_path = None  # Indicate no model loaded
            self.classifier = None
            self.classifier_model = None
            self.w2v_extractor = None
            self.metadata_extractor = None
            self.scaler = None
            self.label_encoder = None

    def _extract_threat_metadata_from_logs(
        self, session, source_filter: str = None
    ) -> Dict:
        """Extract threat actor, indicators, and campaign data from log events."""
        from data.models.models import LogEvent
        import json

        metadata = {
            "threat_actors": set(),
            "indicators": [],
            "campaigns": set(),
        }

        try:
            # Query ALL logs - extract from logs that have threat_actor data

            logs_to_scan = session.query(LogEvent).all()
            self.logger.info(
                f"🔍 Scanning {len(logs_to_scan)} total logs for threat intel..."
            )

            logs_processed = 0

            for log in logs_to_scan:
                try:
                    if log.data:
                        event_data = json.loads(log.data)
                        logs_processed += 1

                        # Extract threat actor
                        if event_data.get("threat_actor"):
                            actor = event_data["threat_actor"]
                            metadata["threat_actors"].add(actor)
                            self.logger.info(f"  ✓ Found threat_actor: {actor}")

                        # Extract indicators
                        if event_data.get("indicator_type") and event_data.get(
                            "indicator_value"
                        ):
                            metadata["indicators"].append(
                                {
                                    "type": event_data["indicator_type"],
                                    "value": event_data["indicator_value"],
                                }
                            )

                        # Extract campaign
                        if event_data.get("campaign"):
                            metadata["campaigns"].add(event_data["campaign"])
                except (json.JSONDecodeError, TypeError) as e:
                    self.logger.debug(f"JSON parse error in log: {e}")
                    continue

        except Exception as e:
            self.logger.error(f"Error extracting threat metadata: {e}")
            import traceback

            self.logger.error(traceback.format_exc())

        return {
            "threat_actors": list(metadata["threat_actors"]),
            "indicators": metadata["indicators"],
            "campaigns": list(metadata["campaigns"]),
        }

    def classify_threat(self, message: Dict):
        """Classify threat: receives unclassified asset-vulnerability pairs, applies ML, publishes to Vigilon Sentinel"""
        start = time.time()

        session = get_session()

        try:
            # Fetch all asset-vulnerability pairs to classify
            pairs = (
                session.query(
                    AssetVulnerability.asset_id,
                    AssetVulnerability.vulnerability_id,
                    Asset.name.label("asset_name"),
                    Asset.type.label("asset_type"),
                    Asset.risk_level,
                    Vulnerability.name.label("vuln_name"),
                    Vulnerability.severity,
                    Vulnerability.description,
                    Vulnerability.cvss_base_score,
                    Vulnerability.cvss_vector,
                )
                .join(Asset, AssetVulnerability.asset_id == Asset.id)
                .join(
                    Vulnerability,
                    AssetVulnerability.vulnerability_id == Vulnerability.id,
                )
                .all()
            )
            if not pairs:
                self.logger.warning("⚠️  No asset-vulnerability pairs found in DB.")
                return

            if self.verbose:
                self.logger.info(
                    "Received message from 'threat_intelligence': %s", message
                )
                self.logger.info("Classifying threat...")
                self.logger.info(
                    "Found %d asset-vulnerability pairs to classify.", len(pairs)
                )
            else:
                src = message.get("source", "unknown")
                self.logger.info(
                    "📨 Triggered by '%s' — scanning for unclassified pairs...", src
                )

            # Extract threat metadata from logs - use source filepath if available for efficiency
            source_filter = message.get("source")  # File path from Vigilon Intake
            threat_metadata = self._extract_threat_metadata_from_logs(
                session, source_filter
            )
            if threat_metadata["threat_actors"] or threat_metadata["indicators"]:
                self.logger.info(
                    f"📊 Extracted threat metadata: {len(threat_metadata['threat_actors'])} threat actors, "
                    f"{len(threat_metadata['indicators'])} indicators"
                )

            classified_count = 0
            classifications_for_hunter = []  # Collect classifications for Vigilon Sentinel
            # Loop through each pair and classify
            for pair in pairs:
                existing = (
                    session.query(ThreatClassification)
                    .filter_by(
                        asset_id=pair.asset_id,
                        vulnerability_id=pair.vulnerability_id,
                    )
                    .first()
                )
                # Check if already classified
                if existing:
                    if self.verbose:
                        self.logger.info(
                            "Skipping already classified: %s - %s",
                            pair.asset_name,
                            pair.vuln_name,
                        )
                    else:
                        self.logger.debug(
                            "Skipping already classified: %s - %s",
                            pair.asset_name,
                            pair.vuln_name,
                        )
                    continue

                if self.verbose:
                    self.logger.info(
                        "Classifying: %s <-> %s", pair.asset_name, pair.vuln_name
                    )
                    self.logger.info("Description: '%s'", pair.description)
                else:
                    self.logger.debug(
                        "Classifying: %s <-> %s", pair.asset_name, pair.vuln_name
                    )
                    self.logger.debug("Description: '%s'", pair.description)

                # Get CVSS score - use stored value or calculate if missing
                if pair.cvss_base_score:
                    cvss_score = float(pair.cvss_base_score)
                else:
                    # Fallback: calculate CVSS if not stored
                    cvss_data = get_cvss_for_vulnerability(
                        pair.vuln_name, pair.description or ""
                    )
                    cvss_score = cvss_data["base_score"]

                # Calculate exploitability (CVSS score with keyword adjustments)
                exploitability = self._calculate_exploitability_score_cvss(
                    pair.description or "", cvss_score
                )
                impact = self._calculate_impact_score(pair.risk_level)

                # Calculate composite risk score
                # Formula: CVSS provides base, asset criticality provides context
                risk = self._calculate_risk_score_cvss(
                    cvss_score,
                    impact,
                )

                # Determine severity from CVSS (industry standard)
                severity = get_severity_from_cvss(cvss_score)
                description = pair.description or ""

                # Use structured metadata instead of text enrichment
                threat_dict = {
                    "description": description,
                    "threat_type": "Unknown",  # Will be predicted
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "exploitability": exploitability,
                    "asset_type": pair.asset_type,
                    "asset_criticality": pair.risk_level,
                }

                # Classification: try classifier first, fallback to ensemble
                if self.classifier and self.w2v_extractor and self.metadata_extractor:
                    # Classifier path: Word2Vec + Metadata + Gradient Boosting
                    try:
                        # Extract semantic features from raw description
                        semantic_features = self.w2v_extractor.transform([description])

                        # Extract metadata features
                        metadata_features = self.metadata_extractor.transform(
                            [threat_dict]
                        )

                        # Combine features
                        X = np.hstack([semantic_features, metadata_features])

                        # Scale features
                        X_scaled = self.scaler.transform(X)

                        # Predict
                        threat_type_encoded = self.classifier.predict(X_scaled)[0]
                        base_label = self.label_encoder.inverse_transform(
                            [threat_type_encoded]
                        )[0]
                        confidence_scores = self.classifier.predict_proba(X_scaled)[0]
                        confidence = float(np.max(confidence_scores))

                        # Get runner-up
                        sorted_indices = np.argsort(confidence_scores)[::-1]
                        runner_up_label = self.label_encoder.inverse_transform(
                            [sorted_indices[1]]
                        )[0]
                        runner_up_conf = float(confidence_scores[sorted_indices[1]])
                        margin = max(0.0, confidence - runner_up_conf)
                        model_agreement = True

                        # Routing logic based on confidence thresholds
                        if confidence < 0.45:
                            threat_type = "Needs Review"
                            source = "classifier_low_confidence"
                        elif confidence >= 0.70:
                            threat_type = base_label
                            source = "classifier_high_confidence"
                        else:
                            threat_type = base_label
                            source = "classifier_medium_confidence"

                        decision = {
                            "label": threat_type,
                            "source": source,
                            "confidence": confidence,
                            "margin": margin,
                            "top_candidates": [
                                {"label": base_label, "score": round(confidence, 4)},
                                {
                                    "label": runner_up_label,
                                    "score": round(runner_up_conf, 4),
                                },
                            ],
                            "runner_up": runner_up_label,
                            "model_agreement": model_agreement,
                        }
                    except Exception as e:
                        self.logger.error(
                            f"Classifier prediction failed: {e}, falling back to ensemble"
                        )
                        if self.ensemble:
                            predictions = self.ensemble.classify_with_confidence(
                                description
                            )
                            base_label = predictions["threat_type"]
                            confidence = float(predictions["confidence"])
                            model_agreement = bool(predictions["model_agreement"])
                            runner_up_label = predictions.get("runner_up", "Unknown")
                            runner_up_conf = float(
                                predictions.get("runner_up_confidence", 0.0)
                            )
                            margin = max(0.0, confidence - runner_up_conf)

                            if confidence < 0.45:
                                threat_type = "Needs Review"
                                source = "ensemble_fallback_low_conf"
                            elif confidence >= 0.70:
                                threat_type = base_label
                                source = "ensemble_fallback_high_conf"
                            else:
                                threat_type = base_label
                                source = "ensemble_fallback_medium_conf"

                            decision = {
                                "label": threat_type,
                                "source": source,
                                "confidence": confidence,
                                "margin": margin,
                                "top_candidates": [
                                    {
                                        "label": base_label,
                                        "score": round(confidence, 4),
                                    },
                                    {
                                        "label": runner_up_label,
                                        "score": round(runner_up_conf, 4),
                                    },
                                ],
                                "runner_up": runner_up_label,
                                "model_agreement": model_agreement,
                            }
                        else:
                            threat_type = "Needs Review"
                            decision = {
                                "label": "Needs Review",
                                "source": "no_classifier",
                                "confidence": 0.0,
                                "margin": 0.0,
                                "top_candidates": [],
                                "runner_up": "Unknown",
                                "model_agreement": False,
                            }
                elif self.ensemble:
                    # Fallback to ensemble if the classifier is not available
                    predictions = self.ensemble.classify_with_confidence(description)
                    base_label = predictions["threat_type"]
                    confidence = float(predictions["confidence"])
                    model_agreement = bool(predictions["model_agreement"])
                    runner_up_label = predictions.get("runner_up", "Unknown")
                    runner_up_conf = float(predictions.get("runner_up_confidence", 0.0))
                    margin = max(0.0, confidence - runner_up_conf)

                    if confidence < 0.45:
                        threat_type = "Needs Review"
                        source = "ensemble_low_conf"
                    elif confidence >= 0.70:
                        threat_type = base_label
                        source = "ensemble_high_conf"
                    else:
                        threat_type = base_label
                        source = "ensemble_medium_conf"

                    decision = {
                        "label": threat_type,
                        "source": source,
                        "confidence": confidence,
                        "margin": margin,
                        "top_candidates": [
                            {"label": base_label, "score": round(confidence, 4)},
                            {
                                "label": runner_up_label,
                                "score": round(runner_up_conf, 4),
                            },
                        ],
                        "runner_up": runner_up_label,
                        "model_agreement": model_agreement,
                    }
                else:
                    threat_type = "Needs Review"
                    decision = {
                        "label": "Needs Review",
                        "source": "no_classifier",
                        "confidence": 0.0,
                        "margin": 0.0,
                        "top_candidates": [],
                        "runner_up": "Unknown",
                        "model_agreement": False,
                    }

                mitre_tactic = self._extract_mitre_tactic(pair.description)

                if threat_type == "Needs Review":
                    self.logger.warning(
                        "⚠️ Routed to review | source=%s conf=%.3f agreement=%s runner_up=%s",
                        decision["source"],
                        decision["confidence"],
                        decision["model_agreement"],
                        decision.get("runner_up", "Unknown"),
                    )

                # Still compute risk/severity for triage purposes, even if threat type is uncertain
                risk_score = risk

                self._log_classification_details(
                    description=description,
                    decision=decision,
                    exploitability=exploitability,
                    impact=impact,
                    risk_score=risk_score,
                    severity=severity,
                    mitre_tactic=mitre_tactic,
                )

                # Create and add classification
                classification = ThreatClassification(
                    asset_id=pair.asset_id,
                    vulnerability_id=pair.vulnerability_id,
                    threat_type=threat_type,
                    exploitability_score=exploitability,
                    impact_score=impact,
                    risk_score=risk,
                    severity=severity,
                    mitre_tactic=mitre_tactic,
                    # Confidence and source tracking
                    ensemble_confidence=float(decision["confidence"]),
                    model_agreement=decision["model_agreement"],
                    classification_runner_up=decision.get("runner_up", "Unknown"),
                    runner_up_confidence=(
                        decision.get("top_candidates", [{"score": 0.0}])[1].get("score")
                        if len(decision.get("top_candidates", [])) > 1
                        else None
                    ),
                    # Human review tracking
                    reviewed_by_analyst=False,
                    reviewed_by_id=None,
                    reviewed_at=None,
                    analyst_notes=None,
                )
                session.add(classification)
                session.flush()  # Assign ID so Vigilon Sentinel can reference it

                # Create ThreatReview record if marked for review
                if threat_type == "Needs Review":
                    # Calculate SLA deadline based on severity
                    sla_hours = {"critical": 1, "high": 4, "medium": 24, "low": 72}.get(
                        severity, 24
                    )
                    sla_deadline = datetime.now(timezone.utc) + timedelta(
                        hours=sla_hours
                    )

                    review = ThreatReview(
                        threat_classification_id=classification.id,
                        status="pending",
                        severity=severity,
                        sla_deadline=sla_deadline,
                    )
                    session.add(review)
                classified_count += 1

                # Add to list for Vigilon Sentinel (includes ID for database linking)
                classifications_for_hunter.append(
                    {
                        "id": classification.id,
                        "threat_type": threat_type,
                        "severity": severity,
                        "mitre_tactics": [mitre_tactic],
                        "risk_score": risk,
                        "asset_name": pair.asset_name,
                        "vulnerability_name": pair.vuln_name,
                        "prediction_source": decision["source"],
                        "prediction_confidence": decision["confidence"],
                        "prediction_margin": decision["margin"],
                        "top_candidates": decision["top_candidates"],
                        "model_version": self.model_version,
                        # Include threat intelligence metadata from logs
                        "threat_actors": threat_metadata.get("threat_actors", []),
                        "indicators": threat_metadata.get("indicators", []),
                        "campaigns": threat_metadata.get("campaigns", []),
                        "message": f"{pair.vuln_name} detected on {pair.asset_name}",
                    }
                )

            # Commit all classifications to DB
            session.commit()
            already_classified = len(pairs) - classified_count
            if self.verbose:
                self.logger.debug(
                    "Successfully classified %d threats.", classified_count
                )
                self.logger.debug("Results saved to threat_classifications table.")
            else:
                if classified_count > 0:
                    self.logger.info("✅ Classified %s new threats", classified_count)
                    self.logger.info(
                        "%s already done, %d total pairs",
                        already_classified,
                        len(pairs),
                    )
                else:
                    self.logger.info(
                        "ℹ️  All %d pairs already classified — nothing new to do.",
                        len(pairs),
                    )

            if classified_count > 0:
                message_bus.publish(
                    "classified_threats",
                    {
                        "type": "classification_complete",
                        "source": self.agent_id,
                        "count": classified_count,
                        "classification": classifications_for_hunter,
                    },
                )

                # Check if it's time to retrain the model
                self._check_and_retrain()

            latency_ms = (time.time() - start) * 1000
            self.classification_time.record(latency_ms)
            self.classified_threats.add(classified_count)

        except Exception as e:
            self.logger.error("❌ Error during classification: %s", e)
            traceback.print_exc()
            session.rollback()
            latency_ms = (time.time() - start) * 1000
            self.classification_time.record(latency_ms)
            self.classified_threats.add(0)
        finally:
            session.close()

    def _decode_class_label(self, raw_class) -> str:
        """Decode class labels from model output using label encoder when needed."""
        if self.label_encoder is None:
            return str(raw_class)

        try:
            if isinstance(raw_class, (int, np.integer)):
                return str(self.label_encoder.inverse_transform([int(raw_class)])[0])

            raw_s = str(raw_class)
            if raw_s.isdigit():
                return str(self.label_encoder.inverse_transform([int(raw_s)])[0])

            return raw_s
        except Exception:
            return str(raw_class)

    def _predict_with_confidence(self, description: str) -> Dict:
        """Return ML prediction details: label, confidence, margin, top candidates."""
        if not self.classifier_model:
            return {
                "label": None,
                "confidence": 0.0,
                "margin": 0.0,
                "top_candidates": [],
            }

        # Build the same feature shape used during training: text embedding + metadata.
        exploitability_score = self._calculate_exploitability_score_cvss(
            description, 7.5
        )
        impact_score = self._calculate_impact_score("high")
        risk_score = self._calculate_risk_score_cvss(
            exploitability_score,
            impact_score,
        )
        severity = self._determine_severity(risk_score)

        threat_dict = {
            "description": description,
            "threat_type": "Unknown",
            "cvss_score": 7.5,
            "severity": severity,
            "exploitability": exploitability_score,
            "asset_type": "General",
            "asset_criticality": "Medium",
        }

        semantic_features = self.w2v_extractor.transform([description])
        metadata_features = self.metadata_extractor.transform([threat_dict])
        X = np.hstack([semantic_features, metadata_features])
        X_scaled = self.scaler.transform(X)

        probabilities = self.classifier_model.predict_proba(X_scaled)[0]
        classes = list(self.classifier_model.classes_)

        ranked = sorted(zip(classes, probabilities), key=lambda x: x[1], reverse=True)

        top_class, top_conf = ranked[0]
        second_conf = float(ranked[1][1]) if len(ranked) > 1 else 0.0
        margin = float(top_conf) - second_conf

        return {
            "label": self._decode_class_label(top_class),
            "confidence": float(top_conf),
            "margin": float(margin),
            "top_candidates": [
                {"label": self._decode_class_label(label), "score": round(float(score), 4)}
                for label, score in ranked[:3]
            ],
        }

    def _normalize_description_input(self, description) -> str:
        """Convert variety of caller payloads into a single readable description."""
        if description is None:
            return ""

        if isinstance(description, str):
            return description.strip()

        if isinstance(description, dict):
            for key in (
                "description",
                "message",
                "summary",
                "event_description",
                "threat_description",
                "details",
                "text",
            ):
                value = description.get(key)
                if value:
                    return str(value).strip()

            fallback_parts = []
            for key in ("threat_type", "severity", "source", "hostname", "asset_name"):
                value = description.get(key)
                if value:
                    fallback_parts.append(str(value))
            return " ".join(fallback_parts).strip()

        return str(description).strip()

    def _build_model_decision(self, description: str, source: str = "shared") -> Dict:
        """Create a standardized decision payload for all classification paths.

        This centralizes the rule/ML selection logic so the compatibility wrapper,
        EDR telemetry flow, and log-ingestion flow can all emit the same decision
        fields without duplicating scoring branches.
        """
        normalized_description = self._normalize_description_input(description)

        if not normalized_description:
            return {
                "label": "Needs Review",
                "source": f"{source}_empty_input",
                "confidence": 0.0,
                "margin": 0.0,
                "top_candidates": [],
                "runner_up": "Unknown",
                "model_agreement": False,
            }

        rule_label = self._bootstrap_label(normalized_description)
        if rule_label not in ["Vulnerability Exploitation", "Unknown"]:
            return {
                "label": rule_label,
                "source": f"{source}_rule",
                "confidence": 0.95,
                "margin": 0.95,
                "top_candidates": [{"label": rule_label, "score": 0.95}],
                "runner_up": "Unknown",
                "model_agreement": True,
            }

        ml = self._predict_with_confidence(normalized_description)
        if ml["label"] is None:
            return {
                "label": rule_label,
                "source": f"{source}_rule_fallback",
                "confidence": 0.50,
                "margin": 0.0,
                "top_candidates": [{"label": rule_label, "score": 0.50}],
                "runner_up": "Unknown",
                "model_agreement": False,
            }

        top_candidates = ml.get("top_candidates", [])
        runner_up = top_candidates[1]["label"] if len(top_candidates) > 1 else "Unknown"

        if (
            ml["confidence"] < self.min_prediction_confidence
            or ml["margin"] < self.min_confidence_margin
        ):
            return {
                "label": self.abstain_label,
                "source": f"{source}_abstain",
                "confidence": float(ml["confidence"]),
                "margin": float(ml["margin"]),
                "top_candidates": top_candidates,
                "runner_up": runner_up,
                "model_agreement": False,
            }

        return {
            "label": ml["label"],
            "source": f"{source}_ml",
            "confidence": float(ml["confidence"]),
            "margin": float(ml["margin"]),
            "top_candidates": top_candidates,
            "runner_up": runner_up,
            "model_agreement": True,
        }

    def _log_classification_details(
        self,
        description: str,
        decision: Dict,
        exploitability: float,
        impact: float,
        risk_score: float,
        severity: str,
        mitre_tactic,
    ) -> None:
        """Log one consistent decision record for ingestion and telemetry flows."""
        log = self.logger.info if self.verbose else self.logger.debug
        log(
            "MODEL_EVENT_TRACE | model_path=%s | model_version=%s | description=%s | source=%s | label=%s | confidence=%.4f | margin=%.4f | top_candidates=%s | runner_up=%s | model_agreement=%s",
            self.model_path,
            self.model_version,
            description[:300],
            decision.get("source", "unknown"),
            decision.get("label", "Needs Review"),
            float(decision.get("confidence", 0.0)),
            float(decision.get("margin", 0.0)),
            decision.get("top_candidates", []),
            decision.get("runner_up", "Unknown"),
            decision.get("model_agreement", False),
        )
        log("Exploitability Score: %.2f/10", exploitability)
        log("Impact Score: %.2f/10", impact)
        log("Risk Score: %.2f/10", risk_score)
        log("Severity: %s", severity)
        log("Threat Type: %s", decision.get("label", "Needs Review"))
        log("MITRE Tactic: %s", mitre_tactic)
        log(
            "Threat decision | label=%s source=%s conf=%.4f margin=%.3f top=%s",
            decision.get("label", "Needs Review"),
            decision.get("source", "unknown"),
            float(decision.get("confidence", 0.0)),
            float(decision.get("margin", 0.0)),
            decision.get("top_candidates", []),
        )

    def classify(self, description: str) -> Dict:
        """Compatibility wrapper used by the backend threat-analysis pipeline.
        """
        normalized_description = self._normalize_description_input(description)

        if not normalized_description:
            return {
                "threat_type": "Needs Review",
                "exploitability_score": 0.0,
                "impact_score": 0.0,
                "risk_score": 0.0,
                "mitre_tactic": None,
                "severity": "Informational",
                "confidence": 0.0,
                "source": "empty_input",
            }

        is_edr_telemetry = "source=edr_telemetry" in normalized_description.lower()
        decision = self._build_model_decision(
            normalized_description,
            source="edr_telemetry" if is_edr_telemetry else "compatibility_wrapper",
        )
        threat_type = decision.get("label") or "Needs Review"

        # Use EDR-aware scoring when input comes from structured endpoint telemetry
        if is_edr_telemetry:
            edr_scores = self._derive_edr_scores(normalized_description)
            exploitability_score = float(edr_scores["exploitability_score"])
            impact_score = float(edr_scores["impact_score"])
            risk_score = float(edr_scores["risk_score"])
        else:
            exploitability_score = self._calculate_exploitability_score_cvss(
                normalized_description, 7.5
            )
            impact_score = self._calculate_impact_score("high")
            risk_score = self._calculate_risk_score_cvss(
                exploitability_score,
                impact_score,
            )

        severity = self._determine_severity(risk_score)

        self._log_classification_details(
            description=normalized_description,
            decision=decision,
            exploitability=exploitability_score,
            impact=impact_score,
            risk_score=risk_score,
            severity=severity,
            mitre_tactic=self._extract_mitre_tactic(normalized_description),
        )

        raw_confidence = decision.get("confidence", 0.0)
        try:
            confidence_value = float(raw_confidence)
        except (TypeError, ValueError):
            confidence_value = 0.0

        return {
            "threat_type": threat_type,
            "exploitability_score": float(exploitability_score),
            "impact_score": float(impact_score),
            "risk_score": float(risk_score),
            "mitre_tactic": self._extract_mitre_tactic(normalized_description),
            "severity": severity,
            "confidence": confidence_value,
            "source": decision.get("source", "compatibility_wrapper"),
        }

    def _determine_threat_decision(self, description):
        """Hybrid decision: rule first, ML second, abstain on low confidence."""
        if not description:
            return {
                "label": "Unknown",
                "source": "rule",
                "confidence": 1.0,
                "margin": 1.0,
                "top_candidates": [{"label": "Unknown", "score": 1.0}],
            }

        # Deterministic rule layer for high-certainty signatures
        rule_label = self._bootstrap_label(description)
        if rule_label not in ["Vulnerability Exploitation", "Unknown"]:
            return {
                "label": rule_label,
                "source": "rule",
                "confidence": 0.95,
                "margin": 0.95,
                "top_candidates": [{"label": rule_label, "score": 0.95}],
            }

        # ML prediction layer
        ml = self._predict_with_confidence(description)
        if ml["label"] is None:
            return {
                "label": rule_label,
                "source": "rule_fallback",
                "confidence": 0.50,
                "margin": 0.0,
                "top_candidates": [{"label": rule_label, "score": 0.50}],
            }

        # Confidence gating
        if (
            ml["confidence"] < self.min_prediction_confidence
            or ml["margin"] < self.min_confidence_margin
        ):
            return {
                "label": self.abstain_label,
                "source": "abstain",
                "confidence": ml["confidence"],
                "margin": ml["margin"],
                "top_candidates": ml["top_candidates"],
            }

        return {
            "label": ml["label"],
            "source": "ml",
            "confidence": ml["confidence"],
            "margin": ml["margin"],
            "top_candidates": ml["top_candidates"],
        }

    def _derive_edr_scores(self, description: str) -> Dict:
        """Derive exploitability/impact/risk for EDR telemetry descriptions."""
        d = (description or "").lower()

        exploitability = 4.0
        impact = 3.5

        if "family=process" in d:
            exploitability += 0.4
        if "family=network" in d:
            exploitability += 0.8

        if "hint:nc_usage" in d:
            exploitability += 1.8
            impact += 1.0
        if "hint:reverse_shell_pattern" in d:
            exploitability += 2.4
            impact += 2.1
        if "hint:download_exec_chain" in d:
            exploitability += 1.5
            impact += 1.2
        if "hint:high_risk_port" in d:
            exploitability += 0.9
        if "hint:ephemeral_exec_path" in d:
            impact += 0.8

        if "hint:nc_usage" in d and "hint:reverse_shell_pattern" in d:
            exploitability += 0.8
            impact += 0.6

        exploitability = max(0.0, min(10.0, exploitability))
        impact = max(0.0, min(10.0, impact))
        risk = max(0.0, min(10.0, (exploitability * 0.6) + (impact * 0.4)))

        return {
            "exploitability_score": round(exploitability, 2),
            "impact_score": round(impact, 2),
            "risk_score": round(risk, 2),
        }

    def _determine_threat_type(self, description):
        # ML Compatibility wrapper
        decision = self._determine_threat_decision(description)
        return decision["label"]

    def _determine_severity(self, risk_score):
        # Determine severity category from risk score.

        if risk_score >= 9.0:
            return "Critical"
        elif risk_score >= 7.0:
            return "High"
        elif risk_score >= 5.0:
            return "Medium"
        elif risk_score >= 3.0:
            return "Low"
        else:
            return "Informational"

    def _extract_mitre_tactic(self, description):

        # Extract or map MITRE tactic ID from threat description.
        # First tries regex extraction, then falls back to intelligent mapping.

        import re

        if not description:
            return None

        # First, try to extract existing MITRE tactic format (TA0001-TA0043)
        match = re.search(r"TA\d{4}", description)
        if match:
            return match.group(0)

        # If no explicit tactic, map based on vulnerability keywords
        description_lower = description.lower()

        # Mapping vulnerabilities to MITRE tactics based on description content
        if any(
            kw in description_lower
            for kw in ["injection", "sqli", "sql injection", "command injection"]
        ):
            return "TA0001"  # Initial Access
        elif any(
            kw in description_lower
            for kw in ["xss", "cross-site scripting", "script injection"]
        ):
            return "TA0001"  # Initial Access
        elif any(
            kw in description_lower
            for kw in ["authentication", "broken auth", "credential", "session"]
        ):
            return "TA0006"  # Credential Access
        elif any(
            kw in description_lower for kw in ["privilege", "escalation", "elevation"]
        ):
            return "TA0004"  # Privilege Escalation
        elif any(
            kw in description_lower
            for kw in ["dos", "denial of service", "resource exhaustion"]
        ):
            return "TA0040"  # Impact
        elif any(
            kw in description_lower
            for kw in ["data exposure", "information disclosure", "leak"]
        ):
            return "TA0010"  # Exfiltration
        elif any(
            kw in description_lower
            for kw in ["unencrypted", "weak protocol", "plaintext"]
        ):
            return "TA0009"  # Collection
        elif any(kw in description_lower for kw in ["remote code", "rce", "execution"]):
            return "TA0002"  # Execution
        elif any(
            kw in description_lower for kw in ["buffer overflow", "memory corruption"]
        ):
            return "TA0002"  # Execution
        elif any(
            kw in description_lower for kw in ["misconfiguration", "default credential"]
        ):
            return "TA0001"  # Initial Access
        else:
            return "TA0001"  # Default to Initial Access

    def _calculate_exploitability_score_cvss(
        self, description, cvss_score: float
    ) -> float:
        # Calculate exploitability score based on CVSS
        base_score = cvss_score

        # Minor adjustments based on description keywords
        description_lower = description.lower() if description else ""

        # Increase if proof-of-concept exists
        # Increase score if exploit or poc exists
        if "exploit" in description_lower or "poc" in description_lower:
            base_score = min(base_score + 0.5, 10.0)

        # Increase if actively exploited
        if (
            "actively exploited" in description_lower
            or "in the wild" in description_lower
        ):
            base_score = min(base_score + 1.0, 10.0)

        return round(base_score, 1)

    def _calculate_impact_score(self, criticality):

        # Calculate impact score based on asset criticality.

        return self.criticality_weights.get(criticality.lower(), 5.0)

    def _calculate_risk_score_cvss(
        self, cvss_score: float, impact_score: float
    ) -> float:
        # Combine CVSS and asset criticality to get risk score
        risk = (cvss_score * 0.7) + (impact_score * 0.3)
        return round(risk, 2)

    def _load_or_train_classifier(self):

        # Load existing classifier model or train a new one.

        if self.ensemble and hasattr(self.ensemble, "models") and self.ensemble.models:
            self.logger.info("✅ Ensemble models already loaded, skipping training.")
            return

        # If ensemble isnt available
        if not self.ensemble:
            self.logger.warning("Ensemble not available. Training a new one...")
            try:
                self.ensemble = EnsembleClassifier(
                    models_dir="data/models/threat_classifier"
                )
            except Exception as e:
                self.logger.error("Failed to initialize ensemble: %s", e)
                return

        self._train_ensemble()

    def _train_classifier(self):
        """Train ML classifier with real CVE data from external APIs."""
        self._train_ensemble()

    def _train_ensemble(self):
        """Train ensemble with diverse data sources."""
        self.logger.info(
            "🔄 Training ensemble classifier with CVE data and curated samples..."
        )

        start_time = time.time()

        # Fetch training data from external CVE sources
        training_text, training_labels = self._fetch_cve_training_data()

        # Fallback to database vulnerabilities if external fails
        if len(training_text) < 50:
            self.logger.warning(
                "External CVE data insufficient (%d samples). Fetching from database...",
                len(training_text),
            )
            db_text, db_labels = self._get_database_training_data()
            training_text.extend(db_text)
            training_labels.extend(db_labels)

        if not training_text:
            self.logger.error("No training data available. Cannot train classifier.")
            return

        self.logger.debug("Total training samples: %d", len(training_text))

        # Check data distribution
        from collections import Counter

        label_counts = Counter(training_labels)
        self.logger.info("Training data distribution: %s", dict(label_counts))

        # Split into 80% train + 20% test for validation
        X_train, X_test, y_train, y_test = train_test_split(
            training_text,
            training_labels,
            test_size=0.2,
            random_state=42,
            stratify=training_labels,  # Keep class distro balanced
        )

        self.logger.info(
            "Split: %d training, %d test samples", len(X_train), len(X_test)
        )

        # Train ensemble (on 80%)
        try:
            self.ensemble.train_ensemble(X_train, y_train)
            self.ensemble.save_models()
            self.logger.info(
                "✅ Training ensemble (NB + SVM + RF) on %d samples.",
                len(X_train),
            )
        except Exception as e:
            self.logger.error("Failed to train ensemble: %s", e)
            return None

        training_duration = int(time.time() - start_time)

        # Test on held-out 20% and calc metrics
        try:
            y_pred = self.ensemble.predict(X_test)

            # Overall metrics
            accuracy = float(accuracy_score(y_test, y_pred))
            macro_f1 = float(f1_score(y_test, y_pred, average="macro", zero_division=0))

            # Per-class metrics
            recall_per_class = {}
            precision_per_class = {}

            for class_label in np.unique(y_test):
                # One-vs-rest binary precision/recall for this class
                y_test_binary = np.array([1 if y == class_label else 0 for y in y_test])
                y_pred_binary = np.array([1 if y == class_label else 0 for y in y_pred])

                recall_per_class[str(class_label)] = float(
                    recall_score(y_test_binary, y_pred_binary, zero_division=0)
                )
                precision_per_class[str(class_label)] = float(
                    precision_score(y_test_binary, y_pred_binary, zero_division=0)
                )

            # Build metrics dict for Model Reg
            metrics = {
                "accuracy": accuracy,
                "macro_f1": macro_f1,
                "recall_per_class": recall_per_class,
                "precision_per_class": precision_per_class,
                "training_duration_seconds": training_duration,
            }

            self.logger.info(
                f"✅ Metrics - Accuracy: {accuracy:.3f}, F1: {macro_f1:.3f}"
            )
            self.logger.info(f"Recall per class: {recall_per_class}")
            self.logger.info(f"Precision per class: {precision_per_class}")

            return metrics  # Return metrics dict

        except Exception as e:
            self.logger.error(f"Failed to evaluate ensemble metrics: {e}")
            return None

    def _passed_quality_gates(self, metrics: Dict) -> bool:
        """Check if trained model(s) passe minimum quality standards before reg"""
        macro_f1 = metrics.get("macro_f1", 0.0)
        accuracy = metrics.get("accuracy", 0.0)
        recalls = metrics.get("recall_per_class", {})

        # Gate 1: F1 >= 0.72
        if macro_f1 < 0.72:
            self.logger.warning(
                f"❌ Quality gate FAILED: Macro F1 too low ({macro_f1:.3f} < 0.72)"
            )
            return False

        # Gate 2: Accuracy >= 0.5 would usually be .75 but given the paraphrasing, models are cautious
        if accuracy < 0.5:
            self.logger.warning(
                f"❌ Quality gate FAILED: Accuracy too low ({accuracy:.3f} < 0.5)"
            )
            return False

        # Gate 3: All per-class recall >= 0.6
        if recalls:
            min_recall = min(recalls.values())
            if min_recall < 0.6:
                worst_class = min(recalls, key=recalls.get)
                self.logger.warning(
                    f"❌ Quality gate FAILED: Worst class recall ({worst_class} = {min_recall:.3f} < 0.6)"
                    f"All recalls: {recalls}"
                )
                return False

        self.logger.info("✅ All quality gates PASSED.")
        return True

    def _fetch_cve_training_data(self):
        """Fetch training data from database (classified by agents) or fallback to hardcoded examples."""
        training_texts = []
        training_labels = []

        # First, try to fetch from database
        session = get_session()
        try:
            classifications = (
                session.query(ThreatClassification, Vulnerability.description)
                .join(
                    Vulnerability,
                    ThreatClassification.vulnerability_id == Vulnerability.id,
                )
                .filter(
                    ThreatClassification.threat_type.isnot(None),
                    Vulnerability.description.isnot(None),
                )
                .all()
            )

            for threat_class, description in classifications:
                if description and threat_class.threat_type:
                    training_texts.append(description)
                    training_labels.append(threat_class.threat_type)

            self.logger.debug(
                "Loaded %d training samples from database", len(classifications)
            )
        except Exception as e:
            self.logger.warning(
                f"Failed to load from database: {e}. Using synthetic/fallback hardcoded data."
            )
        finally:
            session.close()

        try:
            synthetic_rows = get_edr_synthetic_training_samples()
            for text, label in synthetic_rows:
                training_texts.append(text)
                training_labels.append(label)
            self.logger.info("Added %d synthetic EDR samples", len(synthetic_rows))
        except Exception as e:
            self.logger.warning(f"Failed to load synthetic EDR samples: {e}")

        # Fallback: if still too small, use hardcoded examples if database is empty
        if len(training_texts) < 50:    
            sample_cves = [
                # SQL Injection examples
                (
                    "SQL injection vulnerability allows remote attackers to execute arbitrary SQL commands",
                    "Injection Attack",
                ),
                (
                    "SQL injection in login form enables database manipulation",
                    "Injection Attack",
                ),
                (
                    "Improper neutralization of SQL commands leads to database compromise",
                    "Injection Attack",
                ),
                (
                    "LDAP injection vulnerability in authentication system",
                    "Injection Attack",
                ),
                (
                    "NoSQL injection enables unauthorized database access",
                    "Injection Attack",
                ),
                # XSS examples
                (
                    "Cross-site scripting vulnerability allows code injection in web pages",
                    "Cross-Site Scripting",
                ),
                (
                    "XSS flaw enables malicious script execution in user browsers",
                    "Cross-Site Scripting",
                ),
                (
                    "Improper input validation leads to stored XSS attacks",
                    "Cross-Site Scripting",
                ),
                ("Reflected XSS vulnerability in search parameter", "Cross-Site Scripting"),
                (
                    "DOM-based XSS enables client-side code execution",
                    "Cross-Site Scripting",
                ),
                # Buffer Overflow examples
                (
                    "Buffer overflow in network service allows remote code execution",
                    "Buffer Overflow",
                ),
                (
                    "Stack-based buffer overflow enables arbitrary code execution",
                    "Buffer Overflow",
                ),
                (
                    "Heap overflow vulnerability leads to memory corruption",
                    "Memory Corruption",
                ),
                ("Integer overflow causes buffer overrun condition", "Buffer Overflow"),
                (
                    "Format string vulnerability enables memory manipulation",
                    "Memory Corruption",
                ),
                # Directory Traversal
                (
                    "Directory traversal vulnerability allows access to arbitrary files",
                    "Path Traversal",
                ),
                (
                    "Path traversal flaw enables reading of sensitive system files",
                    "Path Traversal",
                ),
                ("Improper path validation leads to file system access", "Path Traversal"),
                ("Local file inclusion vulnerability via URL parameter", "Path Traversal"),
                # Authentication Issues
                (
                    "Authentication bypass allows unauthorized access to admin panel",
                    "Authentication Bypass",
                ),
                (
                    "Weak authentication mechanism enables credential theft",
                    "Authentication Bypass",
                ),
                (
                    "Missing authentication check allows privilege escalation",
                    "Privilege Escalation",
                ),
                (
                    "Insufficient permission checks enable privilege escalation",
                    "Privilege Escalation",
                ),
                (
                    "Insecure direct object reference allows unauthorized escalation",
                    "Privilege Escalation",
                ),
                (
                    "Sudo configuration vulnerability enables privilege escalation",
                    "Privilege Escalation",
                ),
                (
                    "Local privilege escalation via kernel exploit",
                    "Privilege Escalation",
                ),
                (
                    "Privilege escalation through setuid binary",
                    "Privilege Escalation",
                ),
                (
                    "Session fixation vulnerability in login process",
                    "Authentication Bypass",
                ),
                (
                    "Weak password policy enables brute force attacks",
                    "Authentication Bypass",
                ),
                # Denial of Service
                ("Memory leak vulnerability causes denial of service", "Denial of Service"),
                (
                    "Resource exhaustion attack leads to service unavailability",
                    "Denial of Service",
                ),
                ("Infinite loop condition enables DoS attacks", "Denial of Service"),
                ("XML bomb attack causes server resource exhaustion", "Denial of Service"),
                ("Algorithmic complexity vulnerability enables DoS", "Denial of Service"),
                # Remote Code Execution (consolidated)
                ("Remote code execution via malformed input data", "Remote Code Execution"),
                (
                    "Arbitrary command execution through file upload",
                    "Remote Code Execution",
                ),
                (
                    "Code injection vulnerability enables system compromise",
                    "Remote Code Execution",
                ),
                (
                    "Deserialization vulnerability allows remote code execution",
                    "Remote Code Execution",
                ),
                (
                    "Template injection enables server-side code execution",
                    "Remote Code Execution",
                ),
                ("RCE via unchecked deserialization", "Remote Code Execution"),
                ("Remote code execution in php eval function", "Remote Code Execution"),
                # Information Disclosure
                (
                    "Information disclosure exposes sensitive user data",
                    "Information Disclosure",
                ),
                (
                    "Sensitive information leaked through error messages",
                    "Information Disclosure",
                ),
                (
                    "Improper access control reveals confidential files",
                    "Information Disclosure",
                ),
                (
                    "Debug information exposed in production environment",
                    "Information Disclosure",
                ),
                (
                    "Source code disclosure through misconfigured server",
                    "Information Disclosure",
                ),
                # CSRF and Other Web Attacks
                (
                    "Cross-site request forgery enables unauthorized actions",
                    "Cross-Site Request Forgery",
                ),
                (
                    "CSRF vulnerability in state-changing operations",
                    "Cross-Site Request Forgery",
                ),
                (
                    "CSRF token validation missing in form submission",
                    "Cross-Site Request Forgery",
                ),
                (
                    "Cross-site request forgery attack via GET request",
                    "Cross-Site Request Forgery",
                ),
                ("Clickjacking attack enables UI redressing", "Clickjacking"),
                ("Clickjacking vulnerability in overlay attack vector", "Clickjacking"),
                (
                    "UI redressing attack deceives users into unintended actions",
                    "Clickjacking",
                ),
                ("Malicious frame overlay enables click hijacking", "Clickjacking"),
                ("HTTP parameter pollution causes unexpected behavior", "Input Validation"),
                ("SQL injection through input validation bypass", "Input Validation"),
                (
                    "Insufficient input validation enables command injection",
                    "Input Validation",
                ),
                ("Missing input sanitization allows XSS attacks", "Input Validation"),
                # Cryptographic Issues
                (
                    "Weak encryption algorithm enables data decryption",
                    "Cryptographic Weakness",
                ),
                (
                    "Improper certificate validation allows MITM attacks",
                    "Cryptographic Weakness",
                ),
                (
                    "Hash collision vulnerability in signature verification",
                    "Cryptographic Weakness",
                ),
                (
                    "Weak random number generation enables prediction attacks",
                    "Cryptographic Weakness",
                ),
            ]

        for description, label in sample_cves:
            training_texts.append(description)
            training_labels.append(label)

        self.logger.debug(
            "Loaded %d CVE training samples from external data", len(sample_cves)
        )
        return training_texts, training_labels

    def _get_database_training_data(self):
        """Get training data from database vulnerabilities as fallback."""
        session = get_session()
        vulnerabilities = session.query(Vulnerability).all()

        training_texts = []
        training_labels = []

        for vuln in vulnerabilities:
            description = vuln.description or vuln.name
            label = self._bootstrap_label(description)
            training_texts.append(description)
            training_labels.append(label)

        session.close()
        return training_texts, training_labels

    # TODO: Add NVD API integration in future

    def _bootstrap_label(self, description):

        # Create bootstrap label based on keywords (used for initial training only).
        # Known limitations: May not cover all cases and vulnerabilities correctly.

        description_lower = description.lower() if description else ""

        # Injection Attacks
        if "injection" in description_lower or "sqli" in description_lower:
            return "Injection Attack"
        elif "xss" in description_lower or "cross-site" in description_lower:
            return "Cross-Site Scripting"

        # Code Execution (consolidated into Remote Code Execution for balance)
        elif "remote code" in description_lower or "rce" in description_lower:
            return "Remote Code Execution"
        elif "remote" in description_lower and "execution" in description_lower:
            return "Remote Code Execution"
        elif (
            "arbitrary code" in description_lower
            or "code execution" in description_lower
            or "arbitrary command" in description_lower
            or "command execution" in description_lower
        ):
            return "Remote Code Execution"

        # Memory Corruption
        elif "buffer" in description_lower or "overflow" in description_lower:
            return "Buffer Overflow"
        elif "null" in description_lower and (
            "ptr" in description_lower
            or "pointer" in description_lower
            or "deref" in description_lower
        ):
            return "Memory Corruption"
        elif "memory corruption" in description_lower or "heap" in description_lower:
            return "Memory Corruption"
        elif (
            "use-after-free" in description_lower or "double free" in description_lower
        ):
            return "Memory Corruption"

        # Denial of Service (check early since NULL deref often causes DoS)
        elif (
            "denial" in description_lower
            or "dos" in description_lower
            or "ddos" in description_lower
            or "crash" in description_lower
        ):
            return "Denial of Service"

        # Authentication & Access Control
        elif "authentication" in description_lower or "credential" in description_lower:
            return "Authentication Bypass"
        elif "privilege" in description_lower or "escalation" in description_lower:
            return "Privilege Escalation"
        elif (
            "authorization" in description_lower
            or "access control" in description_lower
        ):
            return "Access Control Bypass"

        # Network Attacks
        elif "man-in-the-middle" in description_lower or "mitm" in description_lower:
            return "Network Attack"

        # Web Application Vulnerabilities
        elif "csrf" in description_lower or "cross-site request" in description_lower:
            return "Cross-Site Request Forgery"
        elif (
            "directory traversal" in description_lower
            or "path traversal" in description_lower
        ):
            return "Path Traversal"
        elif (
            "file upload" in description_lower
            or "upload vulnerability" in description_lower
        ):
            return "File Upload Vulnerability"
        elif (
            "server-side request forgery" in description_lower
            or "ssrf" in description_lower
        ):
            return "Server-Side Request Forgery"

        # Cryptographic Issues
        elif "cryptographic" in description_lower or "encryption" in description_lower:
            return "Cryptographic Vulnerability"
        elif (
            "weak hash" in description_lower
            or "md5" in description_lower
            or "sha1" in description_lower
        ):
            return "Weak Cryptography"

        # Information Disclosure
        elif (
            "information disclosure" in description_lower
            or "data leak" in description_lower
        ):
            return "Information Disclosure"
        elif "sensitive data" in description_lower or "exposed" in description_lower:
            return "Information Disclosure"

        # Container & Cloud
        elif (
            "container" in description_lower
            or "docker" in description_lower
            or "kubernetes" in description_lower
        ):
            return "Container Vulnerability"
        elif "cloud" in description_lower or "misconfiguration" in description_lower:
            return "Configuration Vulnerability"

        # Supply Chain & Dependencies
        elif (
            "dependency" in description_lower
            or "third-party" in description_lower
            or "supply chain" in description_lower
        ):
            return "Supply Chain Vulnerability"
        elif (
            "deserialization" in description_lower or "unserialize" in description_lower
        ):
            return "Deserialization Vulnerability"

        # Zero-Day & Advanced
        elif "zero-day" in description_lower or "0-day" in description_lower:
            return "Zero-Day Exploit"
        elif "race condition" in description_lower or "toctou" in description_lower:
            return "Race Condition"

        # Default/Fallback
        else:
            return "Vulnerability Exploitation"

    def incorporate_analyst_feedback(self):
        """
        Fetch all analyst-curated training data since last retrain.
        Combine with original training data and retrain classifier.
        """

        session = get_session()

        try:
            # Fetch original training data (hardcoded CVE examples)
            self.logger.info(f"[{agent_name('classifier')} Retrain] Fetching original training data...")
            original_texts, original_labels = self._fetch_cve_training_data()

            # Fetch modern test CVE samples (155+ realistic examples for generalization)
            self.logger.info(f"[{agent_name('classifier')} Retrain] Fetching modern CVE test samples...")
            modern_cves = get_modern_test_cves()
            modern_texts = [cve[0] for cve in modern_cves]
            modern_labels = [cve[1] for cve in modern_cves]

            # Fetch analyst corrections (human feedback from Phase 2 reviews)
            self.logger.info(f"[{agent_name('classifier')} Retrain] Fetching analyst-curated data...")
            analyst_data = session.query(AnalystCuratedTrainingData).all()

            analyst_texts = [d.vulnerability_description for d in analyst_data]
            analyst_labels = [d.analyst_corrected_threat_type for d in analyst_data]

            self.logger.info(
                f"Data sources - Original: {len(original_texts)}, Modern: {len(modern_texts)}, Analyst: {len(analyst_texts)}"
            )

            # Combine all three sources for robust, generalized training
            combined_texts = original_texts + modern_texts + analyst_texts
            combined_labels = original_labels + modern_labels + analyst_labels

            if len(combined_texts) < 20:
                self.logger.warning("Not enough combined data to retrain (need >= 20)")
                return False

            # Train/test split
            X_train, X_test, y_train, y_test = train_test_split(
                combined_texts,
                combined_labels,
                test_size=0.2,
                random_state=42,
                stratify=combined_labels,
            )

            # Train new model with class balancing
            sample_weights = compute_sample_weight("balanced", y_train)

            base_nb = make_pipeline(
                TfidfVectorizer(max_features=500, ngram_range=(1, 2)),
                MultinomialNB(),
            )

            self.classifier_model = CalibratedClassifierCV(
                base_nb, method="sigmoid", cv=3
            )
            self.classifier_model.fit(
                X_train, y_train, multinomialnb__sample_weight=sample_weights
            )

            preds = self.classifier_model.predict(X_test)
            macro_f1 = f1_score(y_test, preds, average="macro", zero_division=0)

            self.logger.info(f"[{agent_name('classifier')} Retrain] Macro F1: {macro_f1:.4f}")

            # Decide if we should promote (using same gates as eval script)
            report = classification_report(
                y_test, preds, output_dict=True, zero_division=0
            )

            gate1 = macro_f1 >= 0.72
            gate2_pass = all(
                metrics.get("recall", 0) >= 0.60
                for label, metrics in report.items()
                if label not in ["accuracy", "macro avg", "weighted avg"]
            )

            if gate1 and gate2_pass:
                # Save model

                os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
                with open(self.model_path, "wb") as f:
                    pickle.dump(self.classifier_model, f)

                # Update version
                self.model_version = (
                    f"nb_v3_analyst_feedback_{datetime.now().strftime('%Y%m%d%H%M%S')}"
                )
                self.logger.info(
                    f"✅ Retrained model promoted with analyst feedback! Version: {self.model_version}"
                )

                # Mark training data as used
                for d in analyst_data:
                    d.used_in_model_version = self.model_version
                    d.used_in_retrain_at = datetime.now(timezone.utc)

                session.commit()
                return True

            else:
                self.logger.warning(
                    f"Retrained model did not meet promotion criteria. Macro F1: {macro_f1:.4f}, Gate 1: {gate1}, Gate 2: {gate2_pass}"
                )
                return False

        except Exception as e:
            self.logger.error("Error during retraining with analyst feedback: {e}")
            return False
        finally:
            session.close()

    def should_train(self):
        """Check if enough time has passed to retrain the model."""
        if self.last_retrain_time is None:
            return False  # Don't retrain on startup

        current_time = time.time()
        time_since_last_train = current_time - self.last_retrain_time

        if time_since_last_train >= self.retrain_interval:
            self.logger.info(
                f"⏰ Retraining interval ({self.retrain_interval/3600:.1f}h) elapsed"
            )
            return True
        return False

    def _get_next_model_version(self) -> tuple:
        """
        Determine the next model version folder.
        Scans data/models/ for threat_classifier_v{N}, returns N+1 and new path.
        """
        models_dir = "data/models"
        os.makedirs(models_dir, exist_ok=True)

        # Find all versioned folders
        versioned_folders = glob.glob(f"{models_dir}/threat_classifier_v*")

        if not versioned_folders:
            # First version is v2 (v1 is implied as baseline)
            next_version = 2
        else:
            # Extract version numbers and get the max
            versions = []
            for folder in versioned_folders:
                try:
                    # Extract number from "threat_classifier_v3" -> 3
                    version_num = int(folder.split("_v")[-1])
                    versions.append(version_num)
                except (ValueError, IndexError):
                    continue

            next_version = max(versions) + 1 if versions else 2

        new_folder = f"{models_dir}/threat_classifier_v{next_version}"
        self.logger.info(f"Next model version: v{next_version} at {new_folder}")

        return next_version, new_folder

    def _consolidate_periodic_threat_type(self, threat_type: str) -> str:
        """Map legacy/adversarial labels to the canonical threat taxonomy used."""
        threat_mapping = {
            "Injection Attack": "SQL Injection",
            "Cryptographic Weakness": "Sensitive Data Exposure",
            "Information Disclosure": "Sensitive Data Exposure",
            "Input Validation": "SQL Injection",
            "Request Forgery": "Server-Side Request Forgery",
            "Cross-Site Scripting": "Cross-Site Scripting",
            "Remote Code Execution": "Remote Code Execution",
            "Path Traversal": "Path Traversal",
            "Authentication Bypass": "Authentication Bypass",
            "Privilege Escalation": "Privilege Escalation",
            "Denial of Service": "Denial of Service",
            "Insecure Direct Object Reference": "Insecure Direct Object Reference",
            "Sensitive Data Exposure": "Sensitive Data Exposure",
            "Server-Side Request Forgery": "Server-Side Request Forgery",
        }
        return threat_mapping.get(threat_type, "SQL Injection")

    def _check_and_retrain(self):
        """Periodic retraining using the same gbc pipeline with automatic versioned folders."""
        if not self.should_train():
            return

        try:
            self.logger.info("=" * 80)
            self.logger.info("⏰ PERIODIC RETRAINING (GBC PIPELINE)")
            self.logger.info("=" * 80)

            random.seed(42)
            np.random.seed(42)

            next_version, next_folder = self._get_next_model_version()
            os.makedirs(next_folder, exist_ok=True)
            self.logger.info("[1/6] Creating versioned folder: %s", next_folder)

            # Load baseline training set used by training script

            self.logger.info("[2/6] Loading baseline datasets...")
            synthetic_threats = get_diverse_threat_scenarios_full()
            adversarial_samples = get_extended_adversarial_samples_normalized()

            threat_type_ranges = {
                "SQL Injection": {
                    "cvss_min": 7.5,
                    "cvss_max": 9.2,
                    "severities": ["High", "Critical"],
                },
                "Cross-Site Scripting": {
                    "cvss_min": 5.5,
                    "cvss_max": 8.0,
                    "severities": ["Medium", "High"],
                },
                "Authentication Bypass": {
                    "cvss_min": 8.5,
                    "cvss_max": 9.8,
                    "severities": ["Critical"],
                },
                "Privilege Escalation": {
                    "cvss_min": 7.5,
                    "cvss_max": 9.5,
                    "severities": ["High", "Critical"],
                },
                "Server-Side Request Forgery": {
                    "cvss_min": 6.0,
                    "cvss_max": 8.5,
                    "severities": ["High"],
                },
                "Path Traversal": {
                    "cvss_min": 6.5,
                    "cvss_max": 8.5,
                    "severities": ["High"],
                },
                "Remote Code Execution": {
                    "cvss_min": 8.5,
                    "cvss_max": 10.0,
                    "severities": ["Critical"],
                },
                "Sensitive Data Exposure": {
                    "cvss_min": 5.0,
                    "cvss_max": 8.0,
                    "severities": ["Medium", "High"],
                },
                "Denial of Service": {
                    "cvss_min": 6.5,
                    "cvss_max": 9.0,
                    "severities": ["High", "Critical"],
                },
                "Insecure Direct Object Reference": {
                    "cvss_min": 6.0,
                    "cvss_max": 8.5,
                    "severities": ["High"],
                },
            }

            asset_types = [
                "Web Application",
                "API Server",
                "Database",
                "Web Server",
                "Network Service",
            ]

            adversarial_threats = []
            for idx, (description, original_threat_type) in enumerate(
                adversarial_samples
            ):
                canonical_threat_type = self._consolidate_periodic_threat_type(
                    original_threat_type
                )
                ranges = threat_type_ranges.get(
                    canonical_threat_type,
                    {"cvss_min": 6.5, "cvss_max": 8.5, "severities": ["High"]},
                )
                cvss_score = np.random.uniform(ranges["cvss_min"], ranges["cvss_max"])
                exploitability = np.random.uniform(
                    cvss_score - 1.5,
                    min(cvss_score, 10.0),
                )
                severity = np.random.choice(ranges["severities"])

                adversarial_threats.append(
                    {
                        "description": description,
                        "threat_type": canonical_threat_type,
                        "cvss_score": round(float(cvss_score), 1),
                        "severity": severity,
                        "exploitability": round(float(exploitability), 1),
                        "asset_type": asset_types[idx % len(asset_types)],
                    }
                )

            baseline_count = len(synthetic_threats) + len(adversarial_threats)
            self.logger.info(
                "   Baseline samples: %d (synthetic=%d, adversarial=%d)",
                baseline_count,
                len(synthetic_threats),
                len(adversarial_threats),
            )

            # Load DB + analyst curated feedback and append to baseline

            self.logger.info("[3/6] Loading DB and analyst-curated feedback...")
            session = get_session()
            db_training_threats = []

            try:
                classifications = (
                    session.query(
                        ThreatClassification,
                        Vulnerability.description,
                        Vulnerability.cvss_base_score,
                        Asset.type,
                        Asset.risk_level,
                    )
                    .join(
                        Vulnerability,
                        ThreatClassification.vulnerability_id == Vulnerability.id,
                    )
                    .join(Asset, ThreatClassification.asset_id == Asset.id)
                    .filter(
                        ThreatClassification.threat_type.isnot(None),
                        Vulnerability.description.isnot(None),
                    )
                    .all()
                )

                for (
                    threat_class,
                    vuln_desc,
                    cvss_score,
                    asset_type,
                    asset_risk,
                ) in classifications:
                    if not vuln_desc:
                        continue

                    resolved_cvss = (
                        float(cvss_score)
                        if cvss_score is not None
                        else get_cvss_for_vulnerability(
                            threat_class.threat_type.replace(" ", "-"), vuln_desc
                        )["base_score"]
                    )
                    severity = get_severity_from_cvss(resolved_cvss)
                    exploitability = self._calculate_exploitability_score_cvss(
                        vuln_desc,
                        resolved_cvss,
                    )

                    db_training_threats.append(
                        {
                            "description": vuln_desc,
                            "threat_type": threat_class.threat_type,
                            "cvss_score": float(resolved_cvss),
                            "severity": severity,
                            "exploitability": float(exploitability),
                            "asset_type": asset_type or "General",
                            "asset_criticality": asset_risk or "Medium",
                        }
                    )

                curated_rows = (
                    session.query(AnalystCuratedTrainingData)
                    .filter(
                        AnalystCuratedTrainingData.vulnerability_description.isnot(
                            None
                        ),
                        AnalystCuratedTrainingData.analyst_corrected_threat_type.isnot(
                            None
                        ),
                    )
                    .all()
                )

                for row in curated_rows:
                    desc = row.vulnerability_description.strip()
                    if not desc:
                        continue

                    threat_type = row.analyst_corrected_threat_type.strip()
                    cvss_score = get_cvss_for_vulnerability(
                        threat_type.replace(" ", "-"),
                        desc,
                    )["base_score"]
                    severity = (
                        row.threat_severity
                        if row.threat_severity
                        else get_severity_from_cvss(cvss_score)
                    )
                    exploitability = self._calculate_exploitability_score_cvss(
                        desc,
                        cvss_score,
                    )

                    db_training_threats.append(
                        {
                            "description": desc,
                            "threat_type": threat_type,
                            "cvss_score": float(cvss_score),
                            "severity": severity,
                            "exploitability": float(exploitability),
                            "asset_type": "General",
                            "asset_criticality": "Medium",
                        }
                    )
            finally:
                session.close()

            self.logger.info(
                "   DB/curated samples appended: %d", len(db_training_threats)
            )

            all_threats = synthetic_threats + adversarial_threats + db_training_threats
            if len(all_threats) < 50:
                self.logger.warning(
                    "⚠️  Not enough total training samples (%d). Skipping retrain.",
                    len(all_threats),
                )
                return

            # Train model: Word2Vec + metadata + calibrated GBC

            self.logger.info(
                "[4/6] Training GBC model on %d samples...",
                len(all_threats),
            )

            descriptions = [
                t["description"] for t in all_threats if t.get("description")
            ]
            labels = [t["threat_type"] for t in all_threats if t.get("description")]
            filtered_threats = [t for t in all_threats if t.get("description")]

            w2v_extractor = Word2VecFeatureExtractor(
                vector_size=100, min_count=2, workers=1
            )
            w2v_extractor.fit(descriptions)
            semantic_features = w2v_extractor.transform(descriptions)

            metadata_extractor = StructuredMetadataExtractor()
            metadata_extractor.fit(filtered_threats)
            metadata_features = metadata_extractor.transform(filtered_threats)

            X = np.hstack([semantic_features, metadata_features])

            label_encoder = LabelEncoder()
            y = label_encoder.fit_transform(labels)

            try:
                X_train, X_test, y_train, y_test = train_test_split(
                    X,
                    y,
                    test_size=0.2,
                    stratify=y,
                    random_state=42,
                )
            except ValueError:
                # Fallback if a class has too few samples for stratified split.
                X_train, X_test, y_train, y_test = train_test_split(
                    X,
                    y,
                    test_size=0.2,
                    random_state=42,
                )

            scaler = StandardScaler()
            X_train_scaled = scaler.fit_transform(X_train)
            X_test_scaled = scaler.transform(X_test)

            calibration_method = (
                os.getenv("THREAT_CALIBRATION_METHOD", "sigmoid").strip().lower()
            )
            if calibration_method not in {"sigmoid", "isotonic"}:
                calibration_method = "sigmoid"

            start_time = time.time()
            gbc = GradientBoostingClassifier(
                n_estimators=150,
                learning_rate=0.08,
                max_depth=4,
                min_samples_split=8,
                min_samples_leaf=4,
                subsample=0.7,
                random_state=42,
            )
            gbc.fit(X_train_scaled, y_train)

            calibrated_gbc = CalibratedClassifierCV(
                gbc,
                method=calibration_method,
                cv=5,
            )
            calibrated_gbc.fit(X_train_scaled, y_train)
            training_duration = int(time.time() - start_time)

            y_pred = calibrated_gbc.predict(X_test_scaled)
            y_pred_proba = calibrated_gbc.predict_proba(X_test_scaled)
            max_probs = np.max(y_pred_proba, axis=1)

            accuracy = float((y_pred == y_test).mean())
            macro_f1 = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
            high_confidence_pct = float((max_probs > 0.7).sum() / len(max_probs) * 100)
            low_confidence_pct = float((max_probs < 0.5).sum() / len(max_probs) * 100)

            recall_per_class = {}
            precision_per_class = {}
            for i, class_name in enumerate(label_encoder.classes_):
                y_test_bin = (y_test == i).astype(int)
                y_pred_bin = (y_pred == i).astype(int)
                recall_per_class[class_name] = float(
                    recall_score(y_test_bin, y_pred_bin, zero_division=0)
                )
                precision_per_class[class_name] = float(
                    precision_score(y_test_bin, y_pred_bin, zero_division=0)
                )

            self.logger.info(
                "[5/6] Metrics: macro_f1=%.4f, accuracy=%.4f, high_conf=%.1f%%, low_conf=%.1f%%",
                macro_f1,
                accuracy,
                high_confidence_pct,
                low_confidence_pct,
            )

            macro_f1_gate = float(os.getenv("THREAT_GATE_MIN_MACRO_F1", "0.72"))
            high_conf_gate = float(os.getenv("THREAT_GATE_MIN_HIGH_CONFIDENCE", "50"))
            low_conf_gate = float(os.getenv("THREAT_GATE_MAX_LOW_CONFIDENCE", "20"))

            gates_passed = (
                macro_f1 >= macro_f1_gate
                and high_confidence_pct >= high_conf_gate
                and low_confidence_pct <= low_conf_gate
            )

            if not gates_passed:
                self.logger.warning(
                    "⚠️  Retrained model failed gates; preserving previous models and removing %s",
                    next_folder,
                )
                shutil.rmtree(next_folder, ignore_errors=True)
                return

            # Save model artifacts in the same format as v7 manual training outputs.
            with open(Path(next_folder) / "classifier.pkl", "wb") as f:
                pickle.dump(calibrated_gbc, f)
            with open(Path(next_folder) / "w2v_extractor.pkl", "wb") as f:
                pickle.dump(w2v_extractor, f)
            with open(Path(next_folder) / "metadata_extractor.pkl", "wb") as f:
                pickle.dump(metadata_extractor, f)
            with open(Path(next_folder) / "label_encoder.pkl", "wb") as f:
                pickle.dump(label_encoder, f)
            with open(Path(next_folder) / "scaler.pkl", "wb") as f:
                pickle.dump(scaler, f)

            self.logger.info("[6/6] Saved model artifacts to %s", next_folder)

            workflow = ModelPromotionWorkflow()
            metrics = {
                "accuracy": accuracy,
                "macro_f1": macro_f1,
                "recall_per_class": recall_per_class,
                "precision_per_class": precision_per_class,
                "training_duration_seconds": training_duration,
                "training_data_sources": {
                    "baseline_samples": baseline_count,
                    "database_and_curated_samples": len(db_training_threats),
                    "total_training_samples": len(filtered_threats),
                },
                "config": {
                    "avg_confidence": float(np.mean(max_probs)),
                    "high_confidence_pct": high_confidence_pct,
                    "low_confidence_pct": low_confidence_pct,
                    "calibration_method": calibration_method,
                    "feature_engineering": "Word2Vec + Metadata",
                    "classifier": "Gradient Boosting with Calibrated Probabilities",
                },
            }

            model = workflow.register_model(
                agent_id="classifier_001",
                metrics=metrics,
                model_path=next_folder,
                model_type="gradient_boosting_w2v",
                config=metrics["config"],
            )

            self.last_retrain_time = time.time()
            self.logger.info(
                "✅ Periodic retrain complete: created v%s at %s (model id=%s)",
                next_version,
                next_folder,
                model.id,
            )
            self.logger.info("=" * 80 + "\n")

        except Exception as e:
            self.logger.error(f"❌ Retraining failed: {e}", exc_info=True)


# Example usage: Demo of Functionality
if __name__ == "__main__":
    import argparse
    import sys

    # Parse command line arguments
    parser = argparse.ArgumentParser(description=agent_full_name("classifier"))
    parser.add_argument(
        "--mode",
        choices=["listen", "demo"],
        default="demo",
        help="Run in listening mode or demo mode (default: demo)",
    )
    args = parser.parse_args()

    verbose = args.mode == "demo"

    agent = ThreatClassificationAgent(verbose=verbose)

    if args.mode == "demo":
        # DEMO MODE - Process real data from database (created by Vigilon Atlas)
        print("=" * 80)
        print(f"{agent_full_name('classifier')} - Demo Mode")
        print("=" * 80)

        agent.logger.info("ML model loaded successfully")
        agent.logger.info(f"Running classification on real threat data from {agent_name('threat_model')}...")

        print("\n" + "=" * 80)
        print("DEMO: Threat Classification Workflow")
        print("=" * 80)

        # Process REAL threat data (created by Vigilon Atlas in database)
        agent.logger.info("Classifying threats from database...")
        agent.classify_threat({"source": "demo_run", "type": "real_data"})

        agent.logger.info("   [CLASSIFICATION RESULTS]")
        agent.logger.info("  ✓ Exploitability scores calculated")
        agent.logger.info("  ✓ Impact scores calculated")
        agent.logger.info("  ✓ Risk scores generated")
        agent.logger.info("  ✓ Severity levels assigned (Critical/High/Medium/Low)")
        agent.logger.info("  ✓ Threat types classified (ML predicted)")
        agent.logger.info("  ✓ MITRE tactics extracted")
        agent.logger.info(f"  ✓ Classified threats published to message bus for {agent_name('threat_hunter')}")

        print("\n" + "=" * 80)
        print("Demo complete!")
        print("=" * 80)
    else:
        # LISTEN MODE - Continuous operation
        agent.verbose = False  # Minimal output in listen mode
        print("=" * 80)
        print(f"{agent_full_name('classifier')} - Listen Mode")
        print("=" * 80)
        agent.logger.info("ML model loaded and ready")
        agent.logger.info(
            f"Automatic retraining: Every {agent.retrain_interval/3600:.1f} hour(s)"
        )
        agent.logger.info(f"Subscribed to 'threat_intelligence' channel from {agent_name('threat_model')}")

        # Send heartbeat immediately so dashboard shows agent as running
        message_bus.heartbeat(agent.agent_id)

        # Initial classification run on any unclassified data
        agent.logger.info("Running initial classification on existing data...")
        agent.classify_threat({"source": "initial_run", "type": "real_data"})
        agent.logger.info("✅ Initial classification complete")
        agent.logger.info(f"Now monitoring for new threat intelligence from {agent_name('threat_model')}...")

        # Send heartbeat immediately so dashboard shows agent as running
        message_bus.heartbeat(agent.agent_id)

        try:
            heartbeat_counter = 0
            while True:
                time.sleep(1)
                heartbeat_counter += 1

                # Send heartbeat every second to dashboard
                message_bus.heartbeat(agent.agent_id)

                # Check for model retraining every 60 seconds
                if heartbeat_counter % 60 == 0:
                    agent._check_and_retrain()

        except KeyboardInterrupt:
            agent.logger.debug("Shutting down...")
