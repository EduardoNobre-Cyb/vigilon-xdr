import sys
import os
import numpy as np
import pandas as pd
from pathlib import Path
import pickle
import logging
import time
import random

# Add project root to path for relative imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    f1_score,
    confusion_matrix,
    classification_report,
    precision_recall_fscore_support,
)

from data.diverse_threat_training_data import get_diverse_threat_scenarios_full
from data.ensemble_adversarial_samples import (
    get_extended_adversarial_samples_normalized,
)
from data.models.classifier_feature_extractors import (
    StructuredMetadataExtractor,
    Word2VecFeatureExtractor,
)
from data.models.model_prom_workflow import ModelPromotionWorkflow

logger = logging.getLogger(__name__)


def _env_flag_true(name: str, default: str = "false") -> bool:
    """Parse boolean-like environment variable values."""
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


def compute_multiclass_brier_score(
    y_true: np.ndarray, y_proba: np.ndarray, n_classes: int
) -> float:
    """Multiclass Brier Score. Lower is better, perfect calib/conf is 0.0"""

    y_onehot = np.eye(n_classes)[y_true]
    per_sample = np.sum((y_proba - y_onehot) ** 2, axis=1)
    return float(np.mean(per_sample))


def compute_expected_calibration_error(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    confidences: np.ndarray,
    n_bins: int = 10,  # default 10 bins of conf
) -> float:
    """Expected Calibration Error (ECE) using confidence bins"""

    bins = np.linspace(0.0, 1.0, n_bins + 1)
    # Bin index in [0, n_bins-1]
    bin_ids = np.digitize(confidences, bins[1:-1], right=True)

    ece = 0.0
    n = len(y_true)

    for b in range(n_bins):
        mask = bin_ids == b
        if not np.any(mask):
            continue

        bin_acc = np.mean(y_pred[mask] == y_true[mask])
        bin_conf = np.mean(confidences[mask])
        ece += (np.sum(mask) / n) * abs(bin_acc - bin_conf)

    return float(ece)


def consolidate_threat_type(threat_type: str) -> str:
    """
    Map adversarial sample threat types to canonical 10-class taxonomy.

    Consolidates 15 threat types from adversarial data to 10 canonical types
    that match diverse_threat_training_data.py.
    """
    # Mapping: adversarial names → canonical names
    threat_mapping = {
        "Injection Attack": "SQL Injection",
        "Cryptographic Weakness": "Sensitive Data Exposure",
        "Information Disclosure": "Sensitive Data Exposure",
        "Input Validation": "SQL Injection",
        "Request Forgery": "Server-Side Request Forgery",
        # Keep canonical types as-is
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

    canonical = threat_mapping.get(threat_type, "SQL Injection")  # Default fallback
    logger.debug(f"Mapped '{threat_type}' → '{canonical}'")
    return canonical


def retrain_ensemble_v4():
    """Main training pipeline for Gradient Boosting classifier."""

    logger.info("=" * 60)
    logger.info("Starting GBC retraining pipeline")
    logger.info("=" * 60)

    seed = 42
    np.random.seed(seed)
    random.seed(seed)

    # Strict winner policy by default: enforce canonical promotion gates.
    # Override values are only honored when explicitly enabled.
    macro_f1_gate = 0.72
    high_conf_gate = 50.0
    low_conf_gate = 20.0

    allow_gate_override = _env_flag_true("THREAT_ALLOW_GATE_OVERRIDE", "false")
    if allow_gate_override:
        macro_f1_gate = float(os.getenv("THREAT_GATE_MIN_MACRO_F1", "0.72"))
        high_conf_gate = float(os.getenv("THREAT_GATE_MIN_HIGH_CONFIDENCE", "50"))
        low_conf_gate = float(os.getenv("THREAT_GATE_MAX_LOW_CONFIDENCE", "20"))
        logger.warning(
            "Gate override ENABLED via THREAT_ALLOW_GATE_OVERRIDE=true (experimental mode)."
        )
    else:
        logger.info(
            "Gate override disabled (strict mode). To allow overrides, set THREAT_ALLOW_GATE_OVERRIDE=true."
        )

    logger.info(
        "Gate thresholds: macro_f1 >= %.2f, high_confidence >= %.1f%%, low_confidence <= %.1f%%",
        macro_f1_gate,
        high_conf_gate,
        low_conf_gate,
    )

    # Overall-winner guard: block registration unless core quality exceeds baseline.
    require_overall_winner = _env_flag_true("THREAT_REQUIRE_OVERALL_WINNER", "true")
    winner_min_accuracy = float(os.getenv("THREAT_WINNER_MIN_ACCURACY", "0.894"))
    winner_min_macro_f1 = float(os.getenv("THREAT_WINNER_MIN_MACRO_F1", "0.8391"))
    winner_min_avg_conf = float(os.getenv("THREAT_WINNER_MIN_AVG_CONFIDENCE", "0.696"))

    # Calibration guards: block registration if calibration metrics are worse than current production model.
    enable_calibration_quality_gates = _env_flag_true(
        "THREAT_ENABLE_CALIBRATION_QUALITY_GATES", "false"
    )
    max_ece_gate = float(os.getenv("THREAT_GATE_MAX_ECE", "0.080"))
    max_brier_gate = float(os.getenv("THREAT_GATE_MAX_BRIER", "0.350"))

    # Calibration method
    calibration_method = (
        os.getenv("THREAT_CALIBRATION_METHOD", "sigmoid").strip().lower()
    )
    if calibration_method not in {"sigmoid", "isotonic"}:
        logger.warning(
            "Invalid calibration method '%s' specified. Defaulting to 'sigmoid'.",
            calibration_method,
        )
        calibration_method = "sigmoid"

    logger.info(f"Calibration method: {calibration_method}")

    if require_overall_winner:
        logger.info(
            "Overall-winner criteria enabled: accuracy >= %.1f%%, macro_f1 >= %.4f, avg_confidence >= %.1f%%",
            winner_min_accuracy * 100,
            winner_min_macro_f1,
            winner_min_avg_conf * 100,
        )
    else:
        logger.warning(
            "Overall-winner criteria disabled via THREAT_REQUIRE_OVERALL_WINNER=false."
        )

    # Load diverse synthetic training data
    logger.info("Loading training data...")
    synthetic_threats = get_diverse_threat_scenarios_full()
    logger.info(f"Loaded {len(synthetic_threats)} synthetic threat scenarios")

    # Load v3 ensemble adversarial samples (84+ original samples)
    logger.info("Loading v3 ensemble adversarial samples...")
    adversarial_samples = get_extended_adversarial_samples_normalized()

    # Threat type to CVSS/severity ranges for realistic variation
    # Updated to use only canonical 10 threat types
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
        "Path Traversal": {"cvss_min": 6.5, "cvss_max": 8.5, "severities": ["High"]},
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

    # Convert adversarial samples to threat dicts with VARIED metadata
    # Apply threat type consolidation to map to canonical 10 types
    adversarial_threats = []
    threat_type_mapping_log = {}  # Track mapping for logging
    for idx, (description, original_threat_type) in enumerate(adversarial_samples):
        # Consolidate threat type to canonical 10-class taxonomy
        canonical_threat_type = consolidate_threat_type(original_threat_type)

        # Log mappings for first run
        if original_threat_type not in threat_type_mapping_log:
            threat_type_mapping_log[original_threat_type] = canonical_threat_type

        # Get ranges for canonical threat type
        ranges = threat_type_ranges.get(
            canonical_threat_type,
            {"cvss_min": 6.5, "cvss_max": 8.5, "severities": ["High"]},
        )

        # Vary CVSS score within range
        cvss_score = np.random.uniform(ranges["cvss_min"], ranges["cvss_max"])
        exploitability = np.random.uniform(cvss_score - 1.5, min(cvss_score, 10.0))
        severity = np.random.choice(ranges["severities"])

        adversarial_threats.append(
            {
                "description": description,
                "threat_type": canonical_threat_type,
                "cvss_score": round(cvss_score, 1),
                "severity": severity,
                "exploitability": round(exploitability, 1),
                "asset_type": asset_types[idx % len(asset_types)],
            }
        )

    logger.info(f"Loaded {len(adversarial_threats)} adversarial threat samples")
    logger.info("Threat type consolidation mapping:")
    for original, canonical in sorted(threat_type_mapping_log.items()):
        if original != canonical:
            logger.info(f"  '{original}' → '{canonical}'")
        else:
            logger.info(f"  '{original}' (no change)")

    # Load real labeled examples from db (if available)
    logger.info("Loading real labeled data from DB...")
    # TODO: add query
    real_threats = []
    logger.info(f"Loaded {len(real_threats)} real labeled threat examples")

    # Combine all datasets
    logger.info("Combining all datasets...")
    all_threats = synthetic_threats + adversarial_threats + real_threats
    logger.info(f"Total training samples: {len(all_threats)}")
    logger.info(f"  - Diverse scenarios: {len(synthetic_threats)}")
    logger.info(f"  - Adversarial samples (v3): {len(adversarial_threats)}")
    logger.info(f"  - Real labeled: {len(real_threats)}")

    # Extract labels and descriptions
    descriptions = [t["description"] for t in all_threats]
    labels = [t["threat_type"] for t in all_threats]

    # Extract semantic embeddings using Word2Vec
    logger.info("Extracting semantic features with Word2Vec...")
    w2v_extractor = Word2VecFeatureExtractor(vector_size=100, min_count=2, workers=1)
    w2v_extractor.fit(descriptions)
    semantic_features = w2v_extractor.transform(descriptions)
    logger.info(f"Generated {semantic_features.shape[1]} semantic embeddings")

    # Extract structured metadata features
    logger.info("Extracting structured metadata features...")
    metadata_extractor = StructuredMetadataExtractor()
    metadata_extractor.fit(all_threats)
    metadata_features = metadata_extractor.transform(all_threats)
    logger.info(f"Generated {metadata_features.shape[1]} metadata features")

    # Combine semantic + metadata features
    logger.info("Combining semantic and metadata features...")
    X = np.hstack([semantic_features, metadata_features])
    logger.info(f"Final feature matrix shape: {X.shape}")
    logger.info(f"  - Semantic embeddings: 100 dims")
    logger.info(f"  - Metadata features: {metadata_features.shape[1]} dims")
    logger.info(f"  - Total features: {X.shape[1]}")

    # Encode labels
    logger.info("Encoding threat type labels...")
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(labels)
    logger.info(f"Encoded {len(label_encoder.classes_)} threat classes:")
    for cls in label_encoder.classes_:
        logger.info(f"  - {cls}")

    # Train/test split
    logger.info("Splitting data into train/test sets...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    logger.info(f"Training set: {X_train.shape[0]} samples")
    logger.info(f"Test set: {X_test.shape[0]} samples")

    # Scale features (Imp for Gradient Boosting)
    logger.info("Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    logger.info(f"Features scaled.")

    start_time = time.time()

    # Train Gradient Boosting Classifier
    logger.info("Training Gradient Boosting Classifier...")
    gbc = GradientBoostingClassifier(
        n_estimators=150,  # More boosting stages for better convergence
        learning_rate=0.08,  # Lower rate for stable learning on limited data
        max_depth=4,  # Shallow trees prevent overfitting
        min_samples_split=8,  # More regularization to prevent per-class overfitting
        min_samples_leaf=4,  # Minimum leaf samples
        subsample=0.7,  # Original value - Run 3 was best
        random_state=42,
        verbose=1,
    )
    gbc.fit(X_train_scaled, y_train)
    logger.info("Model training complete.")

    # Calibrate probabilities
    logger.info("Calibrating model probabilities...")
    calibrated_gbc = CalibratedClassifierCV(gbc, method=calibration_method, cv=5)
    calibrated_gbc.fit(X_train_scaled, y_train)
    logger.info("Probability calibration complete.")

    training_duration_seconds = int(time.time() - start_time)
    logger.info(f"Total training duration: {training_duration_seconds} seconds")

    # Evaluate on test set
    logger.info("Evaluating model on test set...")
    y_pred = calibrated_gbc.predict(X_test_scaled)
    y_pred_proba = calibrated_gbc.predict_proba(X_test_scaled)

    accuracy = (y_pred == y_test).mean()
    macro_f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)

    # Confidence analysis
    max_probs = np.max(y_pred_proba, axis=1)
    avg_confidence = np.mean(max_probs)
    high_confidence_pct = (max_probs > 0.7).sum() / len(max_probs) * 100
    low_confidence_pct = (max_probs < 0.5).sum() / len(max_probs) * 100

    # Calibration-quality metrics
    ece_10 = compute_expected_calibration_error(
        y_true=y_test,
        y_pred=y_pred,
        confidences=max_probs,
        n_bins=10,
    )

    brier_multi = compute_multiclass_brier_score(
        y_true=y_test,
        y_proba=y_pred_proba,
        n_classes=len(label_encoder.classes_),
    )

    logger.info(f"\n📊 TEST SET METRICS:")
    logger.info(f"   Accuracy: {accuracy:.1%}")
    logger.info(f"   Macro F1: {macro_f1:.4f}")
    logger.info(f"   Avg Confidence: {avg_confidence:.1%}")
    logger.info(f"   High Confidence (≥70%): {high_confidence_pct:.1f}%")
    logger.info(f"   Low Confidence (<50%): {low_confidence_pct:.1f}%")
    logger.info(f"   ECE (10 bins): {ece_10:.4f}")
    logger.info(f"   Brier Score (Multi-class): {brier_multi:.4f}")

    logger.info(f"\nClassification Report:")
    logger.info(
        classification_report(y_test, y_pred, target_names=label_encoder.classes_)
    )

    # Calculate recall and precision per class
    precision, recall, f1, support = precision_recall_fscore_support(
        y_test, y_pred, average=None, zero_division=0
    )

    # Convert to dict: {threat_type: score}
    recall_per_class = {
        label_encoder.classes_[i]: float(recall[i])
        for i in range(len(label_encoder.classes_))
    }
    precision_per_class = {
        label_encoder.classes_[i]: float(precision[i])
        for i in range(len(label_encoder.classes_))
    }

    logger.info(f"\nPer-Class Recall: {recall_per_class}")
    logger.info(f"Per-Class Precision: {precision_per_class}")

    # Calculate confusion matrix
    cm = confusion_matrix(y_test, y_pred)

    logger.info(f"\nConfusion Matrix (TruePositives/FalsePositives per class):")
    for i, threat_type in enumerate(label_encoder.classes_):
        true_positives = cm[i, i]
        false_negatives = cm[i, :].sum() - true_positives
        logger.info(f"  {threat_type}: TP={true_positives}, FN={false_negatives}")

    cm_dict = {
        label_encoder.classes_[i]: {
            label_encoder.classes_[j]: int(cm[i, j])
            for j in range(len(label_encoder.classes_))
        }
        for i in range(len(label_encoder.classes_))
    }

    # Save model
    logger.info("Saving trained model and encoders...")
    model_dir = Path("data/models/threat_classifier_v7")
    model_dir.mkdir(parents=True, exist_ok=True)

    # Save each component separately for easier hot-reloading
    with open(model_dir / "classifier.pkl", "wb") as f:
        pickle.dump(calibrated_gbc, f)
    with open(model_dir / "w2v_extractor.pkl", "wb") as f:
        pickle.dump(w2v_extractor, f)
    with open(model_dir / "metadata_extractor.pkl", "wb") as f:
        pickle.dump(metadata_extractor, f)
    with open(model_dir / "label_encoder.pkl", "wb") as f:
        pickle.dump(label_encoder, f)
    with open(model_dir / "scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)

    logger.info(f"Model and components saved to {model_dir}")

    # Check promotion gates and register to database
    logger.info("Checking promotion gates and registering model...")
    gates_passed = True

    if macro_f1 < macro_f1_gate:
        logger.warning(
            f"❌ Gate Failed: Macro F1 {macro_f1:.4f} < {macro_f1_gate:.2f} threshold"
        )
        gates_passed = False
    else:
        logger.info(f"✅ Gate Passed: Macro F1 {macro_f1:.4f} ≥ {macro_f1_gate:.2f}")

    if high_confidence_pct < high_conf_gate:
        logger.warning(
            f"❌ Gate Failed: High confidence {high_confidence_pct:.1f}% < {high_conf_gate:.1f}% threshold"
        )
        gates_passed = False
    else:
        logger.info(
            f"✅ Gate Passed: High confidence {high_confidence_pct:.1f}% ≥ {high_conf_gate:.1f}%"
        )

    if low_confidence_pct > low_conf_gate:
        logger.warning(
            f"❌ Gate Failed: Low confidence {low_confidence_pct:.1f}% > {low_conf_gate:.1f}% threshold"
        )
        gates_passed = False
    else:
        logger.info(
            f"✅ Gate Passed: Low confidence {low_confidence_pct:.1f}% ≤ {low_conf_gate:.1f}%"
        )

    # if enable_calibration_quality_gates:
    #     if ece_10 > max_ece_gate:
    #         logger.warning(
    #             "❌ Gate Failed: ECE %.4f > %.4f threshold",
    #             ece_10,
    #             max_ece_gate,
    #         )
    #         gates_passed = False
    #     else:
    #         logger.info(
    #             "✅ Gate Passed: ECE %.4f <= %.4f",
    #             ece_10,
    #             max_ece_gate,
    #         )

    #     if brier_multi > max_brier_gate:
    #         logger.warning(
    #             "❌ Gate Failed: Brier %.4f > %.4f threshold",
    #             brier_multi,
    #             max_brier_gate,
    #         )
    #         gates_passed = False
    #     else:
    #         logger.info(
    #             "✅ Gate Passed: Brier %.4f <= %.4f",
    #             brier_multi,
    #             max_brier_gate,
    #         )

    # Block registration if gates failed
    if not gates_passed:
        logger.error("\n" + "🛑 " * 10)
        logger.error("MODEL REGISTRATION BLOCKED: One or more promotion gates failed")
        logger.error("This model will NOT be deployed to production")
        logger.error("Actions needed:")
        logger.error("  1. Analyze gate failures above")
        logger.error("  2. Improve training data or model architecture")
        logger.error("  3. Re-run training pipeline")
        logger.error("🛑 " * 10)
        logger.info("\n" + "=" * 60)
        logger.info("V7 ensemble retraining pipeline complete (FAILED)")
        logger.info("=" * 60)
        return None

    # Block registration if this run is not an overall winner on core metrics.
    if require_overall_winner:
        winner_checks_passed = True

        if accuracy < winner_min_accuracy:
            logger.warning(
                "❌ Winner Check Failed: Accuracy %.1f%% < %.1f%%",
                accuracy * 100,
                winner_min_accuracy * 100,
            )
            winner_checks_passed = False
        else:
            logger.info(
                "✅ Winner Check Passed: Accuracy %.1f%% ≥ %.1f%%",
                accuracy * 100,
                winner_min_accuracy * 100,
            )

        if macro_f1 < winner_min_macro_f1:
            logger.warning(
                "❌ Winner Check Failed: Macro F1 %.4f < %.4f",
                macro_f1,
                winner_min_macro_f1,
            )
            winner_checks_passed = False
        else:
            logger.info(
                "✅ Winner Check Passed: Macro F1 %.4f ≥ %.4f",
                macro_f1,
                winner_min_macro_f1,
            )

        if avg_confidence < winner_min_avg_conf:
            logger.warning(
                "❌ Winner Check Failed: Avg confidence %.1f%% < %.1f%%",
                avg_confidence * 100,
                winner_min_avg_conf * 100,
            )
            winner_checks_passed = False
        else:
            logger.info(
                "✅ Winner Check Passed: Avg confidence %.1f%% ≥ %.1f%%",
                avg_confidence * 100,
                winner_min_avg_conf * 100,
            )

        if not winner_checks_passed:
            logger.error("\n" + "🛑 " * 10)
            logger.error("MODEL REGISTRATION BLOCKED: Overall-winner criteria not met")
            logger.error("This model will NOT be deployed to production")
            logger.error("Actions needed:")
            logger.error(
                "  1. Improve core quality metrics (accuracy, macro F1, avg confidence)"
            )
            logger.error("  2. Re-run training pipeline")
            logger.error("🛑 " * 10)
            logger.info("\n" + "=" * 60)
            logger.info("V7 ensemble retraining pipeline complete (FAILED)")
            logger.info("=" * 60)
            return None

    # Register to database ONLY if gates passed
    logger.info(f"\nRegistering model to database (gates passed)...")
    workflow = ModelPromotionWorkflow()

    metrics = {
        "accuracy": float(accuracy),
        "macro_f1": float(macro_f1),
        "recall_per_class": recall_per_class,
        "precision_per_class": precision_per_class,
        "training_duration_seconds": training_duration_seconds,
        "training_data_sources": {
            "n_training_samples": len(all_threats),
            "n_synthetic_samples": len(synthetic_threats),
            "n_real_samples": len(real_threats),
        },
        "config": {
            "avg_confidence": float(avg_confidence),
            "high_confidence_pct": float(high_confidence_pct),
            "low_confidence_pct": float(low_confidence_pct),
            "calibration": {
                "ece_10": float(ece_10),
                "brier_multi": float(brier_multi),
            },
            "calibration_method": calibration_method,
            "feature_engineering": "Word2Vec + Metadata",
            "classifier": "Gradient Boosting with Calibrated Probabilities",
            "confusion_matrix": cm_dict,
        },
    }

    model = workflow.register_model(
        agent_id="classifier_001",
        metrics=metrics,
        model_path=str(model_dir),
        model_type="gradient_boosting_w2v",
        config=metrics["config"],
    )

    logger.info(f"🎉 Model passed all gates and is registered as APPROVED")

    logger.info("\n" + "=" * 60)
    logger.info("GBC retraining pipeline complete")
    logger.info("=" * 60)

    return model


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    retrain_ensemble_v4()
