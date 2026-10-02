"""
Agent 3 Pattern Detection Model Evaluation Script

Evaluates ML-based attack pattern detection with promotion gates.
Similar structure to eval_agent2_classifier.py but for sequence classification.

Supports blended training: core patterns + expanded patterns for better generalization.
Usage:
  python eval_agent3_pattern_detection.py          # Core patterns only
  python eval_agent3_pattern_detection.py --blend  # Core + expanded patterns (recommended)
"""

import argparse
import os
import pickle
import sys
from collections import Counter

from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import numpy as np

# Import training data
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "data"))
from data.attack_patterns_for_training import get_attack_pattern_sequences
from data.expanded_attack_patterns_for_training import (
    get_expanded_attack_pattern_sequences,
)


def extract_features_from_sequence(threat_sequence):
    """
    Convert threat sequence into numeric features for ML model.

    Returns: numpy array of 9 features
    Features: [num_threats, severity_mean, severity_max, risk_mean, risk_max, time_sum, time_mean, tactic_diversity, threat_diversity]
    """
    severity_map = {"critical": 10, "high": 7.5, "medium": 5, "low": 2.5}

    # Feature extraction
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

    # Tactic diversity
    all_tactics = []
    for threat in threat_sequence:
        all_tactics.extend(threat.get("mitre_tactics", []))
    tactic_diversity = len(set(all_tactics)) / max(len(all_tactics), 1)

    # Threat diversity (how many different threat types)
    threat_types = [t.get("threat_type") for t in threat_sequence]
    threat_diversity = len(set(threat_types)) / len(threat_types) if threat_types else 0

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
    )

    return features


def main(use_blend=False):
    """
    Evaluate Agent 3 pattern detection model.

    Args:
        use_blend: If True, combine core + expanded patterns for blended training
    """
    print("=" * 70)
    print("AGENT 3 PATTERN DETECTION EVALUATION")
    print("=" * 70)

    # Get training sequences
    sequences = list(get_attack_pattern_sequences())

    if use_blend:
        print("\n📊 BLENDED MODE: Combining core + expanded patterns")
        expanded_sequences = list(get_expanded_attack_pattern_sequences())
        sequences.extend(expanded_sequences)
        print(f"   Core patterns: {len(get_attack_pattern_sequences())}")
        print(f"   Expanded patterns: {len(expanded_sequences)}")
        print(f"   Total sequences: {len(sequences)}")
    else:
        print("\n📊 CORE MODE: Using core patterns only")
        print(f"   Total sequences: {len(sequences)}")

    # Extract features and labels
    X = np.array([extract_features_from_sequence(seq[0]) for seq in sequences])
    y = np.array([seq[1] for seq in sequences])  # True/False for real pattern

    real_count = np.sum(y)
    false_count = np.sum(~y)

    print(f"\n   Real patterns: {real_count}")
    print(f"   False positives: {false_count}")
    print(f"   Balance ratio: {real_count / false_count:.2f}:1")

    # Train/test split (stratified to maintain class balance)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    print(f"\n   Train set: {len(X_train)} samples")
    print(f"   Test set: {len(X_test)} samples")

    # Normalize features for Random Forest (helps with mixed scale features)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train Random Forest for pattern detection
    print("\n🔄 Training Random Forest classifier...")
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
    )
    model.fit(X_train_scaled, y_train)
    print("   ✓ Training complete")

    # Predictions
    y_pred = model.predict(X_test_scaled)
    y_pred_proba = model.predict_proba(X_test_scaled)

    # Metrics
    print("\n" + "=" * 70)
    print("PATTERN DETECTION METRICS")
    print("=" * 70)

    macro_f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)
    weighted_f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)

    # Per-class metrics
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
    false_negative_rate = fn / (fn + tp) if (fn + tp) > 0 else 0

    print(f"\nMacro F1:       {macro_f1:.4f}")
    print(f"Weighted F1:    {weighted_f1:.4f}")
    print(f"Accuracy:       {(np.sum(y_pred == y_test) / len(y_test)):.4f}")

    print("\nClassification Report:")
    print(
        classification_report(
            y_test, y_pred, target_names=["Not Pattern", "Real Pattern"], digits=3
        )
    )

    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"                Predicted Not Pattern    Predicted Real Pattern")
    print(f"Actual Not Pattern        {cm[0][0]:3d}                  {cm[0][1]:3d}")
    print(f"Actual Real Pattern       {cm[1][0]:3d}                  {cm[1][1]:3d}")

    # Calculate recall rates for gates
    real_pattern_recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    false_positive_recall = tn / (tn + fp) if (tn + fp) > 0 else 0

    # Promotion gates
    print("\n" + "=" * 70)
    print("MODEL PROMOTION GATES")
    print("=" * 70)

    gate1_pass = macro_f1 >= 0.75
    gate2_pass = real_pattern_recall >= 0.70
    gate3_pass = false_positive_recall >= 0.70

    print(
        f"\n✓ PASS Gate 1: Macro F1 >= 0.75"
        if gate1_pass
        else f"✗ FAIL Gate 1: Macro F1 >= 0.75"
    )
    print(f"         Current: {macro_f1:.4f} (overall balance)")

    print(
        f"\n✓ PASS Gate 2: Real Pattern Recall >= 0.70"
        if gate2_pass
        else f"✗ FAIL Gate 2: Real Pattern Recall >= 0.70"
    )
    print(f"         Current: {real_pattern_recall:.4f} (catch real attacks)")

    print(
        f"\n✓ PASS Gate 3: False Positive Recall >= 0.70"
        if gate3_pass
        else f"✗ FAIL Gate 3: False Positive Recall >= 0.70"
    )
    print(f"         Current: {false_positive_recall:.4f} (avoid false alarms)")

    all_pass = gate1_pass and gate2_pass and gate3_pass

    print("\n" + "=" * 70)
    if all_pass:
        print("✅ ALL GATES PASSED — Model approved for promotion")
        # Save model
        model_dir = os.path.join(os.path.dirname(__file__), "data", "models")
        os.makedirs(model_dir, exist_ok=True)
        model_path = os.path.join(model_dir, "threat_hunter.pkl")

        with open(model_path, "wb") as f:
            pickle.dump({"model": model, "scaler": scaler}, f)
        print(f"   ✓ Model saved to {model_path}")

        # Save metadata
        metadata = {
            "training_mode": "blend" if use_blend else "core",
            "total_sequences": len(sequences),
            "real_patterns": real_count,
            "false_positives": false_count,
            "macro_f1": macro_f1,
            "gates_pass": True,
        }
        print(f"\n   Training metadata:")
        print(f"   - Mode: {metadata['training_mode']}")
        print(f"   - Final Macro F1: {metadata['macro_f1']:.4f}")
    else:
        print("❌ GATES FAILED — Model rejected from promotion")
        print("   Review metrics and retrain with better data:")
        if not gate1_pass:
            print(f"   - Gate 1: Macro F1 too low ({macro_f1:.4f} < 0.75)")
        if not gate2_pass:
            print(
                f"   - Gate 2: Real pattern recall too low ({real_pattern_recall:.4f} < 0.70)"
            )
        if not gate3_pass:
            print(
                f"   - Gate 3: False positive recall too low ({false_positive_recall:.4f} < 0.70)"
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Evaluate Agent 3 pattern detection model"
    )
    parser.add_argument(
        "--blend",
        action="store_true",
        help="Use blended training (core + expanded patterns)",
    )
    args = parser.parse_args()

    main(use_blend=args.blend)
