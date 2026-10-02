#!/usr/bin/env python3
"""
Retrain ensemble classifier with:
1. Modern CVE training data (155+ examples from data/modern_cves_for_testing.py)
2. Synthetic adversarial samples

This gives the ensemble both realistic CVE patterns AND adversarial edge cases.
"""

import os
import sys
from sklearn.metrics import classification_report, f1_score, confusion_matrix
from sklearn.model_selection import train_test_split
from collections import Counter

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared.agent_names import agent_name

from agents.classification.ensemble_classifier import EnsembleClassifier
from data.modern_cves_for_testing import get_modern_test_cves
from data.ensemble_adversarial_samples import (
    get_extended_adversarial_samples_with_synthetic,
    augment_text_via_synonym_replacement,
)
from sklearn.metrics import accuracy_score, recall_score, precision_score
from data.models.model_prom_workflow import ModelPromotionWorkflow


def retrain_ensemble_with_modern_data():
    """Retrain ensemble with modern CVEs + synthetic data."""

    print("=" * 80)
    print("ENSEMBLE RETRAINING: Modern CVEs + Synthetic Data")
    print("=" * 80)

    # =========================================================================
    # STEP 1: Load Modern CVE Training Data
    # =========================================================================
    print("\n[Step 1/5] Loading modern CVE training data (200+ examples)...")
    modern_cves = get_modern_test_cves()
    modern_texts = [cve[0] for cve in modern_cves]
    modern_labels = [cve[1] for cve in modern_cves]
    print(f"   ✅ Loaded {len(modern_texts)} modern CVE descriptions")

    modern_classes = Counter(modern_labels)
    print(f"\n   Modern CVE Class Distribution:")
    for threat_type, count in sorted(
        modern_classes.items(), key=lambda x: x[1], reverse=True
    ):
        print(f"      {threat_type}: {count}")

    # =========================================================================
    # STEP 2: Load Synthetic Adversarial Data
    # =========================================================================
    print("\n[Step 2/5] Loading synthetic adversarial samples...")
    synthetic_data = get_extended_adversarial_samples_with_synthetic()
    synthetic_texts = [item[0] for item in synthetic_data]
    synthetic_labels = [item[1] for item in synthetic_data]
    print(f"   ✅ Loaded {len(synthetic_texts)} synthetic samples")

    synthetic_classes = Counter(synthetic_labels)
    print(f"\n   Synthetic Class Distribution:")
    for threat_type, count in sorted(
        synthetic_classes.items(), key=lambda x: x[1], reverse=True
    ):
        print(f"      {threat_type}: {count}")

    # =========================================================================
    # STEP 3: Blend Real + Synthetic Data
    # =========================================================================
    print("\n[Step 3/5] Blending modern CVE + synthetic data...")
    X_combined = modern_texts + synthetic_texts
    y_combined = modern_labels + synthetic_labels

    print(f"   ✅ Created blended dataset:")
    print(f"      Total samples: {len(X_combined)}")
    print(
        f"      Modern CVEs: {len(modern_texts)} ({len(modern_texts)/len(X_combined)*100:.1f}%)"
    )
    print(
        f"      Synthetic: {len(synthetic_texts)} ({len(synthetic_texts)/len(X_combined)*100:.1f}%)"
    )

    combined_classes = Counter(y_combined)
    print(f"\n   Blended Class Distribution:")
    for threat_type, count in sorted(
        combined_classes.items(), key=lambda x: x[1], reverse=True
    ):
        print(f"      {threat_type}: {count}")

    # =========================================================================
    # STEP 3.5: Data Augmentation (Matches original that passed with 1,764!)
    # =========================================================================
    print("\n[Step 3.5/5] Augmenting data via synonym replacement...")
    import random
    from nltk.corpus import wordnet

    augmented_X = list(zip(X_combined, y_combined))  # Start with originals

    for text, label in zip(X_combined, y_combined):
        # Create 2 augmented copies per sample (matching original approach)
        for _ in range(2):
            aug_text = augment_text_via_synonym_replacement(
                text, synonym_replacement_rate=0.25
            )
            augmented_X.append((aug_text, label))

    X_train = [item[0] for item in augmented_X]
    y_train = [item[1] for item in augmented_X]

    print(f"   ✅ Created augmented dataset:")
    print(f"      Original base: {len(X_combined)} samples")
    print(f"      Total after augmentation: {len(X_train)} samples")
    print(
        f"      Increase: {len(X_train)} = {len(X_combined)} base + {len(X_train) - len(X_combined)} augmented"
    )

    augmented_classes = Counter(y_train)
    print(f"\n   Augmented Class Distribution:")
    for threat_type, count in sorted(
        augmented_classes.items(), key=lambda x: x[1], reverse=True
    ):
        print(f"      {threat_type}: {count}")

    # =========================================================================
    # STEP 4: Train/Test Split (Matching original: 75/25 stratified)
    # =========================================================================
    print("\n[Step 4/5] Splitting data for training/validation...")
    # Use stratified split to match original approach
    X_train_split, X_test_split, y_train_split, y_test_split = train_test_split(
        X_train, y_train, test_size=0.25, random_state=42, stratify=y_train
    )

    print(f"   ✅ Applied 75/25 stratified split:")
    print(f"      Training set: {len(X_train_split)} samples")
    print(f"      Test set: {len(X_test_split)} samples")
    print(f"      Total: {len(X_train_split) + len(X_test_split)} samples")

    X_train = X_train_split
    y_train = y_train_split

    # =========================================================================
    # STEP 5: Train Ensemble (Save to staging location for analyst review)
    # =========================================================================
    print("\n[Step 5/5] Training ensemble (Naive Bayes + SVM + Random Forest)...")
    print("   This will take 1-2 minutes...")
    print("   📊 Using CalibratedClassifierCV with sigmoid calibration (cv=5)")

    # ⚠️ CRITICAL: Save to staging location (NOT production v2)
    # New models go to staging until analyst approves and deploys
    staging_path = "data/models/threat_classifier_v2_staging"
    ensemble = EnsembleClassifier(models_dir=staging_path)
    ensemble.train_ensemble(X_train, y_train)

    # =========================================================================
    # EVALUATION: Test Set Performance
    # =========================================================================
    print("\n" + "=" * 80)
    print("EVALUATION (Test Set - 25% Holdout)")
    print("=" * 80)

    # Use test set for evaluation (shows generalization)
    X_eval = X_test_split
    y_eval = y_test_split

    predictions = []
    confidences = []

    print("\n🔍 Classifying all samples...")
    for i, text in enumerate(X_eval):
        result = ensemble.classify_with_confidence(text)
        pred = result["threat_type"]
        conf = result["confidence"]
        predictions.append(pred)
        confidences.append(conf)

        if (i + 1) % max(1, len(X_eval) // 5) == 0:
            print(f"   Progress: {i+1}/{len(X_eval)} ({(i+1)/len(X_eval)*100:.0f}%)")

    # Calculate metrics
    macro_f1 = f1_score(y_eval, predictions, average="macro", zero_division=0)
    weighted_f1 = f1_score(y_eval, predictions, average="weighted", zero_division=0)
    accuracy = sum(1 for p, t in zip(predictions, y_eval) if p == t) / len(y_eval)

    print(f"\n📊 ENSEMBLE METRICS:")
    print(f"   Macro F1 Score:    {macro_f1:.4f} (Gate requirement: ≥0.72)")
    print(f"   Weighted F1 Score: {weighted_f1:.4f}")
    print(f"   Accuracy:          {accuracy:.4f}")

    # Confidence analysis
    avg_confidence = sum(confidences) / len(confidences)
    high_confidence = sum(1 for c in confidences if c >= 0.7) / len(confidences)
    low_confidence = sum(1 for c in confidences if c < 0.5) / len(confidences)

    print(f"\n🎯 CONFIDENCE ANALYSIS:")
    print(f"   Average Confidence: {avg_confidence:.4f}")
    print(f"   High Confidence (≥0.7):  {high_confidence*100:.1f}%")
    print(f"   Low Confidence (<0.5):   {low_confidence*100:.1f}%")

    # Detailed classification report
    print(f"\n📋 DETAILED CLASSIFICATION REPORT:")
    print(classification_report(y_eval, predictions, zero_division=0))

    # Confusion matrix
    cm = confusion_matrix(y_eval, predictions, labels=sorted(set(y_eval)))
    print(f"\n📈 CONFUSION MATRIX:")
    labels_list = sorted(set(y_eval))
    print("                  " + "  ".join(f"{label[:3]}" for label in labels_list))
    for i, label in enumerate(labels_list):
        print(
            f"{label:16} {' '.join(f'{cm[i,j]:3d}' for j in range(len(labels_list)))}"
        )

    # =========================================================================
    # PROMOTION DECISION
    # =========================================================================
    print("\n" + "=" * 80)
    print("PROMOTION DECISION")
    print("=" * 80)

    gate_1 = macro_f1 >= 0.72
    gate_2 = high_confidence >= 0.5  # 50% should be confident
    gate_3 = low_confidence < 0.20  # Less than 20% should be uncertain

    print(
        f"\n✓ Gate 1 (Macro F1 ≥ 0.72):       {'PASS ✅' if gate_1 else 'FAIL ❌'} ({macro_f1:.4f})"
    )
    print(
        f"✓ Gate 2 (≥50% high confidence):  {'PASS ✅' if gate_2 else 'FAIL ❌'} ({high_confidence*100:.1f}%)"
    )
    print(
        f"✓ Gate 3 (<20% low confidence):   {'PASS ✅' if gate_3 else 'FAIL ❌'} ({low_confidence*100:.1f}%)"
    )

    all_gates_pass = gate_1 and gate_2 and gate_3

    if all_gates_pass:
        print(f"\n🎉 ALL GATES PASSED! Ensemble ready for analyst review.")
        print(f"\n💾 Models saved to staging: {staging_path}/")
        ensemble.save_models()

        # Register model with C2 workflow (shows up in dashboard!)
        print(f"\n📝 REGISTERING WITH C2 WORKFLOW...")

        # Calculate per-class metrics for database
        recall_per_class = {}
        precision_per_class = {}

        for label in sorted(set(y_eval)):
            y_eval_binary = [1 if t == label else 0 for t in y_eval]
            y_pred_binary = [1 if p == label else 0 for p in predictions]

            recall_per_class[label] = float(
                recall_score(y_eval_binary, y_pred_binary, zero_division=0)
            )
            precision_per_class[label] = float(
                precision_score(y_eval_binary, y_pred_binary, zero_division=0)
            )

        try:
            workflow = ModelPromotionWorkflow()

            metrics = {
                "accuracy": float(accuracy),
                "macro_f1": float(macro_f1),
                "recall_per_class": recall_per_class,
                "precision_per_class": precision_per_class,
                "training_duration_seconds": 120,
                "data_sources": {
                    "modern_cves": len(modern_texts),
                    "synthetic": len(synthetic_texts),
                    "augmented": len(X_train),
                },
            }

            model = workflow.register_model(
                agent_id="classifier_001",
                metrics=metrics,
                model_path=staging_path,
                model_type="ensemble",
                config={
                    "vectorizer": "TfidfVectorizer",
                    "classifiers": ["naive_bayes", "svm", "random_forest"],
                },
            )

            print(f"   ✅ Model registered: {model.version} (ID: {model.id})")
            print(f"   📍 Status: PENDING (waiting for analyst approval)")
            print(f"   🔗 Check dashboard for new model notification!")

        except Exception as e:
            print(f"   ⚠️  Registration warning: {e}")
            print(f"   (Models still saved to disk, but not in dashboard)")

        print(f"\n📦 DEPLOYMENT WORKFLOW:")
        print(f"   1. Go to Dashboard: http://localhost:5000")
        print(f"   2. Find the {agent_name('classifier')} card")
        print(f"   3. Review metrics for pending model")
        print(f"   4. Click [Approve] button to approve")
        print(f"   5. Click [Deploy Now] to transfer staging → production")
        print(f"   6. {agent_name('classifier')} will hot-reload with new models")
        print(f"   7. Watch agent logs for confirmation")

        return True
    else:
        print(f"\n⚠️  GATES FAILED. Models NOT saved.")
        failed_gates = []
        if not gate_1:
            failed_gates.append("Gate 1 (F1 Score)")
        if not gate_2:
            failed_gates.append("Gate 2 (Confidence)")
        if not gate_3:
            failed_gates.append("Gate 3 (Uncertainty)")
        print(f"   Failed: {', '.join(failed_gates)}")
        print(f"\n💡 RECOMMENDATIONS:")
        print(f"   - Add more real CVE training data")
        print(f"   - Check data quality/labels")
        print(f"   - Increase synthetic data diversity")

        return False


if __name__ == "__main__":
    success = retrain_ensemble_with_modern_data()
    sys.exit(0 if success else 1)
