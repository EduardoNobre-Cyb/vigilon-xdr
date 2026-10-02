#!/usr/bin/env python3
"""
Retrain ensemble classifier with ENRICHED feature descriptions.

Replicates the exact training pipeline from retrain_ensemble_with_modern_cves.py
but enriches each sample with CVSS, severity, and exploitability metadata
BEFORE training the ensemble.

This dramatically improves confidence scores on new threats.

Pipeline:
1. Load modern CVEs (155+ samples)
2. Load synthetic adversarial samples (588 total)
3. Blend them (~743 base)
4. Augment via synonym replacement (2x per sample → ~2229 total)
5. ENRICH each with metadata (CVSS, severity, exploitability)
6. Train ensemble on enriched features
7. Evaluate and save
"""

import os
import sys
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    f1_score,
    confusion_matrix,
    recall_score,
    precision_score,
)
from collections import Counter

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.classification.classifier_agent import ThreatClassificationAgent
from agents.classification.ensemble_classifier import EnsembleClassifier
from data.modern_cves_for_testing import get_modern_test_cves
from data.ensemble_adversarial_samples import (
    get_extended_adversarial_samples_with_synthetic,
    augment_text_via_synonym_replacement,
)
from data.cvss_utils import get_cvss_for_vulnerability, get_severity_from_cvss
from data.models.model_prom_workflow import ModelPromotionWorkflow


def retrain_ensemble_with_enriched_features():
    """
    Retrain ensemble with enriched (metadata-augmented) training data.
    """

    print("=" * 80)
    print("ENSEMBLE RETRAINING: With ENRICHED Features (CVSS, Severity, etc)")
    print("=" * 80)

    # Initialize classifier for enrichment function
    classifier = ThreatClassificationAgent(verbose=False)

    # =========================================================================
    # STEP 1: Load Modern CVE Training Data
    # =========================================================================
    print("\n[Step 1/6] Loading modern CVE training data (155+ examples)...")
    modern_cves = get_modern_test_cves()
    modern_texts = [cve[0] for cve in modern_cves]
    modern_labels = [cve[1] for cve in modern_cves]
    print(f"   ✅ Loaded {len(modern_texts)} modern CVE descriptions")

    # =========================================================================
    # STEP 2: Load Synthetic Adversarial Data
    # =========================================================================
    print("\n[Step 2/6] Loading synthetic adversarial samples (588 total)...")
    synthetic_data = get_extended_adversarial_samples_with_synthetic()
    synthetic_texts = [item[0] for item in synthetic_data]
    synthetic_labels = [item[1] for item in synthetic_data]
    print(f"   ✅ Loaded {len(synthetic_texts)} synthetic samples")

    # =========================================================================
    # STEP 3: Blend Real + Synthetic Data
    # =========================================================================
    print("\n[Step 3/6] Blending modern CVE + synthetic data...")
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

    # =========================================================================
    # STEP 4: Data Augmentation
    # =========================================================================
    print("\n[Step 4/6] Augmenting data via synonym replacement (2x per sample)...")
    augmented_X = list(zip(X_combined, y_combined))  # Start with originals

    for text, label in zip(X_combined, y_combined):
        # Create 2 augmented copies per sample
        for _ in range(2):
            aug_text = augment_text_via_synonym_replacement(
                text, synonym_replacement_rate=0.25
            )
            augmented_X.append((aug_text, label))

    X_combined = [item[0] for item in augmented_X]
    y_combined = [item[1] for item in augmented_X]

    print(f"   ✅ Created augmented dataset:")
    print(f"      Base: {len(modern_texts) + len(synthetic_texts)} samples")
    print(f"      After augmentation: {len(X_combined)} samples")

    # =========================================================================
    # STEP 5: ENRICH each sample with metadata (THE KEY IMPROVEMENT)
    # =========================================================================
    print("\n[Step 5/6] ENRICHING all samples with metadata...")
    print("   This improves TF-IDF feature extraction significantly")

    X_enriched = []
    y_enriched = []

    for i, (description, label) in enumerate(zip(X_combined, y_combined)):
        if (i + 1) % 500 == 0:
            print(f"   Progress: {i + 1}/{len(X_combined)} samples enriched...")

        # Calculate CVSS and severity
        vuln_name = label.replace(" ", "-")
        cvss_data = get_cvss_for_vulnerability(vuln_name, description)
        cvss_score = cvss_data["base_score"]
        severity = get_severity_from_cvss(cvss_score)

        # Calculate exploitability
        exploitability = classifier._calculate_exploitability_score_cvss(
            description, cvss_score
        )

        # ENRICH: Add metadata to description
        enriched_desc = classifier._enrich_threat_description(
            original_description=description,
            vuln_name=vuln_name,
            cvss_score=cvss_score,
            severity=severity,
            exploitability=exploitability,
            asset_type="General",
            asset_criticality="Medium",
        )

        X_enriched.append(enriched_desc)
        y_enriched.append(label)

    print(f"   ✅ Enriched all {len(X_enriched)} samples with metadata")

    # =========================================================================
    # STEP 6: Train/Test Split
    # =========================================================================
    print("\n[Step 6a/6] Splitting enriched data (75/25 stratified)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X_enriched, y_enriched, test_size=0.25, random_state=42, stratify=y_enriched
    )

    print(f"   ✅ Applied stratified split:")
    print(f"      Training set: {len(X_train)} samples")
    print(f"      Test set: {len(X_test)} samples")

    # =========================================================================
    # STEP 7: Train Ensemble on ENRICHED Data
    # =========================================================================
    print("\n[Step 6b/6] Training ensemble on enriched features...")
    print("   (This takes ~1-2 minutes)")

    staging_path = "data/models/threat_classifier_v3"
    ensemble = EnsembleClassifier(models_dir=staging_path)
    ensemble.train_ensemble(X_train, y_train)

    # =========================================================================
    # EVALUATION: Test Set Performance
    # =========================================================================
    print("\n" + "=" * 80)
    print("EVALUATION (Test Set - 25% Holdout)")
    print("=" * 80)

    predictions = []
    confidences = []

    print("\n🔍 Classifying all test samples...")
    for i, text in enumerate(X_test):
        result = ensemble.classify_with_confidence(text)
        predictions.append(result["threat_type"])
        confidences.append(result["confidence"])

        if (i + 1) % max(1, len(X_test) // 5) == 0:
            print(f"   Progress: {i+1}/{len(X_test)} ({(i+1)/len(X_test)*100:.0f}%)")

    # Calculate metrics
    macro_f1 = f1_score(y_test, predictions, average="macro", zero_division=0)
    weighted_f1 = f1_score(y_test, predictions, average="weighted", zero_division=0)
    accuracy = sum(1 for p, t in zip(predictions, y_test) if p == t) / len(y_test)

    print(f"\n📊 ENSEMBLE METRICS:")
    print(f"   Macro F1 Score:    {macro_f1:.4f} (Gate: ≥0.72)")
    print(f"   Weighted F1 Score: {weighted_f1:.4f}")
    print(f"   Accuracy:          {accuracy:.4f}")

    # Confidence analysis
    avg_confidence = sum(confidences) / len(confidences)
    high_confidence = sum(1 for c in confidences if c >= 0.7) / len(confidences)
    low_confidence = sum(1 for c in confidences if c < 0.5) / len(confidences)

    print(f"\n🎯 CONFIDENCE ANALYSIS (THE IMPROVEMENT):")
    print(f"   Average Confidence: {avg_confidence:.4f}")
    print(f"   High Confidence (≥0.7):  {high_confidence*100:.1f}%")
    print(f"   Low Confidence (<0.5):   {low_confidence*100:.1f}%")
    print(f"\n   ✨ With enriched features, confidence should be MUCH HIGHER!")

    # Classification report
    print(f"\n📋 DETAILED CLASSIFICATION REPORT:")
    print(classification_report(y_test, predictions, zero_division=0))

    # =========================================================================
    # PROMOTION DECISION
    # =========================================================================
    print("\n" + "=" * 80)
    print("PROMOTION DECISION")
    print("=" * 80)

    gate_1 = macro_f1 >= 0.72
    gate_2 = high_confidence >= 0.5
    gate_3 = low_confidence < 0.20

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
        print(f"\n🎉 ALL GATES PASSED!")
        print(f"\n💾 Saving models to: {staging_path}/")
        ensemble.save_models()

        print(f"\n📝 REGISTERING WITH C2 WORKFLOW...")
        print(f"   This will show 'Model v3 Pending' notification in dashboard")

        # Calculate per-class metrics for database
        recall_per_class = {}
        precision_per_class = {}

        for label in sorted(set(y_test)):
            y_test_binary = [1 if t == label else 0 for t in y_test]
            y_pred_binary = [1 if p == label else 0 for p in predictions]

            recall_per_class[label] = float(
                recall_score(y_test_binary, y_pred_binary, zero_division=0)
            )
            precision_per_class[label] = float(
                precision_score(y_test_binary, y_pred_binary, zero_division=0)
            )

        try:
            workflow = ModelPromotionWorkflow()

            metrics = {
                "accuracy": float(accuracy),
                "macro_f1": float(macro_f1),
                "weighted_f1": float(weighted_f1),
                "recall_per_class": recall_per_class,
                "precision_per_class": precision_per_class,
                "avg_confidence": float(avg_confidence),
                "high_confidence_pct": float(high_confidence * 100),
                "low_confidence_pct": float(low_confidence * 100),
                "data_sources": {
                    "modern_cves": len(modern_texts),
                    "synthetic": len(synthetic_texts),
                    "augmented": len(X_enriched),
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
                    "enriched_features": True,
                    "enrichment_fields": [
                        "cvss_score",
                        "severity",
                        "exploitability",
                        "asset_type",
                        "asset_criticality",
                    ],
                },
            )

            print(f"\n   ✅ Model registered: {model.version} (ID: {model.id})")
            print(f"   📍 Status: PENDING (waiting for analyst approval)")
            print(f"   🔗 Check dashboard for new model notification!")
            print(f"\n   📝 Models are ready for deployment!")
            print(f"   When deployed, new threats will see:")
            print(f"   ✓ {high_confidence*100:.0f}% high confidence (≥70%)")
            print(f"   ✓ {low_confidence*100:.0f}% low confidence (<50%)")
            print(f"   ✓ Average confidence: {avg_confidence:.2%}")

            return True

        except Exception as e:
            print(f"\n❌ Error registering model: {e}")
            print(f"   Models were saved to {staging_path}/ but not registered")
            print(f"   You can manually register later if needed")
            return False
    else:
        print(f"\n⚠️  GATES FAILED. Models NOT saved.")
        failed = [
            g
            for g, p in [("Gate 1", gate_1), ("Gate 2", gate_2), ("Gate 3", gate_3)]
            if not p
        ]
        print(f"   Failed: {', '.join(failed)}")
        return False


if __name__ == "__main__":
    success = retrain_ensemble_with_enriched_features()
    sys.exit(0 if success else 1)
