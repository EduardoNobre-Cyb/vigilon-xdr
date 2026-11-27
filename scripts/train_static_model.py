import argparse
import json
import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
)
from imblearn.over_sampling import SMOTE

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from agents.static_feature_extractor import (
    StaticBinaryFeatureExtractor, get_feature_names,
    DocumentFeatureExtractor, get_doc_feature_names,
)


def extract_from_directory(directory: str, label: int, extractor: StaticBinaryFeatureExtractor):
    samples = []
    skipped = 0

    for root, _dirs, files in os.walk(directory):
        for fname in files:
            path = os.path.join(root, fname)
            try:
                features = extractor.extract_features(path)
                if features is None:
                    skipped += 1
                    continue
                features["_label"] = label
                features["_path"] = path
                samples.append(features)
            except Exception as e:
                print(f"    [!] Error processing {path}: {e}")
                skipped += 1

    print(f"    [*] Extracted {len(samples)} samples from {directory}, skipped {skipped} files.")
    return samples


def main():
    parser = argparse.ArgumentParser(description="Train static binary analysis model")
    parser.add_argument("--benign-dir", required=True, help="Directory containing benign files")
    parser.add_argument("--malware-dir", required=True, help="Directory containing malware files")
    parser.add_argument("--output-dir", default="data/model/EDR", help="Where to save model files")
    parser.add_argument("--json-out", default=None, help="Optional: save features as JSON for inspection")
    parser.add_argument("--doc-mode", action="store_true", help="Train document model (PDF/Office/RTF) instead of binary (PE/ELF)")
    args = parser.parse_args()

    if args.doc_mode:
        feature_names = get_doc_feature_names()
        extractor = DocumentFeatureExtractor()
        model_prefix = "doc"
    else: 
        feature_names = get_feature_names()
        extractor = StaticBinaryFeatureExtractor()
        model_prefix = "file"

    print("=" * 60)
    print("STATIC BINARY ANALYSIS — Training Pipeline")
    print("=" * 60)

    print("\n[*] Extracting features from benign samples...")
    benign = extract_from_directory(args.benign_dir, label=0, extractor=extractor)

    print("\n[*] Extracting features from malware samples...")
    malicious = extract_from_directory(args.malware_dir, label=1, extractor=extractor)

    all_samples = benign + malicious
    if len(all_samples) < 20:
        print(f"\n[!] Only {len(all_samples)} samples, need at least 20. Exiting.")
        sys.exit(1)

    df = pd.DataFrame(all_samples)
    labels = df["_label"].values
    paths = df["_path"].values

    for col in feature_names:
        if col not in df.columns:
            df[col] = 0
    X = df[feature_names].values
    y = labels

    print(f"\n  Total Samples: {len(X)}")
    print(f"  Benign Samples: {np.sum(y == 0)}")
    print(f"  Malware Samples: {np.sum(y == 1)}")
    print(f"  Features per sample: {X.shape[1]}")

    if args.json_out:
        records = []
        for i, path in enumerate(paths):
            rec = {name: float(X[i][j]) for j, name in enumerate(feature_names)}
            rec["_label"] = int(y[i])
            rec["_path"] = str(path)
            records.append(rec)
        with open(args.json_out, "w") as f:
            json.dump(records, f, indent=2)
        print(f"\n[*] Saved extracted features to {args.json_out}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    smote = SMOTE(random_state=42)
    X_train_balanced, y_train_balanced = smote.fit_resample(X_train_scaled, y_train)
    print(f"\n[*] After SMOTE: Benign: {np.sum(y_train_balanced == 0)}, Malware: {np.sum(y_train_balanced == 1)}")

    print("\n[*] Training Random Forest Classifier...")
    param_grid = {
        "n_estimators": [100, 200],
        "max_depth": [10, 20, None],
        "min_samples_split": [2, 5],
        "min_samples_leaf": [2, 4],
    }

    grid_search = GridSearchCV(
        RandomForestClassifier(random_state=42, n_jobs=-1),
        param_grid,
        cv=5,
        scoring="f1",
        verbose=1,
        n_jobs=-1,
    )
    grid_search.fit(X_train_balanced, y_train_balanced)
    model = grid_search.best_estimator_

    print(f"\n[*] Best parameters: {grid_search.best_params_}")

    y_pred = model.predict(X_test_scaled)
    y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]

    metrics = {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred),
        "recall": recall_score(y_test, y_pred),
        "f1_score": f1_score(y_test, y_pred),
        "roc_auc": roc_auc_score(y_test, y_pred_proba),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
    }

    print("\n   Results:")
    print(f"   Accuracy:  {metrics['accuracy']:.4f}")
    print(f"   Precision: {metrics['precision']:.4f}")
    print(f"   Recall:    {metrics['recall']:.4f}")
    print(f"   F1-Score:  {metrics['f1_score']:.4f}")
    print(f"   ROC-AUC:   {metrics['roc_auc']:.4f}")
    print(f"\n{classification_report(y_test, y_pred, target_names=['benign', 'malicious'])}")

    importances = pd.DataFrame({
        "feature": feature_names,
        "importance": model.feature_importances_,
    }).sort_values("importance", ascending=False)

    print("   Top 15 Important Features:")
    print(importances.head(15).to_string(index=False))

    os.makedirs(args.output_dir, exist_ok=True)
    model_path = os.path.join(args.output_dir, f"{model_prefix}_model.pkl")
    scaler_path = os.path.join(args.output_dir, f"{model_prefix}_scaler.pkl")

    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)

    for fpath in [model_path, scaler_path]:
        size_mb = os.path.getsize(fpath) / (1024 * 1024)
        print(f"[*] Saved {os.path.basename(fpath)}: {size_mb:.2f} MB")

    metrics_path = os.path.join(args.output_dir, "file_model_metrics.json")
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"[*] Saved metrics to {metrics_path}")

    print("\n" + "=" * 60)
    print("Training complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
