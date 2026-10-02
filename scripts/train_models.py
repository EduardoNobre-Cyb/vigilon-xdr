import argparse
import json
import pickle
import joblib
import os
from typing import Tuple

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)
from imblearn.over_sampling import SMOTE

from agents.feature_extractor import (
    ProcessFeatureExtractor, NetworkFeatureExtractor,
    extract_dataset_features
)
from agents.ml_training.synthetic_data_generator import SyntheticDataGenerator

class BehavioralMLTrainer:
    """Train and evaluate behavioral ML models"""

    def __init__(self, output_dir: str = "data/models/EDR"):
        self.output_dir = output_dir
        self.process_model = None
        self.network_model = None
        self.process_scaler = None
        self.network_scaler = None

    def train_process_model(self, events: list) -> dict:
        """Train process behavior classifier"""
        print("[*] Training Process Behavior Model...")

        # Extract features
        df = extract_dataset_features(events, "process")
        x = df.values
        y = np.array([e["label"] for e in events])

        print(f"   Dataset shape: {x.shape}")
        print(f"   Class distribution: {np.bincount(y)}")

        # Train/test split
        X_train, X_test, y_train, y_test = train_test_split(
            x, y, test_size=0.2, random_state=42, stratify=y
        )

        # Scale features
        self.process_scaler = StandardScaler()
        X_trained_scaled = self.process_scaler.fit_transform(X_train)
        X_test_scaled = self.process_scaler.transform(X_test)

        # Handle class imbalance with SMOTE
        smote = SMOTE(random_state=42)
        X_train_balanced, y_train_balanced = smote.fit_resample(X_trained_scaled, y_train)

        print(f"   After SMOTE: {np.bincount(y_train_balanced)}")

        # Train RandomForest with hyperparameter tuning
        param_grid = {
            "n_estimators": [100, 200],
            "max_depth": [10, 20, None],
            "min_samples_split": [5, 10],
            "min_samples_leaf": [2, 4],
        }

        base_model = RandomForestClassifier(random_state=42, n_jobs=-1)
        grid_search = GridSearchCV(
            base_model, param_grid, cv=5, scoring="f1",
            verbose=1, n_jobs=-1
        )

        print("   Running hyperparameter tuning...")
        grid_search.fit(X_train_balanced, y_train_balanced)

        self.process_model = grid_search.best_estimator_

        print(f"   Best parameters: {grid_search.best_params_}")

        # Evaluate
        y_pred = self.process_model.predict(X_test_scaled)
        y_pred_proba = self.process_model.predict_proba(X_test_scaled)[:, 1]

        metrics = {
            "accuracy": accuracy_score(y_test, y_pred),
            "precision": precision_score(y_test, y_pred),
            "recall": recall_score(y_test, y_pred),
            "f1_score": f1_score(y_test, y_pred),
            "roc_auc": roc_auc_score(y_test, y_pred_proba),
            "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        }

        print("\n   Results:")
        print(f"   Accuracy: {metrics['accuracy']:.4f}")
        print(f"   Precision: {metrics['precision']:.4f}")
        print(f"   Recall: {metrics['recall']:.4f}")
        print(f"   F1-Score: {metrics['f1_score']:.4f}")
        print(f"   ROC-AUC: {metrics['roc_auc']:.4f}")

        # Feature importance
        feature_importance = pd.DataFrame({
            "feature": [f"feature_{i}" for i in range(x.shape[1])],
            "importance": self.process_model.feature_importances_,
        }).sort_values("importance", ascending=False)

        print(f"\n   Top 10 Important Features:")
        print(feature_importance.head(10).to_string(index=False))

        return metrics

    def train_network_model(self, events: list) -> dict:
        """Train network behavior classifier"""

        print("\n[*] Training Network Behavior Model...")

        # Extract features
        df = extract_dataset_features(events, "network")
        x = df.values
        y = np.array([e["label"] for e in events])

        print(f"   Dataset shape: {x.shape}")
        print(f"   Class distribution: {np.bincount(y)}")

        # Train/test split
        X_train, X_test, y_train, y_test = train_test_split(
            x, y, test_size=0.2, random_state=42, stratify=y
        )

        # Scale features
        self.network_scaler = StandardScaler()
        X_train_scaled = self.network_scaler.fit_transform(X_train)
        X_test_scaled = self.network_scaler.transform(X_test)

        # SMOTE
        smote = SMOTE(random_state=42)
        X_train_balanced, y_train_balanced = smote.fit_resample(X_train_scaled, y_train)

        # Train GradientBoosting
        param_grid = {
            "n_estimators": [100, 200],
            "learning_rate": [0.01, 0.1],
            "max_depth": [5, 10],
        }

        base_model = GradientBoostingClassifier(random_state=42)
        grid_search = GridSearchCV(
            base_model, param_grid, cv=5, scoring="f1",
            verbose=1, n_jobs=-1
        )

        print("   Running hyperparameter tuning...")
        grid_search.fit(X_train_balanced, y_train_balanced)

        self.network_model = grid_search.best_estimator_

        print(f"   Best parameters: {grid_search.best_params_}")

        # Evaluate
        y_pred = self.network_model.predict(X_test_scaled)
        y_pred_proba = self.network_model.predict_proba(X_test_scaled)[:, 1]

        metrics = {
            "accuracy": accuracy_score(y_test, y_pred),
            "precision": precision_score(y_test, y_pred),
            "recall": recall_score(y_test, y_pred),
            "f1_score": f1_score(y_test, y_pred),
            "roc_auc": roc_auc_score(y_test, y_pred_proba),
        }

        print(f"\n   Results:")
        print(f"   Accuracy: {metrics['accuracy']:.4f}")
        print(f"   Precision: {metrics['precision']:.4f}")
        print(f"   Recall: {metrics['recall']:.4f}")
        print(f"   F1-Score: {metrics['f1_score']:.4f}")
        print(f"   ROC-AUC: {metrics['roc_auc']:.4f}")

        return metrics

    def save_models(self):
        """Serialize models to disk"""
        print("\n[*] Saving models...")

        os.makedirs(self.output_dir, exist_ok=True)

        joblib.dump(self.process_model, f"{self.output_dir}/process_model.pkl")
        joblib.dump(self.network_model, f"{self.output_dir}/network_model.pkl")
        joblib.dump(self.process_scaler, f"{self.output_dir}/process_scaler.pkl")
        joblib.dump(self.network_scaler, f"{self.output_dir}/network_scaler.pkl")

        print(f"   ✓ Saved to {self.output_dir}/")

        # Check sizes
        for fname in ["process_model.pkl", "network_model.pkl", "process_scaler.pkl", "network_scaler.pkl"]:
            fpath = f"{self.output_dir}/{fname}"
            size_mb = os.path.getsize(fpath) / (1024 * 1024)
            print(f"   {fname}: {size_mb:.2f}MB")

def _load_events_json(path: str) -> list:
    """Load events from a JSON file"""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def main():
    """Train all endpoint models"""

    parser = argparse.ArgumentParser(description="Train endpoint process/network models")
    parser.add_argument("--dataset-mode", choices=["synthetic", "mixed"], default="synthetic", help="Dataset mode to use for training")
    parser.add_argument("--process-events", default="data/training/EDR/prepared/process_events.json", help="Path to process events JSON")
    parser.add_argument("--network-events", default="data/training/EDR/prepared/network_events.json", help="Path to network events JSON")
    parser.add_argument("--process-count", type=int, default=10000, help="Number of process events to generate")
    parser.add_argument("--network-count", type=int, default=10000, help="Number of network events to generate")
    parser.add_argument("--output-dir", default="data/models/EDR", help="Directory to save trained models")
    args = parser.parse_args()

    print("="*60)
    print("PHASE 2: Training Behavioral ML Models")
    print("="*60)

    if args.dataset_mode == "mixed":
        # Load mixed dataset
        print("\n[*] Loading mixed Linux+Windows telemetry datasets...")
        process_events = _load_events_json(args.process_events)
        network_events = _load_events_json(args.network_events)
        print(f"   Loaded {len(process_events)} process events")
        print(f"   Loaded {len(network_events)} network events")

    else:
        # Generate synthetic data
        print("\n[*] Generating synthetic dataset...")
        gen = SyntheticDataGenerator()
        process_events, network_events = gen.generate_all(
            process_count=args.process_count,
            network_count=args.network_count,
        )
        print(f"   Generated {len(process_events)} process events")
        print(f"   Generated {len(network_events)} network events")

    # Train models
    trainer = BehavioralMLTrainer(output_dir=args.output_dir)

    trainer.train_process_model(process_events)
    trainer.train_network_model(network_events)

    # Save
    trainer.save_models()

    print("\n" + "="*60)
    print("Training complete!")
    print("="*60)

    return trainer

if __name__ == "__main__":
    trainer = main()