import os
import pickle
from typing import Dict, List, Tuple

import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC
from sklearn.utils.class_weight import compute_class_weight


class EnsembleClassifier:
    """Combines 3 models for threat classification with confidence scoring."""

    def __init__(self, models_dir: str = "data/models/threat_classifier"):
        self.models_dir = models_dir
        self.models = {}  # Will hold: {'nb': model, 'svm': model, 'rf': model}
        self.classes_ = None
        self.is_trained = False

    @staticmethod
    def get_default_adversarial_samples() -> List[Tuple[str, str]]:
        """Return built-in adversarial/paraphrase samples for quick regression checks."""
        return [
            ("SQL injection in login form", "Injection Attack"),
            ("Database query manipulation via user input", "Injection Attack"),
            ("SQL command injection through form field", "Injection Attack"),
            ("User input directly inserted into database queries", "Injection Attack"),
            ("We insert queries into the database", "Injection Attack"),
            ("The form takes SQL without validation", "Injection Attack"),
        ]

    def _create_enhanced_vectorizer(self):
        """Create an enhanced TF-IDF vectorizer with better feature extraction."""

        return TfidfVectorizer(
            max_features=1000,  # More features than before
            ngram_range=(1, 3),  # Include unigrams, bigrams, and trigrams
            min_df=2,  # Ignore terms appearing in <2 documents
            max_df=0.8,  # Ignore terms appearing in >80% docs
            lowercase=True,
            stop_words="english",  # Remove common words: "the", "a", "is", etc
            analyzer="word",
            token_pattern=r"\w{2,}",  # Ignore single-char tokens like "a"
            sublinear_tf=True,  # Use sublinear TF scaling (helps with imbalance)
            norm="l2",  # L2 normalization to prevent bias towards longer docs
        )

    def train_ensemble(self, X_train, y_train):
        """Train all 3 models on the same training data but seperate pipelines.

        Uses raw model probabilities (no over-calibration) which are already well-behaved
        when averaged across 3 diverse models.
        """

        self.classes_ = np.unique(y_train)
        class_weights = compute_class_weight(
            "balanced",
            classes=self.classes_,
            y=y_train,
        )
        class_weight_dict = dict(zip(self.classes_, class_weights))

        print(f"Class weights: {class_weight_dict}")

        # Naive Bayes Pipeline with proper calibration
        nb_pipeline = Pipeline(
            [
                ("tfidf", self._create_enhanced_vectorizer()),
                (
                    "clf",
                    CalibratedClassifierCV(
                        estimator=MultinomialNB(alpha=0.5),
                        method="sigmoid",
                        cv=5,
                    ),
                ),
            ]
        )

        # Linear Model Pipeline (keep calibration for SVM - it NEEDS it for predict_proba)
        svm_pipeline = Pipeline(
            [
                ("tfidf", self._create_enhanced_vectorizer()),
                (
                    "clf",
                    CalibratedClassifierCV(
                        estimator=LinearSVC(
                            class_weight=class_weight_dict,
                            dual=False,
                            max_iter=5000,
                            random_state=42,
                        ),
                        method="sigmoid",
                        cv=5,
                    ),
                ),
            ]
        )

        # Random Forest Pipeline with proper calibration
        rf_pipeline = Pipeline(
            [
                ("tfidf", self._create_enhanced_vectorizer()),
                (
                    "clf",
                    CalibratedClassifierCV(
                        estimator=RandomForestClassifier(
                            n_estimators=200,  # 200 trees for more stable probabilities
                            max_depth=12,  # Depth cap to reduce overfitting
                            class_weight="balanced",  # Handle class imbalance
                            random_state=42,
                            n_jobs=-1,  # Use all CPU cores for faster training
                        ),
                        method="sigmoid",
                        cv=5,
                    ),
                ),
            ]
        )

        # Train each pipeline on full training data
        self.models["nb"] = nb_pipeline.fit(X_train, y_train)
        self.models["svm"] = svm_pipeline.fit(X_train, y_train)
        self.models["rf"] = rf_pipeline.fit(X_train, y_train)

        self.is_trained = True
        return self

    def _aligned_probabilities(self, model: Pipeline, description: str) -> np.ndarray:
        """Align per-model probabilities to self.classes_ ordering."""
        probs = model.predict_proba([description])[0]
        model_classes = list(model.classes_)

        aligned = np.zeros(len(self.classes_))
        class_to_index = {label: idx for idx, label in enumerate(self.classes_)}

        for model_idx, label in enumerate(model_classes):
            if label in class_to_index:
                aligned[class_to_index[label]] = probs[model_idx]

        return aligned

    def classify_with_confidence(self, description: str) -> Dict:
        """Classify threat and provide confidence score + disagreement detection."""
        if not self.is_trained:
            raise ValueError("Ensemble not trained. Call train_ensemble() first.")

        # Get probability predictions from each model and align to shared class ordering.
        nb_probs = self._aligned_probabilities(self.models["nb"], description)
        svm_probs = self._aligned_probabilities(self.models["svm"], description)
        rf_probs = self._aligned_probabilities(self.models["rf"], description)

        # Average probabilities across all 3 models (simple voting)
        ensemble_probs = (nb_probs + svm_probs + rf_probs) / 3

        # Find top predicted class
        top_class_idx = int(np.argmax(ensemble_probs))
        top_class = self.classes_[top_class_idx]
        top_confidence = float(ensemble_probs[top_class_idx])

        # Check model agreement: did all 3 models pick the same top class?
        nb_top = self.classes_[int(np.argmax(nb_probs))]
        svm_top = self.classes_[int(np.argmax(svm_probs))]
        rf_top = self.classes_[int(np.argmax(rf_probs))]

        # if only 1 unique value in set, all models agreed
        model_agreement = len({nb_top, svm_top, rf_top}) == 1

        # Find runner-up (second most likely class)
        sorted_indices = np.argsort(ensemble_probs)[::-1]  # Sort descending
        if len(sorted_indices) > 1:
            runner_up_idx = int(sorted_indices[1])
            runner_up = self.classes_[runner_up_idx]
            runner_up_confidence = float(ensemble_probs[runner_up_idx])
        else:
            runner_up = top_class
            runner_up_confidence = top_confidence

        return {
            "threat_type": str(top_class),
            "confidence": top_confidence,
            "model_agreement": bool(model_agreement),
            "runner_up": str(runner_up),
            "runner_up_confidence": runner_up_confidence,
        }

    def test_adversarial_examples(self) -> List[Dict]:
        """Test ensemble robustness against adversarial inputs."""
        adversarial_tests = self.get_default_adversarial_samples()

        results = []
        for description, expected_type in adversarial_tests:
            prediction = self.classify_with_confidence(description)

            passed = prediction["threat_type"] == expected_type
            results.append(
                {
                    "input": description,
                    "expected": expected_type,
                    "predicted": prediction["threat_type"],
                    "confidence": prediction["confidence"],
                    "agreement": prediction["model_agreement"],
                    "passed": passed,
                    "status": "PASS" if passed else "FAIL",
                }
            )

        return results

    def save_models(self):
        """Save all 3 trained models to disk."""
        os.makedirs(self.models_dir, exist_ok=True)

        for model_name, model in self.models.items():
            filepath = os.path.join(self.models_dir, f"{model_name}_model.pkl")
            with open(filepath, "wb") as f:
                pickle.dump(model, f)

        classes_path = os.path.join(self.models_dir, "classes.pkl")
        with open(classes_path, "wb") as f:
            pickle.dump(self.classes_, f)

    def load_models(self):
        """Load pre-trained models from disk."""
        for model_name in ["nb", "svm", "rf"]:
            filepath = os.path.join(self.models_dir, f"{model_name}_model.pkl")
            with open(filepath, "rb") as f:
                self.models[model_name] = pickle.load(f)

        classes_path = os.path.join(self.models_dir, "classes.pkl")
        if os.path.exists(classes_path):
            with open(classes_path, "rb") as f:
                self.classes_ = pickle.load(f)
        else:
            self.classes_ = np.array(list(self.models["nb"].classes_))

        self.is_trained = True
