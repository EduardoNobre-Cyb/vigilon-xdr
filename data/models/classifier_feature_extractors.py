"""Shared feature extractors for the threat classifier."""

from typing import List

import numpy as np
from gensim.models import Word2Vec


class Word2VecFeatureExtractor:
    """Extracts semantic features using Word2Vec embeddings."""

    def __init__(self, vector_size=200, min_count=1, workers=4):
        self.vector_size = vector_size
        self.min_count = min_count
        self.workers = workers
        self.model = None
        self.tokenizer = None

    def fit(self, descriptions: list):
        tokenized_sentences = [desc.lower().split() for desc in descriptions]
        self.model = Word2Vec(
            sentences=tokenized_sentences,
            vector_size=self.vector_size,
            min_count=self.min_count,
            workers=self.workers,
            sg=0,
            window=5,
            seed=42,
        )
        return self

    def transform(self, descriptions: list) -> np.ndarray:
        embeddings = []

        for desc in descriptions:
            words = desc.lower().split()
            vectors = [self.model.wv[word] for word in words if word in self.model.wv]

            if vectors:
                doc_embedding = np.mean(vectors, axis=0)
            else:
                doc_embedding = np.zeros(self.vector_size)

            embeddings.append(doc_embedding)

        return np.array(embeddings)


class StructuredMetadataExtractor:
    """Extracts structured metadata as features."""

    keyword_terms = {
        "bypass",
        "credential",
        "deserializ",
        "dos",
        "enumeration",
        "exploit",
        "flood",
        "injection",
        "internal",
        "leak",
        "metadata",
        "overflow",
        "path",
        "privilege",
        "rce",
        "ssrf",
        "sql",
        "traversal",
        "unauthenticated",
        "xss",
    }

    def __init__(self):
        self.severity_categories: List[str] = []
        self.asset_type_categories: List[str] = []
        self.fitted = False

    def fit(self, threats: list):
        severities = [t.get("severity", "Unknown") for t in threats]
        asset_types = [t.get("asset_type", "Unknown") for t in threats]

        self.severity_categories = sorted(set(severities))
        self.asset_type_categories = sorted(set(asset_types))
        self.fitted = True
        return self

    def transform(self, threats: list) -> np.ndarray:
        features = []

        for threat in threats:
            cvss = threat.get("cvss_score", 5.0) / 10.0
            exploitability = threat.get("exploitability", 5.0) / 10.0

            severity_vector = [
                1.0 if threat.get("severity", "Unknown") == category else 0.0
                for category in self.severity_categories
            ]
            asset_type_vector = [
                1.0 if threat.get("asset_type", "Unknown") == category else 0.0
                for category in self.asset_type_categories
            ]

            features.append(
                [
                    cvss,
                    exploitability,
                    *severity_vector,
                    *asset_type_vector,
                ]
            )

        return np.array(features)
