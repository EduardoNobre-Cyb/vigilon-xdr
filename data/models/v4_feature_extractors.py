"""Backward-compatible alias for the neutral classifier feature extractors."""

from data.models.classifier_feature_extractors import (
    StructuredMetadataExtractor,
    Word2VecFeatureExtractor,
)

__all__ = ["Word2VecFeatureExtractor", "StructuredMetadataExtractor"]
