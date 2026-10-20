import hashlib
import json

from agents.feature_extractor import ProcessFeatureExtractor

ROWS = "data/training/EDR/prepared/process_events_linux.json"

with open(ROWS, "r", encoding="utf-8") as f:
    rows = json.load(f)

extractor = ProcessFeatureExtractor()
lines = sorted(json.dumps(extractor.extract_features(row), sort_keys=True) for row in rows)
digest = hashlib.sha256("\n".join(lines).encode("utf-8"))

print(f"{len(rows)} Linux rows, feature fingerprint: {digest.hexdigest()[:16]}")