import json
from pathlib import Path


RAW_DIR = Path("data/training/EDR/raw")

PROCESS_FIELDS = {
    "pid", "ppid", "name", "path", "command_line", "parent_name", "user", "is_first_seen", "label",
}

NETWORK_FIELDS = {
    "source_ip", "source_port", "dest_ip", "dest_port", "process_name", "protocol", "bytes_sent", "bytes_received", "label",
}

def load_jsonl(path):
    rows = []
    with path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {error}") from error
            rows.append((line_number, row))
    return rows

def validate_file(path, required_fields, kind):
    rows = load_jsonl(path)
    positives = 0
    negatives = 0

    if not rows:
        raise ValueError(f"{path}: file is empty")

    for line_number, row in rows:
        missing = required_fields - row.keys()
        if missing:
            raise ValueError(f"{path}:{line_number}: missing fields: {sorted(missing)}")
        if row["label"] not in (0, 1):
            raise ValueError(f"{path}:{line_number}: label must be 0 or 1")
        if kind == "process" and not isinstance(row["is_first_seen"], bool):
            raise ValueError(f"{path}:{line_number}: is_first_seen must be true or false")
        if row["label"] == 1:
            positives += 1
        else:
            negatives += 1

    print(f"{path}: total={len(rows)} benign={negatives} suspicious={positives}")
    if positives == 0 or negatives == 0:
        raise ValueError(f"{path}: both label 0 and label 1 are required")
    return len(rows), positives, negatives

def main():
    process = validate_file(
        RAW_DIR / "process_linux.jsonl", PROCESS_FIELDS, "process"
    ) 
    network = validate_file(
        RAW_DIR / "network_linux.jsonl", NETWORK_FIELDS, "network"
    )

    if process[1] < 20 or process[2] < 50:
        raise ValueError("Need at least 20 suspicious and 50 benign Linux process rows")
    if network[1] < 20 or network[2] < 50:
        raise ValueError("Need at least 20 suspicious and 50 benign Linux network rows")

    print("PASS Linux raw training data contains the minimum Step 5 samples counts.")

if __name__ == "__main__":
    main()

    