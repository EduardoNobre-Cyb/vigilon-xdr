import json
import random
from pathlib import Path


RAW_DIR = Path("data/training/EDR/raw")
OUT_DIR = Path("data/training/EDR/prepared")


def read_jsonl(path: Path):
    records = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records

def normalize_process(e):
    return {
        "pid": int(e.get("pid", 0)),
        "ppid": int(e.get("ppid", 0)),
        "name": str(e.get("name", "")),
        "path": str(e.get("path", "")),
        "command_line": str(e.get("command_line", "")),
        "parent_name": str(e.get("parent_name", "")),
        "user": str(e.get("user", "")),
        "is_first_seen": bool(e.get("is_first_seen", False)),
        "label": int(e.get("label", 0)),
    }

def normalize_network(e):
    return {
        "source_ip": str(e.get("source_ip", "")),
        "source_port": int(e.get("source_port", 0)),
        "dest_ip": str(e.get("dest_ip", "")),
        "dest_port": int(e.get("dest_port", 0)),
        "process_name": str(e.get("process_name", "")),
        "protocol": str(e.get("protocol", "")),
        "bytes_sent": int(e.get("bytes_sent", 0)),
        "bytes_received": int(e.get("bytes_received", 0)),
        "label": int(e.get("label", 0)),
    }

def shuffle_and_write(path: Path, records):
    random.shuffle(records)
    with path.open("w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)

def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    process_linux = [normalize_process(x) for x in read_jsonl(RAW_DIR / "process_linux.jsonl")]
    process_windows = [normalize_process(x) for x in read_jsonl(RAW_DIR / "process_windows.jsonl")]
    network_linux = [normalize_network(x) for x in read_jsonl(RAW_DIR / "network_linux.jsonl")]
    network_windows = [normalize_network(x) for x in read_jsonl(RAW_DIR / "network_windows.jsonl")]

    process_events = process_linux + process_windows
    network_events = network_linux + network_windows

    shuffle_and_write(OUT_DIR / "process_events.json", process_events)
    shuffle_and_write(OUT_DIR / "network_events.json", network_events)

    print("Prepared cross-platform datasets:")
    print(f"  process_events.json: {len(process_events)}")
    print(f"  network_events.json: {len(network_events)}")

    proc_pos = sum(1 for e in process_events if e["label"] == 1)
    net_pos = sum(1 for e in network_events if e["label"] == 1)
    print(f"  process positives: {proc_pos}, negatives: {len(process_events) - proc_pos}")
    print(f"  network positives: {net_pos}, negatives: {len(network_events) - net_pos}")


if __name__ == "__main__":
    main()
