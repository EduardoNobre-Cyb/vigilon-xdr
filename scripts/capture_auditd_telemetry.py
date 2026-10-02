"""Capture real auditd process telemetry to JSONL for training data.

Reuses the agent's own AuditdProcessCollector, so every captured row has the
exact field format the agent emits at runtime (no train/runtime mismatch).

Benign capture is safe: run it during normal machine use. It does NOT run any
attacks - it only records the processes you launch normally.

Usage (from the repo root, needs the audit rule loaded and root to read the log):
    sudo auditctl -a always,exit -F arch=b64 -S execve -k edr_process_exec
    sudo -E env PYTHONPATH="$PWD" "$PWD/venv/bin/python3" \
        scripts/capture_auditd_telemetry.py --label 0 --out data/training/EDR/captures/benign_capture.jsonl
    # ... use your machine normally (browse, apt, dev tools, open apps) ...
    # Press Ctrl+C to stop.
"""
import argparse
import json
import os
import signal
import time

from agents.endpoint_agent.linux_event_collector import AuditdProcessCollector

ROW_FIELDS = ["pid", "ppid", "name", "path", "command_line",
              "parent_name", "user", "is_first_seen"]


def main():
    parser = argparse.ArgumentParser(description="Capture auditd process telemetry to JSONL.")
    parser.add_argument("--out", default="data/training/EDR/captures/benign_capture.jsonl",
                        help="Output JSONL file (appended to).")
    parser.add_argument("--label", type=int, choices=[0, 1], default=None,
                        help="Tag every row with this label (0=benign, 1=malicious). "
                             "Omit to leave rows unlabeled.")
    parser.add_argument("--seconds", type=int, default=0,
                        help="Stop after N seconds (0 = run until Ctrl+C).")
    args = parser.parse_args()

    out_dir = os.path.dirname(args.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    collector = AuditdProcessCollector()
    collector.start()

    stop = {"now": False}

    def handle_sigint(_sig, _frame):
        stop["now"] = True

    signal.signal(signal.SIGINT, handle_sigint)

    tag = f" (label={args.label})" if args.label is not None else ""
    print(f"Capturing auditd process events{tag} -> {args.out}")
    print("Use your machine normally. Press Ctrl+C to stop." if not args.seconds
          else f"Capturing for {args.seconds}s...")

    count = 0
    start = time.time()
    with open(args.out, "a", encoding="utf-8") as fh:
        try:
            while not stop["now"]:
                for event in collector.poll():
                    row = {k: event.get(k) for k in ROW_FIELDS}
                    if args.label is not None:
                        row["label"] = args.label
                    fh.write(json.dumps(row) + "\n")
                    count += 1
                fh.flush()
                if args.seconds and (time.time() - start) >= args.seconds:
                    break
                time.sleep(0.5)
        finally:
            collector.stop()

    print(f"\nCaptured {count} events to {args.out}")


if __name__ == "__main__":
    main()
