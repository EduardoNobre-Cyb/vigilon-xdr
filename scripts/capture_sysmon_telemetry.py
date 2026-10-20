import argparse
import json
import os
import signal
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.endpoint_agent.windows_event_collector import SysmonProcessCollector

ROW_FIELDS = ["pid", "ppid", "name", "path", "command_line", "parent_name", "user", "is_first_seen"]

def main():
    parser = argparse.ArgumentParser(description="Capture Sysmon process telemtry to JSONL")
    parser.add_argument("--out", default="data/training/EDR/captures/benign_capture_windows.jsonl", help="Output JSONL file (append to).")
    parser.add_argument("--label", type=int, choices=[0, 1], default=None, help="Tag every row with this label (0=benign, 1=malicious). Omit to leave rows unlabled.")
    parser.add_argument("--seconds", type=int, default=0, help="Stop after N seconds (0 = run until Ctrl+C).")
    args = parser.parse_args()

    out_dir = os.path.dirname(args.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    collector = SysmonProcessCollector()
    collector.start()

    stop = {"now": False}

    def handle_sigint(_sig, _frame):
        stop["now"] = True

    signal.signal(signal.SIGINT, handle_sigint)

    tag = f" (label={args.label})" if args.label is not None else ""
    print(f"Capturing Sysmon process events{tag} -> {args.out}")
    print("Use the machine normally. Press Ctrl+C to stop." if not args.seconds else f"Capturing for {args.seconds}s...")

    count = 0
    start = time.time()
    last_report = start
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
                if time.time() - last_report >= 30:
                    print(f"  {count} events so far...")
                    last_report = time.time()
                if args.seconds and (time.time() - start) >= args.seconds:
                    break
                time.sleep(0.5)
        finally:
            collector.stop()

    print(f"\nCaptured {count} events to {args.out}")


if __name__ == "__main__":
    main()