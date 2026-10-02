import argparse
import json
import random
from pathlib import Path

RAW_DIR = Path("data/training/EDR/raw")

FILES = {
    "process_linux": RAW_DIR / "process_linux.jsonl",
    "process_windows": RAW_DIR / "process_windows.jsonl",
    "network_linux": RAW_DIR / "network_linux.jsonl",
    "network_windows": RAW_DIR / "network_windows.jsonl",
}


def read_jsonl(path: Path):
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows):
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, separators=(",", ":")) + "\n")


def _flip_bool(v):
    return v if random.random() > 0.2 else (not bool(v))


def mutate_process(event, platform):
    e = dict(event)

    e["pid"] = int(e.get("pid", 1000)) + random.randint(1, 90000)
    e["ppid"] = max(1, int(e.get("ppid", 1)) + random.randint(-200, 200))
    e["is_first_seen"] = _flip_bool(e.get("is_first_seen", False)) if e.get("label", 0) == 0 else True

    if platform == "linux":
        users_benign = ["root", "dudu", "ubuntu", "svc-app"]
        users_susp = ["dudu", "root", "www-data"]
        e["user"] = random.choice(users_susp if e.get("label", 0) == 1 else users_benign)

        proc_suffix = ["", " --quiet", " --verbose", " --once", " --retry 2"]
        cmd = str(e.get("command_line", ""))
        if e.get("label", 0) == 1:
            cmd = cmd.replace("4444", str(random.choice([4444, 5555, 1337, 8081, 9001])))
            if "curl" in cmd and random.random() > 0.5:
                cmd = cmd.replace("http://", "https://")
        e["command_line"] = (cmd + random.choice(proc_suffix)).strip()
    else:
        users_benign = ["CORP\\jane", "CORP\\john", "NT AUTHORITY\\SYSTEM"]
        users_susp = ["CORP\\jane", "CORP\\svc", "NT AUTHORITY\\SYSTEM"]
        e["user"] = random.choice(users_susp if e.get("label", 0) == 1 else users_benign)

        cmd = str(e.get("command_line", ""))
        if e.get("label", 0) == 1:
            for old, new_vals in {
                "4444": ["4444", "5555", "8081", "9001", "1337"],
                "payload.exe": ["payload.exe", "stage.exe", "loader.exe"],
                "http://10.0.0.20": ["http://10.0.0.20", "http://10.0.0.30", "http://10.0.0.40"],
            }.items():
                if old in cmd:
                    cmd = cmd.replace(old, random.choice(new_vals))
        e["command_line"] = cmd

    return e


def _mutate_ip(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return ip
    try:
        octets = [int(x) for x in parts]
    except ValueError:
        return ip

    octets[-1] = max(1, min(254, octets[-1] + random.randint(-20, 20)))
    return ".".join(str(x) for x in octets)


def mutate_network(event, platform):
    e = dict(event)

    e["source_ip"] = _mutate_ip(str(e.get("source_ip", "192.168.56.10")))
    e["dest_ip"] = _mutate_ip(str(e.get("dest_ip", "10.0.0.5")))

    e["source_port"] = max(1, min(65535, int(e.get("source_port", 49152)) + random.randint(-3000, 3000)))

    if e.get("label", 0) == 1:
        e["dest_port"] = random.choice([1337, 4444, 5555, 6666, 6667, 8081, 8888, 9001, 9999, 12345, 31337])
        e["bytes_sent"] = max(10, int(e.get("bytes_sent", 60)) + random.randint(-20, 180))
        e["bytes_received"] = max(10, int(e.get("bytes_received", 60)) + random.randint(-20, 240))
    else:
        benign_ports = [22, 53, 80, 123, 443, 445, 1433, 2049, 3389, 5432]
        e["dest_port"] = random.choice(benign_ports)
        e["bytes_sent"] = max(40, int(e.get("bytes_sent", 500)) + random.randint(-300, 9000))
        e["bytes_received"] = max(40, int(e.get("bytes_received", 900)) + random.randint(-300, 16000))

    if platform == "linux":
        e["process_name"] = random.choice([
            e.get("process_name", "python3"),
            "python3",
            "bash",
            "ssh",
            "curl",
            "wget",
            "apt",
            "firefox",
        ])
    else:
        e["process_name"] = random.choice([
            e.get("process_name", "powershell.exe"),
            "chrome.exe",
            "Teams.exe",
            "OUTLOOK.EXE",
            "svchost.exe",
            "powershell.exe",
            "cmd.exe",
            "rundll32.exe",
        ])

    e["protocol"] = random.choice(["tcp", "udp"]) if e.get("label", 0) == 1 else random.choice(["tcp", "tcp", "udp"])

    return e


def balance_and_expand(rows, target_count, kind, platform):
    if not rows:
        raise ValueError(f"Cannot expand empty dataset for {kind}_{platform}")

    positives = [r for r in rows if int(r.get("label", 0)) == 1]
    negatives = [r for r in rows if int(r.get("label", 0)) == 0]

    if not positives or not negatives:
        raise ValueError(f"Dataset {kind}_{platform} must contain both label 0 and label 1 rows")

    target_pos = target_count // 2
    target_neg = target_count - target_pos

    out_pos = positives[:]
    out_neg = negatives[:]

    while len(out_pos) < target_pos:
        src = random.choice(positives)
        out_pos.append(mutate_process(src, platform) if kind == "process" else mutate_network(src, platform))

    while len(out_neg) < target_neg:
        src = random.choice(negatives)
        out_neg.append(mutate_process(src, platform) if kind == "process" else mutate_network(src, platform))

    out = out_neg[:target_neg] + out_pos[:target_pos]
    random.shuffle(out)
    return out


def summarize(name, rows):
    pos = sum(1 for r in rows if int(r.get("label", 0)) == 1)
    neg = len(rows) - pos
    return f"{name}: total={len(rows)} positive={pos} negative={neg}"


def main():
    parser = argparse.ArgumentParser(description="Expand current raw EDR JSONL files to a larger balanced set")
    parser.add_argument("--target-per-file", type=int, default=250, help="Target rows for each raw file (default: 250)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--dry-run", action="store_true", help="Compute and print summary without writing files")
    args = parser.parse_args()

    if args.target_per_file < 40:
        raise ValueError("--target-per-file must be >= 40 for meaningful expansion")

    random.seed(args.seed)

    proc_linux = read_jsonl(FILES["process_linux"])
    proc_windows = read_jsonl(FILES["process_windows"])
    net_linux = read_jsonl(FILES["network_linux"])
    net_windows = read_jsonl(FILES["network_windows"])

    new_proc_linux = balance_and_expand(proc_linux, args.target_per_file, "process", "linux")
    new_proc_windows = balance_and_expand(proc_windows, args.target_per_file, "process", "windows")
    new_net_linux = balance_and_expand(net_linux, args.target_per_file, "network", "linux")
    new_net_windows = balance_and_expand(net_windows, args.target_per_file, "network", "windows")

    print("Expansion summary:")
    print("  " + summarize("process_linux.jsonl", new_proc_linux))
    print("  " + summarize("process_windows.jsonl", new_proc_windows))
    print("  " + summarize("network_linux.jsonl", new_net_linux))
    print("  " + summarize("network_windows.jsonl", new_net_windows))

    if args.dry_run:
        print("\nDry run enabled: no files were written.")
        return

    write_jsonl(FILES["process_linux"], new_proc_linux)
    write_jsonl(FILES["process_windows"], new_proc_windows)
    write_jsonl(FILES["network_linux"], new_net_linux)
    write_jsonl(FILES["network_windows"], new_net_windows)

    print("\nRaw files updated in-place under data/training/EDR/raw")


if __name__ == "__main__":
    main()
