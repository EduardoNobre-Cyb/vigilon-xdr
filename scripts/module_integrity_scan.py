import os
import json
import ctypes
import ctypes.wintypes as wt
import argparse
import logging
from datetime import datetime, timezone

import psutil

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

MEM_COMMIT = 0x1000
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
MEM_PRIVATE = 0x20000

EXECUTABLE_FLAGS = {PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY}
RWX_FLAGS = {PAGE_EXECUTE_READWRITE}


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

OpenProcess = kernel32.OpenProcess
OpenProcess.restype = wt.HANDLE
OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]

CloseHandle = kernel32.CloseHandle
VirtualQueryEx = kernel32.VirtualQueryEx

GetMappedFileNameW = ctypes.WinDLL("psapi", use_last_error=True).GetMappedFileNameW
GetMappedFileNameW.restype = wt.DWORD
GetMappedFileNameW.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_wchar_p, wt.DWORD]

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("memory_scan")

SKIP_PROCESSES = {"system", "registry", "idle", "smss.exe", "csrss.exe", "mem compression"}

KNOWN_JIT_PROCESSES = {
    "msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe",
    "msedgewebview2.exe", "microsoftedgeupdate.exe",
    "node.exe", "java.exe", "javaw.exe",
    "powershell.exe", "pwsh.exe",
    "dotnet.exe", "msbuild.exe",
    "devenv.exe", "code.exe",
    "sdxhelper.exe", "onenotem.exe",
    "searchhost.exe", "startmenuexperiencehost.exe",
    "runtimebroker.exe", "applicationframehost.exe",
    "explorer.exe", "shellexperiencehost.exe",
    "textinputhost.exe", "widgetservice.exe",
    "dllhost.exe", "smartscreen.exe",
    "windowsterminal.exe", "conhost.exe",
    "dwm.exe", "shellhost.exe",
    "crossdeviceresume.exe", "sppextcomobj.exe",
}


def _prot_string(protect: int) -> str:
    names = {
        0x01: "NOACCESS", 0x02: "READONLY", 0x04: "READWRITE",
        0x08: "WRITECOPY", 0x10: "EXECUTE", 0x20: "EXECUTE_READ",
        0x40: "EXECUTE_READWRITE", 0x80: "EXECUTE_WRITECOPY",
    }
    return names.get(protect & 0xFF, f"0x{protect:04x}")


def _type_string(mem_type: int) -> str:
    if mem_type & MEM_IMAGE:
        return "IMAGE"
    if mem_type & MEM_MAPPED:
        return "MAPPED"
    if mem_type & MEM_PRIVATE:
        return "PRIVATE"
    return f"0x{mem_type:08x}"


def _get_backing_file(handle, address: int) -> str:
    buf = ctypes.create_unicode_buffer(512)
    length = GetMappedFileNameW(handle, ctypes.c_void_p(address), buf, 512)
    if length > 0:
        return buf.value
    return ""


def scan_process(pid: int, proc_name: str) -> list[dict]:
    findings = []
    is_jit_process = proc_name.lower() in KNOWN_JIT_PROCESSES

    handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        return findings

    try:
        address = 0
        mbi = MEMORY_BASIC_INFORMATION()

        while True:
            ret = VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
            if not ret:
                break

            prot = mbi.Protect & 0xFF
            is_committed = mbi.State == MEM_COMMIT
            is_executable = prot in EXECUTABLE_FLAGS
            is_rwx = prot in RWX_FLAGS
            is_private = bool(mbi.Type & MEM_PRIVATE)
            is_image = bool(mbi.Type & MEM_IMAGE)

            if is_committed and is_executable:
                finding_type = None
                severity = None

                if is_rwx and not is_jit_process:
                    finding_type = "rwx_region"
                    severity = "critical"
                elif is_rwx and is_jit_process:
                    finding_type = "rwx_region_jit"
                    severity = "low"

                if finding_type:
                    backing_file = _get_backing_file(handle, mbi.BaseAddress or address)
                    findings.append({
                        "type": finding_type,
                        "severity": severity,
                        "pid": pid,
                        "process": proc_name,
                        "region_base": hex(mbi.BaseAddress) if mbi.BaseAddress else hex(address),
                        "region_size": mbi.RegionSize,
                        "protection": _prot_string(prot),
                        "mem_type": _type_string(mbi.Type),
                        "backing_file": backing_file or "none",
                        "is_jit_process": is_jit_process,
                    })

            address = (mbi.BaseAddress or address) + mbi.RegionSize
            if address >= 0x7FFFFFFFFFFF:
                break

    except Exception as e:
        logger.debug("Error scanning PID %d: %s", pid, e)
    finally:
        CloseHandle(handle)

    return findings


def scan_all(target_pid: int | None = None) -> list[dict]:
    all_findings = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            pid = proc.info["pid"]
            name = (proc.info["name"] or "").lower()
            if name in SKIP_PROCESSES:
                continue
            if target_pid is not None and pid != target_pid:
                continue
            findings = scan_process(pid, proc.info["name"] or "unknown")
            all_findings.extend(findings)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return all_findings


def main():
    parser = argparse.ArgumentParser(description="Memory integrity scanner (G3)")
    parser.add_argument("--pid", type=int, default=None, help="Scan a single PID")
    parser.add_argument("--out", type=str, default=None, help="Output JSONL file path")
    args = parser.parse_args()

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = args.out or f"memory_scan_{timestamp}.jsonl"

    logger.info("Starting memory integrity scan...")
    if args.pid:
        logger.info("Target PID: %d", args.pid)

    findings = scan_all(target_pid=args.pid)

    critical = []
    high = []
    low = []

    with open(out_path, "w") as f:
        for finding in findings:
            finding["scan_timestamp"] = datetime.now(timezone.utc).isoformat()
            f.write(json.dumps(finding) + "\n")

            sev = finding.get("severity", "")
            if sev == "critical":
                critical.append(finding)
            elif sev == "high":
                high.append(finding)
            else:
                low.append(finding)

            label = f"[{sev.upper()}]" if sev != "low" else "[JIT-OK]"
            logger.info("%s PID=%d %s type=%s base=%s size=%d prot=%s backing=%s",
                        label, finding["pid"], finding["process"], finding["type"],
                        finding["region_base"], finding["region_size"],
                        finding["protection"], finding["backing_file"])

    logger.info("Scan complete: %d critical, %d high, %d low (JIT), %d total",
                len(critical), len(high), len(low), len(findings))
    logger.info("Results written to: %s", out_path)


if __name__ == "__main__":
    main()
