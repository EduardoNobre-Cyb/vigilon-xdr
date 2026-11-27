# Vigilon Spectra - File Monitor

import os
import math
import struct
import hashlib
from typing import Dict, Optional
import io
import re
import zipfile

import numpy as np

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    import olefile
    HAS_OLEFILE = True
except ImportError:
    HAS_OLEFILE = False

try:
    from oletools.olevba import VBA_Parser
    HAS_OLETOOLS = True
except ImportError:
    HAS_OLETOOLS = False

try:
    from pypdf import PdfReader
    HAS_PYPDF = True
except ImportError:
    HAS_PYPDF = False

try:
    from signify.authenticode import SignedPEFile
    HAS_SIGNIFY = True
except ImportError:
    HAS_SIGNIFY = False

SUSPICIOUS_SECTION_NAMES = {
    ".upx0", ".upx1", ".upx2", 
    ".aspack", ".adata"
    ".nsp0", ".nsp1",
    ".themida", ".vmp0", ".vmp1",
    ".enigma1", ".enigma2",
    ".petite",
    ".mpress1", ".mpress2",
}

SUSPICIOUS_IMPORTS = {
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory",
    "CreateRemoteThread", "CreateRemoteThreadEx",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
    "OpenProcess", "OpenThread",
    "SetWindowsHookEx", "SetWindowsHookExA", "SetWindowsHookExW",
    "GetProcAddress", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA",
    "URLDownloadToFile", "URLDownloadToFileA", "URLDownloadToFileW",
    "InternetOpen", "InternetOpenA", "InternetOpenUrl", "HttpSendRequest",
    "WinExec", "ShellExecute", "ShellExecuteA", "ShellExecuteW",
    "CreateService", "CreateServiceA", "CreateServiceW",
    "RegSetValueEx", "RegSetValueExA", "RegSetValueExW",
    "CryptEncrypt", "CryptDecrypt", "CryptAcquireContext",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "AdjustTokenPrivileges",
}

SUSPICIOUS_DLLS = {
    "ws2_32.dll", "wininet.dll", "urlmon.dll",
    "crypt32.dll", "advapi32.dll",
    "ntdll.dll", "kernel32.dll", "cabinet.dll", "wtsapi32.dll"
}

SUSPICIOUS_VBA_KEYWORDS = {
    "Shell", "PowerShell", "WScript", "CreateObject", "GetObject", "Environ",
    "URLDownloadToFile", "cmd.exe", "powershell.exe", "CallByName", "MacScript",
    "Execute", "Run", "Open", "Kill", "FileCopy", "MkDir", "RmDir", "SendKeys",
    "RegWrite", "RegRead", "RegDelete", "RegCreateKey", "RegDeleteKey", "RegEnumKey",
}

AUTO_EXECUTE_MACROS = {
    "AutoOpen", "AutoClose", "AutoExec", "AutoExit", "AutoNew", 
    "Document_Open", "Document_Close", "Document_New", 
    "Workbook_Open", "Workbook_Close", "Workbook_Activate",
    "Auto_Open", "Auto_Close",
}

PE_MAGIC = b"MZ"
ELF_MAGIC = b"\x7fELF"
DOC_MAGIC_PDF = b"%PDF"
DOC_MAGIC_OLE = b"\xd0\xcf\x11\xe0"
DOC_MAGIC_OOXML = b"PK\x03\x04"
DOC_MAGIC_RTF = b"{\\rtf"

def _file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    length = len(data)
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / length
            entropy -= p * math.log2(p)
    return entropy

def _byte_histogram(data: bytes) -> np.ndarray:
    hist = np.zeros(256, dtype=np.float64)
    for b in data:
        hist[b] += 1
    total = hist.sum()
    if total > 0:
        hist /= total
    return hist


class StaticBinaryFeatureExtractor:
    def extract_features(self, file_path: str) -> Optional[Dict[str, float]]:
        try:
            with open(file_path, "rb") as f:
                magic = f.read(4)
        except (OSError, PermissionError):
            return None

        if magic[:2] == PE_MAGIC and HAS_PEFILE:
            return self._extract_pe_features(file_path)
        elif magic[:4] == ELF_MAGIC:
            return self._extract_elf_features(file_path)
        return None

    def _extract_pe_features(self, path: str) -> Optional[Dict[str, float]]:
        try:
            pe = pefile.PE(path, fast_load=True)
        except pefile.PEFormatError:
            return None

        features = {}
        file_size = os.path.getsize(path)

        features["file_size"] = file_size
        features["file_size_log"] = math.log2(file_size + 1)

        with open(path, "rb") as f:
            raw = f.read()
        features["whole_file_entropy"] = _byte_entropy(raw)

        features["is_dll"] = 1.0 if pe.FILE_HEADER.Characteristics & 0x2000 else 0.0
        features ["is_exe"] = 1.0 if not features["is_dll"] else 0.0
        features["num_sections"] = float(pe.FILE_HEADER.NumberOfSections)
        features["timestamp"] = float(pe.FILE_HEADER.TimeDateStamp)

        opt = pe.OPTIONAL_HEADER
        features["image_size"] = float(opt.SizeOfImage)
        features["code_size"] = float(opt.SizeOfCode)
        features["entry_point"] = float(opt.AddressOfEntryPoint)
        features["subsystem"] = float(opt.Subsystem)

        features["header_ratio"] = float(opt.SizeOfHeaders) / max(file_size, 1)

        section_entropies = []
        suspicious_section_count = 0
        writable_and_executable = 0

        for section in pe.sections:
            sec_name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace").lower()
            sec_data = section.get_data()
            sec_entropy = _byte_entropy(sec_data)
            section_entropies.append(sec_entropy)

            if sec_name in SUSPICIOUS_SECTION_NAMES:
                suspicious_section_count += 1

            chars = section.Characteristics
            is_writable = bool(chars & 0x80000000)
            is_executable = bool(chars & 0x20000000)
            if is_writable and is_executable:
                writable_and_executable += 1

        features["max_section_entropy"] = max(section_entropies) if section_entropies else 0.0
        features["min_section_entropy"] = min(section_entropies) if section_entropies else 0.0
        features["mean_section_entropy"] = float(np.mean(section_entropies)) if section_entropies else 0.0
        features["suspicious_section_count"] = float(suspicious_section_count)
        features["writable_executable_sections"] = float(writable_and_executable)

        suspicious_import_count = 0
        suspicious_dll_count = 0
        total_imports = 0

        try:
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8", errors="replace").lower()
                    if dll_name in SUSPICIOUS_DLLS:
                        suspicious_dll_count += 1
                    for imp in entry.imports:
                        total_imports += 1
                        if imp.name:
                            func_name = imp.name.decode("utf-8", errors="replace")
                            if func_name in SUSPICIOUS_IMPORTS:
                                suspicious_import_count += 1
        except Exception:
            pass

        features["total_imports"] = float(total_imports)
        features["suspicious_import_count"] = float(suspicious_import_count)
        features["suspicious_import_ratio"] = suspicious_import_count / max(total_imports, 1)
        features["suspicious_dll_count"] = float(suspicious_dll_count)

        has_signature = False
        try:
            if hasattr(pe, "DIRECTORY_ENTRY_SECURITY"):
                has_signature = True
        except Exception:
            pass
        features["has_signature"] = 1.0 if has_signature else 0.0

        has_resources = False
        try:
            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                has_resources = True
        except Exception:
            pass
        features["has_resources"] = 1.0 if has_resources else 0.0

        hist = _byte_histogram(raw)
        for i in range(256):
            features[f"byte_{i:03d}"] = float(hist[i])

        pe.close()
        return features

    def _extract_elf_features(self, path: str) -> Optional[Dict[str, float]]:
        try:
            with open(path, "rb") as f:
                raw = f.read()
        except (OSError, PermissionError):
            return None

        if len(raw) < 64:
            return None

        features = {}
        file_size = len(raw)

        features["file_size"] = float(file_size)
        features["file_size_log"] = math.log2(file_size + 1)
        features["whole_file_entropy"] = _byte_entropy(raw)

        ei_class = raw[4]
        is_64 = ei_class == 2

        if is_64 and len(raw) >= 64:
            e_type = struct.unpack_from("<H", raw, 16)[0]
            e_entry = struct.unpack_from("<Q", raw, 24)[0]
            e_phnum = struct.unpack_from("<H", raw, 56)[0]
            e_shnum = struct.unpack_from("<H", raw, 60)[0]
        elif not is_64 and len(raw) >= 52:
            e_type = struct.unpack_from("<H", raw, 16)[0]
            e_entry = struct.unpack_from("<I", raw, 24)[0]
            e_phnum = struct.unpack_from("<H", raw, 44)[0]
            e_shnum = struct.unpack_from("<H", raw, 48)[0]
        else:
            return None

        features["is_dll"] = 1.0 if e_type == 3 else 0.0
        features["is_exe"] = 1.0 if e_type == 2 else 0.0
        features["num_sections"] = float(e_shnum)
        features["timestamp"] = 0.0
        features["image_size"] = float(file_size)
        features["code_size"] = 0.0
        features["entry_point"] = float(e_entry)
        features["subsystem"] = 0.0
        features["header_ratio"] = 64.0 / max(file_size, 1)

        chunk_size = 4096
        chunk_entropies = []
        for offset in range(0, file_size, chunk_size):
            chunk = raw[offset:offset + chunk_size]
            if len(chunk) >= 256:
                chunk_entropies.append(_byte_entropy(chunk))

        features["max_section_entropy"] = max(chunk_entropies) if chunk_entropies else 0.0
        features["min_section_entropy"] = min(chunk_entropies) if chunk_entropies else 0.0
        features["mean_section_entropy"] = float(np.mean(chunk_entropies)) if chunk_entropies else 0.0
        features["suspicious_section_count"] = 0.0
        features["writable_executable_sections"] = 0.0

        features["total_imports"] = 0.0
        features["suspicious_imports_count"] = 0.0
        features["suspicious_import_ratio"] = 0.0
        features["suspicious_dll_count"] = 0.0

        features["has_signature"] = 0.0
        features["has_resources"] = 0.0

        hist = _byte_histogram(raw)
        for i in range(256):
            features[f"byte_{i:03d}"] = float(hist[i])

        return features


def get_feature_names() -> list:
    names = [
        "file_size", "file_size_log", "whole_file_entropy",
        "is_dll", "is_exe", "num_sections", "timestamp",
        "image_size", "code_size", "entry_point", "subsystem", "header_ratio",
        "max_section_entropy", "min_section_entropy", "mean_section_entropy",
        "suspicious_section_count", "writable_executable_sections",
        "total_imports", "suspicious_import_count", "suspicious_import_ratio",
        "suspicious_dll_count",
        "has_signature", "has_resources",
    ]
    names += [f"byte_{i:03d}" for i in range(256)]
    return names

class DocumentFeatureExtractor:
    def extract_features(self, file_path: str) -> Optional[Dict[str, float]]:
        try:
            with open(file_path, "rb") as f:
                raw = f.read()
        except (OSError, PermissionError):
            return None

        if len(raw) < 8:
            return None

        magic = raw[:8]

        if magic[:4] == DOC_MAGIC_PDF:
            return self._extract_pdf_features(file_path, raw)
        elif magic[:4] == DOC_MAGIC_OLE and HAS_OLEFILE:
            return self._extract_ole_features(file_path, raw)
        elif magic[:4] == DOC_MAGIC_OOXML:
            if self._is_ooxml(raw):
                return self._extract_ooxml_features(file_path, raw)
            return None
        elif raw[:5] == b"{\\rtf":
            return self._extract_rtf_features(file_path, raw)

        return None

    @staticmethod
    def _is_ooxml(raw: bytes) -> bool:
        try:
            zf = zipfile.ZipFile(io.BytesIO(raw))
            has_ct = "[Content_Types].xml" in zf.namelist()
            zf.close()
            return has_ct
        except Exception:
            return False

    def _base_features(self, raw: bytes) -> Dict[str, float]:
        features = {
            "is_pdf": 0.0, "is_ole": 0.0, "is_ooxml": 0.0, "is_rtf": 0.0,
            "file_size": float(len(raw)),
            "file_size_log": math.log2(len(raw) + 1),
            "whole_file_entropy": _byte_entropy(raw),
            "num_pages": 0.0, "num_streams": 0.0,
            "max_stream_entropy": 0.0, "mean_stream_entropy": 0.0,
            "min_stream_entropy": 0.0,
            "has_javascript": 0.0, "has_vba_macros": 0.0, "num_vba_modules": 0.0,
            "has_auto_execute": 0.0, "num_suspicious_keywords": 0.0,
            "suspicious_keyword_ratio": 0.0,
            "has_embedded_file": 0.0, "has_embedded_exe": 0.0,
            "has_launch_action": 0.0, "has_uri_action": 0.0, "num_urls": 0.0,
            "has_encryption": 0.0,
        }
        hist = _byte_histogram(raw)
        for i in range(256):
            features[f"byte_{i:03d}"] = float(hist[i])
        return features

    def _analyze_vba(self, path: str, features: Dict[str, float]) -> None:
        if not HAS_OLETOOLS:
            return
        try:
            vba = VBA_Parser(path)
            if vba.detect_vba_macros():
                features["has_vba_macros"] = 1.0
                modules = list(vba.extract_macros())
                features["num_vba_modules"] = float(len(modules))

                all_code = " ".join(code for _, _, _, code in modules)
                code_lower = all_code.lower()

                has_auto = any(kw.lower() in code_lower for kw in AUTO_EXECUTE_MACROS)
                features["has_auto_execute"] = 1.0 if has_auto else 0.0

                suspicious_count = sum(1 for kw in SUSPICIOUS_VBA_KEYWORDS if kw.lower() in code_lower)
                features["num_suspicious_keywords"] = float(suspicious_count)
                word_count = max(len(all_code.split()), 1)
                features["suspicious_keyword_ratio"] = suspicious_count / word_count
            vba.close()
        except Exception:
            pass

    def _set_stream_entropy(self, entropies: list, features: Dict[str, float]) -> None:
        if entropies:
            features["max_stream_entropy"] = max(entropies)
            features["mean_stream_entropy"] = float(np.mean(entropies))
            features["min_stream_entropy"] = min(entropies)

    def _extract_pdf_features(self, path: str, raw: bytes) -> Dict[str, float]:
        features = self._base_features(raw)
        features["is_pdf"] = 1.0

        if HAS_PYPDF:
            try:
                reader = PdfReader(io.BytesIO(raw))
                features["num_pages"] = float(len(reader.pages))
                features["has_encryption"] = 1.0 if reader.is_encrypted else 0.0
            except Exception:
                pass

        text = raw.decode("latin-1", errors="replace")

        features["has_javascript"] = 1.0 if ("/JavaScript" in text or "/JS " in text or "/JS(" in text) else 0.0
        features["has_launch_action"] = 1.0 if "/Launch" in text else 0.0
        features["has_auto_execute"] = 1.0 if ("/OpenAction" in text or "/AA " in text) else 0.0
        features["has_embedded_file"] = 1.0 if "/EmbeddedFile" in text else 0.0
        features["has_embedded_exe"] = 1.0 if (b"MZ" in raw[1024:] and b"This program" in raw) else 0.0

        urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]()]+', text)
        features["num_urls"] = float(len(urls))

        features["num_streams"] = float(text.count(" obj"))

        stream_entropies = []
        pos = 0
        while True:
            start = raw.find(b"stream", pos)
            if start == -1:
                break
            start += 6
            if start < len(raw) and raw[start:start + 1] == b"\r":
                start += 1
            if start < len(raw) and raw[start:start + 1] == b"\n":
                start += 1
            end = raw.find(b"endstream", start)
            if end == -1:
                break
            stream_data = raw[start:end]
            if len(stream_data) >= 16:
                stream_entropies.append(_byte_entropy(stream_data))
            pos = end + 9
        self._set_stream_entropy(stream_entropies, features)

        return features

    def _extract_ole_features(self, path: str, raw: bytes) -> Dict[str, float]:
        features = self._base_features(raw)
        features["is_ole"] = 1.0

        try:
            ole = olefile.OleFileIO(io.BytesIO(raw))
            streams = ole.listdir()
            features["num_streams"] = float(len(streams))

            stream_entropies = []
            for stream_path in streams:
                try:
                    data = ole.openstream(stream_path).read()
                    if len(data) >= 16:
                        stream_entropies.append(_byte_entropy(data))
                except Exception:
                    pass
            self._set_stream_entropy(stream_entropies, features)
            ole.close()
        except Exception:
            pass

        features["has_embedded_exe"] = 1.0 if b"MZ" in raw[512:] else 0.0
        features["has_embedded_file"] = 1.0 if (b"\x00O\x00b\x00j\x00e\x00c\x00t" in raw) else 0.0

        self._analyze_vba(path, features)
        return features

    def _extract_ooxml_features(self, path: str, raw: bytes) -> Dict[str, float]:
        features = self._base_features(raw)
        features["is_ooxml"] = 1.0

        try:
            zf = zipfile.ZipFile(io.BytesIO(raw))
            entries = zf.namelist()
            features["num_streams"] = float(len(entries))

            stream_entropies = []
            for name in entries:
                try:
                    data = zf.read(name)
                    if len(data) >= 16:
                        stream_entropies.append(_byte_entropy(data))
                except Exception:
                    pass
            self._set_stream_entropy(stream_entropies, features)

            url_count = 0
            has_external = False
            for name in entries:
                if name.endswith(".rels"):
                    try:
                        rels = zf.read(name).decode("utf-8", errors="replace")
                        if 'TargetMode="External"' in rels:
                            has_external = True
                        url_count += rels.lower().count("http")
                    except Exception:
                        pass
            features["has_uri_action"] = 1.0 if has_external else 0.0
            features["num_urls"] = float(url_count)

            for name in entries:
                if "oleObject" in name or "embeddings" in name.lower():
                    features["has_embedded_file"] = 1.0
                    try:
                        data = zf.read(name)
                        if b"MZ" in data[:512]:
                            features["has_embedded_exe"] = 1.0
                    except Exception:
                        pass

            zf.close()
        except Exception:
            pass

        self._analyze_vba(path, features)
        return features

    def _extract_rtf_features(self, path: str, raw: bytes) -> Dict[str, float]:
        features = self._base_features(raw)
        features["is_rtf"] = 1.0

        text = raw.decode("latin-1", errors="replace")

        features["has_embedded_file"] = 1.0 if ("\\objdata" in text or "\\objemb" in text) else 0.0
        features["has_embedded_exe"] = 1.0 if b"MZ" in raw[100:] else 0.0

        urls = re.findall(r'https?://[^\s\\}]+', text)
        features["num_urls"] = float(len(urls))
        features["has_uri_action"] = 1.0 if urls else 0.0

        chunk_size = 4096
        chunk_entropies = []
        for offset in range(0, len(raw), chunk_size):
            chunk = raw[offset:offset + chunk_size]
            if len(chunk) >= 256:
                chunk_entropies.append(_byte_entropy(chunk))
        self._set_stream_entropy(chunk_entropies, features)

        return features

def get_doc_feature_names() -> list:
    names = [
        "is_pdf", "is_ole", "is_ooxml", "is_rtf",
        "file_size", "file_size_log", "whole_file_entropy",
        "num_pages", "num_streams", "max_stream_entropy",
        "mean_stream_entropy", "min_stream_entropy",
        "has_javascript", "has_vba_macros", "num_vba_modules",
        "has_auto_execute", "num_suspicious_keywords", "suspicious_keyword_ratio",
        "has_embedded_file", "has_embedded_exe",
        "has_launch_action", "has_uri_action", "num_urls",
        "has_encryption",
    ]
    names += [f"byte_{i:03d}" for i in range(256)]
    return names

TRUSTED_PUBLISHERS = {
    "microsoft corporation",
    "microsoft windows",
    "microsoft code signing pca",
    "google llc",
    "google inc",
    "mozilla corporation",
    "apple inc.",
    "adobe inc.",
    "adobe systems incorporated",
    "oracle america, inc.",
    "intel corporation",
    "nvidia corporation",
    "vmware, inc.",
    "sysinternals",
    "dell inc.",
    "hp inc.",
    "lenovo",
    "logitech",
    "realtek semiconductor corp.",
}

def verify_authenticode(file_path: str) -> dict:
    result = {"signed": False, "valid": False, "trusted": False, "publisher": ""}

    if os.name == "nt":
        try:
            import subprocess
            cmd = (
                f'Get-AuthenticodeSignature "{file_path}"'
                f' | Select-Object Status,'
                f' @{{N="CN";E={{($_.SignerCertificate.Subject -split ",")[0] -replace "CN=",""}}}}'
                f' | ConvertTo-Json'
            )
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command", cmd],
                capture_output=True, text=True, timeout=10
            )
            if out.returncode == 0 and out.stdout.strip():
                import json
                data = json.loads(out.stdout)
                if data.get("Status") == 0:  # 0 = Valid
                    result["signed"] = True
                    result["valid"] = True
                    publisher = data.get("CN", "").lower().strip()
                    result["publisher"] = publisher
                    if any(trusted in publisher for trusted in TRUSTED_PUBLISHERS):
                        result["trusted"] = True
        except Exception:
            pass
        return result

    if not HAS_SIGNIFY:
        return result

    try:
        with open(file_path, "rb") as f:
            pe_file = SignedPEFile(f)

            for signed_data in pe_file.signed_datas:
                result["signed"] = True
                signer = signed_data.signer_info
                cert = signer.signing_cert
                subject = cert.subject
                cn = ""
                org = ""
                for attr in subject:
                    oid = attr["type"]
                    value = str(attr["value"])
                    if oid.dotted_string == "2.5.4.3":
                        cn = value
                    elif oid.dotted_string == "2.5.4.10":
                        org = value

                publisher = (cn or org).lower().strip()
                result["publisher"] = publisher

                if any(trusted in publisher for trusted in TRUSTED_PUBLISHERS):
                    result["trusted"] = True
                break

        if result["signed"]:
            try:
                with open(file_path, "rb") as f:
                    pe_file = SignedPEFile(f)
                    pe_file.verify()
                    result["valid"] = True
            except Exception:
                pass

    except Exception:
        pass

    return result