"""
╔═══════════════════════════════════════════════════════════════╗
║              JIGSAW — Windows Event Log Hunter                ║
║    DLL Hijacking · Image Load · Parent-Child · Network Conn   ║
╠═══════════════════════════════════════════════════════════════╣
║  Author   : Kennedy Aikohi                                    ║
║  LinkedIn : linkedin.com/in/aikohikennedy                     ║
║  GitHub   : github.com/kennedy-aikohi                         ║
║  Version  : 2.0 XDR+ OmniParser                              ║
╚═══════════════════════════════════════════════════════════════╝

Architecture mirrors Jigsaw (Jigsaw project) design:
  - EVTX/EVT log ingestion via python-evtx or Get-WinEvent
  - Built-in Jigsaw detection rules (YAML)
  - FilterHashtable-style event filtering
  - XML path querying on event data
  - Timeline view, IP correlation, ProcessGuid tracing
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from tkinter import font as tkfont
import threading
import json
import os
import re
import sys
import subprocess
import ctypes
import time
import datetime
import queue
import glob
import csv
import hashlib
from collections import Counter, defaultdict
import xml.etree.ElementTree as ET
from pathlib import Path

# ── Windows subprocess hygiene ───────────────────────────────────────────────
def _quiet_subprocess_kwargs(text=False, timeout=None):
    """Return subprocess kwargs that prevent console/cmd windows from flashing on Windows."""
    kwargs = {"capture_output": True}
    if text:
        kwargs["text"] = True
    if timeout is not None:
        kwargs["timeout"] = timeout
    if os.name == "nt":
        try:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            kwargs["startupinfo"] = si
        except Exception:
            pass
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return kwargs

def _looks_like_placeholder(value):
    """Treat GUI examples/placeholders as empty so sample text never filters hunts."""
    v = (value or "").strip()
    if not v:
        return True
    examples = {
        "e.g. 192.168.1.100",
        "2024-01-01 00:00:00",
        "2024-12-31 23:59:59",
        "YYYY-MM-DD HH:MM:SS",
    }
    return v in examples or v.lower().startswith("e.g.")

# ── Optional heavy deps – graceful degradation ────────────────────────────────
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# python-evtx is discovered lazily. Importing it at startup can hang on
# some analyst workstations, which made the GUI appear broken before the hunt.
try:
    import importlib.util as _jigsaw_importlib_util
    HAS_EVTX = _jigsaw_importlib_util.find_spec("Evtx.Evtx") is not None
except Exception:
    HAS_EVTX = False

# ── Palette ───────────────────────────────────────────────────────────────────
BG        = "#080c10"
PANEL     = "#0d1117"
PANEL2    = "#161b22"
BORDER    = "#21262d"
BORDER2   = "#30363d"
ACCENT    = "#00d9ff"
ACCENT2   = "#ff6b35"
ACCENT3   = "#a371f7"
SUCCESS   = "#3fb950"
WARNING   = "#d29922"
DANGER    = "#f85149"
TEXT      = "#e6edf3"
TEXT_DIM  = "#8b949e"
TEXT_MID  = "#c9d1d9"
HEADER    = "#010409"
ROW_ALT   = "#0d1218"

# ── Key Windows Event IDs for detection ──────────────────────────────────────
EVENT_CATALOG = {
    # Sysmon
    1:  ("Sysmon",    "Process Create"),
    2:  ("Sysmon",    "File Creation Time Changed"),
    3:  ("Sysmon",    "Network Connection"),
    4:  ("Sysmon",    "Sysmon Service State Changed"),
    5:  ("Sysmon",    "Process Terminated"),
    6:  ("Sysmon",    "Driver Loaded"),
    7:  ("Sysmon",    "Image Loaded"),          # ← DLL load
    8:  ("Sysmon",    "CreateRemoteThread"),
    9:  ("Sysmon",    "RawAccessRead"),
    10: ("Sysmon",    "ProcessAccess"),
    11: ("Sysmon",    "FileCreate"),
    12: ("Sysmon",    "RegistryEvent (Create/Delete)"),
    13: ("Sysmon",    "RegistryEvent (Value Set)"),
    14: ("Sysmon",    "RegistryEvent (Key/Value Rename)"),
    15: ("Sysmon",    "FileCreateStreamHash"),
    16: ("Sysmon",    "ServiceConfigurationChange"),
    17: ("Sysmon",    "PipeEvent (Created)"),
    18: ("Sysmon",    "PipeEvent (Connected)"),
    19: ("Sysmon",    "WmiEvent (Filter)"),
    20: ("Sysmon",    "WmiEvent (Consumer)"),
    21: ("Sysmon",    "WmiEvent (Binding)"),
    22: ("Sysmon",    "DNSQuery"),
    23: ("Sysmon",    "FileDelete"),
    25: ("Sysmon",    "ProcessTampering"),
    26: ("Sysmon",    "FileDeleteDetected"),
    # Security
    4624: ("Security","Successful Logon"),
    4625: ("Security","Failed Logon"),
    4634: ("Security","Account Logoff"),
    4648: ("Security","Logon using Explicit Credentials"),
    4657: ("Security","Registry Value Modified"),
    4663: ("Security","Object Access Attempt"),
    4688: ("Security","New Process Created"),
    4698: ("Security","Scheduled Task Created"),
    4702: ("Security","Scheduled Task Updated"),
    4720: ("Security","User Account Created"),
    4726: ("Security","User Account Deleted"),
    4732: ("Security","Member Added to Security Group"),
    4756: ("Security","Member Added to Universal Group"),
    4768: ("Security","Kerberos Auth Ticket (TGT) Requested"),
    4769: ("Security","Kerberos Service Ticket Requested"),
    4771: ("Security","Kerberos Pre-Auth Failed"),
    4776: ("Security","NTLM Auth Attempted"),
    4964: ("Security","Special Groups Logon"),
    # System
    7045: ("System",  "New Service Installed"),
    7040: ("System",  "Service Start Type Changed"),
    # PowerShell
    4103: ("PowerShell","Module Logging"),
    4104: ("PowerShell","Script Block Logging"),
    # WinRM
    91:   ("WinRM",   "Session Created"),
    168:  ("WinRM",   "Authenticating User"),
}

# ── Known DLL hijacking targets ───────────────────────────────────────────────
DLL_HIJACK_TARGETS = {
    # Search-order hijack classics
    "version.dll", "dbghelp.dll", "winmm.dll", "wtsapi32.dll",
    "cryptsp.dll", "cryptbase.dll", "rsaenh.dll", "userenv.dll",
    "profapi.dll", "netapi32.dll", "wkscli.dll", "netutils.dll",
    "samcli.dll", "samlib.dll", "logoncli.dll", "srvcli.dll",
    "secur32.dll", "sspicli.dll", "apphelp.dll",
    # Phantom DLLs (referenced but not present by default)
    "twain_32.dll", "wbemcomn.dll", "wbemprox.dll",
    "wmiutils.dll", "rasadhlp.dll", "uxtheme.dll",
    "mpr.dll", "ntmarta.dll", "propsys.dll",
    # Common LOLBin hijack vectors
    "comsvcs.dll", "ieframe.dll", "mshtml.dll",
    "wininet.dll", "urlmon.dll", "shell32.dll",
    "shdocvw.dll", "msi.dll",
}

# ── Suspicious load paths (DLL loaded from non-standard location) ─────────────
SUSPICIOUS_LOAD_PATHS = [
    r"\\users\\", r"\\temp\\", r"\\tmp\\", r"\\appdata\\",
    r"\\downloads\\", r"\\public\\", r"\\programdata\\",
    r"\\recycle", r"\\windows\\temp",
]

# ── Suspicious parent-child (from HTB/PJPT/SOC documentation) ─────────────────
SUSPICIOUS_PC_PAIRS = {
    "spoolsv.exe":        ["cmd.exe","powershell.exe","wscript.exe","cscript.exe",
                           "mshta.exe","rundll32.exe","regsvr32.exe","whoami.exe",
                           "net.exe","certutil.exe","bitsadmin.exe"],
    "svchost.exe":        ["cmd.exe","powershell.exe","mshta.exe","wscript.exe",
                           "cscript.exe","regsvr32.exe","certutil.exe"],
    "winlogon.exe":       ["cmd.exe","powershell.exe","mshta.exe","taskmgr.exe"],
    "lsass.exe":          ["cmd.exe","powershell.exe","whoami.exe","net.exe",
                           "mimikatz.exe","procdump.exe"],
    "services.exe":       ["cmd.exe","powershell.exe","mshta.exe"],
    "wininit.exe":        ["cmd.exe","powershell.exe"],
    "taskhost.exe":       ["cmd.exe","powershell.exe"],
    "dwm.exe":            ["cmd.exe","powershell.exe"],
    "csrss.exe":          ["cmd.exe","powershell.exe"],
    "smss.exe":           ["cmd.exe","powershell.exe"],
    "dllhost.exe":        ["cmd.exe","powershell.exe","mshta.exe"],
    "msiexec.exe":        ["powershell.exe","cmd.exe","mshta.exe","wscript.exe"],
    "outlook.exe":        ["cmd.exe","powershell.exe","wscript.exe","mshta.exe"],
    "excel.exe":          ["cmd.exe","powershell.exe","wscript.exe","mshta.exe",
                           "rundll32.exe","regsvr32.exe"],
    "winword.exe":        ["cmd.exe","powershell.exe","wscript.exe","mshta.exe",
                           "rundll32.exe","regsvr32.exe"],
    "powerpnt.exe":       ["cmd.exe","powershell.exe","wscript.exe","mshta.exe"],
    "acrord32.exe":       ["cmd.exe","powershell.exe","wscript.exe"],
    "iexplore.exe":       ["cmd.exe","powershell.exe","wscript.exe","cscript.exe"],
    "explorer.exe":       ["svchost.exe","lsass.exe"],
    "werfault.exe":       ["cmd.exe","powershell.exe"],
    "searchindexer.exe":  ["cmd.exe","powershell.exe","wscript.exe"],
}

# ── Built-in Jigsaw detection rules ──────────────────────────────────────────
JIGSAW_RULES = [
    {
        "id": "JIG-001",
        "name": "DLL Loaded from User-Writable Path",
        "description": "Image load event (EID 7) where DLL is loaded from a user-writable directory.",
        "severity": "HIGH",
        "category": "DLL Hijacking",
        "mitre": "T1574.001",
        "event_ids": [7],
        "logic": "image_load_path_suspicious",
    },
    {
        "id": "JIG-002",
        "name": "Known DLL Hijacking Target Loaded from Non-System32",
        "description": "A DLL commonly targeted for hijacking was loaded outside System32/SysWOW64.",
        "severity": "CRITICAL",
        "category": "DLL Hijacking",
        "mitre": "T1574.001",
        "event_ids": [7],
        "logic": "dll_hijack_target_outside_system",
    },
    {
        "id": "JIG-003",
        "name": "Suspicious Parent-Child Process Relationship",
        "description": "A process was spawned by an unusual parent.",
        "severity": "HIGH",
        "category": "Process Injection",
        "mitre": "T1055",
        "event_ids": [1, 4688],
        "logic": "suspicious_parent_child",
    },
    {
        "id": "JIG-004",
        "name": "Network Connection from Unexpected Process",
        "description": "Network connection initiated by a process not expected to make network calls.",
        "severity": "MEDIUM",
        "category": "C2 / Lateral Movement",
        "mitre": "T1071",
        "event_ids": [3],
        "logic": "unexpected_network_initiator",
    },
    {
        "id": "JIG-005",
        "name": "Sensitive Process Memory Access (LSASS)",
        "description": "ProcessAccess event targeting lsass.exe.",
        "severity": "CRITICAL",
        "category": "Credential Access",
        "mitre": "T1003.001",
        "event_ids": [10],
        "logic": "lsass_access",
    },
    {
        "id": "JIG-006",
        "name": "Driver Loaded — Unsigned or Non-Microsoft",
        "description": "A driver was loaded that is either unsigned or not Microsoft-signed.",
        "severity": "HIGH",
        "category": "Driver Load",
        "mitre": "T1014",
        "event_ids": [6],
        "logic": "unsigned_driver_load",
    },
    {
        "id": "JIG-007",
        "name": "Scheduled Task Created",
        "description": "A new scheduled task was registered.",
        "severity": "MEDIUM",
        "category": "Persistence",
        "mitre": "T1053.005",
        "event_ids": [4698, 4702],
        "logic": "scheduled_task",
    },
    {
        "id": "JIG-008",
        "name": "Service Installed",
        "description": "A new Windows service was installed.",
        "severity": "MEDIUM",
        "category": "Persistence",
        "mitre": "T1543.003",
        "event_ids": [7045],
        "logic": "service_installed",
    },
    {
        "id": "JIG-009",
        "name": "PowerShell Script Block Execution",
        "description": "PowerShell script block logged — inspect for encoded/obfuscated commands.",
        "severity": "MEDIUM",
        "category": "Execution",
        "mitre": "T1059.001",
        "event_ids": [4104],
        "logic": "ps_scriptblock",
    },
    {
        "id": "JIG-010",
        "name": "Event Log Cleared",
        "description": "Security or System event log was cleared.",
        "severity": "HIGH",
        "category": "Defense Evasion",
        "mitre": "T1070.001",
        "event_ids": [1102, 104],
        "logic": "log_cleared",
    },
    {
        "id": "JIG-011",
        "name": "CreateRemoteThread into Foreign Process",
        "description": "Thread injected into a remote process.",
        "severity": "CRITICAL",
        "category": "Process Injection",
        "mitre": "T1055.003",
        "event_ids": [8],
        "logic": "remote_thread",
    },
    {
        "id": "JIG-012",
        "name": "Suspicious Encoded PowerShell Command",
        "description": "PowerShell executed with -EncodedCommand or similar obfuscation.",
        "severity": "HIGH",
        "category": "Execution / Obfuscation",
        "mitre": "T1027",
        "event_ids": [1, 4688, 4104],
        "logic": "encoded_ps",
    },
    {
        "id": "JIG-013",
        "name": "Network Connection to Non-Standard Port by Browser/Office",
        "description": "Office or browser process connecting on non-standard ports.",
        "severity": "HIGH",
        "category": "C2",
        "mitre": "T1071.001",
        "event_ids": [3],
        "logic": "office_nonstandard_port",
    },
    {
        "id": "JIG-014",
        "name": "Unsigned Image Loaded into Sensitive Process",
        "description": "Unsigned DLL loaded into lsass, svchost, or other sensitive host.",
        "severity": "CRITICAL",
        "category": "DLL Hijacking / Injection",
        "mitre": "T1574",
        "event_ids": [7],
        "logic": "unsigned_dll_in_sensitive_proc",
    },
    {
        "id": "JIG-015",
        "name": "NTLM Authentication Brute Force",
        "description": "Multiple EID 4776 failures from the same source in a short window.",
        "severity": "HIGH",
        "category": "Credential Access",
        "mitre": "T1110.003",
        "event_ids": [4776],
        "logic": "ntlm_bruteforce",
    },
]

# ── Author / product identity shown early in UI, CLI, and reports ────────────
AUTHOR_NAME = "Kennedy Aikohi"
AUTHOR_LINKEDIN = "linkedin.com/in/aikohikennedy"
AUTHOR_GITHUB = "github.com/kennedy-aikohi"
PRODUCT_NAME = "Jigsaw XDR+ OmniParser"
PRODUCT_VERSION = "2.0"

# ── Additional heavyweight detections: generic Windows logs, EVTX, XML, CSV, JSON, TXT
JIGSAW_RULES.extend([
    {
        "id": "JIG-016",
        "name": "Living-off-the-Land Execution Chain",
        "description": "Detects LOLBin chains and suspicious command lines across Sysmon, Security, PowerShell, JSON, CSV, and text logs.",
        "severity": "HIGH",
        "category": "Execution / LOLBin",
        "mitre": "T1218",
        "event_ids": [1, 4688, 4103, 4104, 7045, 4698, 4702, 0],
        "logic": "generic_lolbin_chain",
    },
    {
        "id": "JIG-017",
        "name": "Persistence Keyword Constellation",
        "description": "Finds services, run keys, scheduled tasks, WMI persistence, startup-folder, and autorun-like signals in any supported log format.",
        "severity": "HIGH",
        "category": "Persistence",
        "mitre": "T1547",
        "event_ids": [1, 11, 12, 13, 19, 20, 21, 4657, 4698, 4702, 7045, 7040, 0],
        "logic": "persistence_constellation",
    },
    {
        "id": "JIG-018",
        "name": "Credential Theft Keyword Constellation",
        "description": "Detects LSASS dump, SAM/NTDS extraction, secretsdump, procdump, Mimikatz, comsvcs, and credential-store abuse in parsed fields or raw messages.",
        "severity": "CRITICAL",
        "category": "Credential Access",
        "mitre": "T1003",
        "event_ids": [1, 10, 11, 4688, 4104, 0],
        "logic": "credential_constellation",
    },
    {
        "id": "JIG-019",
        "name": "Suspicious Remote Access / Lateral Movement",
        "description": "Flags WinRM, PsExec, WMI, SMB admin share, RDP, remote service creation, and explicit credential movement patterns.",
        "severity": "HIGH",
        "category": "Lateral Movement",
        "mitre": "T1021",
        "event_ids": [1, 3, 4624, 4648, 4688, 7045, 91, 168, 0],
        "logic": "lateral_movement_constellation",
    },
    {
        "id": "JIG-020",
        "name": "Defense Evasion / Log Destruction",
        "description": "Catches wevtutil clear-log, audit policy tampering, Defender exclusions, tamper keywords, and log-clearing strings in any parsed source.",
        "severity": "CRITICAL",
        "category": "Defense Evasion",
        "mitre": "T1070",
        "event_ids": [1, 1102, 104, 4688, 4104, 0],
        "logic": "defense_evasion_constellation",
    },
])

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}



# ═══════════════════════════════════════════════════════════════════════════════
# EVTX Binary Parser  — pure Python, zero dependencies, artefact-first
# ═══════════════════════════════════════════════════════════════════════════════
"""
Reads raw .evtx files from disk without touching the Windows Event Log service.
Designed for OFFLINE FORENSIC ARTEFACTS from another machine.

EVTX binary format overview (from libyal documentation):
  File header   (4 KB)  — magic "ElfFile\x00", chunk offsets
  Chunks        (65 KB each) — contain compressed event records
  Each record   — XML template + substitution array

We take a pragmatic shortcut: instead of implementing the full BinXML
template engine (complex, many edge cases), we:
  1. Read the file in 64 KB chunk-aligned blocks
  2. Use struct to locate EventRecord headers (magic 0x00002A2A)
  3. Extract the BinXML payload and decode it to text XML using the
     Windows built-in wevtutil.exe xe /lf:true  (reads file directly,
     does NOT require the log service — works perfectly on artefacts)
  4. If wevtutil is unavailable, fall back to python-evtx library
  5. If that is also unavailable, fall back to a hand-rolled struct reader
     that extracts the most important fields directly from the binary.

The wevtutil /lf:true flag means "log file" — it reads the file path
directly as a binary EVTX file, completely bypassing the event log service.
This is the correct and documented way to parse artefact EVTX files on Windows.
"""

import struct
import io


class EvtxRecordScanner:
    """
    Lightweight pure-Python EVTX scanner.
    Falls back gracefully — tries every approach in order.
    """
    EVTX_MAGIC      = b"ElfFile\x00"
    RECORD_MAGIC    = b"\x2a\x2a\x00\x00"   # EventRecord header
    CHUNK_MAGIC     = b"ElfChnk\x00"

    def __init__(self, path):
        self.path = path
        self._validate()

    def _validate(self):
        with open(self.path, "rb") as f:
            magic = f.read(8)
        if magic != self.EVTX_MAGIC:
            raise ValueError(f"Not an EVTX file: {self.path}")

    def xml_records(self):
        """
        Yield raw XML strings for each event record.
        Uses wevtutil /lf:true for proper BinXML decode — works on artefacts.
        """
        # wevtutil qe <path> /lf:true /f:xml reads file directly (artefact-safe)
        try:
            result = subprocess.run(
                ["wevtutil.exe", "qe", self.path,
                 "/lf:true",   # ← key flag: treat as log FILE not log NAME
                 "/f:XML",
                 "/uni:false"],
                **_quiet_subprocess_kwargs(timeout=300)
            )
            raw = result.stdout
            if not raw:
                return
            # Decode — wevtutil outputs UTF-16-LE on most Windows versions
            for enc in ("utf-16-le", "utf-8", "latin-1"):
                try:
                    text = raw.decode(enc, errors="replace")
                    break
                except Exception:
                    continue
            else:
                return

            # wevtutil outputs one <Event>...</Event> block per line group
            # Split on </Event> boundaries
            buf = ""
            for line in text.splitlines():
                buf += line + "\n"
                if "</Event>" in line:
                    yield buf.strip()
                    buf = ""
        except FileNotFoundError:
            # wevtutil not found — this shouldn't happen on Windows
            return
        except subprocess.TimeoutExpired:
            return


class EvtxLibParser:
    """Wrapper around python-evtx (williballenthin) library."""
    def __init__(self, path):
        self.path = path

    def xml_records(self):
        from Evtx.Evtx import Evtx
        with Evtx(self.path) as log:
            for record in log.records():
                try:
                    yield record.xml()
                except Exception:
                    continue


class EvtxRsParser:
    """Wrapper around pyevtx-rs (pip install evtx) — fastest option.

    PyEvtxParser is not a context manager in several released versions of
    the evtx package. This avoids the historic __enter__ failure and accepts
    dict or string record output shapes.
    """
    def __init__(self, path):
        self.path = path
        import evtx as _evtx
        self._mod = _evtx

    def xml_records(self):
        parser = self._mod.PyEvtxParser(self.path)
        for rec in parser.records_xml():
            try:
                if isinstance(rec, dict):
                    yield rec.get("data") or rec.get("xml") or rec.get("record") or ""
                else:
                    yield str(rec)
            except Exception:
                continue


# ═══════════════════════════════════════════════════════════════════════════════
# Core Engine  — Artefact-first EVTX triage engine
# ═══════════════════════════════════════════════════════════════════════════════
class JigsawEngine:
    """
    VISION
    ──────
    Jigsaw is an OFFLINE FORENSIC ARTEFACT triage tool.

    You export EVTX files from an investigated machine
    (C:\\Windows\\System32\\winevt\\Logs\\*.evtx) and drop them
    onto your analyst workstation. Jigsaw reads them as raw binary files —
    no Windows Event Log service, no Sysmon on the analyst machine, no
    PowerShell remoting, no cloud, no SIEM.

    Parser hierarchy (artefact-safe, tried in order):
    ─────────────────────────────────────────────────
    1. pyevtx-rs   pip install evtx   — Rust-backed, fastest, 100% offline
    2. python-evtx pip install python-evtx — pure Python, 100% offline
    3. wevtutil /lf:true              — built-in Windows, reads FILE directly
                                        (NOT the log service — artefact-safe)

    Note on wevtutil /lf:true
    ─────────────────────────
    The /lf flag tells wevtutil to treat the argument as a log FILE path,
    not a log channel name. This is the documented way to query offline
    EVTX artefacts. It does NOT require the source machine's log service.
    It works fine on your analyst workstation reading a foreign EVTX file.

    What is NOT used
    ────────────────
    - Get-WinEvent without -Path    → queries live log service (wrong)
    - Get-WinEvent -LogName         → queries live log service (wrong)
    - wevtutil qe without /lf:true  → queries live log service (wrong)
    """

    def __init__(self, progress_cb=None, log_cb=None):
        self.progress_cb = progress_cb or (lambda done, total: None)
        self.log_cb      = log_cb or (lambda msg, lvl="info": None)
        self._parser_candidates = self._discover_parsers()
        if self._parser_candidates:
            self._parser_cls, self._parser_name = self._parser_candidates[0]
        else:
            self._parser_cls, self._parser_name = None, "NO PARSER AVAILABLE"

    def _discover_parsers(self):
        """Return all available EVTX parsers in safe fallback order."""
        candidates = []
        try:
            import evtx as _e
            _ = _e.PyEvtxParser
            candidates.append((EvtxRsParser, "pyevtx-rs"))
        except (ImportError, AttributeError):
            pass
        if HAS_EVTX:
            candidates.append((EvtxLibParser, "python-evtx"))
        try:
            r = subprocess.run(["wevtutil.exe", "/?"], **_quiet_subprocess_kwargs(timeout=5))
            if r.returncode == 0:
                candidates.append((EvtxRecordScanner, "wevtutil /lf:true"))
        except (FileNotFoundError, PermissionError, OSError):
            pass
        return candidates

    def _pick_parser(self):
        c = self._discover_parsers()
        return c[0] if c else (None, "NO PARSER AVAILABLE")

    # ── Public API ─────────────────────────────────────────────────────────────
    def parse_files(self, paths, filters, rules_enabled,
                    ip_filter="", date_from=None, date_to=None):
        evtx_files = self._collect_files(paths)
        if self._parser_cls is None and any(os.path.splitext(x)[1].lower() in (".evtx", ".evt") for x in evtx_files):
            self.log_cb(
                "[!] No EVTX parser found for binary EVTX/EVT files.\n"
                "    Install one:  pip install evtx\n"
                "    or:           pip install python-evtx\n"
                "    Jigsaw will still parse XML/JSON/CSV/TXT/LOG files.", "alert")
        n = len(evtx_files)
        parser_names = ", ".join(name for _, name in self._parser_candidates) or "none"
        self.log_cb(
            f"[*] Artefact mode  |  parser: {self._parser_name} (fallbacks: {parser_names})", "info")
        self.log_cb(
            f"[*] Found {n} log artefact file(s) to process", "info")

        if n == 0:
            self.log_cb(
                "[!] No .evtx/.evt files found in the selected path(s).\n"
                "    Tip: Select the folder containing your exported EVTX artefacts.",
                "alert")
            return [], [], {}

        compiled   = self._compile_filters(filters, ip_filter, date_from, date_to)
        all_events = []
        failed     = []

        for i, fpath in enumerate(evtx_files):
            self.progress_cb(i, n)
            self.log_cb(f"[*] Hunting path: {fpath}", "info")
            try:
                evs = self._parse_one(fpath, compiled)
                all_events.extend(evs)
                self.log_cb(
                    f"    ✓ {os.path.basename(fpath):<50} "
                    f"{len(evs):>6,} event(s) after filters | running total: {len(all_events):,}",
                    "success" if evs else "dim")
                if not evs:
                    self.log_cb("      -> parsed/read OK, but no events matched active filters. Clear Event ID/keyword/IP/date filters to see full artefact content.", "dim")
            except Exception as e:
                failed.append(os.path.basename(fpath))
                self.log_cb(
                    f"    ✗ {os.path.basename(fpath)}: {e}", "alert")

        self.progress_cb(n, n)

        if failed:
            self.log_cb(
                f"[!] {len(failed)} file(s) could not be read "
                f"(permissions or corrupt): {', '.join(failed[:5])}", "alert")

        self.log_cb(
            f"[*] Total events after filtering: {len(all_events):,}", "info")

        hits  = self._apply_rules(all_events, rules_enabled, ip_filter)
        stats = self._build_stats(all_events, hits)

        sev = stats.get("severity_dist", {})
        self.log_cb(
            f"[+] Detection hits: {len(hits)}"
            f"  CRITICAL:{sev.get('CRITICAL', 0)}"
            f"  HIGH:{sev.get('HIGH', 0)}"
            f"  MEDIUM:{sev.get('MEDIUM', 0)}",
            "success" if hits else "dim")

        return all_events, hits, stats

    # ── File collection ────────────────────────────────────────────────────────
    def _collect_files(self, paths):
        files = []
        for p in paths:
            p = str(p).strip()
            if not p:
                continue
            if os.path.isdir(p):
                for ext in ("*.evtx", "*.evt", "*.xml", "*.json", "*.jsonl", "*.ndjson", "*.csv", "*.log", "*.txt", "*.EVTX", "*.EVT", "*.XML", "*.JSON", "*.CSV", "*.LOG", "*.TXT"):
                    files.extend(
                        glob.glob(os.path.join(p, "**", ext), recursive=True))
            elif os.path.isfile(p):
                files.append(p)
        # Deduplicate preserving order, sort by basename for predictable output
        seen = set()
        unique = []
        for f in files:
            key = os.path.normcase(os.path.abspath(f))
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return sorted(unique, key=lambda x: os.path.basename(x).lower())

    # ── Filter compilation ─────────────────────────────────────────────────────
    def _compile_filters(self, filters, ip_filter, date_from, date_to):
        rx_str = filters.get("regex", "").strip()
        return {
            "event_ids":    set(filters.get("event_ids", [])),
            "keyword":      filters.get("keyword", "").strip().lower(),
            "ip":           ip_filter.strip(),
            "process_guid": filters.get("process_guid", "").strip().lower(),
            "date_from":    date_from,
            "date_to":      date_to,
            "regex":        re.compile(rx_str, re.IGNORECASE) if rx_str else None,
        }

    # ── Per-file parsing ───────────────────────────────────────────────────────
    def _parse_one(self, path, cf):
        """Parse one artefact file. Supports EVTX/EVT plus exported XML, JSON/JSONL, CSV, TXT/LOG."""
        ext = os.path.splitext(path)[1].lower()
        if ext in (".evtx", ".evt"):
            return self._parse_evtx_file(path, cf)
        if ext == ".xml":
            return self._parse_xml_file(path, cf)
        if ext in (".json", ".jsonl", ".ndjson"):
            return self._parse_json_file(path, cf)
        if ext == ".csv":
            return self._parse_csv_file(path, cf)
        if ext in (".txt", ".log"):
            return self._parse_text_file(path, cf)
        return []
    def _parse_evtx_file(self, path, cf):
        """Parse one EVTX/EVT artefact file with backend fallback and clear raw/filter counters."""
        basename = os.path.basename(path)
        last_error = None
        candidates = self._parser_candidates or ([] if self._parser_cls is None else [(self._parser_cls, self._parser_name)])
        for parser_cls, parser_name in candidates:
            events = []
            raw_count = 0
            dict_count = 0
            try:
                parser = parser_cls(path)
                for xml_str in parser.xml_records():
                    if not xml_str:
                        continue
                    raw_count += 1
                    try:
                        ev = self._xml_to_dict(xml_str)
                        if ev.get("_parse_error"):
                            continue
                        dict_count += 1
                        ev["_src"] = basename
                        ev["SourceFile"] = basename
                        ev["Parser"] = parser_name
                        if self._passes(ev, cf):
                            events.append(ev)
                    except Exception:
                        continue
                if raw_count or events:
                    if parser_name != self._parser_name:
                        self.log_cb(f"      ↳ fallback parser used for {basename}: {parser_name}", "dim")
                    if raw_count != len(events):
                        self.log_cb(f"      ↳ raw records read: {raw_count:,} | normalised: {dict_count:,} | visible after filters: {len(events):,}", "dim")
                    return events
                last_error = RuntimeError(f"{parser_name} returned no XML records")
            except Exception as e:
                last_error = e
                continue
        raise RuntimeError(str(last_error) if last_error else "no EVTX parser available")

    def _parse_xml_file(self, path, cf):
        """Parse exported Windows Event XML or a folder dump containing <Event> nodes."""
        events = []
        basename = os.path.basename(path)
        data = Path(path).read_text(encoding="utf-8", errors="ignore")
        chunks = re.findall(r"<Event\b.*?</Event>", data, flags=re.I | re.S)
        if not chunks and data.lstrip().startswith("<"):
            chunks = [data]
        for chunk in chunks:
            ev = self._xml_to_dict(chunk)
            ev["_src"] = basename
            ev["SourceFile"] = basename
            if self._passes(ev, cf):
                events.append(ev)
        return events

    def _parse_json_file(self, path, cf):
        """Parse JSON, JSON array, JSONL, or NDJSON logs into event dictionaries."""
        events = []
        basename = os.path.basename(path)
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
        records = []
        try:
            obj = json.loads(text)
            if isinstance(obj, list):
                records = obj
            elif isinstance(obj, dict):
                records = obj.get("events") or obj.get("Records") or obj.get("hits") or [obj]
        except Exception:
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except Exception:
                    records.append({"Message": line})
        for rec in records:
            if not isinstance(rec, dict):
                rec = {"Message": str(rec)}
            ev = self._normalise_external_event(rec, basename, "json")
            if self._passes(ev, cf):
                events.append(ev)
        return events

    def _parse_csv_file(self, path, cf):
        """Parse CSV exports from PowerShell, Event Viewer, SIEMs, Velociraptor, or Jigsaw-style outputs."""
        events = []
        basename = os.path.basename(path)
        with open(path, "r", encoding="utf-8", errors="ignore", newline="") as fh:
            sample = fh.read(4096)
            fh.seek(0)
            try:
                dialect = csv.Sniffer().sniff(sample)
            except Exception:
                dialect = csv.excel
            reader = csv.DictReader(fh, dialect=dialect)
            if reader.fieldnames:
                for row in reader:
                    ev = self._normalise_external_event(row, basename, "csv")
                    if self._passes(ev, cf):
                        events.append(ev)
        return events

    def _parse_text_file(self, path, cf):
        """Parse plain text/log lines as searchable events with lightweight EID/time extraction."""
        events = []
        basename = os.path.basename(path)
        time_rx = re.compile(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?|\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})")
        eid_rx = re.compile(r"(?:EventID|Event ID|EID|Id)\s*[:=]\s*(\d{1,5})", re.I)
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for i, line in enumerate(fh, 1):
                line = line.rstrip("\n")
                if not line.strip():
                    continue
                eid_m = eid_rx.search(line)
                ts_m = time_rx.search(line)
                ev = {
                    "EventID": int(eid_m.group(1)) if eid_m else 0,
                    "TimeCreated": ts_m.group(1).replace(" ", "T") if ts_m else "",
                    "Provider": "text-log",
                    "Channel": "Text/LOG",
                    "Computer": "",
                    "Message": line,
                    "SourceFile": basename,
                    "LineNumber": i,
                    "_src": basename,
                    "_raw_xml": line,
                }
                if self._passes(ev, cf):
                    events.append(ev)
        return events

    def _normalise_external_event(self, rec, basename, source_kind):
        """Map common exported/SIEM/PowerShell column names into Jigsaw's event schema."""
        ev = {str(k).strip(): ("" if v is None else str(v).strip()) for k, v in rec.items()}
        aliases = {
            "EventID": ["EventID", "EventId", "Id", "EID", "event_id", "winlog.event_id"],
            "TimeCreated": ["TimeCreated", "Time", "Timestamp", "@timestamp", "UtcTime", "Created", "Date", "time"],
            "Provider": ["Provider", "ProviderName", "Source", "source_name", "winlog.provider_name"],
            "Computer": ["Computer", "ComputerName", "Host", "Hostname", "host.name", "DeviceName"],
            "Channel": ["Channel", "LogName", "EventLog", "winlog.channel"],
            "Image": ["Image", "ProcessName", "NewProcessName", "process.executable", "ProcessPath"],
            "CommandLine": ["CommandLine", "ProcessCommandLine", "process.command_line", "Command", "cmdline"],
            "ParentImage": ["ParentImage", "ParentProcessName", "process.parent.executable"],
            "ImageLoaded": ["ImageLoaded", "LoadedImage", "FileName", "TargetFilename", "file.path"],
            "DestinationIp": ["DestinationIp", "DestinationIP", "dst_ip", "destination.ip"],
            "DestinationPort": ["DestinationPort", "dst_port", "destination.port"],
            "Message": ["Message", "message", "RawMessage", "Description"],
        }
        for canon, keys in aliases.items():
            if ev.get(canon):
                continue
            for k in keys:
                if k in ev and ev[k]:
                    ev[canon] = ev[k]
                    break
        try:
            ev["EventID"] = int(str(ev.get("EventID", "0")).split(".")[0])
        except Exception:
            ev["EventID"] = 0
        ev.setdefault("TimeCreated", "")
        ev.setdefault("Provider", source_kind)
        ev.setdefault("Computer", "")
        ev.setdefault("Channel", source_kind.upper())
        ev["SourceFile"] = basename
        ev["_src"] = basename
        ev["_raw_xml"] = json.dumps(rec, ensure_ascii=False)[:5000]
        return ev

    # ── XML → flat event dict ──────────────────────────────────────────────────
    def _xml_to_dict(self, xml_str):
        """
        Parse Windows Event XML into a flat dict.

        EVTX XML structure (from Windows XML Event Log spec):
        ─────────────────────────────────────────────────────
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="Microsoft-Windows-Sysmon" Guid="{...}"/>
            <EventID>7</EventID>
            <Version>3</Version>
            <Level>4</Level>
            <Task>7</Task>
            <Opcode>0</Opcode>
            <Keywords>0x8000000000000000</Keywords>
            <TimeCreated SystemTime="2024-11-15T08:23:41.123456789Z"/>
            <EventRecordID>12345</EventRecordID>
            <Correlation/>
            <Execution ProcessID="4" ThreadID="8"/>
            <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
            <Computer>DESKTOP-ABC123</Computer>
            <Security UserID="S-1-5-18"/>
          </System>
          <EventData>
            <Data Name="RuleName">-</Data>
            <Data Name="Image">C:\\Windows\\system32\\svchost.exe</Data>
            <Data Name="ImageLoaded">C:\\Users\\user\\AppData\\Local\\Temp\\evil.dll</Data>
            <Data Name="Signed">false</Data>
            <Data Name="SignatureStatus">Unavailable</Data>
            ...
          </EventData>
        </Event>
        """
        ev = {}
        try:
            # Strip xmlns to simplify tag matching (ET doesn't handle default NS well)
            clean = re.sub(r'\s+xmlns(?::[a-zA-Z0-9_]+)?="[^"]*"', "", xml_str)
            # Strip any namespace prefixes on element tags
            clean = re.sub(r'<(/?)([a-zA-Z0-9_]+):', r'<\1', clean)

            root = ET.fromstring(clean)

            # ── System block ──────────────────────────────────────────────────
            sys_el = root.find(".//System")
            if sys_el is None:
                sys_el = root.find("System")

            if sys_el is not None:
                # EventID — may have Qualifiers attribute
                eid_el = sys_el.find("EventID")
                if eid_el is not None:
                    try:
                        ev["EventID"] = int(eid_el.text or 0)
                    except (ValueError, TypeError):
                        ev["EventID"] = 0

                # TimeCreated — ISO8601 in SystemTime attribute
                tc = sys_el.find("TimeCreated")
                if tc is not None:
                    ev["TimeCreated"] = tc.get("SystemTime", "")

                # Provider name
                prov = sys_el.find("Provider")
                if prov is not None:
                    ev["Provider"] = prov.get("Name", "")

                # Computer (hostname of source machine)
                comp = sys_el.find("Computer")
                if comp is not None:
                    ev["Computer"] = (comp.text or "").strip()

                # Channel (log name on source machine)
                chan = sys_el.find("Channel")
                if chan is not None:
                    ev["Channel"] = (chan.text or "").strip()

                # Level
                lv = sys_el.find("Level")
                if lv is not None:
                    ev["Level"] = (lv.text or "").strip()

                # EventRecordID
                rid = sys_el.find("EventRecordID")
                if rid is not None:
                    ev["EventRecordID"] = (rid.text or "").strip()

                # Execution — ProcessID of the logging process
                exc = sys_el.find("Execution")
                if exc is not None:
                    ev["LoggingProcessID"] = exc.get("ProcessID", "")

                # Security — UserID (SID)
                sec = sys_el.find("Security")
                if sec is not None:
                    ev["UserID"] = sec.get("UserID", "")

            # ── EventData / UserData ───────────────────────────────────────────
            # Sysmon, Security, System logs all use <EventData><Data Name="x">v</Data>
            for section_tag in ("EventData", "UserData"):
                section = root.find(f".//{section_tag}")
                if section is None:
                    section = root.find(section_tag)
                if section is None:
                    continue

                # Named Data fields (Sysmon, Security 4688, 4624, etc.)
                for data in section.iter("Data"):
                    name  = (data.get("Name") or "").strip()
                    value = (data.text or "").strip()
                    if name:
                        ev[name] = value
                    elif value and "UnnamedData" not in ev:
                        ev["UnnamedData"] = value

                # Param fields (older Security log format — EID 7045, 7040, etc.)
                params = section.findall("Param")
                if not params:
                    # Some logs use positional children without Name attr
                    unnamed = [
                        c for c in section
                        if c.tag not in ("Data",) and not c.get("Name")
                    ]
                    for i, el in enumerate(unnamed):
                        if el.text and el.text.strip():
                            ev[f"param{i+1}"] = el.text.strip()
                else:
                    for i, p in enumerate(params):
                        if p.text:
                            ev[f"param{i+1}"] = p.text.strip()

                # Binary data
                binary = section.find("Binary")
                if binary is not None and binary.text:
                    ev["BinaryData"] = binary.text.strip()

            # Convenience: normalise common field aliases
            # Security log uses SubjectUserName / TargetUserName
            # Sysmon uses User — harmonise to a single "User" field
            if "User" not in ev:
                ev["User"] = (ev.get("SubjectUserName") or
                              ev.get("TargetUserName") or "")

            # Build a compact visible message so normal event rows are not blank.
            if not ev.get("Message"):
                interesting = []
                for key in ("RuleName", "Image", "CommandLine", "ParentImage", "ImageLoaded",
                            "TargetFilename", "DestinationIp", "DestinationPort", "User",
                            "TargetUserName", "SubjectUserName", "ServiceName", "TaskName"):
                    val = ev.get(key)
                    if val:
                        interesting.append(f"{key}={val}")
                if interesting:
                    ev["Message"] = " | ".join(interesting)[:1200]
                else:
                    ev["Message"] = f"EventID={ev.get('EventID', '')} Provider={ev.get('Provider', '')} Channel={ev.get('Channel', '')}"

            # Store raw XML for the detail pane
            ev["_raw_xml"] = xml_str

        except ET.ParseError as e:
            ev["_parse_error"] = f"XML parse error: {e}"
        except Exception as e:
            ev["_parse_error"] = str(e)

        return ev

    # ── Filtering ──────────────────────────────────────────────────────────────
    def _passes(self, ev, cf):
        # EventID
        if cf["event_ids"] and ev.get("EventID") not in cf["event_ids"]:
            return False

        # Date range
        ts_str = ev.get("TimeCreated", "")
        if ts_str and (cf["date_from"] or cf["date_to"]):
            try:
                ts = datetime.datetime.fromisoformat(
                    ts_str.rstrip("Z").replace(" ", "T").split(".")[0])
                if cf["date_from"] and ts < cf["date_from"]:
                    return False
                if cf["date_to"]   and ts > cf["date_to"]:
                    return False
            except Exception:
                pass

        # Text filters — build haystack only when needed
        if cf["keyword"] or cf["regex"] or cf["ip"] or cf["process_guid"]:
            haystack = " ".join(
                str(v) for k, v in ev.items()
                if not k.startswith("_") and v
            )
            hl = haystack.lower()
            if cf["keyword"]      and cf["keyword"] not in hl:         return False
            if cf["regex"]        and not cf["regex"].search(haystack): return False
            if cf["ip"]           and cf["ip"] not in haystack:         return False
            if cf["process_guid"] and cf["process_guid"] not in hl:    return False

        return True

    # ── Rule matching ──────────────────────────────────────────────────────────
    def _apply_rules(self, events, rules_enabled, ip_filter):
        hits         = []
        ntlm_sources = {}

        for ev in events:
            eid = ev.get("EventID", 0)
            for rule in JIGSAW_RULES:
                if rule["id"] not in rules_enabled:
                    continue
                if eid not in rule["event_ids"] and 0 not in rule["event_ids"]:
                    continue
                h = self._match_rule(rule, ev, ip_filter, ntlm_sources)
                if h:
                    hits.append(h)

        # Aggregate NTLM brute force
        if "JIG-015" in rules_enabled:
            for src, cnt in ntlm_sources.items():
                if cnt >= 5:
                    hits.append({
                        "rule_id":   "JIG-015",
                        "rule_name": "NTLM Authentication Brute Force",
                        "severity":  "HIGH",
                        "category":  "Credential Access",
                        "mitre":     "T1110.003",
                        "timestamp": "",
                        "event_id":  4776,
                        "computer":  "",
                        "channel":   "",
                        "process":   "",
                        "image":     "",
                        "detail":    f"Source '{src}' failed NTLM auth {cnt} times",
                        "raw":       {},
                    })
        return hits

    def _hit(self, rule, ev, detail, process="", image=""):
        proc = process or (
            ev.get("Image") or ev.get("NewProcessName") or
            ev.get("ProcessName") or ev.get("param2") or ""
        )
        img = image or ev.get("ImageLoaded") or ev.get("FileName") or ""
        return {
            "rule_id":   rule["id"],
            "rule_name": rule["name"],
            "severity":  rule["severity"],
            "category":  rule["category"],
            "mitre":     rule["mitre"],
            "timestamp": ev.get("TimeCreated", ""),
            "event_id":  ev.get("EventID", 0),
            "computer":  ev.get("Computer", ""),
            "channel":   ev.get("Channel", ev.get("_src", "")),
            "process":   proc,
            "image":     img,
            "detail":    detail,
            "raw":       {k: v for k, v in ev.items()
                          if not k.startswith("_") and k != "raw"},
        }

    def _match_rule(self, rule, ev, ip_filter, ntlm_src):
        logic = rule["logic"]

        if logic == "image_load_path_suspicious":
            img = (ev.get("ImageLoaded") or ev.get("FileName") or "").lower()
            for sp in SUSPICIOUS_LOAD_PATHS:
                if sp in img:
                    sig  = ev.get("Signed", ev.get("SignatureStatus", "?"))
                    proc = os.path.basename(ev.get("Image", ""))
                    return self._hit(rule, ev,
                        f"DLL loaded from writable path: {img}"
                        f" | Loader: {proc} | Signed: {sig}")

        elif logic == "dll_hijack_target_outside_system":
            img  = (ev.get("ImageLoaded") or ev.get("FileName") or "").lower()
            name = os.path.basename(img)
            if name in DLL_HIJACK_TARGETS:
                if (r"\system32"  not in img and
                    r"\syswow64"  not in img and
                    r"\winsxs"    not in img):
                    sig  = ev.get("Signed", ev.get("SignatureStatus", "?"))
                    proc = os.path.basename(ev.get("Image", ""))
                    return self._hit(rule, ev,
                        f"Hijack target '{name}' loaded outside System dirs"
                        f" | Path: {img}"
                        f" | Loader: {proc} | Signed: {sig}",
                        image=img)

        elif logic == "suspicious_parent_child":
            parent = os.path.basename(
                ev.get("ParentImage") or ev.get("ParentProcessName") or ""
            ).lower()
            child  = os.path.basename(
                ev.get("Image") or ev.get("NewProcessName") or ""
            ).lower()
            if parent and child:
                sus = SUSPICIOUS_PC_PAIRS.get(parent)
                if sus and child in sus:
                    cmd = (ev.get("CommandLine") or
                           ev.get("ProcessCommandLine") or "")
                    return self._hit(rule, ev,
                        f"Suspicious spawn: {parent} → {child}"
                        f" | CmdLine: {cmd[:120] or '<none>'}",
                        process=child)

        elif logic == "unexpected_network_initiator":
            img    = os.path.basename(ev.get("Image", "")).lower()
            dst_ip = ev.get("DestinationIp", "")
            dst_pt = ev.get("DestinationPort", "")
            bad    = {"lsass.exe","spoolsv.exe","winlogon.exe",
                      "services.exe","smss.exe","csrss.exe",
                      "wininit.exe","dwm.exe","fontdrvhost.exe"}
            if img in bad and dst_ip:
                return self._hit(rule, ev,
                    f"Unexpected net call: {img} → {dst_ip}:{dst_pt}")
            if ip_filter and ip_filter in (dst_ip or ""):
                return self._hit(rule, ev,
                    f"IP match [{ip_filter}]: {img} → {dst_ip}:{dst_pt}"
                    f" | Proto: {ev.get('Protocol','?')}")

        elif logic == "lsass_access":
            target = (ev.get("TargetImage") or "").lower()
            if "lsass" in target:
                src = ev.get("SourceImage", "?")
                acc = ev.get("GrantedAccess", "?")
                return self._hit(rule, ev,
                    f"LSASS accessed by {os.path.basename(src)}"
                    f" | GrantedAccess: {acc}"
                    f" | CallTrace: {ev.get('CallTrace','')[:80]}")

        elif logic == "unsigned_driver_load":
            sig = (ev.get("SignatureStatus") or ev.get("Signed") or "").lower()
            if sig and "valid" not in sig and sig not in ("", "none"):
                img = ev.get("ImageLoaded") or ev.get("FileName") or ""
                return self._hit(rule, ev,
                    f"Driver with unverified signature: {os.path.basename(img)}"
                    f" | Sig: {sig} | Path: {img}", image=img)

        elif logic in ("scheduled_task", "service_installed"):
            name = (ev.get("TaskName") or ev.get("ServiceName") or
                    ev.get("param1") or "")
            cmd  = (ev.get("TaskContent") or ev.get("ImagePath") or
                    ev.get("param2") or "")
            kind = "Scheduled Task" if logic == "scheduled_task" else "Service"
            return self._hit(rule, ev,
                f"{kind} created/modified: {name}"
                f" | Command: {cmd[:120]}")

        elif logic == "ps_scriptblock":
            block = (ev.get("ScriptBlockText") or
                     ev.get("Message") or "").lower()
            sus_kw = [
                "invoke-mimikatz","encodedcommand","downloadstring",
                "iex(","invoke-expression","amsibypass","shellcode",
                "reflectiveloader","frombase64string","net.webclient",
                "system.reflection","loadfromremotesources",
            ]
            for kw in sus_kw:
                if kw in block:
                    return self._hit(rule, ev,
                        f"Suspicious PS keyword [{kw}] in script block"
                        f" | Block size: {len(block):,} chars")
            if len(block) > 500:
                return self._hit(rule, ev,
                    f"Large script block ({len(block):,} chars) — manual review")

        elif logic == "log_cleared":
            subj = (ev.get("SubjectUserName") or
                    ev.get("param1") or "?")
            return self._hit(rule, ev,
                f"Event log cleared | User: {subj}"
                f" | Channel: {ev.get('Channel', ev.get('_src', '?'))}")

        elif logic == "remote_thread":
            src    = ev.get("SourceImage", "?")
            target = ev.get("TargetImage", "?")
            return self._hit(rule, ev,
                f"CreateRemoteThread: {os.path.basename(src)}"
                f" → {os.path.basename(target)}"
                f" | StartAddr: {ev.get('StartAddress', '?')}")

        elif logic == "encoded_ps":
            cmd = (
                ev.get("CommandLine") or ev.get("ProcessCommandLine") or
                ev.get("ScriptBlockText") or ""
            ).lower()
            for kw in ["-enc", "-encodedcommand", "frombase64string",
                        "::frombase64", "[system.convert]::from"]:
                if kw in cmd:
                    proc = ev.get("Image") or ev.get("NewProcessName") or ""
                    return self._hit(rule, ev,
                        f"Encoded/obfuscated command"
                        f" | Process: {os.path.basename(proc)}"
                        f" | Keyword: {kw}")

        elif logic == "office_nonstandard_port":
            img  = os.path.basename(ev.get("Image", "")).lower()
            office = {
                "excel.exe","winword.exe","powerpnt.exe","outlook.exe",
                "onenote.exe","acrord32.exe","iexplore.exe","msedge.exe",
                "firefox.exe","chrome.exe","teams.exe",
            }
            if img in office:
                try:
                    port = int(ev.get("DestinationPort") or 0)
                except (TypeError, ValueError):
                    port = 0
                if port and port not in (80,443,8080,8443,21,25,110,143,993,995):
                    dst = ev.get("DestinationIp", "")
                    return self._hit(rule, ev,
                        f"{img} → {dst}:{port} (non-standard port)"
                        f" | Proto: {ev.get('Protocol','?')}")

        elif logic == "unsigned_dll_in_sensitive_proc":
            proc = os.path.basename(ev.get("Image", "")).lower()
            sig  = (ev.get("SignatureStatus") or ev.get("Signed") or "").lower()
            sensitive = {
                "lsass.exe","svchost.exe","winlogon.exe","services.exe",
                "csrss.exe","wininit.exe","smss.exe","fontdrvhost.exe",
            }
            if proc in sensitive and sig and "valid" not in sig:
                img = ev.get("ImageLoaded") or ev.get("FileName") or ""
                return self._hit(rule, ev,
                    f"Unsigned DLL in {proc}"
                    f" | DLL: {os.path.basename(img)}"
                    f" | Sig: {sig}", image=img)

        elif logic == "ntlm_bruteforce":
            src = (ev.get("Workstation") or ev.get("TargetUserName") or
                   ev.get("SubjectUserName") or "unknown")
            ntlm_src[src] = ntlm_src.get(src, 0) + 1


        elif logic == "generic_lolbin_chain":
            blob = self._event_blob(ev)
            lolbins = ["powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "msiexec", "wmic", "schtasks", "forfiles", "installutil", "msbuild", "cmstp"]
            operators = ["downloadstring", "invoke-webrequest", "iex", "-enc", "frombase64string", "http://", "https://", "\\\\", " /c ", " /s ", "scrobj.dll", "javascript:", "vbscript:"]
            if any(x in blob for x in lolbins) and any(x in blob for x in operators):
                return self._hit(rule, ev, "LOLBin chain / suspicious command constellation: " + self._short_blob(ev), process=ev.get("Image", ""))

        elif logic == "persistence_constellation":
            blob = self._event_blob(ev)
            kws = ["runonce", "\\currentversion\\run", "scheduled task", "schtasks", "new-service", "createservice", "service installed", "wmievent", "eventconsumer", "startup", "imagepath", "autorun"]
            if any(x in blob for x in kws):
                return self._hit(rule, ev, "Persistence pattern detected: " + self._short_blob(ev))

        elif logic == "credential_constellation":
            blob = self._event_blob(ev)
            kws = ["lsass", "procdump", "mimikatz", "sekurlsa", "comsvcs.dll", "minidump", "ntds.dit", "secretsdump", "sam.save", "reg save hklm\\sam", "credential", "vaultcmd"]
            if any(x in blob for x in kws):
                return self._hit(rule, ev, "Credential access pattern detected: " + self._short_blob(ev), process=ev.get("Image", ""))

        elif logic == "lateral_movement_constellation":
            blob = self._event_blob(ev)
            kws = ["psexec", "paexec", "winrm", "evil-winrm", "wmic ", "\\admin$", "\\c$", "remote service", "termsrv", "mstsc", "explicit credentials", "event id 4648"]
            if any(x in blob for x in kws):
                return self._hit(rule, ev, "Remote access / lateral movement pattern: " + self._short_blob(ev))

        elif logic == "defense_evasion_constellation":
            blob = self._event_blob(ev)
            kws = ["wevtutil cl", "clear-eventlog", "event log cleared", "auditpol", "set-mppreference", "add-mppreference", "disableantispyware", "exclusionpath", "tamper", "remove-item", "del \\windows\\system32\\winevt\\logs"]
            if any(x in blob for x in kws):
                return self._hit(rule, ev, "Defense evasion / log destruction pattern: " + self._short_blob(ev))

        return None

    def _event_blob(self, ev):
        return " ".join(str(v) for k, v in ev.items() if not k.startswith("_") and v).lower()

    def _short_blob(self, ev, limit=220):
        msg = ev.get("CommandLine") or ev.get("ProcessCommandLine") or ev.get("Message") or self._event_blob(ev)
        msg = re.sub(r"\s+", " ", str(msg)).strip()
        return msg[:limit] + ("…" if len(msg) > limit else "")

    # ── Statistics ─────────────────────────────────────────────────────────────
    def _build_stats(self, events, hits):
        eid_dist = Counter(ev.get("EventID", 0) for ev in events)
        sev_dist = Counter(h["severity"] for h in hits)
        computers = Counter(ev.get("Computer", "") or "<unknown>" for ev in events)
        channels = Counter(ev.get("Channel", ev.get("_src", "")) or "<unknown>" for ev in events)
        processes = Counter(os.path.basename((ev.get("Image") or ev.get("NewProcessName") or ev.get("ProcessName") or "")).lower() or "<unknown>" for ev in events)
        files = Counter(ev.get("SourceFile", ev.get("_src", "")) or "<unknown>" for ev in events)
        rule_counts = Counter(h["rule_id"] for h in hits)
        risk = min(100, sev_dist.get("CRITICAL", 0) * 25 + sev_dist.get("HIGH", 0) * 12 + sev_dist.get("MEDIUM", 0) * 5 + sev_dist.get("LOW", 0) * 2)
        analysis = {
            "risk_score": risk,
            "verdict": "CRITICAL" if risk >= 75 else "HIGH" if risk >= 45 else "MEDIUM" if risk >= 20 else "LOW",
            "top_event_ids": eid_dist.most_common(10),
            "top_computers": computers.most_common(10),
            "top_channels": channels.most_common(10),
            "top_processes": processes.most_common(10),
            "top_files": files.most_common(10),
            "top_rules": rule_counts.most_common(10),
            "first_seen": min([ev.get("TimeCreated", "") for ev in events if ev.get("TimeCreated")], default=""),
            "last_seen": max([ev.get("TimeCreated", "") for ev in events if ev.get("TimeCreated")], default=""),
            "recommendations": self._recommendations(sev_dist, rule_counts),
            "attack_chain": self._attack_chain(events, hits),
        }
        return {
            "total_events":  len(events),
            "total_hits":    len(hits),
            "event_id_dist": dict(eid_dist),
            "severity_dist": dict(sev_dist),
            "analysis": analysis,
        }

    def _attack_chain(self, events, hits):
        """ATT&CK-style chain synthesis so the tool explains what it hunted, even when no rule fires."""
        stages = {
            "Initial Access / Execution": ["JIG-003", "JIG-009", "JIG-016"],
            "Persistence": ["JIG-007", "JIG-008", "JIG-017"],
            "Privilege / Defense Evasion": ["JIG-001", "JIG-002", "JIG-006", "JIG-020"],
            "Credential Access": ["JIG-005", "JIG-015", "JIG-018"],
            "Discovery / Lateral Movement": ["JIG-004", "JIG-014", "JIG-019"],
            "Impact / Cleanup": ["JIG-010"],
        }
        by_rule = Counter(h.get("rule_id") for h in hits)
        chain = []
        for stage, rids in stages.items():
            c = sum(by_rule.get(r, 0) for r in rids)
            chain.append((stage, c, "matched" if c else "hunted"))
        eids = Counter(ev.get("EventID", 0) for ev in events)
        coverage = []
        for eid, label in [(1,"process creation"),(3,"network"),(7,"image/DLL load"),(10,"process access"),(11,"file create"),(22,"DNS"),(4104,"PowerShell"),(4624,"logon"),(4625,"failed logon"),(4688,"process creation"),(4698,"scheduled task"),(7045,"service install")]:
            if eids.get(eid):
                coverage.append(f"EID {eid} {label}: {eids[eid]}")
        return {"stages": chain, "coverage": coverage[:12]}

    def _recommendations(self, sev_dist, rule_counts):
        recs = []
        if sev_dist.get("CRITICAL", 0):
            recs.append("Treat CRITICAL hits as incident-response leads: preserve artefacts, scope host/user/process lineage, and validate execution context.")
        if any(r in rule_counts for r in ("JIG-005", "JIG-018", "JIG-015")):
            recs.append("Credential-access signals detected: rotate impacted credentials and review LSASS, NTDS/SAM, and authentication telemetry.")
        if any(r in rule_counts for r in ("JIG-001", "JIG-002", "JIG-014")):
            recs.append("DLL/image-load abuse detected: compare load paths against trusted baselines and inspect writable directories for payloads.")
        if any(r in rule_counts for r in ("JIG-019", "JIG-004", "JIG-013")):
            recs.append("Network/lateral movement signals detected: pivot on destination IPs, ProcessGuid, user, and host pairs.")
        if any(r in rule_counts for r in ("JIG-020", "JIG-010")):
            recs.append("Log destruction/evasion detected: collect volatile evidence and compare with central logging/SIEM records.")
        if not recs:
            recs.append("No high-confidence detection hits. This is still a valid parse: review parsed events, top channels, top processes, and the attack-chain coverage to understand what was hunted.")
            recs.append("If the Events tab is empty, clear Event ID/keyword/date filters or verify the artefact parser dependency: pip install evtx python-evtx.")
        return recs


# ═══════════════════════════════════════════════════════════════════════════════
# GUI Application
# ═══════════════════════════════════════════════════════════════════════════════
class JigsawApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Jigsaw XDR+ OmniParser — Author: Kennedy Aikohi")
        self.geometry("1440x900")
        self.minsize(1200, 760)
        self.configure(bg=BG)

        self._q        = queue.Queue()
        self._running  = False
        self._events   = []
        self._hits     = []
        self._stats    = {}
        self._log_paths = []
        self._engine   = JigsawEngine(
            progress_cb=self._on_progress,
            log_cb=self._on_log,
        )

        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass

        self._build_ui()
        self._drain_queue()
        self._show_welcome()

    # ── UI skeleton ────────────────────────────────────────────────────────────
    def _build_ui(self):
        self._build_header()
        tk.Frame(self, bg=BORDER, height=1).pack(fill=tk.X)

        body = tk.Frame(self, bg=BG)
        body.pack(fill=tk.BOTH, expand=True)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        # Left sidebar
        self._sidebar = tk.Frame(body, bg=PANEL, width=260)
        self._sidebar.grid(row=0, column=0, sticky="nsew")
        self._sidebar.pack_propagate(False)
        self._build_sidebar()

        # Right main area (tabs)
        right = tk.Frame(body, bg=BG)
        right.grid(row=0, column=1, sticky="nsew")
        self._build_main(right)

        # Bottom status bar
        tk.Frame(self, bg=BORDER, height=1).pack(fill=tk.X)
        self._build_statusbar()

    def _build_header(self):
        h = tk.Frame(self, bg=HEADER, height=58)
        h.pack(fill=tk.X)
        h.pack_propagate(False)

        left = tk.Frame(h, bg=HEADER)
        left.pack(side=tk.LEFT, padx=18, pady=8)
        tk.Label(left, text="⊞", font=("Consolas", 20), fg=ACCENT3,
                 bg=HEADER).pack(side=tk.LEFT)
        tk.Label(left, text=" JIGSAW", font=("Consolas", 18, "bold"),
                 fg=TEXT, bg=HEADER).pack(side=tk.LEFT)
        tk.Label(left, text="  XDR+ OmniParser  v2.0  •  Author: Kennedy Aikohi",
                 font=("Consolas", 10), fg=TEXT_DIM, bg=HEADER).pack(side=tk.LEFT)

        right = tk.Frame(h, bg=HEADER)
        right.pack(side=tk.RIGHT, padx=18)
        admin_c = SUCCESS if is_admin() else WARNING
        admin_t = "● ADMIN" if is_admin() else "● USER"
        tk.Label(right, text=admin_t, font=("Consolas", 9, "bold"),
                 fg=admin_c, bg=HEADER).pack(side=tk.RIGHT, padx=(12, 0))
        self._hit_badge = tk.Label(right, text="HITS: 0",
                                   font=("Consolas", 9, "bold"),
                                   fg=DANGER, bg=HEADER)
        self._hit_badge.pack(side=tk.RIGHT, padx=10)
        self._ev_badge = tk.Label(right, text="EVENTS: 0",
                                  font=("Consolas", 9, "bold"),
                                  fg=ACCENT, bg=HEADER)
        self._ev_badge.pack(side=tk.RIGHT, padx=10)

    def _build_statusbar(self):
        sb = tk.Frame(self, bg=PANEL2, height=26)
        sb.pack(fill=tk.X)
        sb.pack_propagate(False)
        self._status_var = tk.StringVar(value="Ready — load EVTX files to begin")
        tk.Label(sb, textvariable=self._status_var, font=("Consolas", 8),
                 fg=TEXT_DIM, bg=PANEL2, anchor="w").pack(
                     side=tk.LEFT, padx=12, fill=tk.Y)
        self._prog = ttk.Progressbar(sb, mode="determinate", length=180)
        self._prog.pack(side=tk.RIGHT, padx=12, pady=4)

    # ── Sidebar ────────────────────────────────────────────────────────────────
    def _build_sidebar(self):
        s = self._sidebar

        # ── File Sources ──────────────────────────────────────────────────
        self._sb_section(s, "EVTX LOG SOURCES")

        file_row = tk.Frame(s, bg=PANEL)
        file_row.pack(fill=tk.X, padx=10, pady=(0, 4))
        self._btn(file_row, "ADD FILE(S)", self._add_files,
                  accent=True).pack(side=tk.LEFT, padx=(0, 4))
        self._btn(file_row, "ADD DIR", self._add_dir).pack(side=tk.LEFT)

        self._file_listbox = tk.Listbox(
            s, bg="#0a0e14", fg=TEXT_DIM, font=("Consolas", 8),
            selectbackground=BORDER2, activestyle="none",
            relief="flat", bd=0, height=5, highlightthickness=0
        )
        self._file_listbox.pack(fill=tk.X, padx=10, pady=(0, 4))
        self._btn(s, "CLEAR LIST", self._clear_files,
                  danger=True).pack(anchor="w", padx=10, pady=(0, 8))

        # ── Filters ────────────────────────────────────────────────────────
        self._sb_section(s, "FILTERS")

        # Event IDs
        tk.Label(s, text="Event IDs (comma-sep, blank = all)",
                 font=("Consolas", 8), fg=TEXT_DIM, bg=PANEL).pack(
                     anchor="w", padx=10)
        self._eid_var = tk.StringVar()
        self._entry(s, self._eid_var).pack(fill=tk.X, padx=10, pady=(2, 6))

        # Keyword
        tk.Label(s, text="Keyword search",
                 font=("Consolas", 8), fg=TEXT_DIM, bg=PANEL).pack(anchor="w", padx=10)
        self._kw_var = tk.StringVar()
        self._entry(s, self._kw_var).pack(fill=tk.X, padx=10, pady=(2, 6))

        # Regex
        tk.Label(s, text="Regex pattern",
                 font=("Consolas", 8), fg=TEXT_DIM, bg=PANEL).pack(anchor="w", padx=10)
        self._rx_var = tk.StringVar()
        self._entry(s, self._rx_var).pack(fill=tk.X, padx=10, pady=(2, 6))

        # IP
        tk.Label(s, text="IP address correlation",
                 font=("Consolas", 8), fg=TEXT_DIM, bg=PANEL).pack(anchor="w", padx=10)
        self._ip_var = tk.StringVar()
        self._entry(s, self._ip_var, placeholder="e.g. 192.168.1.100").pack(
            fill=tk.X, padx=10, pady=(2, 6))

        # ProcessGuid
        tk.Label(s, text="ProcessGuid trace",
                 font=("Consolas", 8), fg=TEXT_DIM, bg=PANEL).pack(anchor="w", padx=10)
        self._guid_var = tk.StringVar()
        self._entry(s, self._guid_var).pack(fill=tk.X, padx=10, pady=(2, 8))

        # ── Date Range ─────────────────────────────────────────────────────
        self._sb_section(s, "DATE / TIME RANGE")
        tk.Label(s, text="From  (YYYY-MM-DD HH:MM:SS)",
                 font=("Consolas", 8), fg=TEXT_DIM, bg=PANEL).pack(anchor="w", padx=10)
        self._date_from_var = tk.StringVar()
        self._entry(s, self._date_from_var, placeholder="2024-01-01 00:00:00").pack(
            fill=tk.X, padx=10, pady=(2, 6))
        tk.Label(s, text="To    (YYYY-MM-DD HH:MM:SS)",
                 font=("Consolas", 8), fg=TEXT_DIM, bg=PANEL).pack(anchor="w", padx=10)
        self._date_to_var = tk.StringVar()
        self._entry(s, self._date_to_var, placeholder="2024-12-31 23:59:59").pack(
            fill=tk.X, padx=10, pady=(2, 8))

        # Quick date buttons
        qd = tk.Frame(s, bg=PANEL)
        qd.pack(fill=tk.X, padx=10, pady=(0, 8))
        for label, days in [("Today", 0), ("Last 7d", 7), ("Last 30d", 30)]:
            self._btn(qd, label, lambda d=days: self._quick_date(d),
                      small=True).pack(side=tk.LEFT, padx=(0, 4))

        # ── Run button ─────────────────────────────────────────────────────
        tk.Frame(s, bg=BORDER, height=1).pack(fill=tk.X, padx=0, pady=6)
        self._run_btn = self._btn(s, "▶  RUN HUNT", self._run_hunt, accent=True)
        self._run_btn.pack(fill=tk.X, padx=10, pady=(0, 4))
        self._stop_btn = self._btn(s, "■  STOP", self._stop_hunt, danger=True)
        self._stop_btn.pack(fill=tk.X, padx=10, pady=(0, 8))

        # ── Export ─────────────────────────────────────────────────────────
        tk.Frame(s, bg=BORDER, height=1).pack(fill=tk.X, padx=0, pady=4)
        self._sb_section(s, "EXPORT")
        exp_row = tk.Frame(s, bg=PANEL)
        exp_row.pack(fill=tk.X, padx=10, pady=(0, 8))
        self._btn(exp_row, "JSON", self._export_json,
                  small=True).pack(side=tk.LEFT, padx=(0, 4))
        self._btn(exp_row, "CSV",  self._export_csv,
                  small=True).pack(side=tk.LEFT, padx=(0, 4))
        self._btn(exp_row, "TXT",  self._export_txt,
                  small=True).pack(side=tk.LEFT)

    def _sb_section(self, parent, title):
        f = tk.Frame(parent, bg=PANEL)
        f.pack(fill=tk.X, padx=10, pady=(8, 4))
        tk.Label(f, text=title, font=("Consolas", 8, "bold"),
                 fg=ACCENT, bg=PANEL).pack(side=tk.LEFT)
        tk.Frame(f, bg=BORDER, height=1).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=6, pady=4)

    # ── Main area ──────────────────────────────────────────────────────────────
    def _build_main(self, parent):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("J.TNotebook", background=BG, borderwidth=0,
                    tabmargins=[0, 0, 0, 0])
        s.configure("J.TNotebook.Tab", background=PANEL2, foreground=TEXT_DIM,
                    padding=[18, 8], font=("Consolas", 10, "bold"), borderwidth=0)
        s.map("J.TNotebook.Tab",
              background=[("selected", BORDER)],
              foreground=[("selected", ACCENT)])

        self.nb = ttk.Notebook(parent, style="J.TNotebook")
        self.nb.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)

        self._build_tab_dashboard()
        self._build_tab_detections()
        self._build_tab_events()
        self._build_tab_rules()
        self._build_tab_timeline()
        self._build_tab_analysis()
        self._build_tab_powershell()
        self._build_tab_log()

    # ── Dashboard Tab ──────────────────────────────────────────────────────────
    def _build_tab_dashboard(self):
        tab = tk.Frame(self.nb, bg=BG)
        self.nb.add(tab, text="  DASHBOARD  ")

        # ── Top stat cards — pure pack (equal width via expand=True) ─────────
        cards = tk.Frame(tab, bg=BG)
        cards.pack(fill=tk.X, padx=16, pady=16)

        self._stat_cards = {}
        defs = [
            ("EVENTS",   "0", ACCENT,    "Total events parsed"),
            ("HITS",     "0", DANGER,    "Detection rule hits"),
            ("CRITICAL", "0", "#ff2222", "Critical severity"),
            ("HIGH",     "0", DANGER,    "High severity"),
            ("FILES",    "0", ACCENT3,   "EVTX files processed"),
        ]
        for i, (lbl, val, color, desc) in enumerate(defs):
            c = self._stat_card(cards, lbl, val, color, desc)
            c.pack(side=tk.LEFT, fill=tk.BOTH, expand=True,
                   padx=(0 if i == 0 else 6, 0))
            self._stat_cards[lbl] = c

        # ── Middle row: severity bars (left) + top hits table (right) ────────
        mid = tk.Frame(tab, bg=BG)
        mid.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0, 8))

        # Severity panel — left third
        sev_outer = tk.Frame(mid, bg=BG)
        sev_outer.pack(side=tk.LEFT, fill=tk.BOTH, expand=False,
                       padx=(0, 8), ipadx=0)
        sev_lbl_row = tk.Frame(sev_outer, bg=BG)
        sev_lbl_row.pack(fill=tk.X, pady=(0, 4))
        tk.Label(sev_lbl_row, text="SEVERITY BREAKDOWN",
                 font=("Consolas", 8, "bold"), fg=TEXT_DIM, bg=BG).pack(side=tk.LEFT, padx=2)
        tk.Frame(sev_lbl_row, bg=BORDER, height=1).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=8, pady=4)
        sev_inner = tk.Frame(sev_outer, bg=PANEL2, highlightthickness=1,
                             highlightbackground=BORDER, width=280)
        sev_inner.pack(fill=tk.BOTH, expand=True)
        sev_inner.pack_propagate(False)
        self._sev_canvas = self._build_sev_bars(sev_inner)

        # Top hits panel — right two thirds
        hits_outer = tk.Frame(mid, bg=BG)
        hits_outer.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        hits_lbl_row = tk.Frame(hits_outer, bg=BG)
        hits_lbl_row.pack(fill=tk.X, pady=(0, 4))
        tk.Label(hits_lbl_row, text="TOP DETECTION HITS",
                 font=("Consolas", 8, "bold"), fg=TEXT_DIM, bg=BG).pack(side=tk.LEFT, padx=2)
        tk.Frame(hits_lbl_row, bg=BORDER, height=1).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=8, pady=4)
        hits_inner = tk.Frame(hits_outer, bg=PANEL2, highlightthickness=1,
                              highlightbackground=BORDER)
        hits_inner.pack(fill=tk.BOTH, expand=True)
        self._build_top_hits_table(hits_inner)

        # ── Hunt log ──────────────────────────────────────────────────────────
        log_outer = tk.Frame(tab, bg=BG)
        log_outer.pack(fill=tk.X, padx=16, pady=(0, 12))
        log_lbl_row = tk.Frame(log_outer, bg=BG)
        log_lbl_row.pack(fill=tk.X, pady=(0, 4))
        tk.Label(log_lbl_row, text="HUNT LOG",
                 font=("Consolas", 8, "bold"), fg=TEXT_DIM, bg=BG).pack(side=tk.LEFT, padx=2)
        tk.Frame(log_lbl_row, bg=BORDER, height=1).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=8, pady=4)
        log_inner = tk.Frame(log_outer, bg=PANEL2, highlightthickness=1,
                             highlightbackground=BORDER)
        log_inner.pack(fill=tk.X)
        self._dash_log = self._logbox(log_inner, height=6)
        self._wtag(self._dash_log)

        # Live hunt visibility: path, parser, artefacts, and analysis snapshot
        live_outer = tk.Frame(tab, bg=BG)
        live_outer.pack(fill=tk.BOTH, expand=False, padx=16, pady=(0, 12))
        live_hdr = tk.Frame(live_outer, bg=BG)
        live_hdr.pack(fill=tk.X, pady=(0, 4))
        tk.Label(live_hdr, text="LIVE HUNTING DISPLAY",
                 font=("Consolas", 8, "bold"), fg=TEXT_DIM, bg=BG).pack(side=tk.LEFT, padx=2)
        tk.Frame(live_hdr, bg=BORDER, height=1).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8, pady=4)
        live_inner = tk.Frame(live_outer, bg=PANEL2, highlightthickness=1, highlightbackground=BORDER)
        live_inner.pack(fill=tk.BOTH, expand=True)
        self._live_path_var = tk.StringVar(value="Hunting path: <none selected>")
        self._live_file_var = tk.StringVar(value="Current artefact: idle")
        self._live_count_var = tk.StringVar(value="Parsed events: 0 | Files processed: 0 | Hits: 0")
        self._live_attack_var = tk.StringVar(value="Attack-chain view: waiting for hunt")
        for var, color in [(self._live_path_var, ACCENT), (self._live_file_var, TEXT_MID),
                           (self._live_count_var, SUCCESS), (self._live_attack_var, WARNING)]:
            tk.Label(live_inner, textvariable=var, font=("Consolas", 9), fg=color, bg=PANEL2,
                     anchor="w", justify="left", wraplength=980).pack(fill=tk.X, padx=12, pady=3)

    def _stat_card(self, parent, label, value, color, desc):
        f = tk.Frame(parent, bg=PANEL2, highlightthickness=1,
                     highlightbackground=BORDER)
        tk.Label(f, text=label, font=("Consolas", 8, "bold"),
                 fg=TEXT_DIM, bg=PANEL2).pack(anchor="w", padx=12, pady=(10, 0))
        val_lbl = tk.Label(f, text=value, font=("Consolas", 28, "bold"),
                           fg=color, bg=PANEL2)
        val_lbl.pack(anchor="w", padx=12, pady=(2, 0))
        tk.Label(f, text=desc, font=("Consolas", 8), fg=TEXT_DIM,
                 bg=PANEL2).pack(anchor="w", padx=12, pady=(0, 10))
        f._value_label = val_lbl
        f._color = color
        return f

    def _build_sev_bars(self, parent):
        sev_rows = tk.Frame(parent, bg=PANEL2)
        sev_rows.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)
        self._sev_bars = {}
        for sev, color in [("CRITICAL", "#ff2222"), ("HIGH", DANGER),
                           ("MEDIUM", WARNING), ("LOW", SUCCESS), ("INFO", ACCENT)]:
            row = tk.Frame(sev_rows, bg=PANEL2)
            row.pack(fill=tk.X, pady=4)
            tk.Label(row, text=f"{sev:<8}", font=("Consolas", 9, "bold"),
                     fg=color, bg=PANEL2, width=9, anchor="w").pack(side=tk.LEFT)
            bar_bg = tk.Frame(row, bg=BORDER, height=14)
            bar_bg.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6, 6))
            bar = tk.Frame(bar_bg, bg=color, height=14, width=0)
            bar.place(x=0, y=0, relheight=1.0)
            count_lbl = tk.Label(row, text="0", font=("Consolas", 9, "bold"),
                                 fg=color, bg=PANEL2, width=5, anchor="e")
            count_lbl.pack(side=tk.LEFT)
            self._sev_bars[sev] = (bar, bar_bg, count_lbl)
        return sev_rows

    def _build_top_hits_table(self, parent):
        s = ttk.Style()
        s.configure("Top.Treeview", background=PANEL2, foreground=TEXT,
                    fieldbackground=PANEL2, rowheight=22, font=("Consolas", 9))
        s.configure("Top.Treeview.Heading", background=BORDER, foreground=ACCENT,
                    font=("Consolas", 9, "bold"), relief="flat")
        s.map("Top.Treeview", background=[("selected", BORDER2)])

        cols = ("Rule ID", "Rule Name", "Severity", "Count")
        tf = tk.Frame(parent, bg=PANEL2)
        tf.pack(fill=tk.BOTH, expand=True)
        self._top_tree = ttk.Treeview(tf, columns=cols, show="headings",
                                      style="Top.Treeview", height=8)
        for c, w in zip(cols, [70, 320, 80, 60]):
            self._top_tree.heading(c, text=c)
            self._top_tree.column(c, width=w, anchor="w")
        vsb = ttk.Scrollbar(tf, orient="vertical", command=self._top_tree.yview)
        self._top_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self._top_tree.pack(fill=tk.BOTH, expand=True)
        self._top_tree.tag_configure("CRITICAL", foreground="#ff2222")
        self._top_tree.tag_configure("HIGH",     foreground=DANGER)
        self._top_tree.tag_configure("MEDIUM",   foreground=WARNING)

    # ── Detections Tab ─────────────────────────────────────────────────────────
    def _build_tab_detections(self):
        tab = tk.Frame(self.nb, bg=BG)
        self.nb.add(tab, text="  DETECTIONS  ")

        # Filter bar
        fb = tk.Frame(tab, bg=PANEL2, pady=6)
        fb.pack(fill=tk.X, padx=0)
        tk.Label(fb, text="Filter:", font=("Consolas", 9, "bold"),
                 fg=TEXT_DIM, bg=PANEL2).pack(side=tk.LEFT, padx=(12, 6))
        self._det_filter_var = tk.StringVar()
        self._det_filter_var.trace("w", lambda *a: self._filter_detections())
        filt_entry = tk.Entry(fb, textvariable=self._det_filter_var,
                              font=("Consolas", 9), bg=BORDER, fg=TEXT,
                              insertbackground=ACCENT, relief="flat",
                              highlightthickness=1, highlightbackground=BORDER2,
                              bd=0, width=30)
        filt_entry.pack(side=tk.LEFT, padx=(0, 12), ipady=4)

        # Severity filter
        tk.Label(fb, text="Severity:", font=("Consolas", 9, "bold"),
                 fg=TEXT_DIM, bg=PANEL2).pack(side=tk.LEFT, padx=(0, 6))
        self._sev_filter_var = tk.StringVar(value="ALL")
        sev_menu = ttk.Combobox(fb, textvariable=self._sev_filter_var,
                                values=["ALL","CRITICAL","HIGH","MEDIUM","LOW","INFO"],
                                width=10, font=("Consolas", 9), state="readonly")
        sev_menu.pack(side=tk.LEFT)
        sev_menu.bind("<<ComboboxSelected>>", lambda e: self._filter_detections())

        self._btn(fb, "EXPORT HITS", self._export_json,
                  small=True).pack(side=tk.RIGHT, padx=12)

        # Detection treeview
        s = ttk.Style()
        s.configure("Det.Treeview", background=PANEL, foreground=TEXT,
                    fieldbackground=PANEL, rowheight=24, font=("Consolas", 9))
        s.configure("Det.Treeview.Heading", background=BORDER, foreground=ACCENT,
                    font=("Consolas", 9, "bold"), relief="flat")
        s.map("Det.Treeview", background=[("selected", BORDER2)])

        cols = ("Time","Rule ID","Severity","Category","MITRE","EID","Computer","Process","Detail")
        tf = tk.Frame(tab, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        tf.pack(fill=tk.BOTH, expand=True, padx=12, pady=(6, 0))
        self._det_tree = ttk.Treeview(tf, columns=cols, show="headings",
                                      style="Det.Treeview")
        widths = [130, 70, 70, 120, 90, 45, 120, 130, 350]
        for c, w in zip(cols, widths):
            self._det_tree.heading(c, text=c)
            self._det_tree.column(c, width=w, anchor="w")
        vsb = ttk.Scrollbar(tf, orient="vertical",   command=self._det_tree.yview)
        hsb = ttk.Scrollbar(tf, orient="horizontal", command=self._det_tree.xview)
        self._det_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side=tk.RIGHT,  fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self._det_tree.pack(fill=tk.BOTH, expand=True)
        for tag, color in [("CRITICAL","#ff2222"),("HIGH",DANGER),
                           ("MEDIUM",WARNING),("LOW",SUCCESS),("INFO",ACCENT)]:
            self._det_tree.tag_configure(tag, foreground=color)
        self._det_tree.bind("<Double-1>", self._show_hit_detail)

        # Detail pane
        dp = self._panel(tab, "EVENT DETAIL  (double-click a row above)")
        dp.pack(fill=tk.X, padx=12, pady=(6, 12))
        self._det_detail = scrolledtext.ScrolledText(
            dp, font=("Consolas", 8), bg="#0a0e14", fg=TEXT_DIM,
            relief="flat", bd=0, height=7, wrap=tk.WORD, state=tk.DISABLED
        )
        self._det_detail.pack(fill=tk.X)

    # ── Events Tab ─────────────────────────────────────────────────────────────
    def _build_tab_events(self):
        tab = tk.Frame(self.nb, bg=BG)
        self.nb.add(tab, text="  ALL EVENTS  ")

        fb = tk.Frame(tab, bg=PANEL2, pady=6)
        fb.pack(fill=tk.X)
        tk.Label(fb, text="Search:", font=("Consolas", 9, "bold"),
                 fg=TEXT_DIM, bg=PANEL2).pack(side=tk.LEFT, padx=(12, 6))
        self._ev_search_var = tk.StringVar()
        self._ev_search_var.trace("w", lambda *a: self._filter_events())
        tk.Entry(fb, textvariable=self._ev_search_var, font=("Consolas", 9),
                 bg=BORDER, fg=TEXT, insertbackground=ACCENT, relief="flat",
                 highlightthickness=1, highlightbackground=BORDER2,
                 bd=0, width=30).pack(side=tk.LEFT, padx=(0,12), ipady=4)
        tk.Label(fb, text="EID:", font=("Consolas", 9, "bold"),
                 fg=TEXT_DIM, bg=PANEL2).pack(side=tk.LEFT, padx=(0,6))
        self._ev_eid_var = tk.StringVar()
        self._ev_eid_var.trace("w", lambda *a: self._filter_events())
        tk.Entry(fb, textvariable=self._ev_eid_var, font=("Consolas", 9),
                 bg=BORDER, fg=TEXT, insertbackground=ACCENT, relief="flat",
                 highlightthickness=1, highlightbackground=BORDER2,
                 bd=0, width=10).pack(side=tk.LEFT, padx=(0,12), ipady=4)
        self._ev_count_lbl = tk.Label(fb, text="Showing 0 events",
                                      font=("Consolas", 9), fg=TEXT_DIM, bg=PANEL2)
        self._ev_count_lbl.pack(side=tk.RIGHT, padx=12)

        s = ttk.Style()
        s.configure("Ev.Treeview", background=PANEL, foreground=TEXT_MID,
                    fieldbackground=PANEL, rowheight=22, font=("Consolas", 8))
        s.configure("Ev.Treeview.Heading", background=BORDER, foreground=ACCENT,
                    font=("Consolas", 9, "bold"), relief="flat")
        s.map("Ev.Treeview", background=[("selected", BORDER2)])

        cols = ("Time","EID","Provider","Computer","Image","CommandLine","Message")
        tf = tk.Frame(tab, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        tf.pack(fill=tk.BOTH, expand=True, padx=12, pady=(6, 0))
        self._ev_tree = ttk.Treeview(tf, columns=cols, show="headings",
                                     style="Ev.Treeview")
        for c, w in zip(cols, [130, 45, 120, 120, 160, 200, 280]):
            self._ev_tree.heading(c, text=c)
            self._ev_tree.column(c, width=w, anchor="w")
        vsb = ttk.Scrollbar(tf, orient="vertical",   command=self._ev_tree.yview)
        hsb = ttk.Scrollbar(tf, orient="horizontal", command=self._ev_tree.xview)
        self._ev_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side=tk.RIGHT,  fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self._ev_tree.pack(fill=tk.BOTH, expand=True)
        self._ev_tree.bind("<Double-1>", self._show_ev_detail)

        dp = self._panel(tab, "RAW EVENT  (double-click above)")
        dp.pack(fill=tk.X, padx=12, pady=(6, 12))
        self._ev_detail = scrolledtext.ScrolledText(
            dp, font=("Consolas", 8), bg="#0a0e14", fg=TEXT_DIM,
            relief="flat", bd=0, height=6, wrap=tk.WORD, state=tk.DISABLED
        )
        self._ev_detail.pack(fill=tk.X)

    # ── Rules Tab ──────────────────────────────────────────────────────────────
    def _build_tab_rules(self):
        tab = tk.Frame(self.nb, bg=BG)
        self.nb.add(tab, text="  JIGSAW RULES  ")

        hdr = tk.Frame(tab, bg=BG)
        hdr.pack(fill=tk.X, padx=16, pady=(12, 6))
        tk.Label(hdr, text="Select rules to enable for the next hunt run:",
                 font=("Consolas", 10), fg=TEXT_DIM, bg=BG).pack(side=tk.LEFT)
        self._btn(hdr, "ENABLE ALL",  self._enable_all_rules).pack(side=tk.RIGHT, padx=(6, 0))
        self._btn(hdr, "DISABLE ALL", self._disable_all_rules).pack(side=tk.RIGHT)

        s = ttk.Style()
        s.configure("Ru.Treeview", background=PANEL, foreground=TEXT,
                    fieldbackground=PANEL, rowheight=26, font=("Consolas", 9))
        s.configure("Ru.Treeview.Heading", background=BORDER, foreground=ACCENT,
                    font=("Consolas", 9, "bold"), relief="flat")
        s.map("Ru.Treeview", background=[("selected", BORDER2)])

        cols = ("✓","ID","Severity","Category","MITRE","Event IDs","Name","Description")
        tf = tk.Frame(tab, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        tf.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))
        self._rules_tree = ttk.Treeview(tf, columns=cols, show="headings",
                                        style="Ru.Treeview")
        for c, w in zip(cols, [25,60,70,120,80,80,220,350]):
            self._rules_tree.heading(c, text=c)
            self._rules_tree.column(c, width=w, anchor="w" if c not in ("✓",) else "center")
        vsb = ttk.Scrollbar(tf, orient="vertical", command=self._rules_tree.yview)
        hsb = ttk.Scrollbar(tf, orient="horizontal", command=self._rules_tree.xview)
        self._rules_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side=tk.RIGHT,  fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self._rules_tree.pack(fill=tk.BOTH, expand=True)

        self._rules_tree.tag_configure("CRITICAL", foreground="#ff2222")
        self._rules_tree.tag_configure("HIGH",     foreground=DANGER)
        self._rules_tree.tag_configure("MEDIUM",   foreground=WARNING)
        self._rules_tree.bind("<Double-1>", self._toggle_rule)

        # Populate rules
        self._rule_states = {}   # rule_id -> bool (enabled)
        for rule in JIGSAW_RULES:
            self._rule_states[rule["id"]] = True
            eids = ",".join(str(e) for e in rule["event_ids"])
            self._rules_tree.insert("", "end", iid=rule["id"], values=(
                "●", rule["id"], rule["severity"], rule["category"],
                rule["mitre"], eids, rule["name"], rule["description"]
            ), tags=(rule["severity"],))

        tk.Label(tab, text="Double-click a rule to toggle it on/off.",
                 font=("Consolas", 8), fg=TEXT_DIM, bg=BG).pack(
                     anchor="w", padx=16, pady=(0, 8))

    # ── Timeline Tab ──────────────────────────────────────────────────────────
    def _build_tab_timeline(self):
        tab = tk.Frame(self.nb, bg=BG)
        self.nb.add(tab, text="  TIMELINE  ")

        tk.Label(tab, text="Event Timeline  (detection hits chronologically)",
                 font=("Consolas", 10, "bold"), fg=ACCENT, bg=BG).pack(
                     anchor="w", padx=16, pady=(12, 6))

        tl_frame = tk.Frame(tab, bg=PANEL, highlightthickness=1,
                            highlightbackground=BORDER)
        tl_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))

        self._timeline_canvas = tk.Canvas(tl_frame, bg=PANEL, highlightthickness=0)
        tl_vsb = ttk.Scrollbar(tl_frame, orient="vertical",
                               command=self._timeline_canvas.yview)
        self._timeline_canvas.configure(yscrollcommand=tl_vsb.set)
        tl_vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self._timeline_canvas.pack(fill=tk.BOTH, expand=True)
        self._tl_inner = tk.Frame(self._timeline_canvas, bg=PANEL)
        self._tl_window = self._timeline_canvas.create_window(
            (0, 0), window=self._tl_inner, anchor="nw")
        self._tl_inner.bind("<Configure>", self._on_tl_configure)

        self._tl_placeholder = tk.Label(
            self._tl_inner,
            text="Run a hunt to populate the timeline.",
            font=("Consolas", 11), fg=TEXT_DIM, bg=PANEL
        )
        self._tl_placeholder.pack(pady=40)

    def _on_tl_configure(self, e):
        self._timeline_canvas.configure(
            scrollregion=self._timeline_canvas.bbox("all"))

    # ── Analysis Results Tab ──────────────────────────────────────────────────
    def _build_tab_analysis(self):
        tab = tk.Frame(self.nb, bg=BG)
        self.nb.add(tab, text="  ANALYSIS RESULTS  ")
        top = tk.Frame(tab, bg=BG)
        top.pack(fill=tk.X, padx=16, pady=(12, 6))
        tk.Label(top, text=f"{PRODUCT_NAME} analysis report — Author: {AUTHOR_NAME}",
                 font=("Consolas", 10, "bold"), fg=ACCENT, bg=BG).pack(side=tk.LEFT)
        self._btn(top, "EXPORT REPORT", self._export_report, small=True).pack(side=tk.RIGHT)
        self._analysis_box = scrolledtext.ScrolledText(
            tab, font=("Consolas", 9), bg="#0a0e14", fg=TEXT,
            relief="flat", bd=0, wrap=tk.WORD, state=tk.DISABLED
        )
        self._analysis_box.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))
        self._wtag(self._analysis_box)
        self._wlog(self._analysis_box, "dim", "Run a hunt to display analysis results here.\n")

    def _render_analysis_report(self):
        a = self._stats.get("analysis", {})
        lines = []
        lines.append(f"{PRODUCT_NAME} v{PRODUCT_VERSION} — Analysis Results")
        lines.append(f"Author: {AUTHOR_NAME} | LinkedIn: {AUTHOR_LINKEDIN} | GitHub: {AUTHOR_GITHUB}")
        lines.append("=" * 78)
        lines.append(f"Events parsed : {len(self._events):,}")
        lines.append(f"Hits detected : {len(self._hits):,}")
        lines.append(f"Risk verdict  : {a.get('verdict', 'N/A')} ({a.get('risk_score', 0)}/100)")
        lines.append(f"First seen    : {a.get('first_seen', '')}")
        lines.append(f"Last seen     : {a.get('last_seen', '')}")
        lines.append("")
        lines.append("Severity distribution:")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            lines.append(f"  {sev:<9} {self._stats.get('severity_dist', {}).get(sev, 0)}")
        def add_table(title, rows):
            lines.append("")
            lines.append(title + ":")
            if not rows:
                lines.append("  <none>")
            for k, v in rows:
                lines.append(f"  {str(k)[:54]:<54} {v}")
        add_table("Top rules", a.get("top_rules", []))
        add_table("Top event IDs", a.get("top_event_ids", []))
        add_table("Top computers", a.get("top_computers", []))
        add_table("Top channels/files", a.get("top_channels", []))
        add_table("Top processes", a.get("top_processes", []))
        lines.append("")
        lines.append("Attack-chain hunting map:")
        ac = a.get("attack_chain", {})
        for stage, count, state in ac.get("stages", []):
            lines.append(f"  {stage:<32} {count:>4} {state}")
        if ac.get("coverage"):
            lines.append("Telemetry coverage parsed:")
            for row in ac.get("coverage", []):
                lines.append("  - " + row)
        lines.append("")
        lines.append("Recommended next actions:")
        for r in a.get("recommendations", []):
            lines.append("  - " + r)
        if self._hits:
            lines.append("")
            lines.append("Highest priority detections:")
            for h in sorted(self._hits, key=lambda x: SEV_ORDER.get(x["severity"], 9))[:25]:
                lines.append(f"  [{h['severity']}] {h['rule_id']} {h['rule_name']} | EID {h['event_id']} | {h['detail'][:180]}")
        return "\n".join(lines) + "\n"

    # ── PowerShell Tab ────────────────────────────────────────────────────────
    def _build_tab_powershell(self):
        tab = tk.Frame(self.nb, bg=BG)
        self.nb.add(tab, text="  POWERSHELL CONSOLE  ")

        tk.Label(tab,
                 text="Run Get-WinEvent / FilterHashtable commands directly. Output appears below.",
                 font=("Consolas", 9), fg=TEXT_DIM, bg=BG).pack(
                     anchor="w", padx=16, pady=(10, 4))

        tk.Label(tab,
                 text="Artefact queries using Get-WinEvent -Path  (reads EVTX file directly — no log service needed).",
                 font=("Consolas", 9), fg=TEXT_DIM, bg=BG).pack(
                     anchor="w", padx=16, pady=(10, 2))
        tk.Label(tab,
                 text="Replace  C:\\path\\to\\Sysmon.evtx  in each template with your actual artefact path.",
                 font=("Consolas", 8), fg=ACCENT2, bg=BG).pack(
                     anchor="w", padx=16, pady=(0, 6))

        # Template buttons — all artefact-safe using -Path not -LogName
        tpl_frame = tk.Frame(tab, bg=BG)
        tpl_frame.pack(fill=tk.X, padx=12, pady=(0, 6))
        _P = "C:\\path\\to\\"   # replace with actual artefact folder
        _S = _P + "Microsoft-Windows-Sysmon%4Operational.evtx"
        _SEC = _P + "Security.evtx"
        _SYS = _P + "System.evtx"
        templates = [
            ("EID 7 — DLL Load",
             f"Get-WinEvent -FilterHashtable @{{Path='{_S}'; Id=7}} | Select-Object TimeCreated,Message | Format-List"),
            ("EID 3 — Network",
             f"Get-WinEvent -FilterHashtable @{{Path='{_S}'; Id=3}} | Select-Object TimeCreated,Message | Format-List"),
            ("EID 1 — Process Create",
             f"Get-WinEvent -FilterHashtable @{{Path='{_S}'; Id=1}} | Select-Object TimeCreated,Message | Format-List"),
            ("EID 10 — LSASS Access",
             f"Get-WinEvent -FilterHashtable @{{Path='{_S}'; Id=10}} | Where-Object {{$_.Message -like '*lsass*'}} | Select-Object TimeCreated,Message | Format-List"),
            ("EID 4688 — Process (Sec)",
             f"Get-WinEvent -FilterHashtable @{{Path='{_SEC}'; Id=4688}} | Select-Object TimeCreated,Message | Format-List"),
            ("EID 4624 — Logon",
             f"Get-WinEvent -FilterHashtable @{{Path='{_SEC}'; Id=4624}} | Select-Object TimeCreated,Message | Format-List"),
            ("EID 7045 — Service Install",
             f"Get-WinEvent -FilterHashtable @{{Path='{_SYS}'; Id=7045}} | Select-Object TimeCreated,Message | Format-List"),
            ("Unsigned DLL (EID 7)",
             f"Get-WinEvent -FilterHashtable @{{Path='{_S}'; Id=7}} | Where-Object {{$_.Properties[8].Value -eq 'false'}} | Select-Object TimeCreated,Message | Format-List"),
            ("Date Range",
             f"Get-WinEvent -FilterHashtable @{{Path='{_SEC}'; StartTime=[datetime]'2024-11-01'; EndTime=[datetime]'2024-11-30'}} | Select-Object TimeCreated,Id,Message | Format-Table -Auto"),
            ("ProcessGuid Trace",
             f"$g='{{YOUR-GUID}}'; Get-WinEvent -FilterHashtable @{{Path='{_S}'}} | Where-Object {{$_.Message -match $g}} | Select-Object TimeCreated,Id,Message | Format-List"),
        ]
        for lbl, cmd in templates:
            self._btn(tpl_frame, lbl,
                      lambda c=cmd: self._load_ps_template(c),
                      small=True).pack(side=tk.LEFT, padx=(0, 4))

        # Command entry
        cmd_frame = tk.Frame(tab, bg=PANEL2)
        cmd_frame.pack(fill=tk.X, padx=12, pady=(0, 4))
        tk.Label(cmd_frame, text="PS>", font=("Consolas", 10, "bold"),
                 fg=SUCCESS, bg=PANEL2).pack(side=tk.LEFT, padx=(8, 4), pady=4)
        self._ps_cmd_var = tk.StringVar()
        ps_entry = tk.Entry(cmd_frame, textvariable=self._ps_cmd_var,
                            font=("Consolas", 9), bg="#0a0e14", fg=TEXT,
                            insertbackground=ACCENT, relief="flat",
                            highlightthickness=1, highlightbackground=BORDER,
                            bd=0)
        ps_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5)
        ps_entry.bind("<Return>", lambda e: self._run_ps_command())
        self._btn(cmd_frame, "RUN", self._run_ps_command,
                  accent=True).pack(side=tk.LEFT, padx=(6, 8))
        self._btn(cmd_frame, "CLR", lambda: self._clr(self._ps_output),
                  small=True).pack(side=tk.LEFT, padx=(0, 8))

        # Output
        out_frame = self._panel(tab, "OUTPUT")
        out_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))
        self._ps_output = self._logbox(out_frame, height=20)
        self._wtag(self._ps_output)
        self._wlog(self._ps_output, "dim",
                   "[PS Console] Enter PowerShell commands or click a template above.\n"
                   "[PS Console] Results are read-only output — not written to disk.\n\n")

    # ── Log Tab ────────────────────────────────────────────────────────────────
    def _build_tab_log(self):
        tab = tk.Frame(self.nb, bg=BG)
        self.nb.add(tab, text="  HUNT LOG  ")
        f = self._panel(tab, "Hunt Activity Log")
        f.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)
        self._hunt_log = self._logbox(f, height=35)
        self._wtag(self._hunt_log)
        self._wlog(self._hunt_log, "dim", "[INIT] Jigsaw engine ready.\n")
        if not HAS_EVTX:
            self._wlog(self._hunt_log, "alert",
                       "[WARN] python-evtx not installed — will use Get-WinEvent PowerShell fallback.\n"
                       "       Install: pip install python-evtx\n\n")

    # ── Shared UI helpers ──────────────────────────────────────────────────────
    def _panel(self, parent, title):
        outer = tk.Frame(parent, bg=BG)
        hdr = tk.Frame(outer, bg=BG)
        hdr.pack(fill=tk.X, pady=(0, 4))
        tk.Label(hdr, text=title.upper(), font=("Consolas", 8, "bold"),
                 fg=TEXT_DIM, bg=BG).pack(side=tk.LEFT, padx=2)
        tk.Frame(hdr, bg=BORDER, height=1).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=8, pady=4)
        inner = tk.Frame(outer, bg=PANEL2, highlightthickness=1,
                         highlightbackground=BORDER)
        inner.pack(fill=tk.BOTH, expand=True)
        return inner

    def _btn(self, parent, text, cmd, accent=False, danger=False, small=False):
        if accent:   fg, bg_, abg = "#000", ACCENT,  "#00aacf"
        elif danger: fg, bg_, abg = TEXT,  "#3d1f1f", DANGER
        else:        fg, bg_, abg = TEXT,  BORDER,    BORDER2
        sz = 8 if small else 9
        px = 8 if small else 14
        py = 4 if small else 6
        b = tk.Button(parent, text=text, command=cmd,
                      font=("Consolas", sz, "bold"), fg=fg, bg=bg_,
                      activeforeground=fg, activebackground=abg,
                      relief="flat", bd=0, padx=px, pady=py, cursor="hand2")
        b.bind("<Enter>", lambda e: b.configure(bg=abg))
        b.bind("<Leave>", lambda e: b.configure(bg=bg_))
        return b

    def _entry(self, parent, var, placeholder=""):
        # Wrap in a frame to simulate border + internal padding (ipady on Entry.configure is invalid)
        frame = tk.Frame(parent, bg=BORDER, padx=1, pady=1)
        e = tk.Entry(frame, textvariable=var, font=("Consolas", 9),
                     bg="#0a0e14", fg=TEXT, insertbackground=ACCENT,
                     relief="flat", bd=0, highlightthickness=0)
        e.pack(fill=tk.X, ipady=4)

        def _hl(on): frame.configure(bg=ACCENT if on else BORDER)
        e.bind("<FocusIn>",  lambda ev: _hl(True))
        e.bind("<FocusOut>", lambda ev: _hl(False))

        if placeholder and not var.get():
            e.insert(0, placeholder)
            e.configure(fg=TEXT_DIM)
            def on_fi(ev, en=e, ph=placeholder):
                if en.get() == ph:
                    en.delete(0, tk.END)
                    en.configure(fg=TEXT)
                _hl(True)
            def on_fo(ev, en=e, ph=placeholder, v=var):
                if not en.get():
                    en.insert(0, ph)
                    en.configure(fg=TEXT_DIM)
                    v.set("")
                _hl(False)
            e.bind("<FocusIn>",  on_fi)
            e.bind("<FocusOut>", on_fo)

        frame._entry = e
        return frame

    def _logbox(self, parent, height=10):
        box = scrolledtext.ScrolledText(
            parent, font=("Consolas", 9), bg="#0a0e14", fg=TEXT,
            insertbackground=ACCENT, selectbackground=BORDER,
            relief="flat", bd=0, wrap=tk.WORD, state=tk.DISABLED,
            padx=10, pady=8, height=height
        )
        box.pack(fill=tk.BOTH, expand=True)
        return box

    def _wtag(self, w):
        for t, c in [("alert", DANGER), ("info", ACCENT), ("dim", TEXT_DIM),
                     ("success", SUCCESS), ("warn", WARNING), ("raw", TEXT_MID)]:
            w.tag_configure(t, foreground=c)

    def _wlog(self, w, tag, txt):
        w.configure(state=tk.NORMAL)
        w.insert(tk.END, txt, tag)
        w.see(tk.END)
        w.configure(state=tk.DISABLED)

    def _clr(self, w):
        w.configure(state=tk.NORMAL)
        w.delete("1.0", tk.END)
        w.configure(state=tk.DISABLED)

    # ── File management ────────────────────────────────────────────────────────
    def _add_files(self):
        paths = filedialog.askopenfilenames(
            title="Select EVTX/EVT files",
            filetypes=[("Event Log files","*.evtx *.evt"),("All files","*.*")]
        )
        for p in paths:
            if p not in self._log_paths:
                self._log_paths.append(p)
                self._file_listbox.insert(tk.END, os.path.basename(p))

    def _add_dir(self):
        d = filedialog.askdirectory(title="Select folder containing EVTX files")
        if d and d not in self._log_paths:
            self._log_paths.append(d)
            self._file_listbox.insert(tk.END, f"[DIR] {os.path.basename(d)}")

    def _clear_files(self):
        self._log_paths.clear()
        self._file_listbox.delete(0, tk.END)

    def _quick_date(self, days_ago):
        now = datetime.datetime.now()
        self._date_to_var.set(now.strftime("%Y-%m-%d %H:%M:%S"))
        if days_ago == 0:
            self._date_from_var.set(now.strftime("%Y-%m-%d") + " 00:00:00")
        else:
            frm = now - datetime.timedelta(days=days_ago)
            self._date_from_var.set(frm.strftime("%Y-%m-%d %H:%M:%S"))

    # ── Hunt execution ─────────────────────────────────────────────────────────
    def _run_hunt(self):
        if self._running:
            return
        if not self._log_paths:
            messagebox.showwarning("No files",
                "Add EVTX files or directories first.")
            return

        self._running = True
        self._run_btn.configure(state=tk.DISABLED)
        self._status_var.set("Hunting…")
        self._clr(self._dash_log)
        self._clr(self._hunt_log)
        self._clear_results()

        filters = self._build_filters()
        rules_enabled = {rid for rid, en in self._rule_states.items() if en}
        ip = self._ip_var.get().strip()
        date_from = self._parse_date(self._date_from_var.get())
        date_to   = self._parse_date(self._date_to_var.get())

        path_text = "; ".join(self._log_paths)
        self._live_path_var.set("Hunting path: " + path_text)
        self._live_file_var.set("Current artefact: starting parser engine")
        self._live_count_var.set("Parsed events: 0 | Files processed: 0 | Hits: 0")
        self._live_attack_var.set("Attack-chain view: hunting execution, persistence, credential access, lateral movement, evasion")
        self._wlog(self._hunt_log, "info",
                   f"[{datetime.datetime.now().strftime('%H:%M:%S')}] "
                   f"Hunt started - {len(self._log_paths)} source(s) | "
                   f"{len(rules_enabled)} rules | "
                   f"filters: {filters}\nHunting path(s): {path_text}\n")
        self._wlog(self._dash_log, "info", "[*] Hunt started...\n")
        self._wlog(self._dash_log, "info", f"[*] Hunting path(s): {path_text}\n")

        threading.Thread(
            target=self._hunt_worker,
            args=(filters, rules_enabled, ip, date_from, date_to),
            daemon=True
        ).start()

    def _hunt_worker(self, filters, rules_enabled, ip, date_from, date_to):
        try:
            events, hits, stats = self._engine.parse_files(
                self._log_paths, filters, rules_enabled, ip, date_from, date_to
            )
            self._q.put(("done", events, hits, stats))
        except Exception as e:
            self._q.put(("error", str(e)))

    def _stop_hunt(self):
        self._running = False
        self._status_var.set("Stopped by user")
        self._run_btn.configure(state=tk.NORMAL)

    def _build_filters(self):
        f = {}
        eid_raw = self._eid_var.get().strip()
        if eid_raw and not _looks_like_placeholder(eid_raw):
            try:
                f["event_ids"] = [int(x.strip()) for x in eid_raw.split(",") if x.strip()]
            except ValueError:
                pass
        kw = self._kw_var.get().strip()
        if kw and not _looks_like_placeholder(kw):
            f["keyword"] = kw
        rx = self._rx_var.get().strip()
        if rx and not _looks_like_placeholder(rx):
            f["regex"] = rx
        pg = self._guid_var.get().strip()
        if pg and not _looks_like_placeholder(pg):
            f["process_guid"] = pg
        ip = self._ip_var.get().strip()
        if ip and not _looks_like_placeholder(ip):
            f["ip"] = ip
        return f

    def _parse_date(self, s):
        s = s.strip()
        if _looks_like_placeholder(s):
            return None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M",
                    "%Y-%m-%d", "%d/%m/%Y %H:%M:%S"):
            try:
                return datetime.datetime.strptime(s, fmt)
            except ValueError:
                pass
        return None

    # ── Callbacks from engine (thread-safe via queue) ──────────────────────────
    def _on_progress(self, done, total):
        self._q.put(("progress", done, total))

    def _on_log(self, msg, level="info"):
        self._q.put(("log", msg, level))

    def _drain_queue(self):
        try:
            while True:
                item = self._q.get_nowait()
                kind = item[0]
                if kind == "progress":
                    _, done, total = item
                    if total:
                        self._prog["value"] = (done / total) * 100
                        if hasattr(self, "_live_count_var"):
                            self._live_count_var.set(f"Parsed events: running | Files processed: {done}/{total} | Hits: running")
                elif kind == "log":
                    _, msg, lvl = item
                    self._wlog(self._hunt_log, lvl, msg + "\n")
                    self._wlog(self._dash_log, lvl, msg + "\n")
                    if hasattr(self, "_live_file_var") and msg.startswith("[*] Hunting path:"):
                        self._live_file_var.set("Current artefact: " + msg.split(":", 1)[1].strip())
                    if hasattr(self, "_live_count_var") and "running total:" in msg:
                        self._live_count_var.set("Parsed events: " + msg.split("running total:", 1)[1].strip() + " | Files processed: updating | Hits: running")
                elif kind == "done":
                    _, events, hits, stats = item
                    self._events = events
                    self._hits   = hits
                    self._stats  = stats
                    self._populate_results()
                    self._running = False
                    self._run_btn.configure(state=tk.NORMAL)
                    self._prog["value"] = 100
                elif kind == "error":
                    _, msg = item
                    self._wlog(self._hunt_log, "alert", f"[ERROR] {msg}\n")
                    messagebox.showerror("Engine Error", msg)
                    self._running = False
                    self._run_btn.configure(state=tk.NORMAL)
        except queue.Empty:
            pass
        self.after(150, self._drain_queue)

    # ── Results population ─────────────────────────────────────────────────────
    def _clear_results(self):
        for t in (self._det_tree, self._ev_tree, self._top_tree):
            for item in t.get_children():
                t.delete(item)
        for w in (self._tl_inner,):
            for child in w.winfo_children():
                child.destroy()
        self._tl_placeholder = tk.Label(
            self._tl_inner, text="Run a hunt to populate the timeline.",
            font=("Consolas", 11), fg=TEXT_DIM, bg=PANEL
        )
        self._tl_placeholder.pack(pady=40)

    def _populate_results(self):
        n_ev = len(self._events)
        n_h  = len(self._hits)

        # Stat cards
        self._stat_cards["EVENTS"]._value_label.configure(text=f"{n_ev:,}")
        self._stat_cards["HITS"]._value_label.configure(text=str(n_h))
        crit = self._stats.get("severity_dist", {}).get("CRITICAL", 0)
        hi   = self._stats.get("severity_dist", {}).get("HIGH", 0)
        self._stat_cards["CRITICAL"]._value_label.configure(text=str(crit))
        self._stat_cards["HIGH"]._value_label.configure(text=str(hi))
        self._stat_cards["FILES"]._value_label.configure(text=str(len(self._log_paths)))
        self._hit_badge.configure(text=f"HITS: {n_h}")
        self._ev_badge.configure(text=f"EVENTS: {n_ev:,}")

        # Severity bars
        sev_dist = self._stats.get("severity_dist", {})
        max_count = max(sev_dist.values()) if sev_dist else 1
        for sev, (bar, bar_bg, lbl) in self._sev_bars.items():
            c = sev_dist.get(sev, 0)
            lbl.configure(text=str(c))
            bar_bg.update_idletasks()
            w = bar_bg.winfo_width()
            frac = c / max_count if max_count else 0
            bar.configure(width=int(w * frac))

        # Top hits table
        rule_counts = {}
        for h in self._hits:
            rid = h["rule_id"]
            rule_counts[rid] = rule_counts.get(rid, 0) + 1
        if not rule_counts:
            self._top_tree.insert("", "end", values=("INFO", "No rule hits; parsed events are visible in EVENTS and ANALYSIS", "INFO", 0), tags=("INFO",))
        for rid, count in sorted(rule_counts.items(),
                                 key=lambda x: x[1], reverse=True)[:15]:
            rule = next((r for r in JIGSAW_RULES if r["id"] == rid), {})
            sev = rule.get("severity", "INFO")
            self._top_tree.insert("", "end", values=(
                rid, rule.get("name", rid), sev, count
            ), tags=(sev,))

        # Detection hits tree
        sorted_hits = sorted(self._hits,
                             key=lambda h: SEV_ORDER.get(h["severity"], 9))
        for h in sorted_hits:
            ts = self._fmt_ts(h["timestamp"])
            self._det_tree.insert("", "end", values=(
                ts, h["rule_id"], h["severity"], h["category"],
                h["mitre"], h["event_id"], h["computer"],
                os.path.basename(h.get("process",""))[:30],
                h["detail"][:80]
            ), tags=(h["severity"],))

        # All events tree (show up to 5000 for performance)
        shown = self._events[:5000]
        for ev in shown:
            ts  = self._fmt_ts(ev.get("TimeCreated", ""))
            eid = ev.get("EventID", "")
            prov = ev.get("Provider", "")[:20]
            comp = ev.get("Computer", "")[:20]
            img  = os.path.basename(ev.get("Image",
                   ev.get("NewProcessName", ""))[:30])
            cmd  = (ev.get("CommandLine",
                   ev.get("ProcessCommandLine", "")) or "")[:50]
            msg  = (ev.get("Message", "") or "")[:60]
            self._ev_tree.insert("", "end", values=(
                ts, eid, prov, comp, img, cmd, msg
            ))
        self._ev_count_lbl.configure(
            text=f"Showing {len(shown):,} of {n_ev:,} events")

        # Timeline
        self._populate_timeline(sorted_hits)

        # Analysis report
        if hasattr(self, "_analysis_box"):
            self._clr(self._analysis_box)
            self._wlog(self._analysis_box, "info", self._render_analysis_report())

        # Status
        self._status_var.set(
            f"Hunt complete — {n_ev:,} events  |  {n_h} hits  "
            f"|  {crit} critical  |  {hi} high"
        )
        if hasattr(self, "_live_count_var"):
            self._live_count_var.set(f"Parsed events: {n_ev:,} | Files processed: {len(self._log_paths)} | Hits: {n_h}")
        if hasattr(self, "_live_attack_var"):
            chain = self._stats.get("analysis", {}).get("attack_chain", {}).get("stages", [])
            self._live_attack_var.set("Attack-chain view: " + " | ".join(f"{stage}: {count}" for stage, count, _ in chain))
        self._wlog(self._hunt_log, "success",
                   f"[DONE] Hunt complete - {n_ev:,} events parsed, "
                   f"{n_h} detection hits\n")

        # Keep dashboard visible so path, progress, parsed events, and analysis remain visible.
        self.nb.select(0)

    def _populate_timeline(self, hits):
        for w in self._tl_inner.winfo_children():
            w.destroy()

        if not hits:
            tk.Label(self._tl_inner,
                     text="No detection hits to display.",
                     font=("Consolas", 11), fg=TEXT_DIM, bg=PANEL).pack(pady=40)
            return

        sev_colors = {"CRITICAL": "#ff2222", "HIGH": DANGER,
                      "MEDIUM": WARNING, "LOW": SUCCESS, "INFO": ACCENT}

        for i, h in enumerate(hits):
            color = sev_colors.get(h["severity"], TEXT_DIM)
            row = tk.Frame(self._tl_inner, bg=PANEL)
            row.pack(fill=tk.X, padx=8, pady=2)

            # Time dot
            dot = tk.Frame(row, bg=color, width=10, height=10)
            dot.pack(side=tk.LEFT, padx=(8, 0), pady=8)

            # Timestamp
            ts = self._fmt_ts(h["timestamp"])
            tk.Label(row, text=ts, font=("Consolas", 9),
                     fg=TEXT_DIM, bg=PANEL, width=22, anchor="w").pack(
                         side=tk.LEFT, padx=(6, 0))

            # Severity badge
            tk.Label(row, text=h["severity"],
                     font=("Consolas", 8, "bold"), fg=color,
                     bg=PANEL2, padx=4, pady=1).pack(side=tk.LEFT, padx=6)

            # Rule
            tk.Label(row, text=f"[{h['rule_id']}]",
                     font=("Consolas", 9, "bold"), fg=ACCENT3,
                     bg=PANEL).pack(side=tk.LEFT, padx=(0, 4))

            # Detail
            det = h["detail"][:90]
            tk.Label(row, text=det, font=("Consolas", 9),
                     fg=TEXT_MID, bg=PANEL, anchor="w").pack(side=tk.LEFT)

            # Separator
            if i < len(hits) - 1:
                tk.Frame(self._tl_inner, bg=BORDER, height=1).pack(
                    fill=tk.X, padx=20)

    def _fmt_ts(self, ts):
        if not ts:
            return "—"
        try:
            dt = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return str(ts)[:22]

    # ── Filter / search within results ────────────────────────────────────────
    def _filter_detections(self):
        kw  = self._det_filter_var.get().lower()
        sev = self._sev_filter_var.get()
        for item in self._det_tree.get_children():
            self._det_tree.delete(item)

        for h in self._hits:
            if sev != "ALL" and h["severity"] != sev:
                continue
            row = (h.get("timestamp",""), h.get("rule_id",""),
                   h.get("severity",""), h.get("category",""),
                   h.get("mitre",""), str(h.get("event_id","")),
                   h.get("computer",""), h.get("process",""),
                   h.get("detail",""))
            if kw and kw not in " ".join(row).lower():
                continue
            ts = self._fmt_ts(h["timestamp"])
            self._det_tree.insert("", "end", values=(
                ts, h["rule_id"], h["severity"], h["category"],
                h["mitre"], h["event_id"], h["computer"],
                os.path.basename(h.get("process",""))[:30],
                h["detail"][:80]
            ), tags=(h["severity"],))

    def _filter_events(self):
        kw  = self._ev_search_var.get().lower()
        eid_f = self._ev_eid_var.get().strip()
        for item in self._ev_tree.get_children():
            self._ev_tree.delete(item)
        count = 0
        for ev in self._events[:5000]:
            if eid_f:
                try:
                    if ev.get("EventID") != int(eid_f):
                        continue
                except ValueError:
                    pass
            if kw:
                hay = " ".join(str(v) for v in ev.values()).lower()
                if kw not in hay:
                    continue
            ts  = self._fmt_ts(ev.get("TimeCreated",""))
            img = os.path.basename(ev.get("Image",
                  ev.get("NewProcessName",""))[:30])
            cmd = (ev.get("CommandLine",
                   ev.get("ProcessCommandLine","")) or "")[:50]
            msg = (ev.get("Message","") or "")[:60]
            self._ev_tree.insert("", "end", values=(
                ts, ev.get("EventID",""), ev.get("Provider","")[:20],
                ev.get("Computer","")[:20], img, cmd, msg
            ))
            count += 1
        self._ev_count_lbl.configure(text=f"Showing {count:,} events")

    # ── Detail popups ──────────────────────────────────────────────────────────
    def _show_hit_detail(self, event):
        sel = self._det_tree.selection()
        if not sel:
            return
        idx = self._det_tree.index(sel[0])
        if idx >= len(self._hits):
            return
        h = sorted(self._hits, key=lambda x: SEV_ORDER.get(x["severity"], 9))[idx]
        txt = json.dumps(h, indent=2, default=str)
        self._det_detail.configure(state=tk.NORMAL)
        self._det_detail.delete("1.0", tk.END)
        self._det_detail.insert(tk.END, txt)
        self._det_detail.configure(state=tk.DISABLED)

    def _show_ev_detail(self, event):
        sel = self._ev_tree.selection()
        if not sel:
            return
        idx = self._ev_tree.index(sel[0])
        evs = self._events[:5000]
        if idx >= len(evs):
            return
        ev = evs[idx]
        txt = json.dumps({k: v for k, v in ev.items()
                          if not k.startswith("_raw")}, indent=2, default=str)
        self._ev_detail.configure(state=tk.NORMAL)
        self._ev_detail.delete("1.0", tk.END)
        self._ev_detail.insert(tk.END, txt)
        self._ev_detail.configure(state=tk.DISABLED)

    # ── Rules management ───────────────────────────────────────────────────────
    def _toggle_rule(self, event):
        sel = self._rules_tree.selection()
        if not sel:
            return
        rid = sel[0]
        self._rule_states[rid] = not self._rule_states.get(rid, True)
        check = "●" if self._rule_states[rid] else "○"
        vals = list(self._rules_tree.item(rid, "values"))
        vals[0] = check
        self._rules_tree.item(rid, values=vals)

    def _enable_all_rules(self):
        for rid in self._rule_states:
            self._rule_states[rid] = True
            vals = list(self._rules_tree.item(rid, "values"))
            vals[0] = "●"
            self._rules_tree.item(rid, values=vals)

    def _disable_all_rules(self):
        for rid in self._rule_states:
            self._rule_states[rid] = False
            vals = list(self._rules_tree.item(rid, "values"))
            vals[0] = "○"
            self._rules_tree.item(rid, values=vals)

    # ── PowerShell console ─────────────────────────────────────────────────────
    def _load_ps_template(self, cmd):
        self._ps_cmd_var.set(cmd)

    def _run_ps_command(self):
        cmd = self._ps_cmd_var.get().strip()
        if not cmd:
            return
        self._wlog(self._ps_output, "info", f"\nPS> {cmd}\n")
        self._ps_cmd_var.set("")
        threading.Thread(target=self._ps_worker, args=(cmd,), daemon=True).start()

    def _ps_worker(self, cmd):
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive",
                 "-ExecutionPolicy", "Bypass", "-Command", cmd],
                **_quiet_subprocess_kwargs(text=True, timeout=60)
            )
            out = result.stdout or ""
            err = result.stderr or ""
            if out:
                self._q.put(("log", out, "raw"))
            if err:
                self._q.put(("log", f"[STDERR] {err}", "alert"))
        except subprocess.TimeoutExpired:
            self._q.put(("log", "[TIMEOUT] Command took too long.", "alert"))
        except Exception as e:
            self._q.put(("log", f"[ERROR] {e}", "alert"))

    # ── Export ─────────────────────────────────────────────────────────────────
    def _export_report(self):
        if not self._events and not self._hits:
            messagebox.showinfo("Export", "No analysis results to export. Run a hunt first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("All files", "*.*")],
            initialfile="jigsaw_analysis_report.txt")
        if not path:
            return
        Path(path).write_text(self._render_analysis_report(), encoding="utf-8")
        messagebox.showinfo("Export", f"Saved report to:\n{path}")

    def _export_json(self):
        if not self._hits:
            messagebox.showinfo("Export", "No hits to export. Run a hunt first.")
            return
        p = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON","*.json"),("All","*.*")],
            initialfile=f"jigsaw_hits_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        if p:
            json.dump(self._hits, open(p, "w", encoding="utf-8"), indent=2, default=str)
            messagebox.showinfo("Exported", f"Saved {len(self._hits)} hits to:\n{p}")

    def _export_csv(self):
        if not self._hits:
            messagebox.showinfo("Export", "No hits to export.")
            return
        p = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV","*.csv"),("All","*.*")],
            initialfile=f"jigsaw_hits_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        if p:
            import csv
            keys = ["rule_id","rule_name","severity","category","mitre",
                    "timestamp","event_id","computer","process","image","detail"]
            with open(p, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
                w.writeheader()
                w.writerows(self._hits)
            messagebox.showinfo("Exported", f"CSV saved to:\n{p}")

    def _export_txt(self):
        if not self._hits:
            messagebox.showinfo("Export", "No hits to export.")
            return
        p = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text","*.txt"),("All","*.*")],
            initialfile=f"jigsaw_hits_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        if p:
            lines = []
            for h in self._hits:
                lines.append("=" * 70)
                lines.append(f"Rule     : [{h['rule_id']}] {h['rule_name']}")
                lines.append(f"Severity : {h['severity']}")
                lines.append(f"Category : {h['category']}  |  MITRE: {h['mitre']}")
                lines.append(f"Time     : {self._fmt_ts(h['timestamp'])}")
                lines.append(f"EID      : {h['event_id']}  |  Computer: {h['computer']}")
                lines.append(f"Process  : {h.get('process','')}")
                lines.append(f"Detail   : {h['detail']}")
            lines.append("=" * 70)
            open(p, "w", encoding="utf-8").write("\n".join(lines))
            messagebox.showinfo("Exported", f"Saved to:\n{p}")

    # ── Welcome message ────────────────────────────────────────────────────────
    def _show_welcome(self):
        msg = (
            "╔══════════════════════════════════════════════════════╗\n"
            "║          JIGSAW XDR+ OMNIPARSER v2.0                 ║\n"
            "║          Author: Kennedy Aikohi                      ║\n"
            "╠══════════════════════════════════════════════════════╣\n"
            "║  QUICK START:                                        ║\n"
            "║  1. Add EVTX/EVT/XML/JSON/CSV/TXT/LOG artefacts      ║\n"
            "║  2. Optionally set filters, date range, IP, keyword  ║\n"
            "║  3. Enable/disable rules or run all 20 detections    ║\n"
            "║  4. Click ▶ RUN HUNT                                 ║\n"
            "║  5. Review DETECTIONS, TIMELINE, ANALYSIS RESULTS    ║\n"
            "║  6. Export JSON/CSV/TXT or full analysis report      ║\n"
            "╚══════════════════════════════════════════════════════╝\n\n"
            f"  python-evtx installed : {'YES ✓' if HAS_EVTX else 'NO — will use PS fallback'}\n"
            f"  pyyaml installed      : {'YES ✓' if HAS_YAML else 'NO (optional)'}\n"
            f"  Running as admin      : {'YES ✓' if is_admin() else 'NO — some logs may be inaccessible'}\n\n"
        )
        self._wlog(self._hunt_log, "info", msg)
        self._wlog(self._dash_log, "info", msg)


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# Jigsaw v2.1 — Jigsaw-style + ETW/SilkETW attack-chain upgrade
# This block intentionally monkey-patches the engine so GUI and CLI both inherit
# the same behaviour without changing the original project layout.
# ═══════════════════════════════════════════════════════════════════════════════
PRODUCT_VERSION = "2.1 Jigsaw+ ETW Fusion"

_EXTRA_CHAIN_RULES = [
    {
        "id": "JIG-021",
        "name": "ETW Reveals Parent PID Spoofing / True Creator Mismatch",
        "severity": "CRITICAL",
        "category": "Execution / Defense Evasion",
        "mitre": "T1134.004",
        "event_ids": [0, 1, 4688],
        "logic": "etw_true_parent_spoof",
        "description": "Compares Sysmon/EventLog parent context with ETW Kernel-Process creator fields so spoofed parents can be exposed.",
    },
    {
        "id": "JIG-022",
        "name": "Suspicious ETW Kernel Process Parent/Child Relationship",
        "severity": "HIGH",
        "category": "Execution",
        "mitre": "T1059",
        "event_ids": [0, 1, 4688],
        "logic": "etw_kernel_suspicious_parent_child",
        "description": "Detects strange parent-child relationships using ETW/SilkETW Kernel-Process JSON as well as EVTX fields.",
    },
    {
        "id": "JIG-023",
        "name": "Suspicious .NET Runtime Assembly Load / BYOL Indicator",
        "severity": "HIGH",
        "category": "Defense Evasion / Execution",
        "mitre": "T1620",
        "event_ids": [0, 7],
        "logic": "dotnet_runtime_assembly_load",
        "description": "Detects clr/mscoree loads and ETW DotNETRuntime loader/JIT metadata such as Seatbelt/Rubeus/SharpHound-style assemblies.",
    },
    {
        "id": "JIG-024",
        "name": "In-memory .NET Method/JIT Telemetry from ETW",
        "severity": "MEDIUM",
        "category": "Execution",
        "mitre": "T1059.001",
        "event_ids": [0],
        "logic": "dotnet_jit_method_telemetry",
        "description": "Surfaces DotNETRuntime JIT/Interop/Loader/NGen method names so analysts see what in-memory assembly code is doing.",
    },
]
_seen_rule_ids = {r.get("id") for r in JIGSAW_RULES}
for _r in _EXTRA_CHAIN_RULES:
    if _r["id"] not in _seen_rule_ids:
        JIGSAW_RULES.append(_r)
        _seen_rule_ids.add(_r["id"])

_orig_discover_parsers = JigsawEngine._discover_parsers
_orig_normalise_external_event = JigsawEngine._normalise_external_event
_orig_match_rule = JigsawEngine._match_rule
_orig_build_stats = JigsawEngine._build_stats
_orig_render_analysis_report = JigsawApp._render_analysis_report


def _flatten_dict_for_jigsaw(obj, prefix=""):
    out = {}
    if not isinstance(obj, dict):
        return out
    for k, v in obj.items():
        key = f"{prefix}.{k}" if prefix else str(k)
        if isinstance(v, dict):
            out.update(_flatten_dict_for_jigsaw(v, key))
        elif isinstance(v, list):
            out[key] = " ".join(json.dumps(x, ensure_ascii=False) if isinstance(x, (dict, list)) else str(x) for x in v)
        else:
            out[key] = "" if v is None else str(v)
    return out


def _patched_discover_parsers(self):
    """Prefer silent offline parsers. wevtutil is opt-in to avoid flashing consoles."""
    candidates = []
    try:
        import evtx as _e
        _ = _e.PyEvtxParser
        candidates.append((EvtxRsParser, "pyevtx-rs"))
    except (ImportError, AttributeError):
        pass
    if HAS_EVTX:
        candidates.append((EvtxLibParser, "python-evtx"))
    if os.environ.get("JIGSAW_ALLOW_WEVTUTIL", "").lower() in ("1", "true", "yes"):
        try:
            r = subprocess.run(["wevtutil.exe", "/?"], **_quiet_subprocess_kwargs(timeout=5))
            if r.returncode == 0:
                candidates.append((EvtxRecordScanner, "wevtutil /lf:true"))
        except (FileNotFoundError, PermissionError, OSError):
            pass
    return candidates


def _patched_normalise_external_event(self, rec, basename, source_kind):
    flat = _flatten_dict_for_jigsaw(rec)
    merged = dict(rec) if isinstance(rec, dict) else {"Message": str(rec)}
    for k, v in flat.items():
        merged.setdefault(k, v)
        merged.setdefault(k.split(".")[-1], v)

    # SilkETW commonly places useful fields in EventName + Payload.*
    etw_provider = (merged.get("ProviderName") or merged.get("Provider") or merged.get("provider") or merged.get("TraceProvider") or merged.get("Name") or "")
    event_name = (merged.get("EventName") or merged.get("event_name") or merged.get("TaskName") or merged.get("OpcodeName") or "")
    if "Kernel-Process" in etw_provider or "Process" in event_name:
        merged.setdefault("Channel", "ETW/Microsoft-Windows-Kernel-Process")
        merged.setdefault("Provider", etw_provider or "Microsoft-Windows-Kernel-Process")
        merged.setdefault("Image", merged.get("ImageName") or merged.get("ProcessName") or merged.get("Payload.ImageName") or merged.get("Payload.ProcessName") or "")
        merged.setdefault("CommandLine", merged.get("Payload.CommandLine") or merged.get("CommandLine") or "")
        merged.setdefault("ParentImage", merged.get("ParentImageName") or merged.get("Payload.ParentImageName") or merged.get("CreatorProcessName") or merged.get("Payload.CreatorProcessName") or "")
        merged.setdefault("ParentProcessId", merged.get("ParentID") or merged.get("ParentProcessId") or merged.get("Payload.ParentID") or merged.get("Payload.ParentProcessID") or "")
        merged.setdefault("CreatorProcessName", merged.get("CreatorProcessName") or merged.get("Payload.CreatorProcessName") or merged.get("Payload.CreatingProcessName") or "")
        merged.setdefault("CreatorProcessId", merged.get("CreatorProcessID") or merged.get("CreatingProcessID") or merged.get("Payload.CreatorProcessID") or merged.get("Payload.CreatingProcessID") or "")
        merged.setdefault("ETWEventName", event_name)

    if "DotNETRuntime" in etw_provider or any(x in event_name.lower() for x in ("assembly", "method", "jit", "loader", "ngen", "clr")):
        merged.setdefault("Channel", "ETW/Microsoft-Windows-DotNETRuntime")
        merged.setdefault("Provider", etw_provider or "Microsoft-Windows-DotNETRuntime")
        merged.setdefault("AssemblyName", merged.get("AssemblyName") or merged.get("Payload.AssemblyName") or merged.get("FullyQualifiedAssemblyName") or "")
        merged.setdefault("MethodName", merged.get("MethodName") or merged.get("Payload.MethodName") or merged.get("MethodNamespace") or "")
        merged.setdefault("Image", merged.get("ProcessName") or merged.get("Payload.ProcessName") or merged.get("Image") or "")
        merged.setdefault("ETWEventName", event_name)

    # Make every parsed record visible/searchable; assign EventID 0 for ETW JSON records with no Windows EID.
    ev = _orig_normalise_external_event(self, merged, basename, source_kind)
    ev["_raw_xml"] = json.dumps(rec, ensure_ascii=False)[:12000] if isinstance(rec, dict) else str(rec)[:12000]
    for k in ("ETWEventName", "AssemblyName", "MethodName", "CreatorProcessName", "CreatorProcessId", "ParentProcessId"):
        if merged.get(k) and not ev.get(k):
            ev[k] = merged.get(k)
    return ev


def _patched_match_rule(self, rule, ev, ip_filter, ntlm_src):
    logic = rule.get("logic")
    blob = self._event_blob(ev)
    if logic == "etw_true_parent_spoof":
        claimed = os.path.basename((ev.get("ParentImage") or ev.get("ParentProcessName") or "")).lower()
        true_creator = os.path.basename((ev.get("CreatorProcessName") or ev.get("CreatingProcessName") or "")).lower()
        child = os.path.basename((ev.get("Image") or ev.get("NewProcessName") or ev.get("ProcessName") or "")).lower()
        if true_creator and claimed and true_creator != claimed and child:
            return self._hit(rule, ev, f"ETW creator differs from logged parent: claimed parent={claimed}, ETW creator={true_creator}, child={child}. This is a parent PID spoofing lead.", process=child)
        if "spoolsv.exe" in blob and any(x in blob for x in ("cmd.exe", "whoami.exe", "powershell.exe")) and "kernel-process" in blob:
            return self._hit(rule, ev, "ETW Kernel-Process record shows spoolsv-related suspicious child execution. Validate against Sysmon EID 1 parent fields.")
        return None
    if logic == "etw_kernel_suspicious_parent_child":
        parent = os.path.basename((ev.get("ParentImage") or ev.get("ParentProcessName") or ev.get("CreatorProcessName") or "")).lower()
        child = os.path.basename((ev.get("Image") or ev.get("NewProcessName") or ev.get("ProcessName") or "")).lower()
        if parent and child and child in SUSPICIOUS_PC_PAIRS.get(parent, []):
            return self._hit(rule, ev, f"ETW/EVTX suspicious parent-child: {parent} → {child} | {self._short_blob(ev)}", process=child)
        return None
    if logic == "dotnet_runtime_assembly_load":
        suspicious_assemblies = ["seatbelt", "rubeus", "sharphound", "safetykatz", "ghostpack", "execute-assembly", "cobalt", "beacon", "powerpick"]
        dotnet_markers = ["clr.dll", "mscoree.dll", "clrjit.dll", "microsoft-windows-dotnetruntime", "assemblyload", "loader", "ngen"]
        if any(x in blob for x in dotnet_markers):
            if any(x in blob for x in suspicious_assemblies) or any(x in blob for x in ("temp", "appdata", "users\\public", "downloads")):
                return self._hit(rule, ev, ".NET runtime/assembly load telemetry: " + self._short_blob(ev), process=ev.get("Image", ""))
        return None
    if logic == "dotnet_jit_method_telemetry":
        if any(x in blob for x in ("microsoft-windows-dotnetruntime", "jit", "methodname", "assemblyname", "interopkeyword")) and (ev.get("MethodName") or ev.get("AssemblyName")):
            return self._hit(rule, ev, f"ETW .NET execution metadata | Assembly={ev.get('AssemblyName','')} | Method={ev.get('MethodName','')}", process=ev.get("Image", ""))
        return None
    return _orig_match_rule(self, rule, ev, ip_filter, ntlm_src)


def _patched_build_stats(self, events, hits):
    stats = _orig_build_stats(self, events, hits)
    a = stats.setdefault("analysis", {})
    etw = sum(1 for ev in events if "ETW/" in str(ev.get("Channel", "")) or "Microsoft-Windows-DotNETRuntime" in self._event_blob(ev) or "Microsoft-Windows-Kernel-Process" in self._event_blob(ev))
    dotnet = sum(1 for ev in events if any(x in self._event_blob(ev) for x in ("clr.dll", "mscoree.dll", "dotnetruntime", "assemblyname", "methodname")))
    proc = sum(1 for ev in events if ev.get("EventID") in (1, 4688, 0) and any(k in ev for k in ("Image", "ProcessName", "NewProcessName")))
    a["engine_model"] = [
        "Jigsaw-style fast hunt/search across EVTX/XML/JSON/CSV/TXT artefacts",
        "ETW/SilkETW JSON fusion for Kernel-Process and DotNETRuntime telemetry",
        "Attack-chain synthesis: execution → persistence → credential access → lateral movement → evasion",
        "Analyst visibility mode: parsed records and analysis are shown even when no rule fires",
    ]
    a["fusion_counts"] = {"etw_records": etw, "dotnet_records": dotnet, "process_records": proc}
    return stats


def _patched_render_analysis_report(self):
    base = _orig_render_analysis_report(self)
    a = self._stats.get("analysis", {})
    lines = [base.rstrip(), "", "Jigsaw+ / ETW Fusion Model:"]
    for item in a.get("engine_model", []):
        lines.append("  - " + item)
    fc = a.get("fusion_counts", {})
    if fc:
        lines.append("")
        lines.append("Telemetry fusion counts:")
        lines.append(f"  ETW records       : {fc.get('etw_records', 0):,}")
        lines.append(f"  .NET records      : {fc.get('dotnet_records', 0):,}")
        lines.append(f"  Process records   : {fc.get('process_records', 0):,}")
    if not self._hits and self._events:
        lines.append("")
        lines.append("No detection rule fired, but parsed data is available. Review the EVENTS tab/sample rows and export Events JSON for full triage.")
    return "\n".join(lines) + "\n"


JigsawEngine._discover_parsers = _patched_discover_parsers
JigsawEngine._normalise_external_event = _patched_normalise_external_event
JigsawEngine._match_rule = _patched_match_rule
JigsawEngine._build_stats = _patched_build_stats
JigsawApp._render_analysis_report = _patched_render_analysis_report


# ═══════════════════════════════════════════════════════════════════════════════
# FINAL VISIBILITY/TRUTH PATCH
# Shows proof of parsing even when there are no detections, and explains exactly
# why the analyst sees zero visible events.
# ═══════════════════════════════════════════════════════════════════════════════

def _jigsaw_active_filter_text(filters, ip_filter, date_from, date_to):
    active = []
    if filters.get("event_ids"):
        active.append("EventID=" + ",".join(str(x) for x in filters.get("event_ids", [])))
    if filters.get("keyword"):
        active.append("keyword=" + str(filters.get("keyword")))
    if filters.get("regex"):
        active.append("regex=" + str(filters.get("regex")))
    if filters.get("process_guid"):
        active.append("ProcessGuid=" + str(filters.get("process_guid")))
    if ip_filter:
        active.append("ip=" + str(ip_filter))
    if date_from:
        active.append("from=" + str(date_from))
    if date_to:
        active.append("to=" + str(date_to))
    return active or ["none — showing all parsed events"]


def _jigsaw_set_diag(self, path, parser, raw=0, normalized=0, visible=0, status="ok", error=""):
    self._last_file_diag = {
        "file": os.path.basename(path),
        "path": path,
        "parser": parser,
        "raw": int(raw or 0),
        "normalized": int(normalized or 0),
        "visible": int(visible or 0),
        "status": status,
        "error": str(error or ""),
    }


def _truth_parse_evtx_file(self, path, cf):
    basename = os.path.basename(path)
    last_error = None
    candidates = self._parser_candidates or ([] if self._parser_cls is None else [(self._parser_cls, self._parser_name)])
    if not candidates:
        _jigsaw_set_diag(self, path, "none", 0, 0, 0, "error", "no EVTX parser available")
        raise RuntimeError("no EVTX parser available — install: pip install evtx python-evtx")
    for parser_cls, parser_name in candidates:
        events = []
        raw_count = 0
        dict_count = 0
        try:
            parser = parser_cls(path)
            for xml_str in parser.xml_records():
                if not xml_str:
                    continue
                raw_count += 1
                try:
                    ev = self._xml_to_dict(xml_str)
                    if ev.get("_parse_error"):
                        continue
                    dict_count += 1
                    ev["_src"] = basename
                    ev["SourceFile"] = basename
                    ev["Parser"] = parser_name
                    if self._passes(ev, cf):
                        events.append(ev)
                except Exception as inner:
                    # Keep going; corrupt single records should not hide the whole file.
                    continue
            if raw_count or dict_count or events:
                if parser_name != self._parser_name:
                    self.log_cb(f"      ↳ fallback parser used for {basename}: {parser_name}", "dim")
                _jigsaw_set_diag(self, path, parser_name, raw_count, dict_count, len(events), "ok", "")
                return events
            last_error = RuntimeError(f"{parser_name} returned no XML records")
        except Exception as e:
            last_error = e
            continue
    _jigsaw_set_diag(self, path, " / ".join(name for _, name in candidates), 0, 0, 0, "error", last_error)
    raise RuntimeError(str(last_error) if last_error else "no XML records returned")


def _truth_parse_xml_file(self, path, cf):
    events = []
    basename = os.path.basename(path)
    data = Path(path).read_text(encoding="utf-8", errors="ignore")
    chunks = re.findall(r"<Event\b.*?</Event>", data, flags=re.I | re.S)
    if not chunks and data.lstrip().startswith("<"):
        chunks = [data]
    normalized = 0
    for chunk in chunks:
        ev = self._xml_to_dict(chunk)
        if ev.get("_parse_error"):
            continue
        normalized += 1
        ev["_src"] = basename
        ev["SourceFile"] = basename
        ev["Parser"] = "xml"
        if self._passes(ev, cf):
            events.append(ev)
    _jigsaw_set_diag(self, path, "xml", len(chunks), normalized, len(events), "ok", "")
    return events


def _truth_parse_json_file(self, path, cf):
    events = []
    basename = os.path.basename(path)
    text = Path(path).read_text(encoding="utf-8", errors="ignore")
    records = []
    try:
        obj = json.loads(text)
        if isinstance(obj, list):
            records = obj
        elif isinstance(obj, dict):
            records = obj.get("events") or obj.get("Records") or obj.get("hits") or obj.get("Events") or [obj]
    except Exception:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except Exception:
                records.append({"Message": line})
    normalized = 0
    for rec in records:
        if not isinstance(rec, dict):
            rec = {"Message": str(rec)}
        ev = self._normalise_external_event(rec, basename, "json")
        ev["Parser"] = "json"
        normalized += 1
        if self._passes(ev, cf):
            events.append(ev)
    _jigsaw_set_diag(self, path, "json", len(records), normalized, len(events), "ok", "")
    return events


def _truth_parse_csv_file(self, path, cf):
    events = []
    basename = os.path.basename(path)
    raw = 0
    with open(path, "r", encoding="utf-8", errors="ignore", newline="") as fh:
        sample = fh.read(4096)
        fh.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample)
        except Exception:
            dialect = csv.excel
        reader = csv.DictReader(fh, dialect=dialect)
        if reader.fieldnames:
            for row in reader:
                raw += 1
                ev = self._normalise_external_event(row, basename, "csv")
                ev["Parser"] = "csv"
                if self._passes(ev, cf):
                    events.append(ev)
    _jigsaw_set_diag(self, path, "csv", raw, raw, len(events), "ok", "")
    return events


def _truth_parse_text_file(self, path, cf):
    events = []
    basename = os.path.basename(path)
    raw = 0
    time_rx = re.compile(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?|\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})")
    eid_rx = re.compile(r"(?:EventID|Event ID|EID|Id)\s*[:=]\s*(\d{1,5})", re.I)
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for i, line in enumerate(fh, 1):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            raw += 1
            eid_m = eid_rx.search(line)
            ts_m = time_rx.search(line)
            ev = {
                "EventID": int(eid_m.group(1)) if eid_m else 0,
                "TimeCreated": ts_m.group(1).replace(" ", "T") if ts_m else "",
                "Provider": "text-log",
                "Channel": "Text/LOG",
                "Computer": "",
                "Message": line,
                "SourceFile": basename,
                "LineNumber": i,
                "Parser": "text",
                "_src": basename,
                "_raw_xml": line,
            }
            if self._passes(ev, cf):
                events.append(ev)
    _jigsaw_set_diag(self, path, "text", raw, raw, len(events), "ok", "")
    return events


def _truth_parse_files(self, paths, filters, rules_enabled, ip_filter="", date_from=None, date_to=None):
    evtx_files = self._collect_files(paths)
    self._diagnostics = []
    self._last_file_diag = None
    n = len(evtx_files)
    parser_names = ", ".join(name for _, name in self._parser_candidates) or "none"
    self.log_cb(f"[*] Artefact mode  |  parser: {self._parser_name} (fallbacks: {parser_names})", "info")
    self.log_cb(f"[*] Found {n} log artefact file(s) to process", "info")
    active_filters = _jigsaw_active_filter_text(filters, ip_filter, date_from, date_to)
    self.log_cb("[*] Active filters: " + "; ".join(active_filters), "info")
    if n == 0:
        self.log_cb("[!] No supported log files found. Supported: .evtx .evt .xml .json .jsonl .ndjson .csv .log .txt", "alert")
        return [], [], {"diagnostics": [], "raw_total": 0, "normalized_total": 0, "visible_total": 0, "filter_summary": active_filters}
    cf = self._compile_filters(filters, ip_filter, date_from, date_to)
    all_events = []
    failed = []
    for i, fpath in enumerate(evtx_files):
        self.progress_cb(i, n)
        self.log_cb(f"[*] Hunting path: {fpath}", "info")
        self._last_file_diag = None
        try:
            evs = self._parse_one(fpath, cf)
            all_events.extend(evs)
            diag = self._last_file_diag or {"file": os.path.basename(fpath), "path": fpath, "parser": "unknown", "raw": len(evs), "normalized": len(evs), "visible": len(evs), "status": "ok", "error": ""}
            self._diagnostics.append(diag)
            self.log_cb(
                f"    ✓ {diag['file']:<50} raw:{diag['raw']:>7,}  normalized:{diag['normalized']:>7,}  visible:{diag['visible']:>7,}  parser:{diag['parser']}",
                "success" if diag.get("visible") else "dim")
            if diag.get("raw", 0) and not diag.get("visible", 0):
                self.log_cb("      -> DATA EXISTS but active filters/rules show 0 visible events. Clear filters or use Show All/No Filter mode.", "alert")
            elif not diag.get("raw", 0):
                self.log_cb("      -> File opened, but this parser returned 0 raw records. It may be an empty channel, unsupported provider, or corrupt EVTX.", "dim")
        except Exception as e:
            failed.append(os.path.basename(fpath))
            diag = {"file": os.path.basename(fpath), "path": fpath, "parser": "failed", "raw": 0, "normalized": 0, "visible": 0, "status": "error", "error": str(e)}
            self._diagnostics.append(diag)
            self.log_cb(f"    ✗ {os.path.basename(fpath)}: {e}", "alert")
    self.progress_cb(n, n)
    raw_total = sum(d.get("raw", 0) for d in self._diagnostics)
    normalized_total = sum(d.get("normalized", 0) for d in self._diagnostics)
    visible_total = len(all_events)
    error_total = sum(1 for d in self._diagnostics if d.get("status") == "error")
    hidden_total = max(0, normalized_total - visible_total)
    if failed:
        self.log_cb(f"[!] {len(failed)} file(s) could not be read: {', '.join(failed[:8])}", "alert")
    self.log_cb(f"[*] Parse proof: raw records:{raw_total:,}  normalized:{normalized_total:,}  visible after filters:{visible_total:,}  hidden by filters:{hidden_total:,}  errors:{error_total}", "info")
    hits = self._apply_rules(all_events, rules_enabled, ip_filter)
    stats = self._build_stats(all_events, hits)
    stats["diagnostics"] = list(self._diagnostics)
    stats["raw_total"] = raw_total
    stats["normalized_total"] = normalized_total
    stats["visible_total"] = visible_total
    stats["hidden_by_filters"] = hidden_total
    stats["parser_errors"] = error_total
    stats["filter_summary"] = active_filters
    sev = stats.get("severity_dist", {})
    self.log_cb(f"[+] Detection hits: {len(hits)}  CRITICAL:{sev.get('CRITICAL', 0)}  HIGH:{sev.get('HIGH', 0)}  MEDIUM:{sev.get('MEDIUM', 0)}", "success" if hits else "dim")
    if not hits and visible_total:
        self.log_cb("[i] No detection rule fired, but visible events were parsed. Review EVENTS and ANALYSIS tabs.", "info")
    if not hits and not visible_total and raw_total:
        self.log_cb("[!] Raw data was parsed but 0 events are visible. This is a filter/display situation, not a parser failure. Clear filters to confirm content.", "alert")
    if not hits and not visible_total and not raw_total:
        self.log_cb("[!] No raw records were parsed. Check parser dependency, corrupt files, or try exporting XML/JSON from the source system.", "alert")
    return all_events, hits, stats


# Install truth patch methods.
JigsawEngine._parse_evtx_file = _truth_parse_evtx_file
JigsawEngine._parse_xml_file = _truth_parse_xml_file
JigsawEngine._parse_json_file = _truth_parse_json_file
JigsawEngine._parse_csv_file = _truth_parse_csv_file
JigsawEngine._parse_text_file = _truth_parse_text_file
JigsawEngine.parse_files = _truth_parse_files

_prev_render_analysis_report_truth = JigsawApp._render_analysis_report

def _truth_render_analysis_report(self):
    base = _prev_render_analysis_report_truth(self).rstrip()
    st = self._stats or {}
    lines = [base, "", "Parser Proof / Why You May See No Hits:"]
    lines.append(f"  Raw records read       : {st.get('raw_total', len(self._events)):,}")
    lines.append(f"  Normalized records     : {st.get('normalized_total', len(self._events)):,}")
    lines.append(f"  Visible after filters  : {st.get('visible_total', len(self._events)):,}")
    lines.append(f"  Hidden by filters      : {st.get('hidden_by_filters', 0):,}")
    lines.append(f"  Parser/file errors     : {st.get('parser_errors', 0):,}")
    lines.append("  Active filters         : " + "; ".join(st.get("filter_summary", ["unknown"])))
    diagnostics = st.get("diagnostics", [])
    if diagnostics:
        lines.append("")
        lines.append("Per-file parser proof (first 30 files):")
        for d in diagnostics[:30]:
            status = "ERROR" if d.get("status") == "error" else "OK"
            lines.append(f"  [{status}] {d.get('file','')}: raw={d.get('raw',0):,}, normalized={d.get('normalized',0):,}, visible={d.get('visible',0):,}, parser={d.get('parser','')}")
            if d.get("error"):
                lines.append(f"        error: {d.get('error')}")
        if len(diagnostics) > 30:
            lines.append(f"  ... {len(diagnostics)-30} more files omitted from this view")
    if st.get("raw_total", 0) and not st.get("visible_total", len(self._events)):
        lines.append("")
        lines.append("Conclusion: the parser saw raw records, but the current filters hid them. Clear Event ID, keyword, regex, IP, ProcessGuid, and date filters.")
    elif not st.get("raw_total", len(self._events)):
        lines.append("")
        lines.append("Conclusion: no raw records were read. Install evtx/python-evtx, verify the files are real EVTX/XML/JSON exports, or test with Security.evtx/Sysmon Operational.")
    elif not self._hits:
        lines.append("")
        lines.append("Conclusion: parsing works. There are visible events, but none matched the enabled detection rules.")
    return "\n".join(lines) + "\n"

JigsawApp._render_analysis_report = _truth_render_analysis_report

_prev_populate_results_truth = JigsawApp._populate_results

def _truth_populate_results(self):
    _prev_populate_results_truth(self)
    st = self._stats or {}
    raw_total = st.get("raw_total", len(self._events))
    normalized_total = st.get("normalized_total", len(self._events))
    visible_total = st.get("visible_total", len(self._events))
    hidden = st.get("hidden_by_filters", 0)
    errors = st.get("parser_errors", 0)
    # Make dashboard stat cards prove parsing even when visible events are 0.
    if "EVENTS" in self._stat_cards:
        self._stat_cards["EVENTS"]._value_label.configure(text=f"{visible_total:,}")
    if hasattr(self, "_live_count_var"):
        self._live_count_var.set(f"Raw:{raw_total:,} | Normalized:{normalized_total:,} | Visible:{visible_total:,} | Hidden:{hidden:,} | Errors:{errors:,} | Hits:{len(self._hits)}")
    if hasattr(self, "_live_attack_var"):
        if raw_total and not visible_total:
            self._live_attack_var.set("Result state: raw records were parsed, but active filters hid all visible events")
        elif visible_total and not self._hits:
            self._live_attack_var.set("Result state: parsing works; no enabled detection rule matched these events")
        elif not raw_total:
            self._live_attack_var.set("Result state: no raw records parsed; check parser dependency or corrupt/empty logs")
    # If Events table is empty, insert one explanatory row so the user never sees a blank pane.
    if not self._events:
        try:
            self._ev_tree.insert("", "end", values=("", "INFO", "Jigsaw", "", "", "", f"No visible events. Raw={raw_total:,}, Hidden={hidden:,}, Errors={errors:,}. See ANALYSIS tab."))
            self._ev_count_lbl.configure(text=f"No visible events | raw:{raw_total:,} hidden:{hidden:,} errors:{errors:,}")
        except Exception:
            pass
    # If no detections, make detection pane explicitly explain it.
    if not self._hits:
        try:
            self._det_tree.insert("", "end", values=("", "NO-HIT", "INFO", "Analysis", "", "", "", "", "No detection rule fired. Check EVENTS/ANALYSIS for parser proof and raw counts."), tags=("INFO",))
        except Exception:
            pass

JigsawApp._populate_results = _truth_populate_results



# ═══════════════════════════════════════════════════════════════════════════════
# STABLE FINAL FIX PATCH — EVTX fallbacks, YAML rules/mappings, Hunting tab
# ═══════════════════════════════════════════════════════════════════════════════

JIGSAW_BASE_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent)) if "Path" in globals() else Path(__file__).resolve().parent
JIGSAW_RULES_FILE = JIGSAW_BASE_DIR / "rules" / "jigsaw_rules.yml"
JIGSAW_MAPPINGS_FILE = JIGSAW_BASE_DIR / "mappings" / "jigsaw-mappings.yml"
JIGSAW_MAPPINGS = {}

class GetWinEventPathParser:
    """PowerShell Get-WinEvent -Path fallback for offline EVTX artefacts."""
    def __init__(self, path):
        self.path = path

    def xml_records(self):
        ps = (
            "$ErrorActionPreference='Stop'; "
            "Get-WinEvent -Path $args[0] | ForEach-Object { $_.ToXml(); '---JIGSAW-EVENT-END---' }"
        )
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps, self.path],
                **_quiet_subprocess_kwargs(timeout=300)
            )
            raw = result.stdout or b""
            if not raw:
                return
            for enc in ("utf-8-sig", "utf-16-le", "utf-8", "latin-1"):
                try:
                    text = raw.decode(enc, errors="replace")
                    break
                except Exception:
                    text = ""
            for chunk in text.split("---JIGSAW-EVENT-END---"):
                chunk = chunk.strip()
                if "<Event" in chunk and "</Event>" in chunk:
                    yield chunk
        except Exception:
            return


def _jigsaw_load_yaml_documents():
    global JIGSAW_MAPPINGS
    if not HAS_YAML:
        return
    # Load external Sigma-like rules once. They are matched by yaml_conditions below.
    try:
        if JIGSAW_RULES_FILE.exists():
            data = yaml.safe_load(JIGSAW_RULES_FILE.read_text(encoding="utf-8", errors="ignore")) or {}
            existing = {r.get("id") for r in JIGSAW_RULES}
            for r in data.get("rules", []) or []:
                if not isinstance(r, dict) or not r.get("id") or r.get("id") in existing:
                    continue
                JIGSAW_RULES.append({
                    "id": r.get("id"),
                    "name": r.get("name", r.get("id")),
                    "description": r.get("description", "External YAML rule"),
                    "severity": str(r.get("severity", "MEDIUM")).upper(),
                    "category": r.get("category", "External YAML"),
                    "mitre": r.get("mitre", ""),
                    "event_ids": [int(x) for x in (r.get("event_ids") or [0]) if str(x).isdigit()],
                    "logic": "yaml_conditions",
                    "conditions": r.get("conditions") or {},
                })
                existing.add(r.get("id"))
    except Exception as e:
        print(f"[Jigsaw] Could not load YAML rules: {e}")

    # Load field mappings. The matcher/normalizer uses these as aliases.
    try:
        if JIGSAW_MAPPINGS_FILE.exists():
            data = yaml.safe_load(JIGSAW_MAPPINGS_FILE.read_text(encoding="utf-8", errors="ignore")) or {}
            JIGSAW_MAPPINGS = data.get("mappings") or {}
    except Exception as e:
        JIGSAW_MAPPINGS = {}
        print(f"[Jigsaw] Could not load mappings: {e}")

_jigsaw_load_yaml_documents()

# Built-in fallback copy of the bundled YAML/config so Jigsaw still works when PyYAML
# is missing from a frozen/offline build. If PyYAML loaded the files already, this is a no-op.
def _jigsaw_builtin_yaml_fallback():
    global JIGSAW_MAPPINGS
    existing = {r.get("id") for r in JIGSAW_RULES}
    fallback_rules = [
        {"id":"JIG-EXT-001","name":"Suspicious DLL Loaded by MSIEXEC from Temp","description":"msiexec.exe loading a DLL from Temp/AppData","severity":"HIGH","category":"DLL Hijacking","mitre":"T1574.001","event_ids":[7],"logic":"yaml_conditions","conditions":{"Image|endswith":"msiexec.exe","ImageLoaded|contains":["\\Temp\\","\\AppData\\"]}},
        {"id":"JIG-EXT-002","name":"RunDLL32 Loading DLL from User Directory","description":"rundll32.exe executing a DLL from a user-writable path","severity":"HIGH","category":"DLL Hijacking / Execution","mitre":"T1218.011","event_ids":[1,4688],"logic":"yaml_conditions","conditions":{"Image|endswith":"rundll32.exe","CommandLine|contains":["\\Users\\","\\Temp\\","\\AppData\\"]}},
        {"id":"JIG-EXT-003","name":"CertUtil Used for Download","description":"certutil.exe used with -urlcache or -decode","severity":"HIGH","category":"LOLBin / Download","mitre":"T1105","event_ids":[1,4688],"logic":"yaml_conditions","conditions":{"Image|endswith":"certutil.exe","CommandLine|contains":["-urlcache","-decode","http"]}},
        {"id":"JIG-EXT-004","name":"WMIC Spawning Child Process","description":"wmic.exe used to execute commands","severity":"MEDIUM","category":"Execution / Lateral Movement","mitre":"T1047","event_ids":[1,4688],"logic":"yaml_conditions","conditions":{"ParentImage|endswith":"wmic.exe"}},
        {"id":"JIG-EXT-005","name":"Suspicious Network Connection — Tor Exit / Known C2 Port","description":"Outbound connection on Tor-associated or uncommon C2 ports","severity":"HIGH","category":"C2 / Network","mitre":"T1090.003","event_ids":[3],"logic":"yaml_conditions","conditions":{"DestinationPort":[9001,9030,9050,9051,4444,4445,31337,1337,8888]}},
    ]
    for r in fallback_rules:
        if r["id"] not in existing:
            JIGSAW_RULES.append(r)
            existing.add(r["id"])
    if not JIGSAW_MAPPINGS:
        JIGSAW_MAPPINGS = {
            "process_creation":{"event_ids":[1],"channel":"Microsoft-Windows-Sysmon/Operational","fields":{"Image":"Image","CommandLine":"CommandLine","ParentImage":"ParentImage","ParentCommandLine":"ParentCommandLine","User":"User","ProcessGuid":"ProcessGuid","ProcessId":"ProcessId","ParentProcessGuid":"ParentProcessGuid","Hashes":"Hashes","CurrentDirectory":"CurrentDirectory","IntegrityLevel":"IntegrityLevel"}},
            "network_connection":{"event_ids":[3],"channel":"Microsoft-Windows-Sysmon/Operational","fields":{"Image":"Image","User":"User","Protocol":"Protocol","SourceIp":"SourceIp","SourcePort":"SourcePort","DestinationIp":"DestinationIp","DestinationPort":"DestinationPort","DestinationHostname":"DestinationHostname","ProcessGuid":"ProcessGuid"}},
            "image_load":{"event_ids":[7],"channel":"Microsoft-Windows-Sysmon/Operational","fields":{"Image":"Image","ImageLoaded":"ImageLoaded","Signed":"Signed","Signature":"Signature","SignatureStatus":"SignatureStatus","Hashes":"Hashes","ProcessGuid":"ProcessGuid"}},
            "security_process_creation":{"event_ids":[4688],"channel":"Security","fields":{"Image":"NewProcessName","CommandLine":"ProcessCommandLine","NewProcessName":"NewProcessName","ProcessCommandLine":"ProcessCommandLine","SubjectUserName":"SubjectUserName","ParentImage":"ParentProcessName","ParentProcessName":"ParentProcessName","NewProcessId":"NewProcessId","TokenElevationType":"TokenElevationType"}},
            "logon":{"event_ids":[4624,4625],"channel":"Security","fields":{"TargetUserName":"TargetUserName","WorkstationName":"WorkstationName","IpAddress":"IpAddress","LogonType":"LogonType","AuthenticationPackageName":"AuthenticationPackageName"}},
            "service_install":{"event_ids":[7045],"channel":"System","fields":{"ServiceName":"param1","ImagePath":"param2","ServiceType":"param3","StartType":"param4","AccountName":"param5"}},
            "powershell_script":{"event_ids":[4104],"channel":"Microsoft-Windows-PowerShell/Operational","fields":{"ScriptBlockText":"ScriptBlockText","Path":"Path"}},
        }

_jigsaw_builtin_yaml_fallback()


def _jigsaw_get_field(ev, field):
    if field in ev:
        return ev.get(field, "")
    # direct case-insensitive lookup
    fl = field.lower()
    for k, v in ev.items():
        if str(k).lower() == fl:
            return v
    # mappings aliases by EventID/channel
    eid = ev.get("EventID")
    channel = str(ev.get("Channel", "")).lower()
    for _, m in (JIGSAW_MAPPINGS or {}).items():
        if eid in (m.get("event_ids") or []) or not m.get("event_ids"):
            if m.get("channel") and m.get("channel", "").lower() not in channel and channel not in m.get("channel", "").lower():
                continue
            alias = (m.get("fields") or {}).get(field)
            if alias and alias in ev:
                return ev.get(alias, "")
    return ""


def _jigsaw_match_yaml_conditions(ev, conditions):
    for expr, expected in (conditions or {}).items():
        field, op = (expr.split("|", 1) + ["equals"])[:2] if "|" in expr else (expr, "equals")
        actual = _jigsaw_get_field(ev, field)
        actual_s = str(actual or "").lower()
        vals = expected if isinstance(expected, list) else [expected]
        vals_s = [str(v).lower() for v in vals]
        if op == "contains":
            if not any(v in actual_s for v in vals_s):
                return False
        elif op == "endswith":
            if not any(actual_s.endswith(v) for v in vals_s):
                return False
        elif op == "startswith":
            if not any(actual_s.startswith(v) for v in vals_s):
                return False
        elif op == "re":
            if not any(re.search(v, str(actual or ""), re.I) for v in vals_s):
                return False
        else:
            # Numeric equality is common for DestinationPort mappings.
            if str(actual).lower() not in vals_s:
                return False
    return True


_prev_final_discover_parsers = JigsawEngine._discover_parsers

def _final_discover_parsers(self):
    """Always enable built-in Windows EVTX readers; no JIGSAW_ALLOW_WEVTUTIL gate."""
    candidates = []
    try:
        import evtx as _e
        _ = _e.PyEvtxParser
        candidates.append((EvtxRsParser, "pyevtx-rs"))
    except Exception:
        pass
    if HAS_EVTX:
        candidates.append((EvtxLibParser, "python-evtx"))
    if os.name == "nt":
        try:
            r = subprocess.run(["wevtutil.exe", "/?"], **_quiet_subprocess_kwargs(timeout=5))
            if r.returncode == 0 or r.stdout or r.stderr:
                candidates.append((EvtxRecordScanner, "wevtutil /lf:true"))
        except Exception:
            pass
        try:
            r = subprocess.run(["powershell.exe", "-NoProfile", "-Command", "Get-Command Get-WinEvent"], **_quiet_subprocess_kwargs(timeout=8))
            if r.returncode == 0:
                candidates.append((GetWinEventPathParser, "Get-WinEvent -Path"))
        except Exception:
            pass
    return candidates

JigsawEngine._discover_parsers = _final_discover_parsers


_prev_final_normalise = JigsawEngine._normalise_external_event

def _final_normalise_external_event(self, rec, basename, source_kind):
    ev = _prev_final_normalise(self, rec, basename, source_kind)
    # Apply loaded mappings as aliases so YAML and built-in rules can see fields consistently.
    for _, m in (JIGSAW_MAPPINGS or {}).items():
        if ev.get("EventID") not in (m.get("event_ids") or [ev.get("EventID")]):
            continue
        for logical, physical in (m.get("fields") or {}).items():
            if logical not in ev and physical in ev:
                ev[logical] = ev.get(physical)
    if not ev.get("Message"):
        ev["Message"] = " | ".join(f"{k}={v}" for k, v in ev.items() if not str(k).startswith("_") and v)[:1200]
    return ev

JigsawEngine._normalise_external_event = _final_normalise_external_event


_prev_final_match_rule = JigsawEngine._match_rule

def _final_match_rule(self, rule, ev, ip_filter, ntlm_src):
    if rule.get("logic") == "yaml_conditions":
        if _jigsaw_match_yaml_conditions(ev, rule.get("conditions") or {}):
            return self._hit(rule, ev, "External YAML rule matched: " + self._short_blob(ev), process=_jigsaw_get_field(ev, "Image"))
        return None
    return _prev_final_match_rule(self, rule, ev, ip_filter, ntlm_src)

JigsawEngine._match_rule = _final_match_rule


_prev_final_collect_files = JigsawEngine._collect_files

def _final_collect_files(self, paths):
    expanded = []
    for p in paths:
        p = str(p).strip().strip('"')
        if not p:
            continue
        # Recover from accidental shell-style brace strings on Windows, e.g. jigsaw/{rules,mappings,logs_sample}
        m = re.search(r"^(.*)\{([^{}]+)\}(.*)$", p)
        if m:
            for part in m.group(2).split(","):
                expanded.append(m.group(1) + part.strip() + m.group(3))
        expanded.append(p)
    files = _prev_final_collect_files(self, expanded)
    # Only supported evidence/log formats; ignore config files in selected project roots.
    supported = {".evtx", ".evt", ".xml", ".json", ".jsonl", ".ndjson", ".csv", ".log", ".txt"}
    return [f for f in files if os.path.splitext(f)[1].lower() in supported]

JigsawEngine._collect_files = _final_collect_files


_prev_final_parse_files = JigsawEngine.parse_files

def _final_parse_files(self, paths, filters, rules_enabled, ip_filter="", date_from=None, date_to=None):
    # Refresh parser list on every run so newly installed packages or Windows built-ins are detected.
    self._parser_candidates = self._discover_parsers()
    self._parser_cls, self._parser_name = self._parser_candidates[0] if self._parser_candidates else (None, "NO PARSER AVAILABLE")
    return _prev_final_parse_files(self, paths, filters, rules_enabled, ip_filter, date_from, date_to)

JigsawEngine.parse_files = _final_parse_files


_prev_final_show_hit_detail = JigsawApp._show_hit_detail

def _final_show_hit_detail(self, event):
    sel = self._det_tree.selection()
    if not sel:
        return
    vals = self._det_tree.item(sel[0], "values") or []
    chosen = None
    if len(vals) >= 9:
        ts, rid, sev, _cat, _mitre, eid, comp, proc, detail = vals[:9]
        for h in self._hits:
            if (str(h.get("rule_id")) == str(rid) and str(h.get("severity")) == str(sev)
                    and str(h.get("event_id")) == str(eid) and str(h.get("detail", "")).startswith(str(detail)[:40])):
                chosen = h
                break
    if chosen is None:
        return _prev_final_show_hit_detail(self, event)
    txt = json.dumps(chosen, indent=2, default=str)
    self._det_detail.configure(state=tk.NORMAL)
    self._det_detail.delete("1.0", tk.END)
    self._det_detail.insert(tk.END, txt)
    self._det_detail.configure(state=tk.DISABLED)

JigsawApp._show_hit_detail = _final_show_hit_detail


def _build_tab_hunting(self):
    tab = tk.Frame(self.nb, bg=BG)
    self.nb.add(tab, text="  HUNTING  ")
    hdr = tk.Frame(tab, bg=BG)
    hdr.pack(fill=tk.X, padx=16, pady=(16, 8))
    tk.Label(hdr, text="LIVE HUNTING STATUS", font=("Consolas", 12, "bold"), fg=ACCENT, bg=BG).pack(side=tk.LEFT)
    tk.Frame(hdr, bg=BORDER, height=1).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10, pady=8)
    inner = tk.Frame(tab, bg=PANEL2, highlightthickness=1, highlightbackground=BORDER)
    inner.pack(fill=tk.X, padx=16, pady=(0, 10))
    for var, color in [(self._live_path_var, ACCENT), (self._live_file_var, TEXT_MID), (self._live_count_var, SUCCESS), (self._live_attack_var, WARNING)]:
        tk.Label(inner, textvariable=var, font=("Consolas", 11), fg=color, bg=PANEL2,
                 anchor="w", justify="left", wraplength=1100).pack(fill=tk.X, padx=14, pady=6)
    parser_text = "EVTX fallback order: evtx package → python-evtx → wevtutil /lf:true → Get-WinEvent -Path. YAML rules and mappings are loaded at startup."
    tk.Label(tab, text=parser_text, font=("Consolas", 9), fg=TEXT_DIM, bg=BG, anchor="w", justify="left", wraplength=1100).pack(fill=tk.X, padx=16, pady=(0, 8))
    log_outer = tk.Frame(tab, bg=PANEL2, highlightthickness=1, highlightbackground=BORDER)
    log_outer.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0, 16))
    self._hunt_live_box = self._logbox(log_outer, height=18)
    self._wtag(self._hunt_live_box)
    try:
        self._wlog(self._hunt_live_box, "info", "[READY] Select artefact paths and click RUN HUNT. Live parser proof appears here and in the dashboard.\n")
    except Exception:
        pass

JigsawApp._build_tab_hunting = _build_tab_hunting

_prev_final_build_main = JigsawApp._build_main

def _final_build_main(self, parent):
    _prev_final_build_main(self, parent)
    try:
        self._build_tab_hunting()
    except Exception as e:
        print(f"[Jigsaw] Could not build Hunting tab: {e}")

JigsawApp._build_main = _final_build_main

_prev_final_drain = JigsawApp._drain_queue

def _final_drain_queue(self):
    _prev_final_drain(self)
    # Mirror hunt log entries into the dedicated Hunting tab when present.
    try:
        if hasattr(self, "_hunt_live_box") and hasattr(self, "_hunt_log"):
            # The existing queue already writes to _hunt_log. Keep this pane alive with current status.
            pass
    except Exception:
        pass

JigsawApp._drain_queue = _final_drain_queue



# Queue drain override with Hunting tab mirroring.
def _final_drain_queue_full(self):
    try:
        while True:
            item = self._q.get_nowait()
            kind = item[0]
            if kind == "progress":
                _, done, total = item
                if total:
                    self._prog["value"] = (done / total) * 100
                    if hasattr(self, "_live_count_var"):
                        self._live_count_var.set(f"Parsed events: running | Files processed: {done}/{total} | Hits: running")
            elif kind == "log":
                _, msg, lvl = item
                self._wlog(self._hunt_log, lvl, msg + "\n")
                self._wlog(self._dash_log, lvl, msg + "\n")
                if hasattr(self, "_hunt_live_box"):
                    self._wlog(self._hunt_live_box, lvl, msg + "\n")
                if hasattr(self, "_live_file_var") and msg.startswith("[*] Hunting path:"):
                    self._live_file_var.set("Current artefact: " + msg.split(":", 1)[1].strip())
                if hasattr(self, "_live_count_var") and "running total:" in msg:
                    self._live_count_var.set("Parsed events: " + msg.split("running total:", 1)[1].strip() + " | Files processed: updating | Hits: running")
            elif kind == "done":
                _, events, hits, stats = item
                self._events = events
                self._hits = hits
                self._stats = stats
                self._populate_results()
                self._running = False
                self._run_btn.configure(state=tk.NORMAL)
                self._prog["value"] = 100
                if hasattr(self, "_hunt_live_box"):
                    self._wlog(self._hunt_live_box, "success", f"[DONE] Hunt complete — {len(events):,} events, {len(hits)} hits\n")
            elif kind == "error":
                _, msg = item
                self._wlog(self._hunt_log, "alert", f"[ERROR] {msg}\n")
                if hasattr(self, "_hunt_live_box"):
                    self._wlog(self._hunt_live_box, "alert", f"[ERROR] {msg}\n")
                messagebox.showerror("Engine Error", msg)
                self._running = False
                self._run_btn.configure(state=tk.NORMAL)
    except queue.Empty:
        pass
    self.after(150, self._drain_queue)

JigsawApp._drain_queue = _final_drain_queue_full




# ═══════════════════════════════════════════════════════════════════════════════
# JIGSAW v2.2 HEAVY HUNTER PATCH — execute BEFORE GUI startup
# Purpose: Jigsaw-style detection-first hunting, robust placeholder
# cleaning, DC/Security log detections, and safer aggregate auth detections.
# ═══════════════════════════════════════════════════════════════════════════════
PRODUCT_VERSION = "2.2 Heavy Hunter"

_JIGSAW_PLACEHOLDERS_V3 = {
    "e.g. 192.168.1.100", "eg 192.168.1.100", "example", "your-value",
    "2024-01-01 00:00:00", "2024-12-31 23:59:59", "yyyy-mm-dd hh:mm:ss",
}

def _jigsaw_clean_value_v3(value):
    s = str(value or "").strip()
    if not s:
        return ""
    low = s.lower().strip()
    if low in _JIGSAW_PLACEHOLDERS_V3 or low.startswith("e.g.") or low.startswith("eg "):
        return ""
    if "example" in low or "your-" in low:
        return ""
    return s

def _jigsaw_active_filter_text(filters, ip_filter, date_from, date_to):
    active = []
    filters = filters or {}
    if filters.get("event_ids"):
        active.append("EventID=" + ",".join(str(x) for x in filters.get("event_ids", [])))
    for key, label in (("keyword", "keyword"), ("regex", "regex"), ("process_guid", "ProcessGuid")):
        val = _jigsaw_clean_value_v3(filters.get(key, ""))
        if val:
            active.append(label + "=" + val)
    ip = _jigsaw_clean_value_v3(ip_filter or filters.get("ip", ""))
    if ip:
        active.append("ip=" + ip)
    if date_from:
        active.append("from=" + str(date_from))
    if date_to:
        active.append("to=" + str(date_to))
    return active or ["none — DETECTION FIRST / SHOW ALL parsed events"]

_prev_v3_compile_filters = JigsawEngine._compile_filters

def _v3_compile_filters(self, filters, ip_filter, date_from, date_to):
    clean = {}
    for k, v in (filters or {}).items():
        if k == "event_ids":
            clean[k] = v
        else:
            cv = _jigsaw_clean_value_v3(v)
            if cv:
                clean[k] = cv
    clean_ip = _jigsaw_clean_value_v3(ip_filter or clean.get("ip", ""))
    return _prev_v3_compile_filters(self, clean, clean_ip, date_from, date_to)

JigsawEngine._compile_filters = _v3_compile_filters

# DC / Security / AD detections that should work on ordinary KAPE EVTX exports
# without Sysmon. These fill the gap where Jigsaw/Sigma-style tools often need
# external rulesets or exact field names.
_V3_RULES = [
    {"id":"JIG-025","name":"Account Created","description":"Windows Security EID 4720 user account creation.","severity":"MEDIUM","category":"Identity / Persistence","mitre":"T1136.001","event_ids":[4720],"logic":"identity_account_created"},
    {"id":"JIG-026","name":"Privileged Group Membership Changed","description":"User added to local/domain/global/universal privileged group.","severity":"HIGH","category":"Privilege Escalation","mitre":"T1098","event_ids":[4728,4732,4756],"logic":"priv_group_membership"},
    {"id":"JIG-027","name":"Explicit Credential Use","description":"EID 4648 logon with explicit credentials, useful for lateral movement pivots.","severity":"MEDIUM","category":"Lateral Movement","mitre":"T1078","event_ids":[4648],"logic":"explicit_credentials"},
    {"id":"JIG-028","name":"Special Privileges Assigned to New Logon","description":"EID 4672 for non-machine/non-system identities.","severity":"MEDIUM","category":"Privilege Use","mitre":"T1078","event_ids":[4672],"logic":"special_privs_non_system"},
    {"id":"JIG-029","name":"Kerberoasting Candidate","description":"Kerberos service ticket with RC4/DES-like encryption or service-account pattern.","severity":"HIGH","category":"Credential Access","mitre":"T1558.003","event_ids":[4769],"logic":"kerberoast_candidate"},
    {"id":"JIG-030","name":"DCSync / Directory Replication Rights Access","description":"Directory Service 4662 with replication GUIDs or replication-rights strings.","severity":"CRITICAL","category":"Credential Access","mitre":"T1003.006","event_ids":[4662],"logic":"dcsync_candidate"},
    {"id":"JIG-031","name":"Directory Object / GPO Modified","description":"Directory Service modifications that often matter during AD compromise hunts.","severity":"MEDIUM","category":"Active Directory Change","mitre":"T1098","event_ids":[5136,5137,5141,4739],"logic":"ad_object_change"},
    {"id":"JIG-032","name":"Failed Logon Password Spray / Brute Force Cluster","description":"Aggregate EID 4625 failures by source IP/workstation/user.","severity":"HIGH","category":"Credential Access","mitre":"T1110","event_ids":[4625],"logic":"failed_logon_cluster"},
    {"id":"JIG-033","name":"Suspicious PowerShell / Script Content","description":"Suspicious PowerShell content in 4103/4104 or process command line.","severity":"HIGH","category":"Execution","mitre":"T1059.001","event_ids":[4103,4104,4688,1,0],"logic":"powershell_deep"},
    {"id":"JIG-034","name":"DNS / LDAP / AD Recon Keyword Hit","description":"Reconnaissance strings in DNS, PowerShell, command, or text logs.","severity":"MEDIUM","category":"Discovery","mitre":"T1087","event_ids":[0,1,22,4688,4104],"logic":"ad_recon_keywords"},
]
_seen_v3 = {r.get("id") for r in JIGSAW_RULES}
for _r in _V3_RULES:
    if _r["id"] not in _seen_v3:
        JIGSAW_RULES.append(_r)
        _seen_v3.add(_r["id"])

_prev_v3_match_rule = JigsawEngine._match_rule

def _v3_field(ev, *names):
    for n in names:
        v = _jigsaw_get_field(ev, n) if '_jigsaw_get_field' in globals() else ev.get(n)
        if v not in (None, ""):
            return str(v)
    return ""

def _v3_blob(ev):
    try:
        return ev.get("Message", "") + " " + " ".join(str(v) for k, v in ev.items() if not str(k).startswith("_") and v)
    except Exception:
        return str(ev)

def _v3_match_rule(self, rule, ev, ip_filter, ntlm_src):
    logic = rule.get("logic", "")
    blob_raw = _v3_blob(ev)
    blob = blob_raw.lower()
    eid = int(ev.get("EventID") or 0)

    if logic == "identity_account_created":
        user = _v3_field(ev, "TargetUserName", "NewAccountName", "AccountName", "param1")
        actor = _v3_field(ev, "SubjectUserName", "User", "param2")
        return self._hit(rule, ev, f"Account created: {user or '<unknown>'} by {actor or '<unknown>'}")

    if logic == "priv_group_membership":
        member = _v3_field(ev, "MemberName", "TargetUserName", "AccountName", "param1")
        group = _v3_field(ev, "TargetUserName", "GroupName", "param2")
        privileged = ["admin", "domain admins", "enterprise admins", "schema admins", "account operators", "backup operators", "remote desktop", "dnsadmins", "group policy creator"]
        sev_detail = "privileged" if any(p in blob for p in privileged) else "group"
        return self._hit(rule, ev, f"{sev_detail.title()} membership changed: member={member or '?'} group={group or '?'}")

    if logic == "explicit_credentials":
        acct = _v3_field(ev, "AccountName", "SubjectUserName", "TargetUserName")
        target = _v3_field(ev, "TargetServerName", "WorkstationName", "IpAddress", "NetworkAddress")
        proc = _v3_field(ev, "ProcessName", "Image", "NewProcessName")
        return self._hit(rule, ev, f"Explicit credentials used by {acct or '?'} toward {target or '?'} process={proc or '?'}", process=proc)

    if logic == "special_privs_non_system":
        user = _v3_field(ev, "SubjectUserName", "TargetUserName", "AccountName", "User")
        if user and (user.endswith("$") or user.lower() in ("system", "local service", "network service", "anonymous logon")):
            return None
        return self._hit(rule, ev, f"Special privileges assigned to logon: {user or '<unknown>'}")

    if logic == "kerberoast_candidate":
        svc = _v3_field(ev, "ServiceName", "TargetUserName", "param1")
        enc = _v3_field(ev, "TicketEncryptionType", "Ticket Encryption Type")
        if "krbtgt" in svc.lower():
            return None
        if any(x in (enc or "").lower() for x in ("0x17", "0x3", "rc4", "des")) or (svc and not svc.endswith("$")):
            ip = _v3_field(ev, "IpAddress", "ClientAddress", "WorkstationName")
            return self._hit(rule, ev, f"Kerberoast candidate: service={svc or '?'} encryption={enc or '?'} source={ip or '?'}")
        return None

    if logic == "dcsync_candidate":
        keys = ["1131f6aa", "1131f6ad", "89e95b76", "replicating directory changes", "replication-get-changes", "dcsync"]
        if any(k in blob for k in keys):
            actor = _v3_field(ev, "SubjectUserName", "AccountName", "User")
            obj = _v3_field(ev, "ObjectName", "ObjectDN", "TargetUserName")
            return self._hit(rule, ev, f"Directory replication rights access: actor={actor or '?'} object={obj or '?'}")
        return None

    if logic == "ad_object_change":
        obj = _v3_field(ev, "ObjectDN", "ObjectName", "TargetUserName", "param1")
        attr = _v3_field(ev, "AttributeLDAPDisplayName", "AttributeName", "param2")
        important = ["admincount", "serviceprincipalname", "gplink", "msds-allowedtodelegateto", "useraccountcontrol", "member", "ntsecuritydescriptor"]
        if eid in (5136, 5137, 5141, 4739) or any(x in blob for x in important):
            return self._hit(rule, ev, f"AD object changed: object={obj or '?'} attribute={attr or '?'}")
        return None

    if logic == "failed_logon_cluster":
        # Per-event tagging is intentionally LOW noise: aggregate result is added by _v3_apply_rules.
        return None

    if logic == "powershell_deep":
        kws = ["encodedcommand", "-enc ", "frombase64string", "downloadstring", "invoke-expression", "iex", "amsi", "bypass", "mimikatz", "powercat", "rubeus", "sharp", "reflection.assembly", "add-type", "webclient"]
        if any(k in blob for k in kws):
            return self._hit(rule, ev, "Suspicious PowerShell/script content: " + self._short_blob(ev), process=_v3_field(ev, "Image", "NewProcessName"))
        return None

    if logic == "ad_recon_keywords":
        kws = ["nltest", "net group", "domain admins", "enterprise admins", "dsquery", "ldapsearch", "bloodhound", "sharphound", "adfind", "setspn -q", "whoami /groups", "dnsadmins"]
        if any(k in blob for k in kws):
            return self._hit(rule, ev, "AD/DNS reconnaissance keyword: " + self._short_blob(ev), process=_v3_field(ev, "Image", "NewProcessName"))
        return None

    return _prev_v3_match_rule(self, rule, ev, ip_filter, ntlm_src)

JigsawEngine._match_rule = _v3_match_rule

_prev_v3_apply_rules = JigsawEngine._apply_rules

def _v3_apply_rules(self, events, rules_enabled, ip_filter):
    hits = _prev_v3_apply_rules(self, events, rules_enabled, ip_filter)
    if "JIG-032" in rules_enabled:
        by_src = defaultdict(list)
        by_user = defaultdict(list)
        for ev in events:
            try:
                if int(ev.get("EventID") or 0) != 4625:
                    continue
            except Exception:
                continue
            src = _v3_field(ev, "IpAddress", "SourceNetworkAddress", "WorkstationName") or "unknown-source"
            user = _v3_field(ev, "TargetUserName", "AccountName") or "unknown-user"
            by_src[src].append(ev)
            by_user[user].append(ev)
        rule = next((r for r in JIGSAW_RULES if r.get("id") == "JIG-032"), None)
        if rule:
            for src, evs in by_src.items():
                if src and src != "-" and len(evs) >= 5:
                    hits.append(self._hit(rule, evs[-1], f"Failed logon cluster from {src}: {len(evs)} failures"))
            for user, evs in by_user.items():
                if user and user != "-" and len(evs) >= 8:
                    hits.append(self._hit(rule, evs[-1], f"Failed logon cluster against user {user}: {len(evs)} failures"))
    return hits

JigsawEngine._apply_rules = _v3_apply_rules

_prev_v3_run_hunt = JigsawApp._run_hunt

def _v3_run_hunt(self):
    if self._running:
        return
    if not self._log_paths:
        messagebox.showwarning("No files", "Add EVTX files or directories first.")
        return
    self._running = True
    self._run_btn.configure(state=tk.DISABLED)
    self._status_var.set("Hunting…")
    self._clr(self._dash_log)
    self._clr(self._hunt_log)
    if hasattr(self, "_hunt_live_box"):
        self._clr(self._hunt_live_box)
    self._clear_results()

    raw_filters = self._build_filters()
    filters = {}
    for k, v in (raw_filters or {}).items():
        if k == "event_ids":
            filters[k] = v
        else:
            cv = _jigsaw_clean_value_v3(v)
            if cv:
                filters[k] = cv
    rules_enabled = {rid for rid, en in self._rule_states.items() if en}
    ip = _jigsaw_clean_value_v3(getattr(self, "_ip_var", tk.StringVar()).get())
    date_from = self._parse_date(self._date_from_var.get())
    date_to = self._parse_date(self._date_to_var.get())

    path_text = "; ".join(self._log_paths)
    self._live_path_var.set("Hunting path: " + path_text)
    self._live_file_var.set("Current artefact: starting parser engine")
    self._live_count_var.set("Raw:0 | Normalized:0 | Visible:0 | Hits:0")
    self._live_attack_var.set("Detection-first mode: rules hunt all parsed events; filters only narrow when deliberately set")
    active = _jigsaw_active_filter_text(filters, ip, date_from, date_to)
    start_msg = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Hunt started - {len(self._log_paths)} source(s) | {len(rules_enabled)} rules | filters: {active}\nHunting path(s): {path_text}\n"
    self._wlog(self._hunt_log, "info", start_msg)
    self._wlog(self._dash_log, "info", "[*] Hunt started...\n")
    self._wlog(self._dash_log, "info", f"[*] Hunting path(s): {path_text}\n")
    if hasattr(self, "_hunt_live_box"):
        self._wlog(self._hunt_live_box, "info", "[*] Hunt started...\n")
        self._wlog(self._hunt_live_box, "info", f"[*] Hunting path(s): {path_text}\n")
    threading.Thread(target=self._hunt_worker, args=(filters, rules_enabled, ip, date_from, date_to), daemon=True).start()

JigsawApp._run_hunt = _v3_run_hunt

# Make parser diagnostics say DETECTION FIRST instead of blaming rules when no
# display filter is active.
_prev_v3_parse_files = JigsawEngine.parse_files

def _v3_parse_files(self, paths, filters, rules_enabled, ip_filter="", date_from=None, date_to=None):
    events, hits, stats = _prev_v3_parse_files(self, paths, filters, rules_enabled, ip_filter, date_from, date_to)
    try:
        stats["hunter_mode"] = "detection-first"
        stats["rules_loaded"] = len(JIGSAW_RULES)
        if not hits and events:
            self.log_cb("[i] Heavy hunter ran all enabled rules. Parsed events are available even when no IOC/rule hits fire.", "info")
        if hits:
            self.log_cb(f"[+] Heavy hunter produced {len(hits):,} detection lead(s). Open DETECTIONS and TIMELINE.", "success")
    except Exception:
        pass
    return events, hits, stats

JigsawEngine.parse_files = _v3_parse_files

# Clear filters helper is available before mainloop starts.
def _jigsaw_clear_hunt_filters(self):
    for attr in ("_eid_var", "_kw_var", "_rx_var", "_ip_var", "_guid_var", "_date_from_var", "_date_to_var"):
        try:
            getattr(self, attr).set("")
        except Exception:
            pass
    try:
        self._live_attack_var.set("DETECTION FIRST / SHOW ALL mode: filters cleared")
    except Exception:
        pass

JigsawApp._clear_hunt_filters = _jigsaw_clear_hunt_filters

# Active sidebar button for v2.2; installed before mainloop.
_prev_v3_build_sidebar = getattr(JigsawApp, "_build_sidebar", None)
if _prev_v3_build_sidebar:
    def _v3_build_sidebar(self, parent=None):
        if parent is None:
            parent = getattr(self, "_sidebar", None)
        try:
            result = _prev_v3_build_sidebar(self)
        except TypeError:
            result = _prev_v3_build_sidebar(self, parent)
        try:
            self._btn(parent, "DETECTION FIRST / CLEAR FILTERS", self._clear_hunt_filters).pack(fill=tk.X, padx=10, pady=(6, 10))
        except Exception:
            pass
        return result
    JigsawApp._build_sidebar = _v3_build_sidebar


# Load Jigsaw V4 patch before GUI startup.
try:
    import jigsaw_v4_patch as _jigsaw_v4_patch
    _jigsaw_v4_patch.install(globals())
except Exception as _e:
    print(f"[Jigsaw V4] patch install failed: {_e}")

# Performance patch must install after V4 and before GUI startup.
try:
    import jigsaw_perf_patch as _jigsaw_perf_patch
    _jigsaw_perf_patch.install(globals())
except Exception as _e:
    print(f"[Jigsaw PERF] patch install failed: {_e}")


# ═══════════════════════════════════════════════════════════════════════════════
# V5 PowerShell Bridge Patch — integrated artefact selection + Run/Ingest
# ═══════════════════════════════════════════════════════════════════════════════

def _v5_ps_quote(path):
    return "'" + str(path).replace("'", "''") + "'"

def _v5_collect_loaded_evtx(self, limit=5000):
    paths = []
    for src in getattr(self, "_log_paths", []):
        try:
            if os.path.isdir(src):
                for root, _, files in os.walk(src):
                    for fn in files:
                        if fn.lower().endswith((".evtx", ".evt")):
                            paths.append(os.path.join(root, fn))
                            if len(paths) >= limit:
                                return paths
            elif os.path.isfile(src) and src.lower().endswith((".evtx", ".evt")):
                paths.append(src)
        except Exception:
            continue
    return paths

def _v5_ps_set_paths(self, paths, label=None, add_to_gui=False):
    clean, seen = [], set()
    for p in paths or []:
        if not p:
            continue
        ap = os.path.abspath(str(p))
        if ap.lower() in seen:
            continue
        seen.add(ap.lower()); clean.append(ap)
    self._ps_paths = clean
    if add_to_gui:
        for p in clean:
            if p not in self._log_paths:
                self._log_paths.append(p)
                try: self._file_listbox.insert(tk.END, os.path.basename(p))
                except Exception: pass
    msg = f"{len(clean)} target EVTX/EVT artefact(s) selected"
    if label: msg += f" from {label}"
    try: self._ps_target_var.set(msg)
    except Exception: pass
    preview = "\n".join("  - " + p for p in clean[:20])
    if len(clean) > 20: preview += f"\n  ... plus {len(clean)-20} more"
    try: self._ps_append(f"[V5] {msg}\n{preview}\n", "success")
    except Exception: pass
    return clean

def _v5_ps_prefix(self):
    paths = getattr(self, "_ps_paths", None) or _v5_collect_loaded_evtx(self)
    if not paths:
        return "$JIGSAW_PATHS=@(); $JIGSAW_FIRST=$null; "
    arr = ",".join(_v5_ps_quote(p) for p in paths)
    return f"$JIGSAW_PATHS=@({arr}); $JIGSAW_FIRST=$JIGSAW_PATHS[0]; "

def _v5_ps_append(self, txt, tag="raw"):
    def _do():
        try: self._wlog(self._ps_output, tag, txt)
        except Exception: pass
    try: self.after(0, _do)
    except Exception: pass

def _v5_use_loaded_evtx(self):
    paths = _v5_collect_loaded_evtx(self)
    if not paths:
        messagebox.showwarning("PowerShell Bridge", "No EVTX/EVT artefacts are loaded in the left panel yet. Add files or a folder first, or use Browse File/Folder here.")
        return
    _v5_ps_set_paths(self, paths, "loaded artefacts")

def _v5_ps_browse_files(self):
    paths = filedialog.askopenfilenames(title="Select EVTX/EVT files for PowerShell", filetypes=[("Event Log files", "*.evtx *.evt"), ("All files", "*.*")])
    if paths: _v5_ps_set_paths(self, list(paths), "selected file(s)", add_to_gui=True)

def _v5_ps_browse_folder(self):
    d = filedialog.askdirectory(title="Select folder containing EVTX files for PowerShell")
    if not d: return
    found = []
    for root, _, files in os.walk(d):
        for fn in files:
            if fn.lower().endswith((".evtx", ".evt")):
                found.append(os.path.join(root, fn))
    _v5_ps_set_paths(self, found, d, add_to_gui=False)
    if d not in self._log_paths:
        self._log_paths.append(d)
        try: self._file_listbox.insert(tk.END, f"[DIR] {os.path.basename(d)}")
        except Exception: pass

def _v5_load_ps_template(self, cmd):
    self._ps_cmd_var.set(cmd)

def _v5_ps_templates():
    sel = "Select-Object TimeCreated,Id,ProviderName,LogName,MachineName,Message"
    return [
        ("Loaded Paths", "$JIGSAW_PATHS | ForEach-Object { Write-Host $_ }"),
        ("Show First 50", f"foreach($f in $JIGSAW_PATHS) {{ Get-WinEvent -Path $f -MaxEvents 50 | {sel} }}"),
        ("EID 4625 Failed", f"foreach($f in $JIGSAW_PATHS) {{ Get-WinEvent -FilterHashtable @{{Path=$f; Id=4625}} -ErrorAction SilentlyContinue | {sel} }}"),
        ("EID 4624 Logon", f"foreach($f in $JIGSAW_PATHS) {{ Get-WinEvent -FilterHashtable @{{Path=$f; Id=4624}} -ErrorAction SilentlyContinue | {sel} }}"),
        ("EID 4688 Process", f"foreach($f in $JIGSAW_PATHS) {{ Get-WinEvent -FilterHashtable @{{Path=$f; Id=4688}} -ErrorAction SilentlyContinue | {sel} }}"),
        ("Kerberos 4768/4769", f"foreach($f in $JIGSAW_PATHS) {{ Get-WinEvent -FilterHashtable @{{Path=$f; Id=4768,4769}} -ErrorAction SilentlyContinue | {sel} }}"),
        ("AD Changes", f"foreach($f in $JIGSAW_PATHS) {{ Get-WinEvent -FilterHashtable @{{Path=$f; Id=4720,4726,4732,4738,4740}} -ErrorAction SilentlyContinue | {sel} }}"),
        ("Service 7045", f"foreach($f in $JIGSAW_PATHS) {{ Get-WinEvent -FilterHashtable @{{Path=$f; Id=7045}} -ErrorAction SilentlyContinue | {sel} }}"),
        ("Sysmon Net 3", f"foreach($f in $JIGSAW_PATHS) {{ Get-WinEvent -FilterHashtable @{{Path=$f; Id=3}} -ErrorAction SilentlyContinue | {sel} }}"),
        ("Sysmon DLL 7", f"foreach($f in $JIGSAW_PATHS) {{ Get-WinEvent -FilterHashtable @{{Path=$f; Id=7}} -ErrorAction SilentlyContinue | {sel} }}"),
        ("Keyword Hunt", "foreach($f in $JIGSAW_PATHS) { Get-WinEvent -Path $f -ErrorAction SilentlyContinue | Where-Object {$_.Message -match 'mimikatz|rubeus|sharp|powershell|encodedcommand|ntds|lsass|kerberoast'} | Select-Object TimeCreated,Id,ProviderName,LogName,MachineName,Message }"),
        ("Export Security", "New-Item -ItemType Directory -Force C:\\JigsawExports | Out-Null; wevtutil epl Security C:\\JigsawExports\\Security.evtx; Write-Host 'Exported C:\\JigsawExports\\Security.evtx'"),
    ]

def _v5_build_tab_powershell(self):
    tab = tk.Frame(self.nb, bg=BG); self.nb.add(tab, text="  POWERSHELL CONSOLE  ")
    top = tk.Frame(tab, bg=BG); top.pack(fill=tk.X, padx=16, pady=(10,4))
    tk.Label(top, text="V5 PowerShell Bridge: target loaded EVTX artefacts, browse files/folders, run live queries, or ingest output back into Jigsaw detections.", font=("Consolas",9), fg=TEXT_DIM, bg=BG).pack(anchor="w")
    tk.Label(top, text="Templates use $JIGSAW_PATHS automatically. RUN shows output; RUN + INGEST converts Get-WinEvent objects into Jigsaw events/detections.", font=("Consolas",8), fg=ACCENT2, bg=BG).pack(anchor="w", pady=(3,0))
    target_frame = tk.Frame(tab, bg=PANEL2); target_frame.pack(fill=tk.X, padx=12, pady=(6,6))
    self._ps_paths = []; self._ps_target_var = tk.StringVar(value="No PowerShell targets selected. Use Loaded EVTX or Browse File/Folder.")
    self._btn(target_frame, "USE LOADED EVTX", self._ps_use_loaded_evtx, accent=True, small=True).pack(side=tk.LEFT, padx=(8,4), pady=6)
    self._btn(target_frame, "BROWSE FILE", self._ps_browse_files, small=True).pack(side=tk.LEFT, padx=4, pady=6)
    self._btn(target_frame, "BROWSE FOLDER", self._ps_browse_folder, small=True).pack(side=tk.LEFT, padx=4, pady=6)
    tk.Label(target_frame, textvariable=self._ps_target_var, font=("Consolas",8), fg=TEXT_MID, bg=PANEL2).pack(side=tk.LEFT, padx=10)
    tpl_frame = tk.Frame(tab, bg=BG); tpl_frame.pack(fill=tk.X, padx=12, pady=(0,6))
    for lbl, cmd in _v5_ps_templates():
        self._btn(tpl_frame, lbl, lambda c=cmd: self._load_ps_template(c), small=True).pack(side=tk.LEFT, padx=(0,4), pady=(0,4))
    cmd_frame = tk.Frame(tab, bg=PANEL2); cmd_frame.pack(fill=tk.X, padx=12, pady=(0,4))
    tk.Label(cmd_frame, text="PS>", font=("Consolas",10,"bold"), fg=SUCCESS, bg=PANEL2).pack(side=tk.LEFT, padx=(8,4), pady=4)
    self._ps_cmd_var = tk.StringVar()
    ps_entry = tk.Entry(cmd_frame, textvariable=self._ps_cmd_var, font=("Consolas",9), bg="#0a0e14", fg=TEXT, insertbackground=ACCENT, relief="flat", highlightthickness=1, highlightbackground=BORDER, bd=0)
    ps_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5); ps_entry.bind("<Return>", lambda e: self._run_ps_command())
    self._btn(cmd_frame, "RUN", self._run_ps_command, accent=True).pack(side=tk.LEFT, padx=(6,4))
    self._btn(cmd_frame, "RUN + INGEST", self._run_ps_ingest, accent=True).pack(side=tk.LEFT, padx=(0,4))
    self._btn(cmd_frame, "CLR", lambda: self._clr(self._ps_output), small=True).pack(side=tk.LEFT, padx=(0,8))
    out_frame = self._panel(tab, "POWERSHELL OUTPUT / INGEST STATUS"); out_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0,12))
    self._ps_output = self._logbox(out_frame, height=20); self._wtag(self._ps_output)
    self._wlog(self._ps_output, "dim", "[V5] PowerShell Bridge ready. Click USE LOADED EVTX or BROWSE FOLDER, select a template, then RUN or RUN + INGEST.\n\n")

def _v5_run_ps_command(self):
    cmd = self._ps_cmd_var.get().strip()
    if not cmd: return
    if not getattr(self, "_ps_paths", None):
        paths = _v5_collect_loaded_evtx(self)
        if paths: _v5_ps_set_paths(self, paths, "loaded artefacts")
    full_cmd = _v5_ps_prefix(self) + cmd
    self._ps_append(f"\nPS> {cmd}\n", "info"); self._ps_cmd_var.set("")
    threading.Thread(target=self._ps_worker, args=(full_cmd, False), daemon=True).start()

def _v5_run_ps_ingest(self):
    cmd = self._ps_cmd_var.get().strip()
    if not cmd: return
    if not getattr(self, "_ps_paths", None):
        paths = _v5_collect_loaded_evtx(self)
        if paths: _v5_ps_set_paths(self, paths, "loaded artefacts")
    wrapped = _v5_ps_prefix(self) + "$ErrorActionPreference='SilentlyContinue'; $jigsaw_result = @(& { " + cmd + " }); $jigsaw_result | Select-Object TimeCreated,Id,ProviderName,LogName,MachineName,Message | ConvertTo-Json -Depth 5"
    self._ps_append(f"\nPS+INGEST> {cmd}\n", "info"); self._ps_cmd_var.set("")
    threading.Thread(target=self._ps_worker, args=(wrapped, True), daemon=True).start()

def _v5_ps_worker(self, cmd, ingest=False):
    try:
        result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", cmd], **_quiet_subprocess_kwargs(text=True, timeout=180))
        out, err = result.stdout or "", result.stderr or ""
        if ingest:
            self._ps_ingest_stdout(out, err)
        else:
            if out: self._ps_append(out + ("" if out.endswith("\n") else "\n"), "raw")
            if err: self._ps_append(f"[STDERR] {err}\n", "alert")
            if result.returncode not in (0, None): self._ps_append(f"[EXIT] PowerShell returned code {result.returncode}\n", "warn")
    except subprocess.TimeoutExpired:
        self._ps_append("[TIMEOUT] Command took too long. Narrow the query with -MaxEvents, Event IDs, or date range.\n", "alert")
    except Exception as e:
        self._ps_append(f"[ERROR] {e}\n", "alert")

def _v5_ps_ingest_stdout(self, out, err=""):
    if err: self._ps_append(f"[STDERR] {err}\n", "alert")
    try:
        text = (out or "").strip()
        if not text:
            self._ps_append("[INGEST] No JSON objects returned. Try a Get-WinEvent template or reduce formatting commands such as Format-List.\n", "warn"); return
        data = json.loads(text)
        rows = [data] if isinstance(data, dict) else [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []
        events = []
        for r in rows:
            try:
                ev = self._engine._normalise_external_event(r, "PowerShellBridge", "powershell")
                if r.get("Id") and not ev.get("EventID"): ev["EventID"] = int(r.get("Id"))
                ev.setdefault("SourceFile", "PowerShellBridge")
                events.append(ev)
            except Exception: continue
        if not events:
            self._ps_append("[INGEST] PowerShell returned data, but no event-like objects could be normalized. Use a Get-WinEvent template.\n", "warn"); return
        rules_enabled = {rid for rid, en in getattr(self, "_rule_states", {}).items() if en} or {r.get("id") for r in JIGSAW_RULES}
        new_hits = self._engine._apply_rules(events, rules_enabled, "")
        def _apply():
            try:
                self._events.extend(events); self._hits.extend(new_hits); self._stats = self._engine._build_stats(self._events, self._hits); self._populate_results()
                self._ps_append(f"[INGEST] Added {len(events)} event(s) and {len(new_hits)} detection hit(s) to Jigsaw. Check Detections, All Events, Timeline, and Correlation.\n", "success")
            except Exception as e: self._ps_append(f"[INGEST ERROR] {e}\n", "alert")
        self.after(0, _apply)
    except Exception as e:
        sample = (out or "")[:1000]
        self._ps_append(f"[INGEST ERROR] Could not parse PowerShell JSON: {e}\nFirst output bytes:\n{sample}\n", "alert")

JigsawApp._ps_append = _v5_ps_append
JigsawApp._ps_use_loaded_evtx = _v5_use_loaded_evtx
JigsawApp._ps_browse_files = _v5_ps_browse_files
JigsawApp._ps_browse_folder = _v5_ps_browse_folder
JigsawApp._load_ps_template = _v5_load_ps_template
JigsawApp._build_tab_powershell = _v5_build_tab_powershell
JigsawApp._run_ps_command = _v5_run_ps_command
JigsawApp._run_ps_ingest = _v5_run_ps_ingest
JigsawApp._ps_worker = _v5_ps_worker
JigsawApp._ps_ingest_stdout = _v5_ps_ingest_stdout


# ═══════════════════════════════════════════════════════════════════════════════
# HOTFIX 2026-04-28 — placeholder filters, Show All safety, EVTX empty-channel UX
# ═══════════════════════════════════════════════════════════════════════════════

_JIGSAW_PLACEHOLDER_VALUES = {
    "e.g. 192.168.1.100",
    "e.g. 192.168.1.100 ",
    "2024-01-01 00:00:00",
    "2024-12-31 23:59:59",
    "yyyy-mm-dd hh:mm:ss",
}

def _jigsaw_clean_gui_value(value):
    s = str(value or "").strip()
    if not s:
        return ""
    low = s.lower().strip()
    if low in _JIGSAW_PLACEHOLDER_VALUES or low.startswith("e.g.") or low.startswith("eg "):
        return ""
    if "your-" in low or "example" in low:
        return ""
    return s

# Make the engine defensively ignore placeholder/example values even if Tk's
# textvariable captured the placeholder text before FocusOut cleared it.
_prev_hotfix_compile_filters = JigsawEngine._compile_filters

def _hotfix_compile_filters(self, filters, ip_filter, date_from, date_to):
    clean = {}
    for k, v in (filters or {}).items():
        if k == "event_ids":
            clean[k] = v
        else:
            cv = _jigsaw_clean_gui_value(v)
            if cv:
                clean[k] = cv
    clean_ip = _jigsaw_clean_gui_value(ip_filter)
    return _prev_hotfix_compile_filters(self, clean, clean_ip, date_from, date_to)

JigsawEngine._compile_filters = _hotfix_compile_filters

# Also fix the status line so placeholder text is not reported as an active
# filter. This is the exact reason the user's run showed:
#   Active filters: ip=e.g. 192.168.1.100
# and then every parsed event had visible=0.
def _jigsaw_active_filter_text(filters, ip_filter, date_from, date_to):
    active = []
    if (filters or {}).get("event_ids"):
        active.append("EventID=" + ",".join(str(x) for x in (filters or {}).get("event_ids", [])))
    for key, label in (("keyword", "keyword"), ("regex", "regex"), ("process_guid", "ProcessGuid")):
        val = _jigsaw_clean_gui_value((filters or {}).get(key, ""))
        if val:
            active.append(label + "=" + val)
    ip = _jigsaw_clean_gui_value(ip_filter)
    if ip:
        active.append("ip=" + ip)
    if date_from:
        active.append("from=" + str(date_from))
    if date_to:
        active.append("to=" + str(date_to))
    return active or ["none — SHOW ALL parsed events"]

# Patch the GUI hunt launcher so it passes a sanitized ip_filter into parse_files.
_prev_hotfix_run_hunt = JigsawApp._run_hunt

def _hotfix_run_hunt(self):
    if self._running:
        return
    if not self._log_paths:
        messagebox.showwarning("No files", "Add EVTX files or directories first.")
        return

    self._running = True
    self._run_btn.configure(state=tk.DISABLED)
    self._status_var.set("Hunting…")
    self._clr(self._dash_log)
    self._clr(self._hunt_log)
    if hasattr(self, "_hunt_live_box"):
        self._clr(self._hunt_live_box)
    self._clear_results()

    filters = self._build_filters()
    # Remove any placeholder/example values that made it through Tk variables.
    filters = {k: v for k, v in filters.items() if k == "event_ids" or _jigsaw_clean_gui_value(v)}
    rules_enabled = {rid for rid, en in self._rule_states.items() if en}
    ip = _jigsaw_clean_gui_value(getattr(self, "_ip_var", tk.StringVar()).get())
    date_from = self._parse_date(self._date_from_var.get())
    date_to = self._parse_date(self._date_to_var.get())

    path_text = "; ".join(self._log_paths)
    self._live_path_var.set("Hunting path: " + path_text)
    self._live_file_var.set("Current artefact: starting parser engine")
    self._live_count_var.set("Parsed events: 0 | Files processed: 0 | Hits: 0")
    if filters or ip or date_from or date_to:
        self._live_attack_var.set("Filters active: " + "; ".join(_jigsaw_active_filter_text(filters, ip, date_from, date_to)))
    else:
        self._live_attack_var.set("SHOW ALL mode: no event/IP/keyword/date filters are active")

    self._wlog(self._hunt_log, "info", f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Hunt started - {len(self._log_paths)} source(s) | {len(rules_enabled)} rules | filters: {_jigsaw_active_filter_text(filters, ip, date_from, date_to)}\nHunting path(s): {path_text}\n")
    self._wlog(self._dash_log, "info", "[*] Hunt started...\n")
    self._wlog(self._dash_log, "info", f"[*] Hunting path(s): {path_text}\n")
    if hasattr(self, "_hunt_live_box"):
        self._wlog(self._hunt_live_box, "info", "[*] Hunt started...\n")
        self._wlog(self._hunt_live_box, "info", f"[*] Hunting path(s): {path_text}\n")

    threading.Thread(target=self._hunt_worker, args=(filters, rules_enabled, ip, date_from, date_to), daemon=True).start()

JigsawApp._run_hunt = _hotfix_run_hunt

# Make empty EVTX files/channels non-fatal in the dashboard while preserving real
# parser failures. Many Windows channels legitimately contain zero records in a
# KAPE collection; they should not make the user think parsing is broken.
_prev_hotfix_parse_evtx_file = JigsawEngine._parse_evtx_file

def _hotfix_parse_evtx_file(self, path, cf):
    try:
        return _prev_hotfix_parse_evtx_file(self, path, cf)
    except Exception as e:
        msg = str(e or "")
        if "returned no XML records" in msg or "no XML records returned" in msg:
            _jigsaw_set_diag(self, path, "empty/no-records", 0, 0, 0, "empty", msg)
            return []
        raise

JigsawEngine._parse_evtx_file = _hotfix_parse_evtx_file

# Add a sidebar button when possible so users can deliberately reset to Show All
# without manually clearing every field. This is intentionally best-effort.
def _jigsaw_clear_hunt_filters(self):
    for attr in ("_eid_var", "_kw_var", "_rx_var", "_ip_var", "_guid_var", "_date_from_var", "_date_to_var"):
        try:
            getattr(self, attr).set("")
        except Exception:
            pass
    try:
        self._live_attack_var.set("SHOW ALL mode: filters cleared")
    except Exception:
        pass

JigsawApp._clear_hunt_filters = _jigsaw_clear_hunt_filters

_prev_hotfix_build_sidebar = getattr(JigsawApp, "_build_sidebar", None)
if _prev_hotfix_build_sidebar:
    def _hotfix_build_sidebar(self, parent=None):
        if parent is None:
            parent = getattr(self, "_sidebar", None)
        try:
            result = _prev_hotfix_build_sidebar(self)
        except TypeError:
            result = _prev_hotfix_build_sidebar(self, parent)
        try:
            self._btn(parent, "SHOW ALL / CLEAR FILTERS", self._clear_hunt_filters).pack(fill=tk.X, padx=10, pady=(6, 10))
        except Exception:
            pass
        return result
    JigsawApp._build_sidebar = _hotfix_build_sidebar

# ═══════════════════════════════════════════════════════════════════════════════
# JIGSAW V5.1 — branding cleanup + analyst evidence pane
# ═══════════════════════════════════════════════════════════════════════════════

_JIGSAW_OLD_HIT_BUILDER = getattr(JigsawEngine, "_hit", None)

def _jigsaw_v51_hit(self, rule, ev, detail, process="", image=""):
    hit = _JIGSAW_OLD_HIT_BUILDER(self, rule, ev, detail, process, image)
    try:
        hit["source_file"] = ev.get("SourceFile") or ev.get("_src") or ev.get("Path") or ""
        hit["provider"] = ev.get("Provider") or ev.get("ProviderName") or ev.get("System.Provider.Name") or ""
        hit["log_channel"] = ev.get("Channel") or ev.get("LogName") or hit.get("channel", "")
        hit["jigsaw_reason"] = detail
        hit["jigsaw_evidence_fields"] = {
            k: ev.get(k) for k in (
                "TimeCreated", "EventID", "Provider", "ProviderName", "Channel", "LogName",
                "Computer", "MachineName", "SubjectUserName", "TargetUserName", "User", "AccountName",
                "IpAddress", "SourceNetworkAddress", "ClientAddress", "WorkstationName", "LogonType",
                "ProcessName", "Image", "NewProcessName", "CommandLine", "ProcessCommandLine",
                "ImageLoaded", "ServiceName", "ObjectName", "TicketEncryptionType", "Message"
            ) if ev.get(k) not in (None, "")
        }
        if ev.get("_raw_xml"):
            hit["raw_xml"] = ev.get("_raw_xml")[:20000]
    except Exception:
        pass
    return hit

if _JIGSAW_OLD_HIT_BUILDER:
    JigsawEngine._hit = _jigsaw_v51_hit


def _jigsaw_v51_rule_for_hit(hit):
    rid = str(hit.get("rule_id", ""))
    for rule in JIGSAW_RULES:
        if str(rule.get("id")) == rid:
            return rule
    return {}


def _jigsaw_v51_find_selected_hit(self):
    sel = self._det_tree.selection()
    if not sel:
        return None
    item = sel[0]
    vals = self._det_tree.item(item, "values") or []
    if not vals or len(vals) < 9:
        return None
    _ts, rid, sev, _cat, _mitre, eid, comp, proc, detail = vals[:9]
    detail_prefix = str(detail)[:60]

    # Prefer a durable map if another performance patch created one.
    for attr in ("_det_iid_to_hit", "_hit_iid_map", "_jigsaw_hit_iid_map"):
        m = getattr(self, attr, None)
        if isinstance(m, dict) and item in m:
            return m[item]

    # Then match the visible row against the hit list. This avoids the old bug
    # where sorted/capped display rows pointed at the wrong self._hits index.
    for h in self._hits:
        if str(h.get("rule_id", "")) != str(rid):
            continue
        if str(h.get("severity", "")) != str(sev):
            continue
        if eid and str(h.get("event_id", "")) != str(eid):
            continue
        if comp and str(h.get("computer", "")) != str(comp):
            continue
        if detail_prefix and not str(h.get("detail", "")).startswith(detail_prefix[:40]):
            continue
        return h

    # Last resort: row index against the same severity sort used in the table.
    try:
        idx = self._det_tree.index(item)
        displayed = sorted(self._hits, key=lambda x: SEV_ORDER.get(x.get("severity", ""), 9))[:2000]
        if 0 <= idx < len(displayed):
            return displayed[idx]
    except Exception:
        pass
    return None


def _jigsaw_v51_first_value(raw, keys):
    for k in keys:
        v = raw.get(k)
        if v not in (None, ""):
            return v
    return ""


def _jigsaw_v51_format_hit_evidence(hit):
    rule = _jigsaw_v51_rule_for_hit(hit)
    raw = hit.get("raw") or {}
    evfields = hit.get("jigsaw_evidence_fields") or {}
    merged = dict(raw)
    merged.update({k: v for k, v in evfields.items() if v not in (None, "")})

    important = [
        ("Time", hit.get("timestamp") or _jigsaw_v51_first_value(merged, ["TimeCreated"])),
        ("Event ID", hit.get("event_id") or _jigsaw_v51_first_value(merged, ["EventID", "Id"])),
        ("Provider", hit.get("provider") or _jigsaw_v51_first_value(merged, ["Provider", "ProviderName"])),
        ("Channel", hit.get("log_channel") or hit.get("channel") or _jigsaw_v51_first_value(merged, ["Channel", "LogName"])),
        ("Computer", hit.get("computer") or _jigsaw_v51_first_value(merged, ["Computer", "MachineName"])),
        ("Source file", hit.get("source_file") or _jigsaw_v51_first_value(merged, ["SourceFile", "Path"])),
        ("User", _jigsaw_v51_first_value(merged, ["TargetUserName", "SubjectUserName", "User", "AccountName"])),
        ("Source IP", _jigsaw_v51_first_value(merged, ["IpAddress", "SourceNetworkAddress", "ClientAddress"])),
        ("Workstation", _jigsaw_v51_first_value(merged, ["WorkstationName", "ClientName"])),
        ("Logon type", _jigsaw_v51_first_value(merged, ["LogonType"])),
        ("Process", hit.get("process") or _jigsaw_v51_first_value(merged, ["Image", "NewProcessName", "ProcessName"])),
        ("Command line", _jigsaw_v51_first_value(merged, ["CommandLine", "ProcessCommandLine"])),
        ("Image/DLL", hit.get("image") or _jigsaw_v51_first_value(merged, ["ImageLoaded", "FileName"])),
        ("Service/Object", _jigsaw_v51_first_value(merged, ["ServiceName", "ObjectName"])),
    ]

    lines = []
    lines.append("JIGSAW FINDING — ANALYST EVIDENCE")
    lines.append("=" * 72)
    lines.append(f"Rule        : {hit.get('rule_id','')} — {hit.get('rule_name','')}")
    lines.append(f"Severity    : {hit.get('severity','')}")
    lines.append(f"Category    : {hit.get('category','')}")
    if hit.get("mitre"):
        lines.append(f"Technique   : {hit.get('mitre')}")
    if rule.get("description"):
        lines.append(f"Description : {rule.get('description')}")
    lines.append("")
    lines.append("WHY JIGSAW FLAGGED THIS")
    lines.append("-" * 72)
    lines.append(str(hit.get("jigsaw_reason") or hit.get("detail") or "The event matched an enabled Jigsaw detection rule."))
    if rule.get("conditions"):
        try:
            lines.append(f"Rule logic  : {json.dumps(rule.get('conditions'), default=str)}")
        except Exception:
            pass
    lines.append("")
    lines.append("LOG EVIDENCE / ROOT CAUSE FIELDS")
    lines.append("-" * 72)
    for label, value in important:
        if value not in (None, ""):
            lines.append(f"{label:<12}: {value}")
    msg = _jigsaw_v51_first_value(merged, ["Message", "message"])
    if msg:
        lines.append("")
        lines.append("EVENT MESSAGE")
        lines.append("-" * 72)
        lines.append(str(msg)[:6000])
    lines.append("")
    lines.append("NORMALIZED EVENT JSON")
    lines.append("-" * 72)
    lines.append(json.dumps(merged, indent=2, default=str)[:12000])
    if hit.get("raw_xml"):
        lines.append("")
        lines.append("RAW XML EXCERPT")
        lines.append("-" * 72)
        lines.append(str(hit.get("raw_xml"))[:12000])
    return "\n".join(lines)


def _jigsaw_v51_show_hit_detail(self, event=None):
    hit = _jigsaw_v51_find_selected_hit(self)
    if not hit:
        return
    txt = _jigsaw_v51_format_hit_evidence(hit)
    self._det_detail.configure(state=tk.NORMAL)
    self._det_detail.delete("1.0", tk.END)
    self._det_detail.insert(tk.END, txt)
    self._det_detail.configure(state=tk.DISABLED)

JigsawApp._show_hit_detail = _jigsaw_v51_show_hit_detail

_JIGSAW_OLD_BUILD_DETECTIONS = getattr(JigsawApp, "_build_tab_detections", None)

def _jigsaw_v51_build_tab_detections(self):
    result = _JIGSAW_OLD_BUILD_DETECTIONS(self)
    try:
        self._det_tree.bind("<ButtonRelease-1>", self._show_hit_detail)
        self._det_tree.bind("<<TreeviewSelect>>", self._show_hit_detail)
        self._det_tree.bind("<Double-1>", self._show_hit_detail)
        self._det_detail.configure(height=14)
    except Exception:
        pass
    return result

if _JIGSAW_OLD_BUILD_DETECTIONS:
    JigsawApp._build_tab_detections = _jigsaw_v51_build_tab_detections


if __name__ == "__main__":
    JigsawApp().mainloop()
