"""
Diaphora MCP — path configuration.

Resolution order (first wins):
  1. Environment variables (DIAPHORA_DIR, IDAT_PATH, DIAPHORA_PYTHON)
  2. Auto-detection (common install locations, PATH)
  3. Fallback hints for the user

Set any of these env vars to override auto-detection:
  DIAPHORA_DIR    — path to the diaphora plugin directory
  IDAT_PATH       — path to idat.exe / idat64
  DIAPHORA_PYTHON — Python interpreter to use for diff (default: sys.executable)
"""

import os
import shutil
import sys

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _which(name: str) -> str:
    """Return the full path of *name* if found on PATH, else ''."""
    found = shutil.which(name)
    return found if found else ""


def _find_on_path(*names: str) -> str:
    for name in names:
        p = _which(name)
        if p:
            return p
    return ""


def _find_idat() -> str:
    """Try to locate idat.exe / idat64 on this machine."""
    # 1) Environment variable
    v = _env("IDAT_PATH")
    if v and os.path.isfile(v):
        return v

    # 2) On PATH
    p = _find_on_path("idat64.exe", "idat.exe", "idat64", "idat")
    if p:
        return p

    # 3) Common install locations
    candidates = [
        os.path.expandvars(R"%ProgramFiles%\IDA Pro 9.3\idat.exe"),
        os.path.expandvars(R"%ProgramFiles%\IDA Pro 9.2\idat.exe"),
        os.path.expandvars(R"%ProgramFiles%\IDA Pro 9.1\idat.exe"),
        os.path.expandvars(R"%ProgramFiles%\IDA Pro 9.0\idat.exe"),
        os.path.expandvars(R"%ProgramFiles(x86)%\IDA Pro 9.3\idat.exe"),
        os.path.expandvars(R"%ProgramFiles(x86)%\IDA Pro 9.2\idat.exe"),
        os.path.expandvars(R"%ProgramFiles%\IDA 9.3\idat.exe"),
        os.path.expandvars(R"%ProgramFiles%\IDA 8.4\idat.exe"),
        os.path.expandvars(R"%LOCALAPPDATA%\Programs\IDA\idat.exe"),
        # Custom / portable installs
        R"D:\Programs\IDA Professional 9.3\idat.exe",
        R"D:\Programs\IDA 9.3\idat.exe",
        R"D:\tools\IDA Pro 9.3\idat.exe",
        R"D:\ida\idat64.exe",
        # Linux / macOS
        "/opt/idapro-9.3/idat64",
        "/opt/idapro-9.2/idat64",
        "/opt/idapro-9.0/idat64",
        "/usr/local/bin/idat64",
        os.path.expanduser("~/ida/idat64"),
        os.path.expanduser("~/IDA/idat64"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c

    return ""


def _find_diaphora() -> str:
    """Try to locate the Diaphora plugin directory."""
    v = _env("DIAPHORA_DIR")
    if v and os.path.isdir(v):
        return v

    idat = IDAT_PATH  # resolved above
    if idat:
        ida_dir = os.path.dirname(idat)  # e.g. D:\Programs\IDA Professional 9.3
        plugins = os.path.join(ida_dir, "plugins")
        if os.path.isdir(plugins):
            for entry in sorted(os.listdir(plugins), reverse=True):
                full = os.path.join(plugins, entry)
                if os.path.isdir(full) and "diaphora" in entry.lower():
                    if os.path.isfile(os.path.join(full, "diaphora.py")):
                        return full

    # Last-resort glob under common IDA roots
    roots = [
        os.path.expandvars(R"%ProgramFiles%\IDA Pro 9.3"),
        os.path.expandvars(R"%ProgramFiles%\IDA Pro 9.2"),
        os.path.expandvars(R"%ProgramFiles%\IDA Pro 9.1"),
        R"D:\Programs\IDA Professional 9.3",
        R"D:\Programs\IDA 9.3",
        R"D:\tools\IDA Pro 9.3",
        R"D:\ida",
        "/opt/idapro-9.3",
        "/opt/idapro-9.2",
        os.path.expanduser("~/ida"),
        os.path.expanduser("~/IDA"),
    ]
    for root in roots:
        plugins = os.path.join(root, "plugins")
        if not os.path.isdir(plugins):
            continue
        try:
            for entry in sorted(os.listdir(plugins), reverse=True):
                if "diaphora" in entry.lower():
                    full = os.path.join(plugins, entry)
                    if os.path.isfile(os.path.join(full, "diaphora.py")):
                        return full
        except (PermissionError, FileNotFoundError):
            continue

    return ""


# ---------------------------------------------------------------------------
# Resolved paths  (evaluated once at import time)
# ---------------------------------------------------------------------------
IDAT_PATH = _find_idat()
DIAPHORA_DIR = _find_diaphora()
DIAPHORA_SCRIPT = os.path.join(DIAPHORA_DIR, "diaphora.py") if DIAPHORA_DIR else ""
HEADLESS_WRAPPER = os.path.join(_PROJECT_ROOT, "_diaphora_headless.py")
PYTHON = _env("DIAPHORA_PYTHON", sys.executable)
