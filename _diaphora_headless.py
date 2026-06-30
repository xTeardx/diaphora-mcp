"""
Thin wrapper for headless Diaphora export via IDA.

Invoked by idat.exe  -A -S this_script.py binary.i64

Uses the built-in Diaphora environment-variable mechanism (DIAPHORA_AUTO,
DIAPHORA_EXPORT_FILE, DIAPHORA_USE_DECOMPILER) to trigger export without any
GUI interaction.

After export completes, forces IDA to exit via idaapi.qexit() — otherwise
idat.exe hangs indefinitely after the script finishes (see Problems.md #11).
"""

import os
import sys

sys.setrecursionlimit(100000)

# -- Tell Diaphora where to find its sibling modules --------------------------
# Diaphora MCP core sets cwd to DIAPHORA_DIR when launching idat.exe.
# We can also check the environment variable DIAPHORA_DIR or fallback to cwd.
DIAPHORA_DIR = os.environ.get("DIAPHORA_DIR") or os.getcwd()
if not os.path.isfile(os.path.join(DIAPHORA_DIR, "diaphora.py")):
    # Generic fallback if not running in the correct cwd or environment
    DIAPHORA_DIR = r"C:\Path\To\IDA\plugins\diaphora-3.4.1"

sys.path.insert(0, DIAPHORA_DIR)
os.chdir(DIAPHORA_DIR)

# -- Run export, then force-exit IDA -----------------------------------------
import diaphora_ida  # noqa: E402

try:
    diaphora_ida.main()
except Exception:
    pass  # Export may have partially failed; still need to exit
finally:
    try:
        import idaapi
        idaapi.qexit(0)  # Force IDA to shut down cleanly
    except ImportError:
        pass  # Not running inside IDA (should not happen in normal use)
    sys.exit(0)
