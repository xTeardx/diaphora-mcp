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

# -- Tell Diaphora where to find its sibling modules --------------------------
DIAPHORA_DIR = r"D:\Programs\IDA Professional 9.3\plugins\diaphora-3.4.1"
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
