"""
Thin wrapper for headless Diaphora export via IDA.

Invoked by idat.exe  -A -S this_script.py binary.i64

Uses the built-in Diaphora environment-variable mechanism (DIAPHORA_AUTO,
DIAPHORA_EXPORT_FILE, DIAPHORA_USE_DECOMPILER) to trigger export without any
GUI interaction.

Why a wrapper instead of pointing -S directly at diaphora_ida.py?
  The Diaphora installation path contains spaces ("IDA Professional 9.3/…"),
  which some IDA versions handle poorly on the -S argument.  This file lives
  in the project directory (no spaces) and simply delegates to main().
"""

import os
import sys

# -- Tell Diaphora where to find its sibling modules --------------------------
DIAPHORA_DIR = r"D:\Programs\IDA Professional 9.3\plugins\diaphora-3.4.1"
sys.path.insert(0, DIAPHORA_DIR)
os.chdir(DIAPHORA_DIR)

# -- Delegate to Diaphora's built-in headless entry point ---------------------
import diaphora_ida  # noqa: E402

diaphora_ida.main()
