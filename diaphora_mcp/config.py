"""
Diaphora MCP — path configuration.

All machine-local paths live here so other modules can import them.
"""

import os
import sys

_PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_PACKAGE_DIR)

DIAPHORA_DIR = r"D:\Programs\IDA Professional 9.3\plugins\diaphora-3.4.1"
IDAT_PATH = r"D:\Programs\IDA Professional 9.3\idat.exe"
DIAPHORA_SCRIPT = os.path.join(DIAPHORA_DIR, "diaphora.py")
HEADLESS_WRAPPER = os.path.join(PROJECT_ROOT, "_diaphora_headless.py")
PYTHON = sys.executable
