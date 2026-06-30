#!/c/Users/olegc/AppData/Local/Programs/Python/Python312/python.exe
"""
Diaphora MCP Server — thin entry point.

Delegates to the diaphora_mcp package.  All logic lives in:
  diaphora_mcp/core/     — domain modules
  diaphora_mcp/utils/    — shared utilities
  diaphora_mcp/diaphora_mcp_server.py  — MCP registration (thin layer)
"""

import sys
import os

# Ensure the package is importable from the project root.
_pkg_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "diaphora_mcp")
if os.path.isdir(_pkg_dir) and _pkg_dir not in sys.path:
    sys.path.insert(0, os.path.dirname(_pkg_dir))

from diaphora_mcp import mcp

if __name__ == "__main__":
    mcp.run()
