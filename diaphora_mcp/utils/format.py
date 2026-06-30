"""
Diaphora MCP — formatting and feature-extraction utilities.
"""

import difflib
import json
from typing import Any


def dumps(data: Any, *, indent: int = 2, default: Any = None) -> str:
    """Serialize to JSON with project-wide defaults (indent=2, str for non-serializable)."""
    if default is None:
        default = str
    return json.dumps(data, indent=indent, default=default)


def err_json(msg: str, extra: dict[str, Any] | None = None) -> str:
    """Shortcut for ``{"error": msg}`` with optional extra fields."""
    d: dict[str, Any] = {"error": msg}
    if extra:
        d.update(extra)
    return dumps(d)



def pseudocode_simple_diff(pseudo1: str, pseudo2: str) -> list:
    """Return a list of {'type': 'added'|'removed'|'context', 'line': str}."""
    lines1 = (pseudo1 or "").splitlines()
    lines2 = (pseudo2 or "").splitlines()
    diff = []
    for line in difflib.unified_diff(
        lines1, lines2, n=1, lineterm=""
    ):
        if line.startswith("---") or line.startswith("+++") or line.startswith("@@"):
            continue
        if line.startswith("-"):
            diff.append({"type": "removed", "line": line[1:]})
        elif line.startswith("+"):
            diff.append({"type": "added", "line": line[1:]})
        else:
            diff.append({"type": "context", "line": line[1:]})
    return diff


def func_features(func: dict) -> dict:
    """Extract a feature vector for similarity/comparison."""
    return {
        "nodes": func.get("nodes", 0),
        "edges": func.get("edges", 0),
        "instructions": func.get("instructions", 0),
        "cyclomatic_complexity": func.get("cyclomatic_complexity", 0),
        "mnemonics": (func.get("mnemonics") or ""),
        "constants": (func.get("constants") or ""),
        "bytes_hash": (func.get("bytes_hash") or ""),
        "prototype": (func.get("prototype") or ""),
        "loops": func.get("loops", 0),
        "strongly_connected": func.get("strongly_connected", 0),
        "names": (func.get("names") or ""),
    }
