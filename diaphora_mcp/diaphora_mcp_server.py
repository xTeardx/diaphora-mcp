"""
Diaphora MCP Server for Claude Code.

Thin registration layer — imports tool implementations from core modules
and registers them with FastMCP.  No business logic lives here.
"""

import json
import os
import sys

from mcp.server.fastmcp import FastMCP

from .core.export import export_idb_to_diaphora as _export_idb_to_diaphora
from .core.export import batch_export_and_diff as _batch_export_and_diff
from .core.diff import diff_diaphora_dbs as _diff_diaphora_dbs
from .core.diff import get_diff_results as _get_diff_results
from .core.diff import get_diff_summary as _get_diff_summary
from .core.analysis import search_export_db as _search_export_db
from .core.analysis import get_function_pseudocode as _get_function_pseudocode
from .core.analysis import get_export_info as _get_export_info
from .core.analysis import compare_functions as _compare_functions
from .core.analysis import find_function_match as _find_function_match
from .core.analysis import explain_similarity as _explain_similarity
from .core.analysis import detect_behavior_change as _detect_behavior_change
from .core.report import summarize_patch as _summarize_patch
from .core.security import analyze_diff_results as _analyze_diff_results
from .core.security import detect_security_patches as _detect_security_patches
from .core.ranking import rank_changes as _rank_changes
from .core.graph import get_changed_callgraph as _get_changed_callgraph
from .core.graph import compare_call_path as _compare_call_path
from .core.graph import find_patch_root as _find_patch_root
from .core.metadata import transfer_metadata as _transfer_metadata
from .core.performance import performance_report as _performance_report

# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------
mcp = FastMCP("Diaphora")

# ---------------------------------------------------------------------------
# Tools — Export
# ---------------------------------------------------------------------------
mcp.tool(
    description="Export an IDB/i64 database to Diaphora SQLite. "
    "export_mode='auto' tries the active GUI bridges then headless; 'gui' requires GUI and never falls back; "
    "'headless' always uses idat.exe and validates the official matching schema. "
    "use_decompiler=True adds pseudocode but makes export 10-30x slower. "
    "Default is False for a quick first pass. "
    "summaries_only=True skips detailed assembly/pseudocode for much faster export on large binaries. "
    "When summaries_only=None (default), auto-detects based on file size (>100 MB enables summaries)."
)(_export_idb_to_diaphora)

mcp.tool(
    description="Complete pipeline: export two IDB databases, diff them, and return a summary. "
    "The pipeline requires export_mode='headless' so both databases use the official matching schema. "
    "use_decompiler=True adds pseudocode but makes export significantly slower. "
    "summaries_only=True/False/auto — see export_idb_to_diaphora for details."
)(_batch_export_and_diff)

# ---------------------------------------------------------------------------
# Tools — Diff & Query
# ---------------------------------------------------------------------------
mcp.tool(
    description="Diff two Diaphora-exported SQLite databases. Returns structured match results (best/partial/unreliable)."
)(_diff_diaphora_dbs)

mcp.tool(
    description="Read and filter a previously saved .diaphora diff results file."
)(_get_diff_results)

mcp.tool(
    description="Get a high-level summary of a .diaphora diff results file."
)(_get_diff_summary)

# ---------------------------------------------------------------------------
# Tools — Database query
# ---------------------------------------------------------------------------
mcp.tool(
    description="Search for functions in an exported Diaphora database by name, size, or complexity."
)(_search_export_db)

mcp.tool(
    description="Get pseudocode or assembly of a specific function in an exported database."
)(_get_function_pseudocode)

mcp.tool(
    description="Get basic info about an exported Diaphora database — function count, processor, MD5."
)(_get_export_info)

# ---------------------------------------------------------------------------
# Tools — Analysis
# ---------------------------------------------------------------------------
mcp.tool(
    description="Filter .diaphora diff results for security-relevant changes. Returns a curated list suitable for IDA Pro MCP follow-up."
)(_analyze_diff_results)

mcp.tool(
    description="Compare the same function side-by-side across two exported databases. Returns pseudocode 'was' / 'became' with addresses for IDA Pro MCP drill-down."
)(_compare_functions)

mcp.tool(
    description="Find the corresponding function between two binary versions with confidence and reasoning. Searches by address, name, hash, and heuristic similarity."
)(_find_function_match)

mcp.tool(
    description="Explain why two matched functions have a given similarity ratio. Breaks down contribution by CFG, instructions, mnemonics, constants, calls, and bytes."
)(_explain_similarity)

mcp.tool(
    description="Generate a concise natural-language description of how a function's logic changed between two binary versions."
)(_detect_behavior_change)

mcp.tool(
    description="Generate a comprehensive patch summary report with categorised changes, statistics, and security analysis."
)(_summarize_patch)

# ---------------------------------------------------------------------------
# Tools — Security
# ---------------------------------------------------------------------------
mcp.tool(
    description="Detect likely security patches by analysing pattern changes in pseudocode: new bounds checks, validation, crypto, anti-debug, and integrity checks."
)(_detect_security_patches)

# ---------------------------------------------------------------------------
# Tools — Ranking
# ---------------------------------------------------------------------------
mcp.tool(
    description="Rank changed functions by importance using CFG, pseudocode, complexity, strings, imports, and security indicators."
)(_rank_changes)

# ---------------------------------------------------------------------------
# Tools — Callgraph
# ---------------------------------------------------------------------------
mcp.tool(
    description="Show changes in incoming/outgoing calls and execution paths for a function between two binary versions."
)(_get_changed_callgraph)

mcp.tool(
    description="Compare call chains before and after update for a function. Traces callees (or callers) to N levels deep."
)(_compare_call_path)

mcp.tool(
    description="Identify functions likely to be the root cause of cascading changes by analysing callgraph dependency chains."
)(_find_patch_root)

# ---------------------------------------------------------------------------
# Tools — Metadata
# ---------------------------------------------------------------------------
mcp.tool(
    description="Selectively transfer metadata (names, comments, prototypes, types) from one exported database to another. Returns structured data ready for IDA Pro MCP application."
)(_transfer_metadata)

# ---------------------------------------------------------------------------
# Tools — Performance
# ---------------------------------------------------------------------------
mcp.tool(
    description="Return aggregated performance report: memory, cache state, and connection stats."
)(_performance_report)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    mcp.run()
