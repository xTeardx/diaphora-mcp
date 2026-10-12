"""
Diaphora MCP server for local AI-assisted comparison.

Thin registration layer — imports tool implementations from core modules
and registers them with FastMCP.  No business logic lives here.
"""

import os

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

CORE_TOOLS = frozenset({
    "export_idb_to_diaphora", "batch_export_and_diff", "diff_diaphora_dbs",
    "get_diff_results", "get_diff_summary", "search_export_db",
    "get_function_pseudocode", "get_export_info", "compare_functions",
    "get_changed_callgraph",
})
LEGACY_TOOLS_ENABLED = os.environ.get("DIAPHORA_ENABLE_LEGACY_TOOLS") == "1"


def _tool(*, description):
    """Keep the default agent surface focused; retain explicit compatibility."""
    def register(function):
        if function.__name__ in CORE_TOOLS:
            return mcp.tool(description=description)(function)
        if LEGACY_TOOLS_ENABLED:
            return mcp.tool(description="Legacy optional tool. " + description)(function)
        return function
    return register

# ---------------------------------------------------------------------------
# Tools — Export
# ---------------------------------------------------------------------------
_tool(
    description="Export an IDB/i64 database to Diaphora SQLite. "
    "export_mode='auto' tries the active GUI bridges then headless; 'gui' requires GUI and never falls back; "
    "'headless' always uses idat.exe and validates the official matching schema. "
    "use_decompiler=True adds pseudocode and can substantially increase export time. "
    "Default is False for a quick first pass. "
    "summaries_only=True skips detailed assembly/pseudocode for much faster export on large binaries. "
    "When summaries_only=None (default), auto-detects based on file size (>100 MB enables summaries)."
)(_export_idb_to_diaphora)

_tool(
    description="Complete pipeline: export two IDB databases, diff them, and return a summary. "
    "The pipeline requires export_mode='headless' so both databases use the official matching schema. "
    "use_decompiler=True adds pseudocode but makes export significantly slower. "
    "summaries_only=True/False/auto — see export_idb_to_diaphora for details."
)(_batch_export_and_diff)

# ---------------------------------------------------------------------------
# Tools — Diff & Query
# ---------------------------------------------------------------------------
_tool(
    description="Diff two Diaphora-exported SQLite databases. Returns structured match results (best/partial/unreliable)."
)(_diff_diaphora_dbs)

_tool(
    description="Read and filter a saved .diaphora file with bounded SQL pagination. Follow next_offset and next_unmatched_offset; lowest ratios first by default."
)(_get_diff_results)

_tool(
    description="Get a high-level summary of a .diaphora diff results file."
)(_get_diff_summary)

# ---------------------------------------------------------------------------
# Tools — Database query
# ---------------------------------------------------------------------------
_tool(
    description="Search for functions in an exported Diaphora database by name, size, or complexity."
)(_search_export_db)

_tool(
    description="Get pseudocode or assembly of a specific function in an exported database."
)(_get_function_pseudocode)

_tool(
    description="Get basic info about an exported Diaphora database — function count, processor, MD5."
)(_get_export_info)

# ---------------------------------------------------------------------------
# Tools — Analysis
# ---------------------------------------------------------------------------
_tool(
    description="Filter .diaphora diff results for security-relevant changes. Returns a curated list suitable for IDA Pro MCP follow-up."
)(_analyze_diff_results)

_tool(
    description="Compare the same function side-by-side across two exported databases. Returns pseudocode 'was' / 'became' with addresses for IDA Pro MCP drill-down."
)(_compare_functions)

_tool(
    description="Find a counterpart from explicit selectors, Diaphora mapping, or unambiguous name/hash evidence. Equal addresses alone do not establish identity."
)(_find_function_match)

_tool(
    description="Compare observed function features. The optional feature score is an arbitrary heuristic, not an explanation of Diaphora ratio or calibrated confidence."
)(_explain_similarity)

_tool(
    description="Describe measured code/CFG changes between matched functions. This does not establish semantic behavior; missing counterparts remain unknown."
)(_detect_behavior_change)

_tool(
    description="Summarize matching statistics and optional keyword triage. Unmatched functions are not proven additions or deletions."
)(_summarize_patch)

# ---------------------------------------------------------------------------
# Tools — Security
# ---------------------------------------------------------------------------
_tool(
    description="Detect likely security patches by analysing pattern changes in pseudocode: new bounds checks, validation, crypto, anti-debug, and integrity checks."
)(_detect_security_patches)

# ---------------------------------------------------------------------------
# Tools — Ranking
# ---------------------------------------------------------------------------
_tool(
    description="Prioritize review with arbitrary heuristic weights over observed differences. Scores do not measure calibrated importance or risk."
)(_rank_changes)

# ---------------------------------------------------------------------------
# Tools — Callgraph
# ---------------------------------------------------------------------------
_tool(
    description="Show changes in incoming/outgoing calls and execution paths for a function between two binary versions."
)(_get_changed_callgraph)

_tool(
    description="Compare call chains before and after update for a function. Traces callees (or callers) to N levels deep."
)(_compare_call_path)

_tool(
    description="List graph-based review candidates with heuristic scores; graph position does not establish causation."
)(_find_patch_root)

# ---------------------------------------------------------------------------
# Tools — Metadata
# ---------------------------------------------------------------------------
_tool(
    description="Selectively transfer metadata (names, comments, prototypes, types) from one exported database to another. Returns structured data ready for IDA Pro MCP application."
)(_transfer_metadata)

# ---------------------------------------------------------------------------
# Tools — Performance
# ---------------------------------------------------------------------------
_tool(
    description="Return aggregated performance report: memory, cache state, and connection stats."
)(_performance_report)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    mcp.run()
