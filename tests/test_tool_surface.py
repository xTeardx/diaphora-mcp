"""The default MCP surface exposes evidence, with legacy tools opt-in."""

import json
import os
import subprocess
import sys


CORE_TOOLS = {
    "export_idb_to_diaphora", "batch_export_and_diff", "diff_diaphora_dbs",
    "get_diff_results", "get_diff_summary", "get_export_info",
    "search_export_db", "get_function_pseudocode", "compare_functions",
    "get_changed_callgraph",
}


def registered_tools(legacy):
    env = os.environ.copy()
    env["DIAPHORA_ENABLE_LEGACY_TOOLS"] = legacy
    result = subprocess.run(
        [sys.executable, "-c", "import json, diaphora_mcp; print(json.dumps(sorted(diaphora_mcp.mcp._tool_manager._tools)))"],
        env=env, capture_output=True, text=True, check=True,
    )
    return set(json.loads(result.stdout))


def test_default_tools_are_focused_on_comparison():
    assert registered_tools("0") == CORE_TOOLS


def test_legacy_tools_are_explicitly_opt_in():
    tools = registered_tools("1")
    assert CORE_TOOLS < tools
    assert len(tools) == 21
    assert "performance_report" in tools


def test_other_values_do_not_enable_legacy_tools():
    assert registered_tools("true") == CORE_TOOLS
