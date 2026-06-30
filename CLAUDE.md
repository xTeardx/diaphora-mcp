# Diaphora MCP — Automated Binary Diffing Pipeline

MCP server for automating binary diffing via Diaphora + IDA Pro.

## Project Structure and Setup

| Component | Path |
|-----------|------|
| MCP Server | `diaphora_mcp_server.py` |
| Headless wrapper | `_diaphora_headless.py` |
| GUI Listener Plugin | `diaphora_gui_listener.py` |
| Diaphora Plugin | `<your_ida_path>\plugins\diaphora-3.4.1\` |
| IDA (idat.exe) | `<your_ida_path>\idat.exe` |
| IDB databases | `.i64` / `.idb` files |
| MCP Config | `%USERPROFILE%\.claude\.mcp.json` |

## Available Tools

### Export
- `export_idb_to_diaphora` — Exports `.i64`/`.idb` to SQLite via `idat.exe` (headless)
- `batch_export_and_diff` — Full pipeline: export primary → export secondary → diff → summary

### Diff
- `diff_diaphora_dbs` — Diffs two exported SQLite databases
- `get_diff_results` — Reads `.diaphora` file with filtering
- `get_diff_summary` — Returns match statistics and summaries

### Analysis
- `analyze_diff_results` — Security screening and matching
- `compare_functions` — Side-by-side comparison of a function in both databases
- `search_export_db` — Queries functions by name/instructions/complexity
- `get_function_pseudocode` — Retrieves pseudocode + metadata for a function
- `get_export_info` — Retrieves general database metadata

### Agent-first Tools
- `find_function_match` — Matches a function in the second binary with confidence metrics
- `transfer_metadata` — Prepares names, comments, and prototypes for bulk transfer
- `get_changed_callgraph` — Compares incoming and outgoing calls of a function
- `rank_changes` — Ranks changed functions by importance (0-100 score)
- `find_patch_root` — Detects root-cause functions causing call cascades
- `compare_call_path` — Walks callgraph from a function (BFS call path comparison, up to N levels)
- `detect_security_patches` — Detects probable security fixes (bounds checks, memory safety, anti-debug, etc.)
- `detect_behavior_change` — Provides natural language summary of function logic changes
- `summarize_patch` — Produces comprehensive update report
- `explain_similarity` — Breaks down similarity factors (mnemonics, CFG, constants, prototype, hash)

## Typical Workflow

```python
# 1. Diff already exported databases
diff_diaphora_dbs(db1="old.sqlite", db2="new.sqlite")

# 2. Run full pipeline starting from IDBs
batch_export_and_diff(idb1="old.i64", idb2="new.i64")

# 3. Analyze diff results for security issues
analyze_diff_results(results_path="old_vs_new.diaphora")

# 4. Rank changes
rank_changes(results_path="old_vs_new.diaphora", top_n=20)

# 5. Locate root changes
find_patch_root(results_path="old_vs_new.diaphora")

# 6. Detect security fixes
detect_security_patches(results_path="old_vs_new.diaphora")

# 7. Compare a function side-by-side
compare_functions(db1="old.sqlite", db2="new.sqlite", address="401000")

# 8. Explain function similarity
explain_similarity(db1="old.sqlite", db2="new.sqlite", address="401000")

# 9. Get full update report
summarize_patch(results_path="old_vs_new.diaphora")
```

## Agent Rules (AI Instructions)

- **Limit details on large databases**: If the source `.i64`/`.idb` file is larger than **100 MB** or contains **> 100,000 functions**, you **MUST** use `summaries_only=True` (or leave as `None` to auto-detect). This prevents huge database size bloat, speeds up export time from 1.5 hours to **1-2 minutes**, and reduces SQLite database size from 300+ MB to 15 MB.
- **Decompiler usage**: For large binaries, the Hex-Rays decompiler **should be turned off** (`use_decompiler=False`), otherwise headless export might take over 5 hours.
- **Work in summaries_only mode**: In `summaries_only` mode, detailed assembly/pseudocode diff is not stored. Use live IDA Pro MCP tools (`ida-pro-mcp`) to guide the user in the GUI to analyze the target address.

## Technical Details

- **GUI Integration (XML-RPC)**: The plugin `diaphora_gui_listener.py` opens port `28652` inside active GUI IDA Pro sessions. The MCP server checks this port first. If alive, the export is executed inside the GUI.
- **Headless export** uses Diaphora's built-in environment variables (`DIAPHORA_AUTO`, `DIAPHORA_EXPORT_FILE`, `DIAPHORA_USE_DECOMPILER`, `DIAPHORA_FUNCTION_SUMMARIES_ONLY`).
- `idat.exe` is run via the wrapper script `_diaphora_headless.py`.
- **Export Timeout**: Set to 14,400 seconds (4 hours) to support large binaries in detailed mode. Diff timeout: 1 hour (3600 seconds). Watchdog disk inactivity check triggers after 120 seconds.
- Recursion limit is automatically set to `100000` to prevent recursion errors on large call graphs.
