# Diaphora MCP — Automated Binary Diffing Pipeline

> Основная инструкция для агентов этого репозитория находится в [AGENTS.md](AGENTS.md). Этот файл сохранён для совместимости с Claude Code.

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
| MCP Config | Конфигурация конкретного MCP-клиента; для Codex — `%USERPROFILE%\.codex\config.toml` |
| **ida-pro-mcp integration** | Upstream `ida-pro-mcp` + headless `idalib-mcp`; отдельный GUI listener этого проекта — `diaphora_gui_listener.py` |

## ida-pro-mcp Integration

When **ida-pro-mcp** and/or its `idalib-mcp` backend are configured, `export_idb_to_diaphora` can use the active IDA integration before falling back to the project's GUI listener and headless `idat.exe`. See [GUI_INSTRUCTIONS.md](GUI_INSTRUCTIONS.md) for the current installation flow.

**Export priority:**
1. Проверяется доступный upstream/headless IDA integration.
2. Затем используется optional GUI listener этого проекта на порту `28652`.
3. В конце выполняется headless экспорт через `idat.exe` с проверкой lock-файла.

Для GUI-сессий legacy listener использует порт `13337` для Diaphora HTTP endpoint только если соответствующий мост действительно установлен. Не считайте наличие фиксированного пункта меню или порта доказательством работоспособности: проверяйте MCP-инструментами и реальным экспортом.

**Prerequisite:** Install the upstream integration with its installer; do not copy an old plugin manually. The repository's Diaphora server remains independently usable through `diaphora_mcp_server.py`.

**Export differences vs headless idat64:**

| Data | idat64 headless | ida_mcp plugin |
|---|---|---|
| Functions, call graph, CFG | ✅ | ✅ |
| Pseudocode (Hex-Rays) | ✅ | ✅ |
| Structures (struct/union) | ❌ | ✅ |
| Enums | ❌ | ✅ |
| Comments | ❌ | ✅ |
| Function types (thunk/leaf/…) | ❌ | ✅ |

## Available Tools

### Export
- `export_idb_to_diaphora` — Exports `.i64`/`.idb` to SQLite.
  **Priority:** ① ida_mcp plugin (port 13337) → ② GUI listener (port 28652) → ③ idat64 headless.
  When ida_mcp is active, export runs inside the existing IDA — no license conflict, richer data (structures, enums, comments).
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
- **MCP client timeout**: Claude Code and other MCP clients have a built-in timeout for tool calls (typically 5–20 minutes). If the user works with large binaries (>100 MB) and the export might exceed this, **ask the user to increase the MCP timeout** in their MCP client config (see below). Without this, the client may kill the session mid-export even though the server is still working.

### Increasing MCP Timeout

For Claude Code, add or modify the `timeout` field in `~/.claude.json` (or `.mcp.json`) under the `diaphora` server config:

```json
"mcpServers": {
  "diaphora": {
    "command": "python",
    "args": ["path/to/diaphora_mcp_server.py"],
    "env": {
      "IDAT_PATH": "C:\\Program Files\\IDA Pro 9.3\\idat.exe",
      "DIAPHORA_DIR": "C:\\Program Files\\IDA Pro 9.3\\plugins\\diaphora-3.4.1"
    },
    "timeout": 7200  ← increase to 2 hours for large binaries
  }
}
```

For other MCP-compatible clients (Claude Desktop, Continue.dev, etc.), set the equivalent timeout/requestTimeout option to at least **7200** (2 hours) when working with binaries over 100 MB.

If the export takes longer than expected, the AI agent can split the work:
1. Export the binary with `summaries_only=True` and `use_decompiler=False` first (fast — minutes)
2. Analyse results from the diff
3. Only re-export with decompiler for SPECIFIC functions of interest (fast per-function)

## Technical Details

- **ida-pro-mcp integration (HTTP)**: When the patched `ida_mcp.py` plugin is active inside IDA GUI, `export_idb_to_diaphora` sends `POST /diaphora/export` to `127.0.0.1:13337`. The export runs in a background thread inside the existing IDA process — **no second license needed**, no session loss. Export includes structures, enums, and comments (not available via headless idat64).
- **GUI Integration (XML-RPC)**: The plugin `diaphora_gui_listener.py` opens port `28652` inside active GUI IDA Pro sessions. This is the second priority fallback if ida_mcp is not installed.
- **Headless export** uses Diaphora's built-in environment variables (`DIAPHORA_AUTO`, `DIAPHORA_EXPORT_FILE`, `DIAPHORA_USE_DECOMPILER`, `DIAPHORA_FUNCTION_SUMMARIES_ONLY`).
- `idat.exe` is run via the wrapper script `_diaphora_headless.py` (third priority fallback).
- **Export Timeout**: 14,400 seconds (4 hours) for idat headless; 600 seconds (10 min) for ida_mcp plugin.
- **Diff timeout**: 1 hour (3600 seconds). Watchdog disk inactivity check triggers after 120 seconds.
- Recursion limit is automatically set to `100000` to prevent recursion errors on large call graphs.
- Current installation instructions are in [GUI_INSTRUCTIONS.md](GUI_INSTRUCTIONS.md). Treat `AGENTS.md` as the repository source of truth for agent workflows.
