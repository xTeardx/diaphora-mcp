# Diaphora MCP — Claude Code compatibility notes

The canonical repository instructions are in [AGENTS.md](AGENTS.md). This file exists so Claude Code discovers the same project rules without maintaining a second architecture document.

## Project role

This repository contains a local stdio MCP server for:

- exporting `.i64`/`.idb` databases through Diaphora;
- comparing official Diaphora SQLite exports;
- matching functions across rebased binaries;
- analyzing call graphs, rankings, security signals, and patch reports.

## Source map

- `diaphora_mcp_server.py`: stdio entry point.
- `diaphora_mcp/`: tool registration and implementation.
- `diaphora_mcp/core/export.py`: `auto`/`headless`/`gui` export modes and batch pipeline.
- `diaphora_mcp/core/mapping.py`: old/new function address mapping.
- `diaphora_mcp/core/analysis.py`: matching and function comparison.
- `diaphora_mcp/core/graph.py`: mapped call-graph tools.
- `_diaphora_headless.py`: IDA headless wrapper.
- `diaphora_gui_listener.py`: optional legacy XML-RPC GUI fallback.
- `tests/`: synthetic regression tests.

## Non-negotiable data rules

1. `.i64`/`.idb` is an IDA database, not a results SQLite file.
2. Results tools accept generated `.diaphora.sqlite` and `.diaphora` files.
3. `batch_export_and_diff` uses `export_mode="headless"`.
4. When old/new bases differ, pass `match_results_path` to address-aware tools.
5. Never infer cross-version identity from equal addresses alone.
6. Keep IDBs, binaries, exports, logs, and generated artifacts out of commits.

## Large database defaults

- Start with `use_decompiler=false`.
- For large inputs, use `summaries_only=true`.
- Increase the MCP client timeout for long exports.
- Use `ida-pro-mcp`/`idalib-mcp` for detailed address-level inspection after matching.

## Required checks before changes

```powershell
git status --short
python -m pytest -q
python -m compileall -q .
git diff --check
```

For behavior changes, add a regression test first. Preserve the explicit export-mode contract, output-root validation, schema validation, cancellation, and old/new mapping behavior. Do not modify an upstream `ida_mcp.py` manually.

For the full agent workflow and repository rules, follow [AGENTS.md](AGENTS.md). For GUI/headless setup, follow [GUI_INSTRUCTIONS.md](GUI_INSTRUCTIONS.md).
