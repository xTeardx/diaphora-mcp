# Diaphora MCP — agent instructions

## Mission

This repository provides a local stdio MCP server for exporting IDA databases, comparing Diaphora SQLite exports, and analyzing diff results.

## Source map

- `diaphora_mcp_server.py`: top-level stdio entry point.
- `diaphora_mcp/`: MCP registration and implementation.
- `diaphora_mcp/core/export.py`: export modes and batch pipeline.
- `diaphora_mcp/core/diff.py`: result reading and summaries.
- `diaphora_mcp/core/analysis.py`: matching and function comparison.
- `diaphora_mcp/core/graph.py`: mapped call-graph analysis.
- `_diaphora_headless.py`: IDA headless wrapper.
- `diaphora_gui_listener.py`: optional legacy GUI bridge.
- `tests/`: tracked synthetic regression tests.
- `docs/`: user-facing and maintenance documentation.

## Data contract

1. `.i64`/`.idb` is an IDA database, not SQLite.
2. Results tools accept only generated `.diaphora.sqlite` and `.diaphora` files.
3. For comparisons, old input is primary and new input is secondary.
4. When image bases differ, use `match_results_path` to map old addresses to new addresses.
5. `batch_export_and_diff` must use `export_mode="headless"`.

## Export rules

- `headless`: deterministic `idat.exe` export with official diff-schema validation.
- `auto`: active GUI bridge first, then headless fallback.
- `gui`: active GUI bridge only; it must not silently fall back.
- Never overwrite an existing generated target.
- Keep output below `DIAPHORA_OUTPUT_ROOT`.
- Do not pass user IDBs or generated SQLite files into Git.

## Change protocol

Before a non-trivial change:

1. Inspect `git status --short`, current branch, and relevant tests.
2. Write a focused plan identifying files, failure mode, and verification.
3. For behavior changes, write a regression test first and reproduce the failure.
4. Make the smallest compatible patch.
5. Run the full suite, compilation check, and `git diff --check`.

Do not use `git reset --hard`, `git clean -fd`, force-push, or broad deletion of fixtures.

## Required checks

```powershell
python -m pytest -q
python -m compileall -q .
git diff --check
```

`pip check` may report unrelated packages installed in the host environment; compare the diagnostic with the project dependency set before treating it as a project failure.

## Technical limitations to preserve

- Matching and security analysis are heuristic and require manual validation.
- IDA locks, process state, decompiler availability, and database quality affect exports.
- Large inputs can take a long time; preserve timeout and cancellation behavior.
- Do not claim GUI output is diffable without checking the official schema.
- Do not modify the upstream `ida_mcp.py`; it is a separate IDA inspection integration.

## Review checklist

- Does the change preserve old/new address mapping?
- Does it distinguish an IDA DB from a Diaphora SQLite/results file?
- Does it avoid leaking raw subprocess exceptions or sensitive paths unnecessarily?
- Does it add a regression test for a fixed bug?
- Are docs/examples consistent with current MCP function signatures?
