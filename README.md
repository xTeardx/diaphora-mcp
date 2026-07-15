[Русская версия](README.ru.md)

# Diaphora MCP

Diaphora MCP is a local [Model Context Protocol](https://modelcontextprotocol.io/) server that connects AI agents to [IDA Pro](https://hex-rays.com/ida-pro/) and [Diaphora](https://github.com/joxeankoret/diaphora). It exports analyzed IDA databases, runs Diaphora diffs, and exposes structured tools for matching, call-graph analysis, ranking, security triage, and patch reporting.

> This project is an analysis assistant. It does not replace IDA Pro, Diaphora, or human reverse-engineering review.

## What it does

- Export `.i64`/`.idb` databases to Diaphora SQLite.
- Compare two official Diaphora exports and preserve match categories.
- Map old function addresses to new addresses across rebased binaries.
- Inspect matched functions, call paths, changed call graphs, and metadata.
- Rank changes and flag heuristic security signals for manual validation.
- Run as a local stdio MCP server for Codex, Claude Code, Cursor, and other MCP clients.

## Recommended workflow

Use headless export for anything that will be diffed or matched:

```text
IDB/i64 files
    -> batch_export_and_diff(export_mode="headless")
    -> .diaphora.sqlite + .diaphora
    -> get_diff_summary / get_diff_results
    -> find_function_match / compare_functions / graph tools
```

The server supports three export modes:

| Mode | Behavior | Use it when |
| --- | --- | --- |
| `headless` | Always launches `idat.exe`; validates the official diff schema | Recommended for export, diff, and matching |
| `auto` | Tries the active GUI bridge, then falls back to headless | You want convenience for one-off exports |
| `gui` | Requires a matching active GUI bridge and never falls back | You intentionally export from an open IDA session |

`batch_export_and_diff` requires `export_mode="headless"` so both inputs use a schema compatible with Diaphora matching.

## Prerequisites

- Python 3.10 or newer.
- An IDA Pro installation with `idat.exe`/`idat64.exe`.
- Diaphora installed in the IDA plugins directory.
- An MCP-compatible client.
- Enough disk space for two SQLite exports and a diff results file.

IDA Pro and Diaphora are external dependencies and are not bundled with this repository.

## Installation

```bash
git clone https://github.com/xTeardx/diaphora-mcp.git
cd diaphora-mcp
python -m pip install -e .
```

For development:

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

## Configuration

Set these environment variables for deterministic operation:

| Variable | Purpose |
| --- | --- |
| `IDAT_PATH` | Absolute path to the IDA headless executable |
| `DIAPHORA_DIR` | Directory containing the Diaphora scripts/plugin |
| `DIAPHORA_OUTPUT_ROOT` | Allowed root for newly created exports |
| `DIAPHORA_PYTHON` | Optional Python interpreter used to run the diff script |

Example values are intentionally omitted from the repository because IDA paths differ by installation. See [Configuration](docs/CONFIGURATION.md).

## MCP client configuration

The server uses stdio. Point the client at the repository entry point and pass the environment explicitly:

```json
{
  "mcpServers": {
    "diaphora": {
      "command": "python",
      "args": ["C:/path/to/diaphora-mcp/diaphora_mcp_server.py"],
      "env": {
        "IDAT_PATH": "C:/Program Files/IDA Professional 9.3/idat.exe",
        "DIAPHORA_DIR": "C:/Program Files/IDA Professional 9.3/plugins/diaphora",
        "DIAPHORA_OUTPUT_ROOT": "C:/diaphora-outputs"
      }
    }
  }
}
```

Use forward slashes in JSON paths or escape Windows backslashes. Client-specific examples are in [`examples/`](examples/).

## First diff

After IDA has analyzed both binaries, call:

```text
batch_export_and_diff(
  idb1_path="C:/analysis/old.i64",
  idb2_path="C:/analysis/new.i64",
  output_dir="C:/diaphora-outputs/run-001",
  export_mode="headless",
  use_decompiler=false,
  summaries_only=true
)
```

Then pass only the returned `.diaphora.sqlite` and `.diaphora` paths to result tools. An `.i64` file is an IDA database, not a results SQLite database.

For a matched function:

```text
find_function_match(db1_path=OLD_SQLITE, db2_path=NEW_SQLITE, address="1800d6b80")
compare_functions(
  db1_path=OLD_SQLITE,
  db2_path=NEW_SQLITE,
  address="1800d6b80",
  match_results_path=DIAPHORA_RESULTS
)
```

See [Workflows](docs/WORKFLOWS.md) for GUI export, address mapping, call-graph analysis, and recovery procedures.

## Tool groups

| Group | Purpose |
| --- | --- |
| Export | `export_idb_to_diaphora`, `batch_export_and_diff` |
| Diff/results | `diff_diaphora_dbs`, `get_diff_summary`, `get_diff_results` |
| Database | `get_export_info`, `search_export_db`, `get_function_pseudocode` |
| Matching/analysis | `find_function_match`, `compare_functions`, `explain_similarity`, `detect_behavior_change` |
| Graph | `get_changed_callgraph`, `compare_call_path`, `find_patch_root` |
| Ranking/security | `rank_changes`, `analyze_diff_results`, `detect_security_patches`, `summarize_patch` |
| Metadata/performance | `transfer_metadata`, `performance_report` |

## Important limitations

- Matching is heuristic. A `best` or high-ratio match is evidence, not proof.
- Security tools are triage heuristics and require manual assembly/decompiler validation.
- GUI export requires the correct IDB to be open and may expose a schema that is not suitable for diffing; use headless mode for comparisons.
- An IDB open in another IDA process can hold locks and block a second IDA process.
- Large databases can take minutes or hours and require a client timeout that covers the export.
- Binaries, IDBs, exports, logs, and crash artifacts must stay outside commits.

Full details: [Limitations and known behavior](docs/LIMITATIONS.md) and [Security policy](SECURITY.md).

## Development

```powershell
python -m pytest -q
python -m compileall -q .
git diff --check
```

IDA-dependent tests require a local IDA/Diaphora installation and are not run in public CI. See [Contributing](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md).

## Repository map

| Path | Role |
| --- | --- |
| `diaphora_mcp_server.py` | stdio entry point |
| `diaphora_mcp/` | MCP registrations and implementation |
| `_diaphora_headless.py` | IDA headless wrapper |
| `diaphora_gui_listener.py` | Optional legacy GUI bridge |
| `tests/` | Tracked regression tests |
| `docs/` | Detailed user and maintenance documentation |
| `Fixes/` | Local binary fixtures; never publish |
