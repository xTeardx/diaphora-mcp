[Русская версия](README.ru.md)

# Diaphora MCP

Compare two IDA-analyzed binaries from your AI assistant. Diaphora MCP exports the saved IDA databases, runs [Diaphora](https://github.com/joxeankoret/diaphora), and lets the AI inspect corresponding functions and their call graphs.

The default interface has **10 tools** focused on comparison. Diaphora supplies matches; the AI reads the actual code and explains the changes.

[Quick start](#quick-start) · [Examples](#examples) · [Tools](#tools) · [Troubleshooting](#troubleshooting)

```text
old.i64 + new.i64 → headless export → SQLite exports + diff results
                                       ↓
                            summary → matched code → call graph
```

## Requirements

- Python 3.10+, IDA Pro with `idat.exe`/`idat64`, and an installed Diaphora plugin.
- Both binaries analyzed and saved as `.i64`/`.idb` databases.
- A local MCP client, such as Codex, Claude Code or Cursor.
- A compatible Hex-Rays decompiler only if you want pseudocode.

IDA and Diaphora are installed separately. Diff-schema validation currently targets Diaphora **3.4.1**; other schemas may need compatibility updates. The Python interpreter used for the diff must have Diaphora's standalone dependencies installed.

## Quick start

### 1. Install and create an output directory

```powershell
git clone https://github.com/xTeardx/diaphora-mcp.git
cd diaphora-mcp
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
New-Item -ItemType Directory -Force C:\diaphora-outputs | Out-Null
```

### 2. Connect the MCP server

Add this entry to your client's MCP configuration. Replace the repository, IDA and Diaphora paths with your installation paths. Use the Python executable from the environment where you installed this project.

```json
{
  "mcpServers": {
    "diaphora": {
      "command": "C:/src/diaphora-mcp/.venv/Scripts/python.exe",
      "args": ["C:/src/diaphora-mcp/diaphora_mcp_server.py"],
      "env": {
        "IDAT_PATH": "C:/Program Files/IDA Professional 9.3/idat.exe",
        "DIAPHORA_DIR": "C:/Program Files/IDA Professional 9.3/plugins/diaphora",
        "DIAPHORA_OUTPUT_ROOT": "C:/diaphora-outputs"
      }
    }
  }
}
```

The client launches the server over stdio; there is no separate web service to start. Restart the MCP server after changing its code or environment. A successful connection exposes the 10 tools listed below.

### 3. Ask your assistant to compare the files

```text
Use Diaphora to compare C:/analysis/old.i64 (old) against
C:/analysis/new.i64 (new). Save output under C:/diaphora-outputs/run-001.
Export headlessly with assembly detail, keep the exports, show a summary,
then inspect partial matches and explain the code changes in the interesting
functions. Use the result mapping when comparing functions and call graphs.
```

Choose a **fresh run directory** each time. Existing generated targets are never overwritten.

## Examples

The following JSON blocks are **MCP tool arguments**, not shell commands. Your assistant can call the named tools directly. Paths and `0x401000` are examples; use the paths and addresses returned by your own run.

### 1. Export and compare two IDA databases

Tool: **`batch_export_and_diff`**. Old is always the first input, new the second.

```json
{
  "idb1_path": "C:/analysis/old.i64",
  "idb2_path": "C:/analysis/new.i64",
  "output_dir": "C:/diaphora-outputs/run-001",
  "export_mode": "headless",
  "use_decompiler": false,
  "summaries_only": false,
  "cleanup": false,
  "limit": 100,
  "unmatched_limit": 50
}
```

This keeps assembly detail without requiring Hex-Rays. Select the export profile you need:

| Detail | `use_decompiler` | `summaries_only` | Use |
| --- | --- | --- | --- |
| Matching summaries | `false` | `true` | Fast first pass; no detailed code |
| Assembly | `false` | `false` | Compare disassembly without a decompiler |
| Assembly + pseudocode | `true` | `false` | Code review with a compatible Hex-Rays decompiler; slower |

Always take output paths from the response:

```text
OLD_SQLITE = steps.export1.output
NEW_SQLITE = steps.export2.output
RESULTS    = steps.diff.output
```

For this example, the generated files are `old.diaphora.sqlite`, `new.diaphora.sqlite`, and `old_vs_new.diaphora` under `run-001`. Equal input basenames produce distinct `old_`/`new_` export names. Keep `cleanup=false` for later function inspection.

### 2. Get a summary and inspect changed matches

Tool: **`get_diff_summary`**.

```json
{
  "results_path": "C:/diaphora-outputs/run-001/old_vs_new.diaphora"
}
```

Tool: **`get_diff_results`**. This page starts with lower-ratio partial matches.

```json
{
  "results_path": "C:/diaphora-outputs/run-001/old_vs_new.diaphora",
  "match_type": "partial",
  "min_ratio": 0.0,
  "limit": 50,
  "offset": 0,
  "unmatched_limit": 50,
  "unmatched_offset": 0,
  "sort_by": "ratio",
  "sort_order": "asc"
}
```

`partial` selects a Diaphora match category, not a guarantee of a behavioral change. Use `match_type="all"` for all supported categories. The response includes category counts, the filtered total, matches, unmatched rows, `next_offset` and `next_unmatched_offset`.

To continue, copy the returned next offsets into the next call, keeping the same filters and sort. For example, if they are `50` and `50`, use `offset=50` and `unmatched_offset=50`. A `null` next offset means that list is finished; stop advancing it. The two lists progress independently. Page sizes must be positive and are capped at 5000. Use `sort_order="desc"` to inspect the strongest matches first.

### 3. Compare a matched function and its graph

Tool: **`compare_functions`**.

```json
{
  "db1_path": "C:/diaphora-outputs/run-001/old.diaphora.sqlite",
  "db2_path": "C:/diaphora-outputs/run-001/new.diaphora.sqlite",
  "address": "0x401000",
  "match_results_path": "C:/diaphora-outputs/run-001/old_vs_new.diaphora"
}
```

The response contains `function_old`, `function_new`, available assembly/pseudocode, measured differences, and identity evidence. You can use `name` instead of `address`. If both selectors are supplied, the address takes precedence; omit it when selecting by name.

Tool: **`get_changed_callgraph`** accepts the same arguments above. It translates corresponding caller/callee addresses before reporting changes, and separates unresolved neighbors from confirmed edge differences.

Prefer **`0x`-prefixed addresses** to make hexadecimal input explicit. Supply `match_results_path` when available: it handles rebasing and renamed functions. Equal addresses alone do not establish identity. Ambiguous or missing matches remain unresolved rather than being called deletions. If you have manually verified a pair, you can provide `address2` or `name2` explicitly.

### 4. Find a function and read its code

Tool: **`search_export_db`**. `name_pattern` uses SQL LIKE: `%` matches any sequence.

```json
{
  "db_path": "C:/diaphora-outputs/run-001/old.diaphora.sqlite",
  "name_pattern": "%parse%",
  "min_instructions": 20,
  "limit": 20
}
```

Tool: **`get_function_pseudocode`** returns available pseudocode **and assembly**, despite its name.

```json
{
  "db_path": "C:/diaphora-outputs/run-001/old.diaphora.sqlite",
  "address": "0x401000"
}
```

If pseudocode is empty, rerun the export into a new run directory with `use_decompiler=true` and `summaries_only=false`, using a compatible decompiler. Use `get_export_info` with `db_path` to inspect export metadata.

### 5. Compare exports you already have

Tool: **`diff_diaphora_dbs`**. This skips IDA export and compares the existing official SQLite exports.

```json
{
  "db1_path": "C:/diaphora-outputs/run-001/old.diaphora.sqlite",
  "db2_path": "C:/diaphora-outputs/run-001/new.diaphora.sqlite",
  "output_path": "C:/diaphora-outputs/another-diff.diaphora"
}
```

For one new export, use `export_idb_to_diaphora` with `idb_path`, a fresh `output_path`, and `export_mode="headless"`.

## Tools

| Tool | Purpose |
| --- | --- |
| `export_idb_to_diaphora` | Export one saved IDA database |
| `batch_export_and_diff` | Export both databases and compare them |
| `diff_diaphora_dbs` | Compare existing exports |
| `get_diff_summary` | Match statistics and bounded examples |
| `get_diff_results` | Filtered, sorted, paginated results |
| `get_export_info` | Export metadata and counts |
| `search_export_db` | Search functions |
| `get_function_pseudocode` | Read assembly/pseudocode |
| `compare_functions` | Compare a resolved old/new pair |
| `get_changed_callgraph` | Compare mapped callers/callees |

Exact signatures are discoverable through MCP `tools/list`. See [Tool reference](docs/TOOLS.md).

## Export modes and configuration

| Mode | Behavior |
| --- | --- |
| `headless` | Launch IDA headlessly and validate the diff schema; recommended for comparisons |
| `auto` | Try the active GUI bridge, then headless fallback |
| `gui` | Require the correct open GUI session; no headless fallback |

`batch_export_and_diff` requires `headless`.

| Environment variable | Meaning |
| --- | --- |
| `IDAT_PATH` | Absolute path to the IDA headless executable |
| `DIAPHORA_DIR` | Directory containing the Diaphora scripts |
| `DIAPHORA_OUTPUT_ROOT` | Existing allowed root for new exports and diff results |
| `DIAPHORA_PYTHON` | Optional diff interpreter; defaults to the MCP server's interpreter |
| `DIAPHORA_ENABLE_LEGACY_TOOLS` | Exactly `1` enables the previous 21-tool interface |

Legacy matching, feature scores, security triage, reports, metadata and diagnostics remain opt-in. To enable them, add the following entry to the configuration's `env` object and restart:

```json
{
  "DIAPHORA_ENABLE_LEGACY_TOOLS": "1"
}
```

These tools use heuristics; their scores do not prove semantic equivalence, security fixes or causation. [Configuration](docs/CONFIGURATION.md) · [GUI setup](GUI_INSTRUCTIONS.md).

## Troubleshooting

| Symptom | Action |
| --- | --- |
| Target already exists | Use a fresh run directory or output filename |
| Output outside allowed root | Choose a destination under `DIAPHORA_OUTPUT_ROOT`; create the root first |
| IDA database passed to a result tool | Use returned `.diaphora.sqlite` exports or `.diaphora` results, as appropriate |
| Missing/ambiguous counterpart | Check old/new order and mapping; inspect the candidate manually |
| Empty assembly/pseudocode | Check the export profile; obtain a new detailed export |
| Export/diff takes a long time | Increase the MCP client timeout; inspect local `logs/`; consider a summaries-only first pass |
| IDB locked by an IDA session | Close the session or use the matching GUI export mode for a single export |
| Unsupported schema | Re-export with the supported Diaphora version; see the reported missing tables/columns |

Matching remains heuristic; a high ratio is evidence, not proof. Unmatched functions are not confirmed additions/deletions. Keep binaries, IDBs, exports and logs out of Git. See [Workflows](docs/WORKFLOWS.md), [Limitations](docs/LIMITATIONS.md), and [Security](SECURITY.md).

## Development

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m compileall -q .
git diff --check
```

The regression suite uses synthetic databases and mocked IDA processes. Real IDA export requires local integration validation. [Contributing](CONTRIBUTING.md) · [Agent instructions](AGENTS.md).
