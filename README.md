[Читать на русском языке](README.ru.md)

# Diaphora MCP

**Diaphora MCP** is an MCP (Model Context Protocol) server for automated binary diffing. It connects [Diaphora](https://github.com/joxeankoret/diaphora) (the diffing engine) and IDA Pro (the disassembler) via the MCP protocol, allowing AI agents (such as Claude Code) to perform binary file comparison, find security patches, and analyze changes.

## Features

- **Export**: Converts analyzed `.i64` / `.idb` databases to the Diaphora SQLite format (via `idat.exe` headless mode)
- **Diffing**: Compares two exported databases, filters results by match type and ratio
- **Vulnerability Analysis**: Searches for security-relevant changes using keyword matching and heuristics
- **Patch Detection**: Automatically detects new bounds checks, null checks, error handling, and cryptographic changes
- **Ranking**: Ranks changed functions by importance based on CFG, complexity jumps, and security indicators
- **Call Graph**: Compares call paths (BFS, up to N levels), and detects root-cause changes in call cascades
- **Metadata Transfer**: Prepares names, comments, and prototypes for transfer between databases
- **IDA Pro MCP Integration**: All tools return addresses and database paths ready to be passed directly to IDA Pro MCP tools

## Installation

### 1. Dependencies

- Python 3.10+
- [IDA Pro](https://hex-rays.com/IDA-pro/) 8.x / 9.x (for headless exports via `idat.exe`)
- [Diaphora](https://github.com/joxeankoret/diaphora) plugin installed in IDA
- [Claude Code](https://claude.ai/code) (or any other MCP-compliant client)

### 2. Package Installation

```bash
git clone https://github.com/xTeardx/diaphora-mcp.git
cd diaphora-mcp
pip install -e .
```

### 3. Path Configuration

The package tries to **automatically find** IDA Pro and Diaphora in standard installation locations. If not found, you can set the following environment variables:

| Variable | Description | Example |
|-----------|-------------|---------|
| `IDAT_PATH` | Full path to idat.exe | `C:\Program Files\IDA Pro 9.3\idat.exe` |
| `DIAPHORA_DIR` | Folder containing diaphora.py | `C:\Program Files\IDA Pro 9.3\plugins\diaphora-3.4.1` |
| `DIAPHORA_PYTHON` | Python interpreter for diff | `/usr/bin/python3` (defaults to sys.executable) |

For Claude Code, you can specify them in `~/.claude.json` (or the corresponding config file of your MCP client):

```json
{
  "mcpServers": {
    "diaphora": {
      "command": "python",
      "args": ["path/to/repo/diaphora_mcp_server.py"],
      "env": {
        "IDAT_PATH": "C:\\Program Files\\IDA Pro 9.3\\idat.exe",
        "DIAPHORA_DIR": "C:\\Program Files\\IDA Pro 9.3\\plugins\\diaphora-3.4.1"
      },
      "timeout": 7200
    }
  }
}
```

> **Note:** For very large binaries (>100 MB), ensure `timeout` is at least **7200** (2 hours).

### 4. Preparing Databases for Diffing

IDA Pro must analyze the binaries first (creating `.i64` or `.idb` files). After that:

```
┃ export_idb_to_diaphora(idb_path="old_version.i64")
┃ export_idb_to_diaphora(idb_path="new_version.i64")
```

Or run the full pipeline in one command:

```
┃ batch_export_and_diff(idb1="old.i64", idb2="new.i64")
```

## Usage

### Quick Start

```
┃ # 1. Full pipeline: export two .i64 → diff → summary report
┃ batch_export_and_diff(idb1="v1.0.i64", idb2="v1.1.i64")
 
┃ # 2. If databases are already exported
┃ diff_diaphora_dbs(db1="v1.0.sqlite", db2="v1.1.sqlite")
 
┃ # 3. Security analysis of diff results
┃ analyze_diff_results(results_path="v1.0_vs_v1.1.diaphora")
 
┃ # 4. Importance ranking of changes
┃ rank_changes(results_path="v1.0_vs_v1.1.diaphora", top_n=20)
 
┃ # 5. Find root-cause changes
┃ find_patch_root(results_path="v1.0_vs_v1.1.diaphora")
 
┃ # 6. Detect probable security patches
┃ detect_security_patches(results_path="v1.0_vs_v1.1.diaphora")
 
┃ # 7. Generate full report
┃ summarize_patch(results_path="v1.0_vs_v1.1.diaphora")
```

### Investigating a Single Database

```
┃ # Get database export info
┃ get_export_info(db_path="app.sqlite")
 
┃ # Search for functions
┃ search_export_db(db_path="app.sqlite", name_pattern="%crypt%", min_instructions=50)
 
┃ # Retrieve pseudocode
┃ get_function_pseudocode(db_path="app.sqlite", address="401000")
```

## Project Structure

```
diaphora-mcp/
├── diaphora_mcp_server.py          # Main entrypoint
├── diaphora_mcp/
│   ├── diaphora_mcp_server.py      # MCP tool registration
│   ├── config.py                   # Path configuration and auto-detection
│   ├── models.py                   # Constants and models
│   ├── core/
│   │   ├── export.py               # Headless export, batch pipeline
│   │   ├── diff.py                 # Diffing and .diaphora results reader
│   │   ├── analysis.py             # Function search, compare, explain
│   │   ├── security.py             # Keyword matching, patch detection
│   │   ├── ranking.py              # Importance ranking
│   │   ├── graph.py                # Callgraph, BFS call trees, root cause
│   │   ├── metadata.py             # Metadata preparation (names, comments)
│   │   └── report.py               # Overall patch report generation
│   └── utils/
│       ├── sqlite.py               # SQLite helpers
│       ├── format.py               # Pseudocode diff, feature vector extraction
│       └── log.py                  # Export logging utilities
├── _diaphora_headless.py           # idat.exe -S thin wrapper
└── logs/                           # Automated export logs (created dynamically)
```

## MCP Tools Reference (20 tools)

### Export
| Tool | Description |
|------|-------------|
| `export_idb_to_diaphora` | Exports `.i64`/`.idb` database to SQLite format using IDA headless |
| `batch_export_and_diff` | Full pipeline: export primary → export secondary → diff → summary |

### Diff
| Tool | Description |
|------|-------------|
| `diff_diaphora_dbs` | Diffs two exported Diaphora SQLite databases |
| `get_diff_results` | Reads `.diaphora` diff file with filtering |
| `get_diff_summary` | Returns match statistics |

### Analysis
| Tool | Description |
|------|-------------|
| `analyze_diff_results` | Screens results using security keywords and filters |
| `compare_functions` | Side-by-side comparison of a function in both databases |
| `find_function_match` | Matches a function in the second binary with confidence metrics |
| `explain_similarity` | Breaks down similarity factors (mnemonics, CFG, constants, prototype, hash) |
| `detect_behavior_change` | Provides natural language summary of function logic changes |
| `summarize_patch` | Produces comprehensive update report |
| `search_export_db` | Queries exported functions by name/instructions/complexity |
| `get_function_pseudocode` | Fetches pseudocode and metadata for a function |
| `get_export_info` | Retrieves general database metadata |

### Security
| Tool | Description |
|------|-------------|
| `detect_security_patches` | Detects probable security fixes (bounds checks, memory safety, anti-debug, etc.) |

### Ranking
| Tool | Description |
|------|-------------|
| `rank_changes` | Ranks changed functions by importance (0-100 score) |

### Callgraph
| Tool | Description |
|------|-------------|
| `get_changed_callgraph` | Compares incoming and outgoing calls of a function |
| `compare_call_path` | Walks callgraph from a function (BFS call path comparison, up to N levels) |
| `find_patch_root` | Detects root-cause functions causing call cascades |

### Metadata
| Tool | Description |
|------|-------------|
| `transfer_metadata` | Prepares names, comments, and prototypes for bulk transfer |

## IDA Pro GUI Integration (XML-RPC Bridge)

The project includes built-in integration with running GUI IDA Pro sessions, enabling instant exports directly from active IDA windows without database locking conflicts.

1. **Auto-start**: Copy [diaphora_gui_listener.py](diaphora_gui_listener.py) to your IDA Pro `plugins/` directory. It will start a background XML-RPC server on port `28652` whenever IDA starts.
2. **Smart Export**: When calling `export_idb_to_diaphora`, the MCP server checks port `28652`. If a session is active, it runs the export directly in the GUI. Otherwise, it automatically falls back to headless background execution via `idat.exe`.

For detailed instructions on configuring the bridge, see [GUI_INSTRUCTIONS.md](GUI_INSTRUCTIONS.md).

## Handling Gigantic Databases (100k+ functions)

When processing extremely large projects, Diaphora MCP applies specific optimizations:
- **Recursion Limit**: Python recursion limit is automatically raised to `100000` (`sys.setrecursionlimit`) to prevent crashes during large callgraph traversals.
- **SQLite Transaction Optimizations**: In your `diaphora_config.py`, setting `COMMIT_AFTER_EACH_GUI_UPDATE = False` reduces disk writes, speeding up GUI export 2x to 3x.
- **Hex-Rays Microcode**: Disable microcode export (`EXPORTING_USE_MICROCODE = False` in Diaphora config) for a faster export when decompiler is not strictly required.

## IDA Pro MCP Integration

Tools like `analyze_diff_results`, `compare_functions`, and `find_function_match` return an `ida_pro_mcp` block containing addresses and paths. This information can be passed directly to the `ida-pro-mcp` tools:

```
┃ # 1. Diaphora finds a suspicious function
┃ analyze_diff_results(results_path="diff.diaphora")
┃   → addr1="401000", db1="old.sqlite"
 
┃ # 2. IDA Pro MCP decompiles it
┃ decompile_function(address="401000")
```

## Examples

To see Diaphora MCP in action, check out the following examples:
- [Diffing sqlite3.dll (AIMP vs Python)](examples/sqlite3_example.md): A step-by-step guide to exporting, diffing, and comparing functions with different addresses using real-world DLLs on your system. Also available in [Russian](examples/sqlite3_example.ru.md).

## AI Agent Guidelines (Important)

If you are an AI coding assistant (like Claude Code) using this protocol, keep the following compatibility rules in mind:

1. **GUI vs. Headless Export Schemas**:
   - Exporting via an active GUI session (`ida_mcp.py` plugin) produces a custom schema containing tables like `calls`, `strings`, `structures`, but **no `program` table**.
   - Headless export (via `idat.exe`) produces the official Diaphora schema containing the `program` table.
   - **Crucial**: The diff engine (`diff_diaphora_dbs`) requires the official schema. **Always export headlessly if you intend to compare/diff databases**.
   
2. **Locked Databases in GUI**:
   - A database currently open in GUI IDA Pro is locked. Attempting to export it headlessly will fail.
   - If you need to diff the currently open database, ask the user to close it in the GUI (or open a dummy database) to release the file lock, then trigger a headless export.

3. **Avoid Database Name Collisions**:
   - Diaphora export databases default to `<basename>.diaphora.sqlite`.
   - Never use `<basename>.sqlite` for Diaphora exports, as this conflicts with the internal cache database created by the `ida-pro-mcp` supervisor.

## License

MIT
