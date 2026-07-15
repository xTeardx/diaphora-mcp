# Limitations and known behavior

## Analysis quality

Diaphora matching combines names, hashes, CFG features, instruction-level signals, and heuristics. Address rebasing is expected between builds. A high ratio or `best` category does not prove semantic identity; inspect the actual function and callers.

Security and behavior tools are triage aids. They can miss changes, over-report benign changes, and cannot establish exploitability without manual validation.

## IDA and Diaphora dependencies

The project does not bundle IDA Pro or Diaphora. Export behavior depends on the installed IDA/Diaphora versions, processor modules, decompiler availability, process state, and database quality.

Headless export is the reproducible path for diffing. GUI bridges are optional and require the correct IDB to be open. An open IDB may hold locks that prevent another IDA process from using it.

## Performance

Large databases can require minutes or hours. `use_decompiler=true` is substantially slower. `summaries_only=true` is useful for a fast first pass but reduces low-level detail. Set MCP client timeouts accordingly.

## Data and security boundaries

The server reads local IDA databases and writes generated SQLite/diff files under the configured output root. Do not point it at directories containing unrelated sensitive data. Never commit binaries, IDBs, exports, logs, crash files, or credentials.

The MCP server is a local tool process. Client approval policies, filesystem permissions, IDA plugin behavior, and the security of connected MCP servers remain outside this repository.

## Unsupported assumptions

- `.i64`/`.idb` is not interchangeable with Diaphora SQLite.
- The upstream `ida-pro-mcp`/`idalib-mcp` server is not a diff engine.
- GUI export is not a drop-in replacement for headless diff exports.
- A heuristic security flag is not a vulnerability verdict.
