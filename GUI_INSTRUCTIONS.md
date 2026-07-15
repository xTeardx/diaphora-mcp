[Русская версия](GUI_INSTRUCTIONS.ru.md)

# GUI, headless, and IDA integration

This project has three separate pieces that are often confused:

| Component | Role | Transport/port |
| --- | --- | --- |
| `diaphora-mcp` | Export IDA databases, run Diaphora diff, analyze results | Local stdio MCP server |
| `ida-pro-mcp` / `idalib-mcp` | Inspect IDA databases, open functions, decompile, and validate addresses | Upstream service, commonly `127.0.0.1:8745` |
| `diaphora_gui_listener.py` | Optional legacy GUI export fallback | XML-RPC, `127.0.0.1:28652` |

The upstream IDA inspection service does not replace the Diaphora diff server. Use both only when you need both workflows.

## Choose the export mode first

`export_idb_to_diaphora` exposes an explicit `export_mode`:

| Mode | Behavior | Recommendation |
| --- | --- | --- |
| `headless` | Always starts `idat.exe`/`idat64.exe` and validates the official diff schema | Use for matching and batch diff |
| `auto` | Tries the active HTTP GUI integration, then the legacy listener, then headless | Use for convenient single exports |
| `gui` | Uses only an active matching GUI integration; never falls back | Use only when GUI export is intentional |

`batch_export_and_diff` requires `export_mode="headless"`. GUI output is accepted only if it passes the same schema checks required for matching.

## Recommended setup for address-level inspection

This is optional and independent of the Diaphora server.

1. Install/register the upstream IDA MCP integration for your client:

   ```powershell
   uv run ida-pro-mcp --install codex --transport streamable-http --scope global --ida-rpc http://127.0.0.1:8745/mcp
   ```

2. Activate the IDA Library environment for your installation if the upstream setup requires it:

   ```powershell
   uv run "C:\Path\To\IDA\idalib\python\py-activate-idalib.py"
   ```

3. Start the upstream inspection backend:

   ```powershell
   uv run idalib-mcp --host 127.0.0.1 --port 8745 --max-workers 2
   ```

4. Restart the MCP client and verify the upstream `idb_list`/`idb_open` tools.

5. Keep `diaphora-mcp` configured separately as a stdio server. Its tools are `export_idb_to_diaphora`, `batch_export_and_diff`, diff readers, matching, graph, ranking, and report tools.

## Optional GUI export integrations

### HTTP integration

If the upstream IDA plugin exposes the Diaphora endpoints, the server probes:

```text
GET  http://127.0.0.1:13337/diaphora/health
POST http://127.0.0.1:13337/diaphora/export
```

Do not copy or replace an upstream `ida_mcp.py` manually. Install the upstream integration using its installer, then restart IDA Pro and open the requested IDB. The exact menu item or hotkey is version-dependent; a successful health check/export is the reliable test.

### Legacy XML-RPC listener

`diaphora_gui_listener.py` is an optional fallback maintained by this repository. Install it only when you specifically need the legacy GUI path. It listens on `127.0.0.1:28652` and verifies the requested IDB path before exporting.

The listener is not required for headless operation and should not be treated as the primary matching path.

## End-to-end matching workflow

1. Analyze and save both `.i64`/`.idb` inputs.
2. Call `batch_export_and_diff` with `export_mode="headless"`, `use_decompiler=false`, and `summaries_only=true` for a fast first pass.
3. Keep the returned `.diaphora.sqlite` and `.diaphora` paths.
4. Read the result with `get_diff_summary` or `get_diff_results`.
5. For an old address, call `find_function_match`.
6. Call `compare_functions`, `get_changed_callgraph`, or `compare_call_path` with `match_results_path` so rebased addresses are mapped correctly.
7. Use upstream `ida-pro-mcp`/`idalib-mcp` to inspect the original IDA address after the match is confirmed.

Example:

```text
batch_export_and_diff(
  idb1_path="C:/analysis/old.i64",
  idb2_path="C:/analysis/new.i64",
  output_dir="C:/diaphora-outputs/old-new",
  export_mode="headless",
  summaries_only=true,
  use_decompiler=false
)

compare_functions(
  db1_path=OLD_SQLITE,
  db2_path=NEW_SQLITE,
  address="1800d6b80",
  match_results_path=RESULTS
)
```

## Locks and process safety

Do not start headless IDA against an IDB that is currently being held open by another IDA process. Use one of these paths:

- close the GUI IDB and run `export_mode="headless"`;
- export a copy of the IDB;
- use `export_mode="gui"` against the active session when that integration is available.

The server may stage a copy when it detects a lock, but a copy is not a substitute for saving the latest GUI analysis. Always save first and verify which file is being exported.

## Restart checklist

Restart the relevant layer after changing it:

- changed `diaphora_mcp` Python code or environment: restart the `diaphora-mcp` stdio server/client;
- changed upstream `ida_mcp.py`: restart IDA Pro and the upstream backend;
- changed `diaphora_gui_listener.py`: restart IDA Pro;
- changed only an IDB analysis: save the IDB, then rerun the export.

On Windows, identify the process command line before stopping anything. Stop only the Diaphora server when restarting it; do not terminate unrelated IDA or `idalib-mcp` processes.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `idat.exe not found` | Verify `IDAT_PATH` and restart the server |
| GUI mode unavailable | Confirm the requested IDB is open and the correct bridge is responding |
| Export succeeds but diff rejects it | Use `headless`; the output is missing the official `program`/call-graph metadata |
| Function is not found in the new DB | Use the `.diaphora` result as `match_results_path`; do not reuse the old address directly |
| Export hangs | Check IDA locks, disk activity, timeout, and the generated export log |
| Results tools reject input | Pass `.diaphora.sqlite`/`.diaphora`, not `.i64`/`.idb` |
