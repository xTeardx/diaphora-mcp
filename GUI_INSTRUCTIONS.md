[Читать на русском языке](GUI_INSTRUCTIONS.ru.md)

# Diaphora MCP GUI Bridge and Headless Integration

The GUI Bridge allows the MCP server to run database exports instantly from a running, active IDA Pro instance on your screen. This avoids file-locking conflicts and eliminates the need to close IDA.

---

## Recommended: headless IDA MCP

For Codex, the recommended setup is the headless `idalib-mcp` service. It is the backend for upstream `ida-pro-mcp`; you do not need to add a separate Codex server named `idalib-mcp`.

1. Install the upstream plugin and register it with Codex:
   ```powershell
   uv run ida-pro-mcp --install codex --transport streamable-http --scope global --ida-rpc http://127.0.0.1:8745/mcp
   ```
2. Activate IDA Library (adjust the path for your installation):
   ```powershell
   uv run "D:\Programs\IDA Professional 9.3\idalib\python\py-activate-idalib.py"
   ```
3. Start the backend:
   ```powershell
   uv run idalib-mcp --host 127.0.0.1 --port 8745 --max-workers 2
   ```
4. Fully restart Codex, then verify the `idb_list` and `idb_open` tools.

`diaphora-mcp` remains a separate stdio server from this repository: it exports IDBs to SQLite, runs Diaphora diff, and analyzes results.

## Optional GUI bridge

The upstream installer places `ida_mcp.py` in the user plugin directory. Manual copying from this repository is not required:

```powershell
uv run ida-pro-mcp --install codex --transport streamable-http --scope global --ida-rpc http://127.0.0.1:8745/mcp
```

Restart IDA Pro and open the target IDB. The plugin loads automatically; the exact menu item or hotkey depends on the upstream version and is not a reliable health check.

`diaphora_gui_listener.py` is this project's optional legacy XML-RPC fallback on port `28652`. Install it only when that GUI fallback is explicitly needed.

---

## Step 2. Running and Verifying the Setup

1. Open your database (e.g., `sqlite3_aimp.dll.i64`) in IDA Pro GUI.
2. Check that the backend is reachable on port `8745`; for the legacy GUI fallback, check port `28652`.
3. Verify upstream access through the `idb_list`/`idb_open` MCP tools rather than a fixed menu item.
4. Ask your AI agent to export the database:
   > *“Export sqlite3_aimp.dll.i64”*
5. If the IDB is already open in GUI, export may use the active GUI bridge. Otherwise the server uses headless `idat.exe`.

Do not run a headless export while `idb_open` holds the same IDB: IDA may keep a file lock. Close that session or use a copy of the database.

For the legacy GUI fallback, the IDA Output Window may show:
   ```
   [MCP] Plugin loaded, server will start automatically
   Config: http://127.0.0.1:13337/config.html
   Diaphora: http://127.0.0.1:13337/diaphora/health
   ```
6. The terminal will log the export progress in real-time:
   ```
   [Diaphora MCP] Export progress: 6% (200/3362 functions)...
   [Diaphora MCP] Export progress: 12% (400/3362 functions)...
   ```

---

## Parallel Headless Exports

If you request a database that is **not currently open in the GUI**, the server starts a headless `idat.exe` process when `IDAT_PATH`, `DIAPHORA_DIR`, and `DIAPHORA_OUTPUT_ROOT` are configured correctly.

Your active GUI session will remain fully responsive and unaffected during the entire headless export.
