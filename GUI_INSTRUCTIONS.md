[Читать на русском языке](GUI_INSTRUCTIONS.ru.md)

# Installation and Usage Instructions for the Diaphora MCP GUI Bridge

The GUI Bridge allows the MCP server to run database exports instantly from a running, active IDA Pro instance on your screen. This avoids file-locking conflicts and eliminates the need to close IDA.

---

## Step 1. Installing the Plugin in IDA Pro

The plugin is part of the `ida-pro-mcp` package. To install it:
1. Locate the `ida_mcp.py` plugin file in the repository under `idalib/ida_mcp.py`.
2. Copy it to your IDA Pro user plugins directory:
   - **Windows**: `%APPDATA%\Hex-Rays\IDA Pro\plugins\ida_mcp.py` (e.g. `C:\Users\<Name>\AppData\Roaming\Hex-Rays\IDA Pro\plugins\ida_mcp.py`)
   - **macOS/Linux**: `~/.idapro/plugins/ida_mcp.py`

*The plugin will load automatically when you open IDA Pro GUI.*

---

## Step 2. Running and Verifying the Setup

1. Open your database (e.g., `sqlite3_aimp.dll.i64`) in IDA Pro GUI.
2. In IDA Pro menu, select **Edit -> Plugins -> MCP** (or press **Ctrl+Alt+M**) to start the MCP integration HTTP server.
3. You should see the following lines in the Output Window at the bottom of IDA Pro:
   ```
   [MCP] Plugin loaded, server will start automatically
   Config: http://127.0.0.1:13337/config.html
   Diaphora: http://127.0.0.1:13337/diaphora/health
   ```
4. Ask your AI Agent to export the database:
   > *“Export sqlite3_aimp.dll.i64”*
5. The client will detect the running GUI session on port `13337`, verify that it has the requested file open, and trigger the export in a thread-safe background worker.
6. The terminal will log the export progress in real-time:
   ```
   [Diaphora MCP] Export progress: 6% (200/3362 functions)...
   [Diaphora MCP] Export progress: 12% (400/3362 functions)...
   ```

---

## Parallel Headless Exports

If you request an export of a database file that is **not currently open in the GUI**, the client will automatically bypass the GUI and spawn a headless `idat.exe` process in the background. 

Your active GUI session will remain fully responsive and unaffected during the entire headless export.
