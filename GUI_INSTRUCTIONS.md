[Читать на русском языке](GUI_INSTRUCTIONS.ru.md)

# Installation and Usage Instructions for the Diaphora MCP GUI Bridge

The GUI Bridge allows the MCP server to run database exports instantly from a running, active IDA Pro instance on your screen. This avoids file-locking conflicts and eliminates the need to close IDA.

---

## Step 1. Installing the Plugin in IDA Pro

You have two options to run the listener plugin in IDA Pro:

### Option A: Automatic Start (Recommended)
Copy the `diaphora_gui_listener.py` file to your IDA Pro plugins directory:
* Path: `<IDA_INSTALL_DIR>\plugins\` (e.g. `C:\Program Files\IDA Pro 9.3\plugins\`)

*The plugin will run automatically in the background on port 28652 every time IDA Pro starts.*

### Option B: Manual Start (For one-time testing)
1. In your active IDA Pro window, press **Alt+F7** (or select `File` -> `Script file...` from the menu).
2. Select the `diaphora_gui_listener.py` script from the root of this repository:
   `<DIAPHORA_MCP_REPO_DIR>\diaphora_gui_listener.py`
3. You should see the following line in the Output Window at the bottom of IDA Pro:
   `[Diaphora MCP] GUI listener active on port 28652`

---

## Step 2. Verifying the Setup

1. Open any project (e.g., `aces.exe.i64`) in IDA Pro GUI and ensure the listener plugin is active.
2. Ask your AI Agent to export the database:
   > *“Export <PATH_TO_YOUR_IDB>\aces.exe.i64”*
3. The MCP server will detect the running GUI session, forward the request to port 28652, and log:
   `[Diaphora MCP] Active GUI IDA Pro session found! Exporting via GUI...`
4. The export will execute directly inside your active IDA Pro session, writing the results to SQLite without restarting processes.
