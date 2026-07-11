"""Diaphora MCP — GUI IDA Pro XML-RPC Listener Plugin.

This is a formal IDA Pro plugin. Copy it to your IDA plugins directory
to automatically start the listener on port 28652 at IDA startup.
"""

import os
import sys
import threading
import uuid
from xmlrpc.server import SimpleXMLRPCServer
import idaapi

PORT = 28652

# Auto-detect DIAPHORA_DIR relative to this plugin file if placed in IDA plugins directory
PLUGINS_DIR = os.path.dirname(os.path.abspath(__file__))
DIAPHORA_DIR = ""

# Look for any subdirectory containing "diaphora" in plugins
if os.path.isdir(PLUGINS_DIR):
    for entry in sorted(os.listdir(PLUGINS_DIR), reverse=True):
        full = os.path.join(PLUGINS_DIR, entry)
        if os.path.isdir(full) and "diaphora" in entry.lower():
            if os.path.isfile(os.path.join(full, "diaphora.py")):
                DIAPHORA_DIR = full
                break

# Generic fallback placeholder if not found (user should customize)
if not DIAPHORA_DIR:
    # Check common install/plugin locations as candidate fallbacks
    _candidates = [
        r"D:\Programs\IDA Professional 9.3\plugins\diaphora-3.4.1",
        r"D:\Programs\IDA 9.3\plugins\diaphora-3.4.1",
        r"C:\Program Files\IDA Pro 9.3\plugins\diaphora-3.4.1",
        r"C:\Program Files\IDA Pro 9.2\plugins\diaphora-3.4.1",
    ]
    for c in _candidates:
        if os.path.isdir(c) and os.path.isfile(os.path.join(c, "diaphora.py")):
            DIAPHORA_DIR = c
            break

if not DIAPHORA_DIR:
    DIAPHORA_DIR = r"C:\Path\To\IDA\plugins\diaphora-3.4.1"


# Make sure Diaphora module can be imported
if DIAPHORA_DIR not in sys.path:
    sys.path.insert(0, DIAPHORA_DIR)


class DiaphoraGuiAPI:

    def ping(self) -> bool:
        """Simple ping to verify server is alive."""
        print("[Diaphora MCP] Received ping request")
        return True

    def version(self) -> int:
        """Return the API version of this listener. 2 = summaries_only supported."""
        return 2

    def get_idb_path(self) -> str:
        """Return the absolute path of the currently open IDB."""
        return idaapi.get_idb_path()

    def export_current_db(self, output_path: str, use_decompiler: bool, summaries_only: bool = False) -> bool | str:
        """Triggers export of the active database in the main IDA GUI thread."""
        current_idb = os.path.realpath(idaapi.get_idb_path())
        configured_root = os.path.realpath(
            os.environ.get("DIAPHORA_OUTPUT_ROOT") or os.path.dirname(current_idb)
        )
        target = os.path.realpath(output_path)
        try:
            if os.path.commonpath([configured_root, target]) != configured_root:
                return f"Output path must be inside the configured output root: {configured_root}"
        except ValueError:
            return "Output path is on a different volume from the configured output root"
        if os.path.lexists(output_path):
            return f"Refusing to overwrite existing output path: {output_path}"
        target_output_path = output_path
        target = os.path.abspath(output_path)
        staged_output_path = os.path.join(
            os.path.dirname(target),
            f".{os.path.basename(target)}.{uuid.uuid4().hex}.tmp",
        )
        print(
            f"[Diaphora MCP] Export request received: out={output_path}, decomp={use_decompiler}, summaries={summaries_only}"
        )

        def do_export() -> bool | str:
            # Set environment variables that Diaphora checks for auto-export
            os.environ["DIAPHORA_AUTO"] = "1"
            os.environ["DIAPHORA_EXPORT_FILE"] = staged_output_path
            if use_decompiler:
                os.environ["DIAPHORA_USE_DECOMPILER"] = "1"
            else:
                os.environ.pop("DIAPHORA_USE_DECOMPILER", None)

            if summaries_only:
                os.environ["DIAPHORA_FUNCTION_SUMMARIES_ONLY"] = "1"
            else:
                os.environ.pop("DIAPHORA_FUNCTION_SUMMARIES_ONLY", None)

            try:
                import sys
                sys.setrecursionlimit(100000)

                import diaphora_ida

                # Reload module if already imported to ensure clean state
                if "diaphora_ida" in sys.modules:
                    import importlib

                    importlib.reload(diaphora_ida)

                print("[Diaphora MCP] Running Diaphora export...")
                diaphora_ida.main()
                print("[Diaphora MCP] Export completed successfully!")
                return True
            except Exception as e:
                import traceback

                err_msg = f"Export failed: {e}\n{traceback.format_exc()}"
                print(f"[Diaphora MCP] {err_msg}")
                return err_msg
            finally:
                # Clean up env vars
                for var in [
                    "DIAPHORA_AUTO",
                    "DIAPHORA_EXPORT_FILE",
                    "DIAPHORA_USE_DECOMPILER",
                    "DIAPHORA_FUNCTION_SUMMARIES_ONLY",
                ]:
                    os.environ.pop(var, None)

        # Run safely in the main thread of IDA GUI
        result = idaapi.execute_sync(do_export, idaapi.MFF_WRITE)
        if result is not True:
            try:
                if os.path.lexists(staged_output_path):
                    os.remove(staged_output_path)
            except OSError:
                pass
            return result
        if not os.path.isfile(staged_output_path):
            if os.path.lexists(target_output_path):
                return f"Refusing to overwrite existing output path: {target_output_path}"
            return "Export completed without producing a staged output file"
        try:
            os.link(staged_output_path, target_output_path)
        except FileExistsError:
            return f"Refusing to overwrite existing output path: {target_output_path}"
        except OSError as exc:
            return f"Failed to publish export output: {exc}"
        finally:
            try:
                if os.path.lexists(staged_output_path):
                    os.remove(staged_output_path)
            except OSError:
                pass
        return True


server = None
server_thread = None


def start_server():
    global server
    try:
        # allow_reuse_address is True by default in SimpleXMLRPCServer
        server = SimpleXMLRPCServer(
            ("127.0.0.1", PORT), logRequests=False, allow_none=True
        )
        server.register_instance(DiaphoraGuiAPI())
        print(f"[Diaphora MCP] GUI listener active on port {PORT}")
        server.serve_forever()
    except Exception as e:
        print(f"[Diaphora MCP] Failed to start RPC server: {e}")


class DiaphoraMcpListenerPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL  # Unloadable plugin
    comment = "Diaphora MCP GUI RPC Listener"
    help = "Starts a background XML-RPC server on port 28652 for MCP exports"
    wanted_name = "Diaphora MCP Listener"
    wanted_hotkey = ""

    def init(self):
        global server_thread
        # Start server thread if not already running
        if server_thread is None or not server_thread.is_alive():
            server_thread = threading.Thread(target=start_server, daemon=True)
            server_thread.start()
        return idaapi.PLUGIN_KEEP  # Keep the plugin in memory

    def run(self, arg):
        # Called if user selects the plugin from the menu
        print(f"[Diaphora MCP] Listener is already active on port {PORT}")

    def term(self):
        global server
        # Shutdown the server cleanly when IDA exits
        if server is not None:
            try:
                server.shutdown()
                print("[Diaphora MCP] Listener stopped")
            except Exception:
                pass


def PLUGIN_ENTRY():
    return DiaphoraMcpListenerPlugin()
