"""Diaphora MCP — GUI IDA Pro XML-RPC Listener.

Place this file in your IDA Pro plugins directory, or run it via Alt+F7 inside IDA.
It starts an XML-RPC server on port 28652 allowing the MCP server to trigger
exports of the currently active GUI database.
"""

import os
import sys
import threading
from xmlrpc.server import SimpleXMLRPCServer
import idaapi

PORT = 28652
DIAPHORA_DIR = r"D:\Programs\IDA Professional 9.3\plugins\diaphora-3.4.1"

# Make sure Diaphora module can be imported
if DIAPHORA_DIR not in sys.path:
    sys.path.insert(0, DIAPHORA_DIR)


class DiaphoraGuiAPI:

    def ping(self) -> bool:
        """Simple ping to verify server is alive."""
        print("[Diaphora MCP] Received ping request")
        return True

    def export_current_db(self, output_path: str, use_decompiler: bool) -> bool | str:
        """Triggers export of the active database in the main IDA GUI thread."""
        print(
            f"[Diaphora MCP] Export request received: out={output_path}, decomp={use_decompiler}"
        )

        def do_export() -> bool | str:
            # Set environment variables that Diaphora checks for auto-export
            os.environ["DIAPHORA_AUTO"] = "1"
            os.environ["DIAPHORA_EXPORT_FILE"] = output_path
            os.environ["DIAPHORA_USE_DECOMPILER"] = (
                "1" if use_decompiler else "0"
            )

            try:
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
                ]:
                    os.environ.pop(var, None)

        # Run safely in the main thread of IDA GUI
        result = idaapi.execute_sync(do_export, idaapi.MFF_WRITE)
        return result


server = None


def start_server():
    global server
    try:
        server = SimpleXMLRPCServer(
            ("127.0.0.1", PORT), logRequests=False, allow_none=True
        )
        server.register_instance(DiaphoraGuiAPI())
        print(f"[Diaphora MCP] GUI listener active on port {PORT}")
        server.serve_forever()
    except Exception as e:
        print(f"[Diaphora MCP] Failed to start RPC server: {e}")


# Run the server in a daemon thread so it doesn't block the IDA GUI
t = threading.Thread(target=start_server, daemon=True)
t.start()
