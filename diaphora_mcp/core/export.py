"""
Diaphora MCP — IDB export and batch pipeline.

Handles headless IDA export via idat.exe + Diaphora env-var mechanism,
and the full export→export→diff→summary pipeline.
"""

import asyncio
import json
import os
import subprocess
import threading
import time
import xmlrpc.client
import uuid
from pathlib import Path

import requests
import psutil

from ..config import IDAT_PATH, DIAPHORA_DIR, HEADLESS_WRAPPER, DIAPHORA_SCRIPT, PYTHON
from ..utils.sqlite import check_db, check_db_for_diff, force_delete_file
from ..utils.connection import close_connection, get_connection, get_cache_manager
from ..utils.log import ExportLogger, OperationLogger
from ..utils.format import dumps, err_json


_EXPORT_MODES = {"auto", "headless", "gui"}


def _normalize_export_mode(export_mode: str) -> str | None:
    mode = str(export_mode or "auto").strip().lower()
    return mode if mode in _EXPORT_MODES else None


def _schema_for_export(path: str) -> tuple[str | None, str | None]:
    basic_error = check_db(path)
    if basic_error:
        return None, basic_error
    diff_error = check_db_for_diff(path)
    if diff_error is None:
        return "official_diaphora", None
    return "basic_diaphora", diff_error


def _validate_export_output_path(idb_path: str, output_path: str) -> str | None:
    """Проверить, что новый файл экспорта находится внутри разрешённого каталога."""
    root = Path(os.environ.get("DIAPHORA_OUTPUT_ROOT") or Path(idb_path).parent)
    root = Path(os.path.realpath(root))
    target = Path(output_path)
    target_real = Path(os.path.realpath(target))
    try:
        target_real.relative_to(root)
    except ValueError:
        return f"Output path must be inside the configured output root: {root}"
    if target.exists() or target.is_symlink():
        return f"Refusing to overwrite existing output path: {target}"
    if not root.is_dir():
        return f"Configured output root does not exist: {root}"
    return None


def _staged_export_path(output_path: str) -> str:
    """Вернуть уникальный временный target в том же каталоге, что и output."""
    target = Path(output_path)
    return str(target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp"))


def _publish_staged_export(staged_path: str, output_path: str) -> str | None:
    """Эксклюзивно опубликовать staged-файл, не перезаписывая target."""
    try:
        os.link(staged_path, output_path)
    except FileExistsError:
        return f"Refusing to overwrite existing output path: {output_path}"
    except OSError as exc:
        return f"Failed to publish export output: {exc}"
    try:
        close_connection(staged_path)
        os.remove(staged_path)
    except OSError as exc:
        return f"Export published but temporary file cleanup failed: {exc}"
    return None


def _remove_staged_export(staged_path: str) -> None:
    try:
        if os.path.lexists(staged_path):
            os.remove(staged_path)
    except OSError:
        pass


def _kill_and_reap(proc) -> None:
    """Остановить IDA и дождаться закрытия процесса после timeout/cancellation."""
    try:
        proc.kill()
    except Exception:
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
            proc.wait(timeout=5)
        except (Exception, subprocess.TimeoutExpired):
            pass
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Headless export
# ---------------------------------------------------------------------------
async def run_export(
    idb_path: str,
    output_path: str,
    use_decompiler: bool,
    summaries_only: bool | None = None,
) -> str | None:
    """Run IDA headless export via idat.exe and the headless wrapper.

    Writes a detailed log to logs/export_<timestamp>.log so the user
    can track progress in real time.

    Returns an error string on failure, or None on success.
    """
    if not os.path.isfile(idb_path):
        return f"Input file not found: {idb_path}"
    if not os.path.isfile(IDAT_PATH):
        return f"idat.exe not found at {IDAT_PATH}"
    if not os.path.isfile(HEADLESS_WRAPPER):
        return f"Headless wrapper not found at {HEADLESS_WRAPPER}"

    if summaries_only is None:
        try:
            idb_size = os.path.getsize(idb_path)
            # If IDB/i64 size is > 100 MB, enable summaries_only to avoid long export
            summaries_only = idb_size > 100 * 1024 * 1024
        except Exception:
            summaries_only = False

    # 0. Try via plugin disabled to guarantee official Diaphora schema export
    pass

    # XML-RPC GUI fallback removed to prevent GUI freezes and incorrect database exports

    # Lock file checks and temporary file copying are handled by the caller export_idb_to_diaphora
    pass

    # Running IDA check bypassed to allow headless exports of other databases
    pass

    # ── 4. Headless export via idat.exe ──
    with ExportLogger(idb_path, output_path) as log:
        _clean_stale_locks(idb_path, log)

        env = os.environ.copy()
        env["DIAPHORA_AUTO"] = "1"
        env["DIAPHORA_EXPORT_FILE"] = output_path
        env["DIAPHORA_DIR"] = DIAPHORA_DIR
        if use_decompiler:
            env["DIAPHORA_USE_DECOMPILER"] = "1"
        else:
            env.pop("DIAPHORA_USE_DECOMPILER", None)

        if summaries_only:
            env["DIAPHORA_FUNCTION_SUMMARIES_ONLY"] = "1"
        else:
            env.pop("DIAPHORA_FUNCTION_SUMMARIES_ONLY", None)

        wal_path = output_path + "-wal"
        log.info(f"Launching: {IDAT_PATH} -A -S{HEADLESS_WRAPPER} {os.path.basename(idb_path)}")
        log.info(f"cwd: {DIAPHORA_DIR}")
        log.info(f"DIAPHORA_EXPORT_FILE={output_path}")
        log.info(f"DIAPHORA_USE_DECOMPILER={'1' if use_decompiler else 'None (False)'}")
        log.info(f"DIAPHORA_FUNCTION_SUMMARIES_ONLY={'1' if summaries_only else 'None (False)'}")

        try:
            proc = subprocess.Popen(
                [IDAT_PATH, "-A", f"-S{HEADLESS_WRAPPER}", idb_path],
                cwd=DIAPHORA_DIR,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                text=True,
            )
        except FileNotFoundError:
            log.error(f"idat.exe not found at {IDAT_PATH}")
            return f"idat.exe not found at {IDAT_PATH}"
        except Exception as exc:
            log.error(f"Failed to launch IDA: {exc}")
            return f"Failed to launch IDA headless: {exc}"

        # Monitor progress and read outputs asynchronously to avoid PIPE block
        stdout_chunks = []
        stderr_chunks = []

        def read_pipe(pipe, chunks):
            try:
                for line in pipe:
                    chunks.append(line)
            except Exception as e:
                log.warn(f"Pipe reader thread error: {e}")

        t_out = threading.Thread(target=read_pipe, args=(proc.stdout, stdout_chunks), daemon=True)
        t_err = threading.Thread(target=read_pipe, args=(proc.stderr, stderr_chunks), daemon=True)
        t_out.start()
        t_err.start()

        timeout_seconds = 14400
        idle_timeout = 120
        start_time = time.time()
        last_size = 0
        last_change_time = time.time()

        try:
            while proc.poll() is None:
                if time.time() - start_time > timeout_seconds:
                    _kill_and_reap(proc)
                    log.error(f"Export timed out after {timeout_seconds} s")
                    return f"Export timed out after {timeout_seconds} s"

                current_size = 0
                if os.path.isfile(output_path):
                    try:
                        current_size += os.path.getsize(output_path)
                    except OSError:
                        pass  # file may have been deleted since isfile check
                if os.path.isfile(wal_path):
                    try:
                        current_size += os.path.getsize(wal_path)
                    except OSError:
                        pass

                if current_size != last_size:
                    if last_size != 0:
                        log.info(f"  Export progress: size increased to {current_size} bytes")
                    last_size = current_size
                    last_change_time = time.time()
                else:
                    idle_duration = time.time() - last_change_time
                    if idle_duration > idle_timeout:
                        if check_db_for_diff(output_path) is None:
                            log.info("  Watchdog: DB structure is fully valid, but process is hung. Force terminating.")
                            proc.kill()
                            break

                await asyncio.sleep(5)
        finally:
            if proc.poll() is None:
                try:
                    _kill_and_reap(proc)
                    log.info("Headless export subprocess killed due to cancellation or error.")
                except Exception:
                    pass
            t_out.join(timeout=2)
            t_err.join(timeout=2)
            stdout = "".join(stdout_chunks)
            stderr = "".join(stderr_chunks)

        crash_file = f"{output_path}-crash"
        crash_present = os.path.isfile(crash_file)
        output_exists = os.path.isfile(output_path)
        has_functions = False
        if output_exists:
            has_functions = check_db(output_path) is None

        log.info(f"idat exit code: {proc.returncode}")
        log.info(f"Output file exists: {output_exists}")
        log.info(f"Output has functions: {has_functions}")
        log.info(f"Crash file present: {crash_present}")
        log.log_subprocess_output(stdout or "", stderr or "")

        # Clean up crash-file artifact if DB is actually valid
        if crash_present and has_functions:
            try:
                os.remove(crash_file)
                log.info("Removed stale crash-file (DB is valid)")
                crash_present = False
            except OSError:
                pass

        if crash_present and not has_functions:
            return (
                "Export appears to have crashed (crash file present, DB empty).\n"
                f"  idat stdout (last 2K):\n{(stdout or '')[-2048:]}\n"
                f"  idat stderr (last 2K):\n{(stderr or '')[-2048:]}"
            )

        if not output_exists:
            return (
                "Export completed but no output file was produced.\n"
                f"  idat stdout (last 2K):\n{(stdout or '')[-2048:]}\n"
                f"  idat stderr (last 2K):\n{(stderr or '')[-2048:]}"
            )

        if not has_functions:
            return (
                f"Export produced a database with 0 functions at {output_path}.\n"
                f"  idat stdout (last 2K):\n{(stdout or '')[-2048:]}\n"
                f"  idat stderr (last 2K):\n{(stderr or '')[-2048:]}"
            )

        log.info(f"Export OK — {os.path.getsize(output_path)} bytes, functions OK")

        # Post-check: program table must be filled for diff to work
        try:
            _pc = get_connection(output_path)
            _pcur = _pc.cursor()
            _pcur.execute("SELECT count(*) FROM program")
            if _pcur.fetchone()[0] == 0:
                log.warn(
                    "Export incomplete: program table is empty. "
                    "Callgraph metadata not written — diff will fail on this database. "
                    "This happens when IDA crashes during finalization (see Problems.md #3)."
                )
        except Exception:
            pass

        return None  # success


# ---------------------------------------------------------------------------
# ida_mcp plugin integration
# ---------------------------------------------------------------------------

_PLUGIN_HEALTH_URL = "http://127.0.0.1:13337/diaphora/health"
_PLUGIN_EXPORT_URL = "http://127.0.0.1:13337/diaphora/export"


def _any_ida_running() -> bool:
    """Return ``True`` if an ``ida.exe``, ``ida64.exe``, ``idat.exe``, or ``idat64.exe`` process is running."""
    try:
        for proc in psutil.process_iter(["name"]):
            name = (proc.info["name"] or "").lower()
            if name in ("ida.exe", "ida64.exe", "idat.exe", "idat64.exe"):
                return True
    except Exception:
        pass
    return False


def _ida_plugin_responding(idb_path: str) -> bool:
    """Return ``True`` if the ``ida_mcp`` HTTP endpoint is reachable and has the requested IDB open."""
    try:
        resp = requests.get(_PLUGIN_HEALTH_URL, timeout=2)
        if resp.status_code == 200:
            data = resp.json()
            open_idb = data.get("idb_path", "")
            if open_idb:
                return os.path.normpath(open_idb).lower() == os.path.normpath(idb_path).lower()
        return False
    except requests.RequestException:
        return False


def _try_via_plugin(
    idb_path: str,
    output_path: str,
    use_decompiler: bool,
    summaries_only: bool | None,
) -> str | None:
    """Try to delegate the export to an already-running IDA via the ``ida_mcp`` plugin.

    The plugin uses an asynchronous task pattern:
      1. ``POST /diaphora/export`` → returns ``{"task_id": "…"}`` immediately
      2. Poll ``GET /diaphora/export/<task_id>`` until ``done == True``

    Returns:
        * ``None`` on success (output written to *output_path*).
        * A non-empty error string on failure.
        * The magic value ``"NO_PLUGIN"`` when the plugin is not reachable
          (caller should fall through to another method).
    """
    # Fast path: no IDA running at all → skip the HTTP probe
    if not _any_ida_running():
        return "NO_PLUGIN"

    if not _ida_plugin_responding(idb_path):
        return "NO_PLUGIN"

    if summaries_only is None:
        try:
            idb_size = os.path.getsize(idb_path)
            summaries_only = idb_size > 100 * 1024 * 1024
        except Exception:
            summaries_only = False

    body = {
        "output_path": output_path,
        "use_decompiler": use_decompiler,
        "summaries_only": summaries_only,
    }

    # ── Step 1: POST → start the export task ──
    try:
        resp = requests.post(_PLUGIN_EXPORT_URL, json=body, timeout=30)
        resp.raise_for_status()
        task_data = resp.json()
    except requests.ConnectionError as e:
        return f"ida_mcp plugin connection failed: {e}"
    except requests.RequestException as e:
        return f"ida_mcp plugin HTTP error: {e}"
    except Exception as e:
        return f"ida_mcp plugin unexpected error: {e}"

    if not task_data.get("ok"):
        return f"ida_mcp plugin rejected export: {task_data.get('error', 'unknown')}"

    task_id = task_data.get("task_id")
    if not task_id:
        return "ida_mcp plugin returned ok but no task_id"

    # ── Step 2: Poll until done (max 600 seconds) ──
    poll_url = f"{_PLUGIN_EXPORT_URL}/{task_id}"
    deadline = time.monotonic() + 600

    while time.monotonic() < deadline:
        try:
            poll_resp = requests.get(poll_url, timeout=10)
            poll_resp.raise_for_status()
            status = poll_resp.json()
        except requests.RequestException as e:
            return f"ida_mcp plugin poll error: {e}"

        if status.get("done"):
            if status.get("ok"):
                reported_path = status.get("path", output_path)
                if check_db(reported_path) is not None:
                    return f"ida_mcp plugin reported success but database at {reported_path} is invalid."
                if reported_path != output_path:
                    try:
                        import shutil
                        shutil.copy2(reported_path, output_path)
                    except OSError as e:
                        return f"Failed to copy export result: {e}"
                return None  # success
            else:
                err = status.get("error", "unknown error")
                if err == "cancelled":
                    return "Export cancelled by user during execution (Cancel was pressed in IDA GUI)."
                return f"Export via ida_mcp plugin failed: {err}"
        else:
            percentage = status.get("percentage", 0)
            progress = status.get("progress", 0)
            total = status.get("total", 0)
            if total > 0:
                print(f"[Diaphora MCP] Export progress: {percentage}% ({progress}/{total} functions)...")
            else:
                print(f"[Diaphora MCP] Export is starting/initializing...")

        time.sleep(2)

    return "Export via ida_mcp plugin timed out after 600s."


def _try_via_gui_listener(
    idb_path: str,
    output_path: str,
    use_decompiler: bool,
    summaries_only: bool | None,
) -> str | None:
    """Try to delegate the export to an already-running IDA GUI via XML-RPC listener on port 28652.

    Returns:
        * ``None`` on success (output written to *output_path*).
        * A non-empty error string on failure.
        * The magic value ``"NO_PLUGIN"`` when the listener is not reachable.
    """
    import xmlrpc.client
    try:
        proxy = xmlrpc.client.ServerProxy(
            "http://127.0.0.1:28652",
            allow_none=True,
            use_builtin_types=True,
        )
        # Probe if reachable
        try:
            proxy.ping()
        except Exception:
            return "NO_PLUGIN"

        # Check if version matches/supports get_idb_path
        try:
            open_idb = proxy.get_idb_path()
            if os.path.normpath(open_idb).lower() != os.path.normpath(idb_path).lower():
                # Not the right database open
                return "NO_PLUGIN"
        except Exception:
            # If get_idb_path doesn't exist, we can't verify if it's the right IDB,
            # so we skip GUI listener export to be safe.
            return "NO_PLUGIN"

        if summaries_only is None:
            try:
                idb_size = os.path.getsize(idb_path)
                summaries_only = idb_size > 100 * 1024 * 1024
            except Exception:
                summaries_only = False

        res = proxy.export_current_db(output_path, use_decompiler, summaries_only)
        if res is True:
            if check_db(output_path) is not None:
                return f"GUI listener reported success but database at {output_path} is invalid."
            return None
        else:
            return f"GUI listener export failed: {res}"
    except Exception as e:
        return f"GUI listener unexpected error: {e}"


def _is_ida_running() -> list[tuple[int, str]]:
    """Check if any IDA Pro process is currently running.

    Returns a list of (PID, process_name) tuples for every running
    ``ida64.exe`` or ``idat64.exe`` process.  Empty list means the
    Hex-Rays license is free.
    """
    import psutil

    found: list[tuple[int, str]] = []
    for proc in psutil.process_iter(["name", "pid"]):
        try:
            name = (proc.info["name"] or "").lower()
            if name in ("ida.exe", "ida64.exe", "idat.exe", "idat64.exe"):
                pid = proc.info["pid"]
                if pid is not None:
                    found.append((pid, proc.info["name"]))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return found


def _rpc_shutdown_ida(log: ExportLogger) -> bool:
    """Try to shut down an already-running IDA Pro via XML-RPC on port 13337.

    Port 13337 is the standard control port used by the ``ida_mcp`` /
    ``idalib-mcp`` plugin.  We probe for known exit methods and call the
    first one that matches.

    Returns ``True`` if the RPC call was accepted (the remote process
    *should* begin shutting down), ``False`` if the endpoint is not
    reachable or does not expose a compatible API.
    """
    import xmlrpc.client

    try:
        proxy = xmlrpc.client.ServerProxy(
            "http://127.0.0.1:13337",
            allow_none=True,
            use_builtin_types=True,
        )

        # 1) Discover available methods, if the server supports introspection
        known = []
        try:
            known = proxy.system.listMethods()
            log.info(f"IDA XML-RPC methods available: {known}")
        except Exception:
            pass

        # 2) Try known shutdown methods
        candidates = ["exit", "exit_ida", "shutdown", "save_and_exit", "close"]
        for m in candidates:
            if m in known:
                log.info(f"Calling IDA RPC {m}() with save=True …")
                result = getattr(proxy, m)(True)
                log.info(f"IDA RPC {m}() returned: {result}")
                return True

        # 3) Blind probe (server doesn't support listMethods)
        for m in ("exit", "shutdown", "save_and_exit"):
            try:
                log.info(f"Blind probe: IDA RPC {m}() with save=True …")
                result = getattr(proxy, m)(True)
                log.info(f"IDA RPC {m}() returned: {result}")
                return True
            except (xmlrpc.client.Fault, AttributeError):
                continue

        log.warn("IDA RPC port 13337 responded but no shutdown method found")
        return False

    except (ConnectionRefusedError, OSError):
        log.info("IDA RPC port 13337 not reachable — no IDA-MCP plugin running")
        return False
    except xmlrpc.client.ProtocolError as e:
        log.info(f"IDA RPC protocol error on port 13337: {e}")
        return False


def _backup_idb(idb_path: str, log: ExportLogger) -> str | None:
    """Create a timestamped ``.bak`` copy of *idb_path*.

    Returns the backup path on success, ``None`` if the file does not
    exist or the copy failed.
    """
    import shutil
    from pathlib import Path

    src = Path(idb_path)
    if not src.is_file():
        return None

    backup = src.with_name(f"{src.stem}.i64.bak.{int(time.time())}")
    try:
        shutil.copy2(src, backup)
        log.info(f"IDB backup created: {backup}")
        return str(backup)
    except OSError as e:
        log.warn(f"Failed to create IDB backup: {e}")
        return None


def _ensure_license_free(idb_path: str, log: ExportLogger) -> str | None:
    """Check for running IDA processes and attempt to resolve license conflicts.

    Workflow:
      1. Scan for ``ida64.exe`` / ``idat64.exe`` processes via *psutil*.
      2. If any are found, try a graceful XML-RPC ``save + exit`` on
         port 13337 (the standard ``ida_mcp`` / ``idalib-mcp`` control port).
      3. If RPC succeeds, wait up to 15 seconds for the process(es) to exit.
      4. If RPC fails, back up ``.i64`` → ``.i64.bak.<timestamp>`` and return
         a clear error message with recovery instructions.

    Returns ``None`` when the license is free to use, or an error string.
    """
    running = _is_ida_running()
    if not running:
        return None  # License is free, proceed

    pid_list = ", ".join(f"{name}(PID {pid})" for pid, name in running)
    log.info(
        f"IDA Pro already running ({pid_list}). "
        "Attempting graceful shutdown via XML-RPC on port 13337 …"
    )

    rpc_ok = _rpc_shutdown_ida(log)

    if rpc_ok:
        import psutil

        # Wait for processes to exit
        for pid, _name in running:
            try:
                proc = psutil.Process(pid)
                proc.wait(timeout=15)
                log.info(f"IDA process PID {pid} exited cleanly after RPC shutdown")
            except (psutil.NoSuchProcess,):
                pass  # Already gone
            except psutil.TimeoutExpired:
                log.warn(f"IDA process PID {pid} did not exit within 15s of RPC call")

        # One last check
        stragglers = _is_ida_running()
        if stragglers:
            still = ", ".join(f"PID {p}" for p, _ in stragglers)
            log.warn(
                f"RPC shutdown sent but {still} still running — "
                "proceeding anyway; idat64 may fail."
            )
        return None  # Proceed — best-effort shutdown attempted

    # RPC failed — back up and return a clear error
    backup_path = _backup_idb(idb_path, log)
    msg = (
        f"IDA Pro is already running ({pid_list}) and could not be shut "
        "down automatically.\n"
        "The Hex-Rays licence is in use, so headless idat64.exe cannot start.\n"
    )
    if backup_path:
        msg += f"A backup was saved to: {backup_path}\n"
    msg += (
        "To resolve:\n"
        "  1. Save your work in IDA Pro (File → Save)\n"
        "  2. Close IDA Pro (File → Exit)\n"
        "  3. Retry the export\n"
        "\n"
        "Alternatively, export from the running GUI session directly:\n"
        "  File → Diaphora → Export, then use diff_diaphora_dbs() instead."
    )
    return msg


def _clean_stale_locks(idb_path: str, log: ExportLogger):
    """Remove stale IDB lock files that would prevent idat from restarting."""
    base = os.path.splitext(idb_path)[0]
    patterns = [".id0", ".id1", ".id2", ".nam", ".til"]
    cleaned = 0
    for ext in patterns:
        path = base + ext
        try:
            if os.path.isfile(path):
                force_delete_file(path)
                cleaned += 1
        except OSError as e:
            log.warn(f"Could not remove stale lock {os.path.basename(path)}: {e}")
    if cleaned:
        log.info(f"Cleaned {cleaned} stale IDB lock file(s)")


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
async def export_idb_to_diaphora(
    idb_path: str,
    output_path: str | None = None,
    use_decompiler: bool = False,
    summaries_only: bool | None = None,
    export_mode: str = "auto",
) -> str:
    """Export an IDB/i64 database to Diaphora SQLite format using IDA headless.

    NOTE: Enabling `use_decompiler=True` will include Hex-Rays pseudocode in
    the export, but this SIGNIFICANTLY increases export time – expect 5–30+
    minutes for large binaries. Default is False for fast export; re-export
    with decompiler only if pseudocode analysis is needed.
    """
    mode = _normalize_export_mode(export_mode)
    if mode is None:
        return err_json(
            f"Unsupported export_mode {export_mode!r}; use one of: auto, headless, gui"
        )
    if not os.path.isfile(idb_path):
        return err_json(f"IDB file not found: {idb_path}")

    if use_decompiler:
        log_warn = (
            "WARNING: Decompiler enabled – export will be significantly slower "
            "(5–30+ min for large binaries). Consider setting use_decompiler=False "
            "for a fast first pass (~1-2 min)."
        )
    else:
        log_warn = None

    if not output_path:
        base = os.path.splitext(os.path.basename(idb_path))[0]
        output_path = os.path.join(os.path.dirname(idb_path), f"{base}.diaphora.sqlite")

    path_error = _validate_export_output_path(idb_path, output_path)
    if path_error:
        return err_json(path_error)

    target_output_path = output_path
    staged_output_path = _staged_export_path(target_output_path)
    output_path = staged_output_path

    # ── 1. Try via ida_mcp plugin (HTTP) ──
    backend = None
    if mode in {"auto", "gui"}:
        plugin_err = _try_via_plugin(idb_path, output_path, use_decompiler, summaries_only)
        if plugin_err is None:
            backend = "ida_mcp"
        elif plugin_err != "NO_PLUGIN":
            _remove_staged_export(output_path)
            result = {"error": plugin_err}
            if log_warn:
                result["warning"] = log_warn
            return dumps(result)

    # ── 2. Try via XML-RPC GUI listener (port 28652) ──
    if backend is None and mode in {"auto", "gui"}:
        gui_err = _try_via_gui_listener(idb_path, output_path, use_decompiler, summaries_only)
        if gui_err is None:
            backend = "gui_listener"
        elif gui_err != "NO_PLUGIN":
            _remove_staged_export(output_path)
            result = {"error": gui_err}
            if log_warn:
                result["warning"] = log_warn
            return dumps(result)

    if backend is None and mode == "gui":
        _remove_staged_export(output_path)
        return err_json(
            "GUI export requested, but no matching ida_mcp or GUI listener session is available"
        )

    if backend is not None:
        if os.path.lexists(target_output_path):
            _remove_staged_export(output_path)
            return err_json(
                f"Refusing to overwrite existing output path: {target_output_path}"
            )
        schema, schema_error = _schema_for_export(output_path)
        if schema != "official_diaphora":
            _remove_staged_export(output_path)
            return err_json(
                "GUI export produced a database with an invalid schema for Diaphora matching: "
                f"{schema_error or 'official diff schema is missing'}"
            )
        publish_err = _publish_staged_export(output_path, target_output_path)
        if publish_err:
            _remove_staged_export(output_path)
            return err_json(publish_err)
        result = {"ok": True, "path": target_output_path, "backend": backend, "schema": schema}
        if log_warn:
            result["warning"] = log_warn
        return dumps(result)

    # ── Check if database lock files are held by a running GUI instance ──
    base = os.path.splitext(idb_path)[0]
    lock_files = [base + ext for ext in [".id0", ".id1", ".id2", ".nam", ".til"]]
    is_active_in_gui = False
    for lf in lock_files:
        if os.path.isfile(lf):
            try:
                with open(lf, "r+b") as f:
                    pass
            except OSError:
                is_active_in_gui = True
                break

    temp_idb_path = None
    target_idb_path = idb_path
    if is_active_in_gui:
        import shutil
        base_name, ext = os.path.splitext(idb_path)
        temp_idb_path = f"{base_name}_diaphora_tmp{ext}"
        try:
            shutil.copy2(idb_path, temp_idb_path)
            target_idb_path = temp_idb_path
        except Exception as e:
            return err_json(f"Failed to create temporary copy of active database to bypass lock: {e}")

    try:
        err = await run_export(target_idb_path, output_path, use_decompiler, summaries_only)
    finally:
        if temp_idb_path and os.path.exists(temp_idb_path):
            try:
                os.remove(temp_idb_path)
                temp_base = os.path.splitext(temp_idb_path)[0]
                for ext in [".id0", ".id1", ".id2", ".nam", ".til"]:
                    lf = temp_base + ext
                    if os.path.exists(lf):
                        os.remove(lf)
            except Exception:
                pass

    if err:
        _remove_staged_export(output_path)
        result = {"error": err}
        if log_warn:
            result["warning"] = log_warn
        return dumps(result)

    schema, schema_error = _schema_for_export(output_path)
    if schema != "official_diaphora":
        _remove_staged_export(output_path)
        result = {
            "error": "Headless export produced a database that is not usable for Diaphora matching: "
            f"{schema_error or 'official diff schema is missing'}"
        }
        if log_warn:
            result["warning"] = log_warn
        return dumps(result)

    publish_err = _publish_staged_export(output_path, target_output_path)
    if publish_err:
        _remove_staged_export(output_path)
        return err_json(publish_err)

    output_path = target_output_path
    result = {
        "success": True,
        "ok": True,
        "output_path": output_path,
        "size_bytes": os.path.getsize(output_path),
        "exported_from": os.path.basename(idb_path),
        "decompiler_used": use_decompiler,
        "backend": "headless",
        "schema": schema,
    }
    if log_warn:
        result["warning"] = log_warn

    # Check if program table was filled (required for diff)
    try:
        _c = get_connection(output_path)
        _r = _c.execute("SELECT count(*) FROM program").fetchone()[0]
        if _r == 0:
            prog_warn = (
                "Export incomplete: program table is empty. "
                "Diff will fail – see Problems.md #3."
            )
            if "warning" in result:
                result["warning"] += " " + prog_warn
            else:
                result["warning"] = prog_warn
    except Exception:
        pass

    return dumps(result)


async def batch_export_and_diff(
    idb1_path: str,
    idb2_path: str,
    output_dir: str | None = None,
    use_decompiler: bool = False,
    summaries_only: bool | None = None,
    cleanup: bool = False,
    limit: int = 500,
    unmatched_limit: int = 100,
    export_mode: str = "headless",
) -> str:
    """Run the full Diaphora pipeline: export → export → diff → summary.

    NOTE: Enabling `use_decompiler=True` will include Hex-Rays pseudocode,
    but this SIGNIFICANTLY increases export time for large binaries.
    Default is False for a fast pipeline run.

    When `summaries_only=True`, exports skip detailed assembly/pseudocode and
    only store function summaries — much faster for large binaries.
    When `None` (default), auto-detects based on .i64/.idb file size (>100 MB).

    The intermediate .sqlite export databases are kept by default (cleanup=False)
    because downstream tools — explain_similarity, rank_changes,
    detect_behavior_change, compare_functions, search_export_db, etc. — all
    require them to do per-function analysis. Set cleanup=True only if you
    are sure you won't need any per-function drill-down after this call.
    """
    mode = _normalize_export_mode(export_mode)
    if mode != "headless":
        return err_json(
            "batch_export_and_diff requires export_mode='headless' because matching needs "
            "the complete official Diaphora schema"
        )

    b1 = os.path.splitext(os.path.basename(idb1_path))[0]
    b2 = os.path.splitext(os.path.basename(idb2_path))[0]

    if not output_dir:
        output_dir = os.path.dirname(os.path.abspath(idb1_path))
    os.makedirs(output_dir, exist_ok=True)

    sqlite1 = os.path.join(output_dir, f"{b1}.diaphora.sqlite")
    sqlite2 = os.path.join(output_dir, f"{b2}.diaphora.sqlite")
    diff_out = os.path.join(output_dir, f"{b1}_vs_{b2}.diaphora")

    # Validate input files before setting up logger
    for p, label in [(idb1_path, "idb1"), (idb2_path, "idb2")]:
        if not os.path.isfile(p):
            return err_json(f"{label} not found: {p}")

    desc = f"Batch pipeline: {b1} + {b2}"
    with OperationLogger(desc, tag="batch") as batch_log:
        if use_decompiler:
            batch_log.info(
                "WARNING: Decompiler enabled — both exports will be significantly slower "
                "(potentially 10–60+ min total for large binaries). Consider setting "
                "use_decompiler=False for a fast first pass."
            )

        batch_log.info(f"idb1: {idb1_path}")
        batch_log.info(f"idb2: {idb2_path}")
        batch_log.info(f"use_decompiler: {use_decompiler}")
        batch_log.info(f"summaries_only: {summaries_only}")
        batch_log.info(f"sqlite1: {sqlite1}")
        batch_log.info(f"sqlite2: {sqlite2}")
        batch_log.info(f"diff_out: {diff_out}")

        step_results = {}
        result_data = None

        try:
            err = await run_export(idb1_path, sqlite1, use_decompiler, summaries_only)
            if err:
                batch_log.error(f"Export 1 failed: {err}")
                result_data = {"error": f"Export of {b1} failed: {err}", "steps": step_results}
            else:
                step_results["export1"] = {
                    "database": b1,
                    "output": sqlite1,
                    "size_bytes": os.path.getsize(sqlite1),
                }
                batch_log.info(f"Export 1 OK: {sqlite1} ({os.path.getsize(sqlite1)} bytes)")

                # Step 2: export secondary
                err = await run_export(idb2_path, sqlite2, use_decompiler, summaries_only)
                if err:
                    batch_log.error(f"Export 2 failed: {err}")
                    result_data = {"error": f"Export of {b2} failed: {err}", "steps": step_results}
                else:
                    step_results["export2"] = {
                        "database": b2,
                        "output": sqlite2,
                        "size_bytes": os.path.getsize(sqlite2),
                    }
                    batch_log.info(f"Export 2 OK: {sqlite2} ({os.path.getsize(sqlite2)} bytes)")

                    # Step 3: diff
                    batch_log.info("Starting diff...")
                    try:
                        from ..utils.connection import close_connection
                        close_connection(sqlite1)
                        close_connection(sqlite2)
                        close_connection(diff_out)
                        # Remove old .diaphora file so Diaphora can write new one without PermissionError
                        for old_path in [diff_out, f"{diff_out}-wal", f"{diff_out}-shm"]:
                            try:
                                if os.path.isfile(old_path):
                                    os.remove(old_path)
                            except Exception:
                                pass
                        proc = subprocess.run(
                            [PYTHON, DIAPHORA_SCRIPT, sqlite1, sqlite2, "-o", diff_out],
                            cwd=DIAPHORA_DIR,
                            capture_output=True,
                            stdin=subprocess.DEVNULL,
                            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                            text=True,
                            timeout=3600,
                        )
                        batch_log.info(f"Diff exit code: {proc.returncode}")
                        batch_log.log_subprocess_output(proc.stdout or "", proc.stderr or "")

                        if proc.returncode != 0:
                            result_data = {
                                "error": f"Diff failed with exit code {proc.returncode}",
                                "steps": step_results,
                                "stdout": (proc.stdout or "")[-3000:],
                                "stderr": (proc.stderr or "")[-3000:],
                            }
                        elif not os.path.isfile(diff_out):
                            batch_log.error("Diff produced no output file")
                            result_data = {
                                "error": "Diff completed but no output file produced",
                                "steps": step_results,
                                "stdout": (proc.stdout or "")[-3000:],
                                "stderr": (proc.stderr or "")[-3000:],
                            }
                        else:
                            diff_size = os.path.getsize(diff_out)
                            step_results["diff"] = {
                                "output": diff_out,
                                "size_bytes": diff_size,
                            }
                            batch_log.info(f"Diff output: {diff_out} ({diff_size} bytes)")

                            # Step 4: read and return results
                            from .diff import read_results as _read_results
                            try:
                                results = _read_results(diff_out, limit=limit, unmatched_limit=unmatched_limit)
                                batch_log.info(f"Diff results: {results['total_matches']} matches, {results['unmatched_count']} unmatched")
                                result_data = {
                                    "success": True,
                                    "steps": step_results,
                                    "summary": {
                                        "best_matches": results["counts"]["best"],
                                        "partial_matches": results["counts"]["partial"],
                                        "unreliable_matches": results["counts"]["unreliable"],
                                        "multimatches": results["counts"]["multimatch"],
                                        "unmatched_primary": results["unmatched_count"],
                                    },
                                    "results": results,
                                }
                            except Exception as exc:
                                batch_log.error(f"Failed to read diff results: {exc}")
                                result_data = {"error": f"Failed to read diff results: {exc}", "steps": step_results}

                    except subprocess.TimeoutExpired:
                        batch_log.error("Diff timed out after 3600 s")
                        result_data = {"error": "Diff timed out after 3600 s", "steps": step_results}
                    except Exception as exc:
                        batch_log.error(f"Diff failed: {exc}")
                        result_data = {"error": f"Diff failed: {exc}", "steps": step_results}

        finally:
            if cleanup:
                batch_log.info("Evicting databases from cache and cleaning up transient SQLite files...")
                cache_mgr = get_cache_manager()
                for sqlite_path in [sqlite1, sqlite2]:
                    try:
                        cache_mgr.evict(sqlite_path)
                    except Exception as e:
                        batch_log.warn(f"Failed to evict database {sqlite_path}: {e}")

                for path in [sqlite1, f"{sqlite1}-wal", f"{sqlite1}-shm",
                             sqlite2, f"{sqlite2}-wal", f"{sqlite2}-shm"]:
                    try:
                        if os.path.exists(path):
                            force_delete_file(path)
                    except Exception as e:
                        batch_log.warn(f"Failed to delete temporary file {path}: {e}")

    return dumps(result_data)
