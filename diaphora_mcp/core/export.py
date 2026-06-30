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

from ..config import IDAT_PATH, DIAPHORA_DIR, HEADLESS_WRAPPER, DIAPHORA_SCRIPT, PYTHON
from ..utils.sqlite import check_db, check_db_for_diff, force_delete_file
from ..utils.log import ExportLogger, OperationLogger
from ..utils.format import dumps, err_json


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

    # 1. Try exporting via active GUI IDA Pro session first
    try:
        client = xmlrpc.client.ServerProxy("http://127.0.0.1:28652")
        if client.ping():
            # Check API version for backward compat with older listeners
            api_version = 1
            try:
                api_version = client.version()
            except Exception:
                api_version = 1

            if api_version >= 2:
                res = client.export_current_db(output_path, use_decompiler, summaries_only)
            else:
                res = client.export_current_db(output_path, use_decompiler)
            if res is True:
                if check_db(output_path) is None:
                    return None
                else:
                    return f"GUI export finished but database at {output_path} is invalid."
            else:
                return f"GUI export failed: {res}"
    except (ConnectionRefusedError, OSError, xmlrpc.client.Fault, xmlrpc.client.ProtocolError):
        # GUI server is not listening or ping failed, fall back to headless idat.exe
        pass

    # 2. Check if database lock files exist and are locked by a running GUI instance of IDA
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

    if is_active_in_gui:
        return (
            f"The database {os.path.basename(idb_path)} is currently locked/active. "
            f"It is likely open in GUI IDA Pro. Please close it in the GUI first, "
            f"or manually export it to SQLite from the GUI (File -> Diaphora -> Export) "
            f"and use the resulting SQLite database."
        )

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
                    proc.kill()
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
                    proc.kill()
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
            import sqlite3
            _pc = sqlite3.connect(output_path)
            try:
                _pcur = _pc.cursor()
                _pcur.execute("SELECT count(*) FROM program")
                if _pcur.fetchone()[0] == 0:
                    log.warn(
                        "Export incomplete: program table is empty. "
                        "Callgraph metadata not written — diff will fail on this database. "
                        "This happens when IDA crashes during finalization (see Problems.md #3)."
                    )
            finally:
                _pc.close()
        except Exception:
            pass

        return None  # success


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
) -> str:
    """Export an IDB/i64 database to Diaphora SQLite format using IDA headless.

    NOTE: Enabling `use_decompiler=True` will include Hex-Rays pseudocode in
    the export, but this SIGNIFICANTLY increases export time — expect 5–30+
    minutes for large binaries. Default is False for fast export; re-export
    with decompiler only if pseudocode analysis is needed.
    """
    if not os.path.isfile(idb_path):
        return err_json(f"IDB file not found: {idb_path}")

    if use_decompiler:
        log_warn = (
            "WARNING: Decompiler enabled — export will be significantly slower "
            "(5–30+ min for large binaries). Consider setting use_decompiler=False "
            "for a fast first pass (~1-2 min)."
        )
    else:
        log_warn = None

    if not output_path:
        base = os.path.splitext(os.path.basename(idb_path))[0]
        output_path = os.path.join(os.path.dirname(idb_path), f"{base}.sqlite")

    err = await run_export(idb_path, output_path, use_decompiler, summaries_only)
    if err:
        result = {"error": err}
        if log_warn:
            result["warning"] = log_warn
        return dumps(result)

    result = {
        "success": True,
        "output_path": output_path,
        "size_bytes": os.path.getsize(output_path),
        "exported_from": os.path.basename(idb_path),
        "decompiler_used": use_decompiler,
    }
    if log_warn:
        result["warning"] = log_warn

    # Check if program table was filled (required for diff)
    try:
        import sqlite3
        _c = sqlite3.connect(output_path)
        try:
            _r = _c.execute("SELECT count(*) FROM program").fetchone()[0]
            if _r == 0:
                prog_warn = (
                    "Export incomplete: program table is empty. "
                    "Diff will fail — see Problems.md #3."
                )
                if "warning" in result:
                    result["warning"] += " " + prog_warn
                else:
                    result["warning"] = prog_warn
        finally:
            _c.close()
    except Exception:
        pass

    return dumps(result)


def batch_export_and_diff(
    idb1_path: str,
    idb2_path: str,
    output_dir: str | None = None,
    use_decompiler: bool = False,
    summaries_only: bool | None = None,
    cleanup: bool = True,
    limit: int = 500,
    unmatched_limit: int = 100,
) -> str:
    """Run the full Diaphora pipeline: export → export → diff → summary.

    NOTE: Enabling `use_decompiler=True` will include Hex-Rays pseudocode,
    but this SIGNIFICANTLY increases export time for large binaries.
    Default is False for a fast pipeline run.

    When `summaries_only=True`, exports skip detailed assembly/pseudocode and
    only store function summaries — much faster for large binaries.
    When `None` (default), auto-detects based on .i64/.idb file size (>100 MB).
    """
    b1 = os.path.splitext(os.path.basename(idb1_path))[0]
    b2 = os.path.splitext(os.path.basename(idb2_path))[0]

    if not output_dir:
        output_dir = os.path.dirname(os.path.abspath(idb1_path))
    os.makedirs(output_dir, exist_ok=True)

    sqlite1 = os.path.join(output_dir, f"{b1}.sqlite")
    sqlite2 = os.path.join(output_dir, f"{b2}.sqlite")
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
            # Step 1: export primary
            err = run_export(idb1_path, sqlite1, use_decompiler, summaries_only)
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
                err = run_export(idb2_path, sqlite2, use_decompiler, summaries_only)
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
                batch_log.info("Cleaning up temporary SQLite and WAL databases...")
                for path in [sqlite1, f"{sqlite1}-wal", f"{sqlite1}-shm",
                             sqlite2, f"{sqlite2}-wal", f"{sqlite2}-shm"]:
                    try:
                        if os.path.exists(path):
                            force_delete_file(path)
                    except Exception as e:
                        batch_log.warn(f"Failed to delete temporary file {path}: {e}")

    return dumps(result_data)
