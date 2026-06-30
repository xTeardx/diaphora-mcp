"""
Diaphora MCP — IDB export and batch pipeline.

Handles headless IDA export via idat.exe + Diaphora env-var mechanism,
and the full export→export→diff→summary pipeline.
"""

import json
import os
import subprocess
import threading
import time

from ..config import IDAT_PATH, DIAPHORA_DIR, HEADLESS_WRAPPER, DIAPHORA_SCRIPT, PYTHON
from ..utils.sqlite import check_db
from ..utils.log import ExportLogger, OperationLogger


# ---------------------------------------------------------------------------
# Headless export
# ---------------------------------------------------------------------------
def run_export(idb_path: str, output_path: str, use_decompiler: bool) -> str | None:
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

    with ExportLogger(idb_path, output_path) as log:
        _clean_stale_locks(idb_path, log)

        env = os.environ.copy()
        env["DIAPHORA_AUTO"] = "1"
        env["DIAPHORA_EXPORT_FILE"] = output_path
        env["DIAPHORA_USE_DECOMPILER"] = "1" if use_decompiler else "0"

        wal_path = output_path + "-wal"
        log.info(f"Launching: {IDAT_PATH} -A -S{HEADLESS_WRAPPER} {os.path.basename(idb_path)}")
        log.info(f"cwd: {DIAPHORA_DIR}")
        log.info(f"DIAPHORA_EXPORT_FILE={output_path}")
        log.info(f"DIAPHORA_USE_DECOMPILER={'1' if use_decompiler else '0'}")

        try:
            proc = subprocess.Popen(
                [IDAT_PATH, "-A", f"-S{HEADLESS_WRAPPER}", idb_path],
                cwd=DIAPHORA_DIR,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError:
            log.error(f"idat.exe not found at {IDAT_PATH}")
            return f"idat.exe not found at {IDAT_PATH}"
        except Exception as exc:
            log.error(f"Failed to launch IDA: {exc}")
            return f"Failed to launch IDA headless: {exc}"

        # Monitor WAL growth while idat runs
        stop_monitor = threading.Event()

        def monitor_wal():
            last_size = 0
            while not stop_monitor.is_set():
                time.sleep(30)
                try:
                    sz = os.path.getsize(wal_path)
                except OSError:
                    sz = 0
                if sz != last_size:
                    log.log_file_growth(wal_path, "WAL")
                    last_size = sz
                if os.path.isfile(output_path + "-crash"):
                    log.info("  crash-file present (export in progress)")

        monitor = threading.Thread(target=monitor_wal, daemon=True)
        monitor.start()

        try:
            stdout, stderr = proc.communicate(timeout=3600)
        except subprocess.TimeoutExpired:
            proc.kill()
            stop_monitor.set()
            monitor.join(timeout=5)
            log.error("Export timed out after 3600 s")
            return "Export timed out after 3600 s"
        finally:
            stop_monitor.set()
            monitor.join(timeout=5)

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
                os.remove(path)
                cleaned += 1
        except OSError as e:
            log.warn(f"Could not remove stale lock {os.path.basename(path)}: {e}")
    if cleaned:
        log.info(f"Cleaned {cleaned} stale IDB lock file(s)")


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
def export_idb_to_diaphora(
    idb_path: str,
    output_path: str | None = None,
    use_decompiler: bool = False,
) -> str:
    """Export an IDB/i64 database to Diaphora SQLite format using IDA headless.

    NOTE: Enabling `use_decompiler=True` will include Hex-Rays pseudocode in
    the export, but this SIGNIFICANTLY increases export time — expect 5–30+
    minutes for large binaries.  Default is False for fast export; re-export
    with decompiler only if pseudocode analysis is needed.
    """
    if not os.path.isfile(idb_path):
        return json.dumps({"error": f"IDB file not found: {idb_path}"})

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

    err = run_export(idb_path, output_path, use_decompiler)
    if err:
        result = {"error": err}
        if log_warn:
            result["warning"] = log_warn
        return json.dumps(result)

    result = {
        "success": True,
        "output_path": output_path,
        "size_bytes": os.path.getsize(output_path),
        "exported_from": os.path.basename(idb_path),
        "decompiler_used": use_decompiler,
    }
    if log_warn:
        result["warning"] = log_warn
    return json.dumps(result, indent=2, default=str)


def batch_export_and_diff(
    idb1_path: str,
    idb2_path: str,
    output_dir: str | None = None,
    use_decompiler: bool = False,
) -> str:
    """Run the full Diaphora pipeline: export → export → diff → summary.

    NOTE: Enabling `use_decompiler=True` will include Hex-Rays pseudocode,
    but this SIGNIFICANTLY increases export time for large binaries.
    Default is False for a fast pipeline run.
    """
    b1 = os.path.splitext(os.path.basename(idb1_path))[0]
    b2 = os.path.splitext(os.path.basename(idb2_path))[0]

    sqlite1 = os.path.join(output_dir, f"{b1}.sqlite")
    sqlite2 = os.path.join(output_dir, f"{b2}.sqlite")
    diff_out = os.path.join(output_dir, f"{b1}_vs_{b2}.diaphora")

    # Batch-level log
    batch_log = OperationLogger(
        f"Batch pipeline: {b1} + {b2}",
        tag="batch"
    )
    batch_log.__enter__()

    for p, label in [(idb1_path, "idb1"), (idb2_path, "idb2")]:
        if not os.path.isfile(p):
            batch_log.__exit__(None, None, None)
            return json.dumps({"error": f"{label} not found: {p}"})

    if use_decompiler:
        log_warn = (
            "WARNING: Decompiler enabled — both exports will be significantly slower "
            "(potentially 10–60+ min total for large binaries). Consider setting "
            "use_decompiler=False for a fast first pass."
        )
    else:
        log_warn = None

    batch_log.info(f"idb1: {idb1_path}")
    batch_log.info(f"idb2: {idb2_path}")
    batch_log.info(f"use_decompiler: {use_decompiler}")
    batch_log.info(f"sqlite1: {sqlite1}")
    batch_log.info(f"sqlite2: {sqlite2}")
    batch_log.info(f"diff_out: {diff_out}")


    step_results = {}

    # Step 1: export primary
    err = run_export(idb1_path, sqlite1, use_decompiler)
    if err:
        batch_log.error(f"Export 1 failed: {err}")
        batch_log.__exit__(None, None, None)
        return json.dumps({"error": f"Export of {b1} failed: {err}", "steps": step_results})
    step_results["export1"] = {
        "database": b1,
        "output": sqlite1,
        "size_bytes": os.path.getsize(sqlite1),
    }
    batch_log.info(f"Export 1 OK: {sqlite1} ({os.path.getsize(sqlite1)} bytes)")

    # Step 2: export secondary
    err = run_export(idb2_path, sqlite2, use_decompiler)
    if err:
        batch_log.error(f"Export 2 failed: {err}")
        batch_log.__exit__(None, None, None)
        return json.dumps({"error": f"Export of {b2} failed: {err}", "steps": step_results})
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
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        batch_log.error("Diff timed out after 600 s")
        batch_log.__exit__(None, None, None)
        return json.dumps({"error": "Diff timed out after 600 s", "steps": step_results})
    except Exception as exc:
        batch_log.error(f"Diff failed: {exc}")
        batch_log.__exit__(None, None, None)
        return json.dumps({"error": f"Diff failed: {exc}", "steps": step_results})

    batch_log.info(f"Diff exit code: {proc.returncode}")
    batch_log.log_subprocess_output(proc.stdout or "", proc.stderr or "")

    if not os.path.isfile(diff_out):
        batch_log.error("Diff produced no output file")
        batch_log.__exit__(None, None, None)
        return json.dumps(
            {
                "error": "Diff completed but no output file produced",
                "steps": step_results,
                "stdout": (proc.stdout or "")[-3000:],
                "stderr": (proc.stderr or "")[-3000:],
            }
        )

    diff_size = os.path.getsize(diff_out)
    step_results["diff"] = {
        "output": diff_out,
        "size_bytes": diff_size,
    }
    batch_log.info(f"Diff output: {diff_out} ({diff_size} bytes)")

    # Step 4: read and return results
    from .diff import read_results as _read_results

    try:
        results = _read_results(diff_out)
    except Exception as exc:
        batch_log.error(f"Failed to read diff results: {exc}")
        batch_log.__exit__(None, None, None)
        return json.dumps({"error": f"Failed to read diff results: {exc}", "steps": step_results})

    batch_log.info(f"Diff results: {results['total_matches']} matches, {results['unmatched_count']} unmatched")
    batch_log.__exit__(None, None, None)

    return json.dumps(
        {
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
        },
        indent=2,
        default=str,
    )
