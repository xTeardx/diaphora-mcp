"""
Diaphora MCP — IDB export and batch pipeline.

Handles headless IDA export via idat.exe + Diaphora env-var mechanism,
and the full export→export→diff→summary pipeline.
"""

import json
import os
import subprocess
import tempfile

from ..config import IDAT_PATH, DIAPHORA_DIR, HEADLESS_WRAPPER, DIAPHORA_SCRIPT, PYTHON
from ..utils.sqlite import check_db


# ---------------------------------------------------------------------------
# Headless export
# ---------------------------------------------------------------------------
def run_export(idb_path: str, output_path: str, use_decompiler: bool) -> str | None:
    """Run IDA headless export via idat.exe and the headless wrapper.

    Returns an error string on failure, or None on success.
    """
    if not os.path.isfile(idb_path):
        return f"Input file not found: {idb_path}"
    if not os.path.isfile(IDAT_PATH):
        return f"idat.exe not found at {IDAT_PATH}"
    if not os.path.isfile(HEADLESS_WRAPPER):
        return f"Headless wrapper not found at {HEADLESS_WRAPPER}"

    env = os.environ.copy()
    env["DIAPHORA_AUTO"] = "1"
    env["DIAPHORA_EXPORT_FILE"] = output_path
    env["DIAPHORA_USE_DECOMPILER"] = "1" if use_decompiler else "0"

    try:
        proc = subprocess.run(
            [IDAT_PATH, "-A", f"-S{HEADLESS_WRAPPER}", idb_path],
            cwd=DIAPHORA_DIR,
            env=env,
            capture_output=True,
            text=True,
            timeout=3600,
        )
    except subprocess.TimeoutExpired:
        return "Export timed out after 3600 s"
    except FileNotFoundError:
        return f"idat.exe not found at {IDAT_PATH}"
    except Exception as exc:
        return f"Failed to launch IDA headless: {exc}"

    crash_file = f"{output_path}-crash"
    if os.path.isfile(crash_file):
        try:
            os.remove(crash_file)
        except OSError:
            pass
        return (
            "Export appears to have crashed (crash file still present).\n"
            f"  idat stdout (last 2K):\n{(proc.stdout or '')[-2048:]}\n"
            f"  idat stderr (last 2K):\n{(proc.stderr or '')[-2048:]}"
        )

    if not os.path.isfile(output_path):
        return (
            "Export completed but no output file was produced.\n"
            f"  idat stdout (last 2K):\n{(proc.stdout or '')[-2048:]}\n"
            f"  idat stderr (last 2K):\n{(proc.stderr or '')[-2048:]}"
        )

    db_err = check_db(output_path)
    if db_err:
        return f"Export produced invalid database:\n  {db_err}"

    return None


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
def export_idb_to_diaphora(
    idb_path: str,
    output_path: str | None = None,
    use_decompiler: bool = True,
) -> str:
    """Export an IDB/i64 database to Diaphora SQLite format using IDA headless."""
    if not os.path.isfile(idb_path):
        return json.dumps({"error": f"IDB file not found: {idb_path}"})

    if not output_path:
        base = os.path.splitext(os.path.basename(idb_path))[0]
        output_path = os.path.join(os.path.dirname(idb_path), f"{base}.sqlite")

    err = run_export(idb_path, output_path, use_decompiler)
    if err:
        return json.dumps({"error": err})

    return json.dumps(
        {
            "success": True,
            "output_path": output_path,
            "size_bytes": os.path.getsize(output_path),
            "exported_from": os.path.basename(idb_path),
        },
        indent=2,
        default=str,
    )


def batch_export_and_diff(
    idb1_path: str,
    idb2_path: str,
    output_dir: str | None = None,
    use_decompiler: bool = True,
) -> str:
    """Run the full Diaphora pipeline: export → export → diff → summary."""
    for p, label in [(idb1_path, "idb1"), (idb2_path, "idb2")]:
        if not os.path.isfile(p):
            return json.dumps({"error": f"{label} not found: {p}"})

    if not output_dir:
        output_dir = os.path.dirname(os.path.abspath(idb1_path))
    os.makedirs(output_dir, exist_ok=True)

    b1 = os.path.splitext(os.path.basename(idb1_path))[0]
    b2 = os.path.splitext(os.path.basename(idb2_path))[0]

    sqlite1 = os.path.join(output_dir, f"{b1}.sqlite")
    sqlite2 = os.path.join(output_dir, f"{b2}.sqlite")
    diff_out = os.path.join(output_dir, f"{b1}_vs_{b2}.diaphora")

    step_results = {}

    # Step 1: export primary
    err = run_export(idb1_path, sqlite1, use_decompiler)
    if err:
        return json.dumps({"error": f"Export of {b1} failed: {err}", "steps": step_results})
    step_results["export1"] = {
        "database": b1,
        "output": sqlite1,
        "size_bytes": os.path.getsize(sqlite1),
    }

    # Step 2: export secondary
    err = run_export(idb2_path, sqlite2, use_decompiler)
    if err:
        return json.dumps({"error": f"Export of {b2} failed: {err}", "steps": step_results})
    step_results["export2"] = {
        "database": b2,
        "output": sqlite2,
        "size_bytes": os.path.getsize(sqlite2),
    }

    # Step 3: diff
    try:
        proc = subprocess.run(
            [PYTHON, DIAPHORA_SCRIPT, sqlite1, sqlite2, "-o", diff_out],
            cwd=DIAPHORA_DIR,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "Diff timed out after 600 s", "steps": step_results})
    except Exception as exc:
        return json.dumps({"error": f"Diff failed: {exc}", "steps": step_results})

    if not os.path.isfile(diff_out):
        return json.dumps(
            {
                "error": "Diff completed but no output file produced",
                "steps": step_results,
                "stdout": (proc.stdout or "")[-3000:],
                "stderr": (proc.stderr or "")[-3000:],
            }
        )

    step_results["diff"] = {
        "output": diff_out,
        "size_bytes": os.path.getsize(diff_out),
    }

    # Step 4: read and return results
    from .diff import read_results as _read_results

    try:
        results = _read_results(diff_out)
    except Exception as exc:
        return json.dumps({"error": f"Failed to read diff results: {exc}", "steps": step_results})

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
