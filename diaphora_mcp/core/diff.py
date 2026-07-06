"""
Diaphora MCP — diff operations.

Reading, filtering, and summarising .diaphora diff results files,
plus the raw database diff subprocess call.
"""

import json
import os
import sqlite3
import subprocess
import threading
import time

from ..config import DIAPHORA_SCRIPT, DIAPHORA_DIR, PYTHON
from ..utils.sqlite import check_db, check_db_for_diff
from ..utils.log import OperationLogger, log_path, write_log
from ..models import MATCH_TYPES
from ..utils.format import dumps, err_json


# ---------------------------------------------------------------------------
# Read results
# ---------------------------------------------------------------------------
def read_results(
    results_path: str,
    match_type: str = "all",
    min_ratio: float = 0.0,
    limit: int = 500,
    unmatched_limit: int = 100,
):
    """Read a .diaphora results file and return structured data."""
    conn = sqlite3.connect(results_path)
    try:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("SELECT * FROM config")
        config_info = dict(cur.fetchone() or {})

        mtypes = MATCH_TYPES.get(match_type, MATCH_TYPES["all"])
        placeholders = ",".join("?" for _ in mtypes)

        # Enforce query-level LIMIT to avoid loading thousands of rows into memory
        effective_limit = min(limit or 500, 5000) if limit and limit > 0 else 500

        if min_ratio > 0:
            sql = (
                f"SELECT address, name, address2, name2, ratio, type, "
                f"nodes1, nodes2, description "
                f"FROM results WHERE type IN ({placeholders}) AND ratio >= ?"
                f" ORDER BY ratio DESC LIMIT ?"
            )
            params = [*mtypes, min_ratio, effective_limit]
        else:
            sql = (
                f"SELECT address, name, address2, name2, ratio, type, "
                f"nodes1, nodes2, description "
                f"FROM results WHERE type IN ({placeholders})"
                f" ORDER BY ratio DESC LIMIT ?"
            )
            params = [*mtypes, effective_limit]

        cur.execute(sql, params)
        results = [dict(r) for r in cur.fetchall()]

        counts = {}
        for t in ["best", "partial", "unreliable", "multimatch"]:
            cur.execute("SELECT count(*) FROM results WHERE type = ?", (t,))
            counts[t] = cur.fetchone()[0]

        cur.execute("SELECT * FROM unmatched")
        unmatched = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

    res_slice = results[:limit] if (limit is not None and limit > 0) else results
    unm_slice = unmatched[:unmatched_limit] if (unmatched_limit is not None and unmatched_limit > 0) else unmatched

    return {
        "config": config_info,
        "counts": counts,
        "total_matches": len(results),
        "unmatched_count": len(unmatched),
        "results": res_slice,
        "truncated": len(results) > len(res_slice),
        "unmatched": unm_slice,
        "unmatched_truncated": len(unmatched) > len(unm_slice),
    }


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
def diff_diaphora_dbs(
    db1_path: str,
    db2_path: str,
    output_path: str | None = None,
) -> str:
    """Diff two exported Diaphora databases and return the results."""
    err1 = check_db_for_diff(db1_path)
    if err1:
        return err_json(f"db1 ({db1_path}): {err1}")
    err2 = check_db_for_diff(db2_path)
    if err2:
        return err_json(f"db2 ({db2_path}): {err2}")

    if not output_path:
        b1 = os.path.splitext(os.path.basename(db1_path))[0]
        b2 = os.path.splitext(os.path.basename(db2_path))[0]
        output_path = os.path.join(
            os.path.dirname(db1_path), f"{b1}_vs_{b2}.diaphora"
        )

    desc = f"Diff {os.path.basename(db1_path)} vs {os.path.basename(db2_path)}"
    with OperationLogger(desc, tag="diff") as log:
        log.info(f"  db1: {db1_path}")
        log.info(f"  db2: {db2_path}")
        log.info(f"  out: {output_path}")

        result_data = None  # Collects error result; None means continue to success
        stdout_str = ""
        stderr_str = ""

        try:
            start = time.time()
            proc = subprocess.Popen(
                [PYTHON, DIAPHORA_SCRIPT, db1_path, db2_path, "-o", output_path],
                cwd=DIAPHORA_DIR,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                text=True,
            )

            # Read stdout and stderr concurrently to avoid PIPE deadlock
            stdout_chunks = []
            stderr_chunks = []

            def _read_pipe(pipe, chunks):
                try:
                    for line in pipe:
                        chunks.append(line)
                except Exception as e:
                    log.warn(f"Pipe reader error: {e}")

            t_out = threading.Thread(target=_read_pipe, args=(proc.stdout, stdout_chunks), daemon=True)
            t_err = threading.Thread(target=_read_pipe, args=(proc.stderr, stderr_chunks), daemon=True)
            t_out.start()
            t_err.start()

            proc.wait(timeout=3600)

            t_out.join(timeout=2)
            t_err.join(timeout=2)

            stdout_str = "".join(stdout_chunks)
            stderr_str = "".join(stderr_chunks)
            elapsed = time.time() - start
            log.info(f"diaphora.py exit code: {proc.returncode} ({elapsed:.0f}s)")
            if proc.returncode != 0:
                log.log_subprocess_output(stdout_str, stderr_str)

        except subprocess.TimeoutExpired:
            proc.kill()
            log.error("Diff timed out after 3600 s")
            result_data = {"error": "Diaphora diff timed out after 3600 s"}
        except FileNotFoundError:
            log.error(f"diaphora.py not found at {DIAPHORA_SCRIPT}")
            result_data = {"error": f"diaphora.py not found at {DIAPHORA_SCRIPT}"}
        except Exception as exc:
            log.error(f"Failed to launch Diaphora: {exc}")
            result_data = {"error": f"Failed to launch Diaphora: {exc}"}

        if result_data:
            return dumps(result_data)

        if not os.path.isfile(output_path):
            log.error("No output file produced")
            return err_json(
                "Diaphora completed but did not produce an output file",
                {
                    "stdout_tail": (stdout_str or "")[-3000:],
                    "stderr_tail": (stderr_str or "")[-3000:],
                }
            )

        out_size = os.path.getsize(output_path)
        log.info(f"Output created: {out_size} bytes")

        # Read result stats for the log
        try:
            conn = sqlite3.connect(output_path)
            try:
                cur = conn.cursor()
                cur.execute("SELECT type, count(*) FROM results GROUP BY type")
                counts = dict(cur.fetchall())
                log.info(f"Matches: {counts}")
                cur.execute("SELECT count(*) FROM unmatched")
                log.info(f"Unmatched: {cur.fetchone()[0]}")
            finally:
                conn.close()
        except Exception:
            pass

    return dumps(read_results(output_path))


def get_diff_results(
    results_path: str,
    match_type: str = "all",
    min_ratio: float = 0.0,
    limit: int = 500,
    unmatched_limit: int = 100,
) -> str:
    """Return matches from a .diaphora results file, optionally filtered."""
    if not os.path.isfile(results_path):
        return err_json(f"Results file not found: {results_path}")

    try:
        return dumps(
            read_results(results_path, match_type, min_ratio, limit, unmatched_limit)
        )
    except Exception as exc:
        return err_json(f"Error reading results: {exc}")


def get_diff_summary(results_path: str) -> str:
    """Return match statistics, top matches, and unmatched counts."""
    if not os.path.isfile(results_path):
        return err_json(f"Results file not found: {results_path}")

    conn = sqlite3.connect(results_path)
    try:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("SELECT * FROM config")
        config_info = dict(cur.fetchone() or {})

        cur.execute(
            """SELECT type, count(*) as cnt,
                      round(avg(ratio), 4) as avg_ratio,
                      round(max(ratio), 4) as max_ratio,
                      round(min(ratio), 4) as min_ratio
               FROM results GROUP BY type"""
        )
        type_stats = [dict(r) for r in cur.fetchall()]

        cur.execute(
            "SELECT * FROM results WHERE type='best' ORDER BY ratio DESC LIMIT 10"
        )
        top_best = [dict(r) for r in cur.fetchall()]

        cur.execute(
            "SELECT * FROM results WHERE type='partial' ORDER BY ratio DESC LIMIT 10"
        )
        top_partial = [dict(r) for r in cur.fetchall()]

        cur.execute("SELECT type, count(*) FROM unmatched GROUP BY type")
        unmatched = [dict(zip(["type", "count"], r)) for r in cur.fetchall()]
    finally:
        conn.close()

    return dumps(
        {
            "config": config_info,
            "match_statistics": type_stats,
            "unmatched": unmatched,
            "top_best_matches": top_best,
            "top_partial_matches": top_partial,
        }
    )
