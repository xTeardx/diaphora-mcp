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
from ..utils.sqlite import (
    check_db, check_db_for_diff,
    read_adaptive_table,
    get_table_columns,
    check_results_db,
    _RESULTS_COLUMN_MAP, _UNMATCHED_COLUMN_MAP,
)
from ..utils.connection import get_connection
from ..utils.log import OperationLogger, log_path, write_log
from ..models import MATCH_TYPES
from ..utils.format import dumps, err_json


def _kill_and_reap(proc) -> None:
    """Остановить дочерний процесс и bounded-образом дождаться его завершения."""
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
# Read results
# ---------------------------------------------------------------------------
def read_results(
    results_path: str,
    match_type: str = "all",
    min_ratio: float = 0.0,
    limit: int = 500,
    unmatched_limit: int = 100,
):
    """Read a .diaphora results file and return structured data.

    Schema-adaptive: detects available columns and maps known variants
    (address/addr1, address2/addr2, ratio/similarity, etc.).
    """
    conn = get_connection(results_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT * FROM config")
    config_info = dict(cur.fetchone() or {})

    # Build adaptive WHERE clause for match_type filter
    mtypes = MATCH_TYPES.get(match_type, MATCH_TYPES["all"])
    available_cols = get_table_columns(results_path, "results")

    # Determine the actual column name for "type"
    type_col = "type"
    if type_col not in available_cols:
        for variant in ["match_type", "result_type"]:
            if variant in available_cols:
                type_col = variant
                break

    placeholders = ",".join("?" for _ in mtypes)
    effective_limit = min(limit or 500, 5000) if limit and limit > 0 else 500

    # Build safe ORDER BY — use available ratio column
    ratio_col = "ratio"
    if ratio_col not in available_cols:
        for variant in ["similarity", "match_ratio", "confidence"]:
            if variant in available_cols:
                ratio_col = variant
                break

    # Read results using adaptive column detection
    extra_where = f"{type_col} IN ({placeholders})"
    if min_ratio > 0:
        extra_where += f" AND CAST({ratio_col} AS REAL) >= ?"
        raw_results = read_adaptive_table(
            results_path, _RESULTS_COLUMN_MAP, "results",
            extra_where=extra_where,
            params=tuple(mtypes) + (min_ratio,),
            row_factory=sqlite3.Row,
        )
        # Filter by mtypes and min_ratio in Python (the SQL WHERE may not match
        # column names exactly after adaptive mapping)
        raw_results = [
            r for r in raw_results
            if r.get("type") in mtypes
        ]
        # Sort by ratio descending, handling None/string
        def _ratio_key(r):
            v = r.get("ratio")
            try:
                return float(v) if v is not None else 0.0
            except (TypeError, ValueError):
                return 0.0
        raw_results.sort(key=_ratio_key, reverse=True)
    else:
        raw_results = read_adaptive_table(
            results_path, _RESULTS_COLUMN_MAP, "results",
            extra_where=extra_where,
            params=tuple(mtypes),
            row_factory=sqlite3.Row,
        )
        raw_results = [r for r in raw_results if r.get("type") in mtypes]
        def _ratio_key(r):
            v = r.get("ratio")
            try:
                return float(v) if v is not None else 0.0
            except (TypeError, ValueError):
                return 0.0
        raw_results.sort(key=_ratio_key, reverse=True)

    # Counts via GROUP BY (always works regardless of column names)
    counts = {"best": 0, "partial": 0, "unreliable": 0, "multimatch": 0}
    try:
        cur.execute(f"SELECT {type_col}, count(*) as cnt FROM results GROUP BY {type_col}")
        for row in cur.fetchall():
            t = row[0] if not isinstance(row, dict) else row.get(type_col)
            if t in counts:
                counts[t] = row["cnt"] if isinstance(row, dict) else row[1]
    except Exception:
        pass

    # Read unmatched with adaptive columns
    unmatched = read_adaptive_table(
        results_path, _UNMATCHED_COLUMN_MAP, "unmatched",
        row_factory=sqlite3.Row,
    )

    total_match_count = len(raw_results)
    res_slice = raw_results[:effective_limit]
    unm_slice = unmatched[:unmatched_limit] if (unmatched_limit is not None and unmatched_limit > 0) else unmatched

    return {
        "config": config_info,
        "counts": counts,
        "total_matches": total_match_count,
        "unmatched_count": len(unmatched),
        "results": res_slice,
        "truncated": total_match_count > len(res_slice),
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
            from ..utils.connection import close_connection
            close_connection(db1_path)
            close_connection(db2_path)
            close_connection(output_path)
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
            _kill_and_reap(proc)
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
            conn = get_connection(output_path)
            cur = conn.cursor()
            cur.execute("SELECT type, count(*) FROM results GROUP BY type")
            counts = dict(cur.fetchall())
            log.info(f"Matches: {counts}")
            cur.execute("SELECT count(*) FROM unmatched")
            log.info(f"Unmatched: {cur.fetchone()[0]}")
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
    if (err := check_results_db(results_path)):
        return err_json(err)

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
    if (err := check_results_db(results_path)):
        return err_json(err)

    conn = get_connection(results_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT * FROM config")
    config_info = dict(cur.fetchone() or {})

    available = get_table_columns(results_path, "results")
    # Determine the actual type and ratio column names
    type_col = "type" if "type" in available else "match_type"
    ratio_col = "ratio" if "ratio" in available else "similarity"

    # Safe aggregation — use the actual type column
    agg_sql = (
        f"SELECT {type_col} as type, count(*) as cnt, "
        f"round(avg(CAST({ratio_col} AS REAL)), 4) as avg_ratio, "
        f"round(max(CAST({ratio_col} AS REAL)), 4) as max_ratio, "
        f"round(min(CAST({ratio_col} AS REAL)), 4) as min_ratio "
        f"FROM results GROUP BY {type_col}"
    )
    try:
        cur.execute(agg_sql)
        type_stats = [dict(r) for r in cur.fetchall()]
    except Exception:
        type_stats = []

    # Read top best and partial using adaptive approach
    where_best = f"{type_col} = 'best'"
    best_results = read_adaptive_table(
        results_path, _RESULTS_COLUMN_MAP, "results",
        extra_where=where_best,
        row_factory=sqlite3.Row,
    )[:10]

    where_partial = f"{type_col} = 'partial'"
    partial_results = read_adaptive_table(
        results_path, _RESULTS_COLUMN_MAP, "results",
        extra_where=where_partial,
        row_factory=sqlite3.Row,
    )[:10]

    # Unmatched counts
    try:
        avail_unmatched = get_table_columns(results_path, "unmatched")
        utype_col = "type" if "type" in avail_unmatched else "match_type"
        cur.execute(f"SELECT {utype_col}, count(*) FROM unmatched GROUP BY {utype_col}")
        unmatched = [dict(zip(["type", "count"], r)) for r in cur.fetchall()]
    except Exception:
        unmatched = []

    return dumps(
        {
            "config": config_info,
            "match_statistics": type_stats,
            "unmatched": unmatched,
            "top_best_matches": best_results,
            "top_partial_matches": partial_results,
        }
    )
