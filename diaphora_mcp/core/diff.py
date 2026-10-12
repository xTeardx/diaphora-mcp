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
    offset: int = 0,
    unmatched_offset: int = 0,
    sort_by: str = "ratio",
    sort_order: str = "asc",
):
    """Read bounded, deterministic pages; lower ratios surface changes first."""
    import math
    from ..utils.sqlite import resolve_columns
    for name, value, minimum in (
        ("limit", limit, 1), ("unmatched_limit", unmatched_limit, 1),
        ("offset", offset, 0), ("unmatched_offset", unmatched_offset, 0),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            raise ValueError(f"{name} must be an integer >= {minimum}")
    if match_type not in MATCH_TYPES:
        raise ValueError("Unknown match_type")
    if isinstance(min_ratio, bool) or not isinstance(min_ratio, (int, float)) or not math.isfinite(min_ratio) or not 0 <= min_ratio <= 1:
        raise ValueError("min_ratio must be between 0 and 1")
    if sort_by not in ("ratio", "address", "address2", "name", "name2", "type"):
        raise ValueError("Unsupported sort_by")
    if sort_order not in ("asc", "desc"):
        raise ValueError("sort_order must be asc or desc")
    limit, unmatched_limit = min(limit, 5000), min(unmatched_limit, 5000)
    conn = get_connection(results_path)
    conn.row_factory = sqlite3.Row
    columns = dict(resolve_columns(get_table_columns(results_path, "results"), _RESULTS_COLUMN_MAP))
    for key in ("type", "ratio", sort_by):
        if not columns.get(key):
            raise ValueError(f"Results schema missing {key} column")
    type_col, ratio_col = columns["type"], columns["ratio"]
    mtypes = MATCH_TYPES[match_type]
    where = f'"{type_col}" IN ({",".join("?" for _ in mtypes)})'
    params = tuple(mtypes)
    if min_ratio > 0:
        where += f' AND CAST("{ratio_col}" AS REAL) >= ?'
        params += (min_ratio,)
    sort_expr = f'CAST("{ratio_col}" AS REAL)' if sort_by == "ratio" else f'"{columns[sort_by]}"'
    # rowid is a unique, stable final tie-breaker in official results tables.
    order = f'{sort_expr} {sort_order.upper()}, rowid ASC'
    total = conn.execute(f"SELECT count(*) FROM results WHERE {where}", params).fetchone()[0]
    results = read_adaptive_table(results_path, _RESULTS_COLUMN_MAP, extra_where=where,
                                  params=params, limit=limit, offset=offset, order_by=order)
    counts = dict.fromkeys(MATCH_TYPES["all"], 0)
    for kind, count in conn.execute(f'SELECT "{type_col}", count(*) FROM results GROUP BY "{type_col}"'):
        if kind in counts:
            counts[kind] = count
    unmatched_columns = get_table_columns(results_path, "unmatched")
    unmatched_count = conn.execute("SELECT count(*) FROM unmatched").fetchone()[0] if unmatched_columns else 0
    unmatched = read_adaptive_table(results_path, _UNMATCHED_COLUMN_MAP, "unmatched",
                                    limit=unmatched_limit, offset=unmatched_offset,
                                    order_by="rowid ASC") if unmatched_columns else []
    next_offset = offset + len(results) if offset + len(results) < total else None
    next_unmatched = unmatched_offset + len(unmatched) if unmatched_offset + len(unmatched) < unmatched_count else None
    return {
        "config": dict(conn.execute("SELECT * FROM config LIMIT 1").fetchone() or {}),
        "counts": counts, "total_matches": total, "unmatched_count": unmatched_count,
        "results": results, "truncated": next_offset is not None,
        "unmatched": unmatched, "unmatched_truncated": next_unmatched is not None,
        "offset": offset, "unmatched_offset": unmatched_offset,
        "next_offset": next_offset, "next_unmatched_offset": next_unmatched,
        "sort_by": sort_by, "sort_order": sort_order,
    }


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
def _prepare_diff(db1_path, db2_path, output_path):
    from .export import _validate_export_output_path, _staged_export_path
    db1_path, db2_path = os.path.abspath(db1_path), os.path.abspath(db2_path)
    for label, path in [("db1", db1_path), ("db2", db2_path)]:
        error = check_db_for_diff(path)
        if error:
            return None, None, {"error": f"{label}: {error}"}
    if not output_path:
        b1 = os.path.splitext(os.path.basename(db1_path))[0]
        b2 = os.path.splitext(os.path.basename(db2_path))[0]
        root = os.environ.get("DIAPHORA_OUTPUT_ROOT") or os.path.dirname(db1_path)
        output_path = os.path.join(root, f"{b1}_vs_{b2}.diaphora")
    output_path = os.path.abspath(output_path)
    error = _validate_export_output_path(db1_path, output_path)
    if error:
        return None, None, {"error": error}
    return output_path, _staged_export_path(output_path), None


def _diff_command(db1, db2, staged):
    from ..utils.connection import close_connection
    close_connection(db1)
    close_connection(db2)
    return [PYTHON, DIAPHORA_SCRIPT, os.path.abspath(db1), os.path.abspath(db2), "-o", os.path.abspath(staged)]


def _finish_diff(returncode, staged, target, limit=500, unmatched_limit=100):
    from .export import _publish_staged_export
    if returncode != 0:
        return {"error": f"Diaphora diff failed with exit code {returncode}"}
    if not os.path.isfile(staged):
        return {"error": "Diaphora completed but did not produce an output file"}
    error = check_results_db(staged)
    if error:
        return {"error": error}
    # Read before publishing so corrupt/inaccessible results never become final outputs.
    results = read_results(staged, limit=limit, unmatched_limit=unmatched_limit)
    from ..utils.sqlite import resolve_columns
    unmatched_columns = dict(resolve_columns(get_table_columns(staged, "unmatched"), _UNMATCHED_COLUMN_MAP))
    type_column = unmatched_columns.get("type")
    results["unmatched_counts"] = dict(get_connection(staged).execute(
        f'SELECT "{type_column}", count(*) FROM unmatched GROUP BY "{type_column}"'
    )) if type_column else {}
    error = _publish_staged_export(staged, target)
    return {"error": error} if error else results


def diff_diaphora_dbs(db1_path: str, db2_path: str, output_path: str | None = None) -> str:
    """Compare old-primary and new-secondary exports without replacing artifacts."""
    target, staged, error = _prepare_diff(db1_path, db2_path, output_path)
    if error:
        return dumps(error)
    from .export import _remove_staged_export
    proc = None
    log = OperationLogger("Diaphora comparison", tag="diff")
    log.__enter__()
    stdout_tail, stderr_tail = [""], [""]
    try:
        proc = subprocess.Popen(_diff_command(db1_path, db2_path, staged),
                                cwd=DIAPHORA_DIR, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                stdin=subprocess.DEVNULL, text=True,
                                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        # Drain both pipes while waiting, preserving the timeout/kill contract.
        def drain(pipe, tail):
            try:
                for line in pipe:
                    tail[0] = (tail[0] + line)[-3000:]
            except Exception:
                pass
        readers = [threading.Thread(target=drain, args=(pipe, tail), daemon=True)
                   for pipe, tail in ((proc.stdout, stdout_tail), (proc.stderr, stderr_tail))]
        for reader in readers:
            reader.start()
        proc.wait(timeout=3600)
        for reader in readers:
            reader.join(timeout=2)
        log.info(f"Diff exit code: {proc.returncode}")
        log.log_subprocess_output(stdout_tail[0], stderr_tail[0])
        result = _finish_diff(proc.returncode, staged, target)
        if "error" in result:
            result.update(stdout_tail=stdout_tail[0], stderr_tail=stderr_tail[0])
        return dumps(result)
    except subprocess.TimeoutExpired:
        return err_json("Diaphora diff timed out after 3600 s")
    except Exception:
        return err_json("Unable to run or read Diaphora diff")
    finally:
        if proc is not None and proc.poll() is None:
            _kill_and_reap(proc)
        _remove_staged_export(staged)
        log.__exit__(None, None, None)


async def _diff_diaphora_dbs_async(db1_path, db2_path, output_path, limit=500, unmatched_limit=100):
    import asyncio
    target, staged, error = _prepare_diff(db1_path, db2_path, output_path)
    if error:
        return error
    from .export import _remove_staged_export
    proc = None
    log = OperationLogger("Diaphora comparison", tag="diff")
    log.__enter__()
    stdout_tail, stderr_tail = [""], [""]
    try:
        proc = subprocess.Popen(_diff_command(db1_path, db2_path, staged),
                                cwd=DIAPHORA_DIR, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                stdin=subprocess.DEVNULL, text=True,
                                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        stdout, stderr = await asyncio.wait_for(asyncio.to_thread(proc.communicate), timeout=3600)
        log.info(f"Diff exit code: {proc.returncode}")
        log.log_subprocess_output((stdout or "")[-3000:], (stderr or "")[-3000:])
        result = _finish_diff(proc.returncode, staged, target, limit, unmatched_limit)
        if "error" in result:
            result.update(stdout_tail=(stdout or "")[-3000:], stderr_tail=(stderr or "")[-3000:])
        return result
    except asyncio.TimeoutError:
        return {"error": "Diaphora diff timed out after 3600 s"}
    except Exception:
        return {"error": "Unable to run or read Diaphora diff"}
    finally:
        if proc is not None and proc.poll() is None:
            _kill_and_reap(proc)
        _remove_staged_export(staged)
        log.__exit__(None, None, None)


def get_diff_results(
    results_path: str,
    match_type: str = "all",
    min_ratio: float = 0.0,
    limit: int = 500,
    unmatched_limit: int = 100,
    offset: int = 0,
    unmatched_offset: int = 0,
    sort_by: str = "ratio",
    sort_order: str = "asc",
) -> str:
    """Return matches from a .diaphora results file, optionally filtered."""
    if not os.path.isfile(results_path):
        return err_json(f"Results file not found: {results_path}")
    if (err := check_results_db(results_path)):
        return err_json(err)

    try:
        return dumps(
            read_results(results_path, match_type, min_ratio, limit, unmatched_limit,
                         offset, unmatched_offset, sort_by, sort_order)
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

    cur.execute("SELECT * FROM config LIMIT 1")
    config_info = dict(cur.fetchone() or {})

    from ..utils.sqlite import resolve_columns
    columns = dict(resolve_columns(get_table_columns(results_path, "results"), _RESULTS_COLUMN_MAP))
    type_col, ratio_col = columns.get("type"), columns.get("ratio")
    if not type_col or not ratio_col:
        return err_json("Results schema missing type or ratio column")

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
        row_factory=sqlite3.Row, limit=10,
        order_by=f"CAST({ratio_col} AS REAL) ASC, rowid ASC",
    )

    where_partial = f"{type_col} = 'partial'"
    partial_results = read_adaptive_table(
        results_path, _RESULTS_COLUMN_MAP, "results",
        extra_where=where_partial,
        row_factory=sqlite3.Row, limit=10,
        order_by=f"CAST({ratio_col} AS REAL) ASC, rowid ASC",
    )

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
