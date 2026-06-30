"""
Diaphora MCP — diff operations.

Reading, filtering, and summarising .diaphora diff results files,
plus the raw database diff subprocess call.
"""

import json
import os
import sqlite3
import subprocess
import time

from ..config import DIAPHORA_SCRIPT, DIAPHORA_DIR, PYTHON
from ..utils.sqlite import check_db
from ..utils.log import OperationLogger, log_path, write_log
from ..models import MATCH_TYPES


# ---------------------------------------------------------------------------
# Read results
# ---------------------------------------------------------------------------
def read_results(results_path: str, match_type: str = "all", min_ratio: float = 0.0):
    """Read a .diaphora results file and return structured data."""
    conn = sqlite3.connect(results_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT * FROM config")
    config_info = dict(cur.fetchone() or {})

    mtypes = MATCH_TYPES.get(match_type, MATCH_TYPES["all"])
    placeholders = ",".join("?" for _ in mtypes)

    if min_ratio > 0:
        sql = (
            f"SELECT * FROM results WHERE type IN ({placeholders}) AND ratio >= ?"
            " ORDER BY ratio DESC"
        )
        params = [*mtypes, min_ratio]
    else:
        sql = f"SELECT * FROM results WHERE type IN ({placeholders}) ORDER BY ratio DESC"
        params = [*mtypes]

    cur.execute(sql, params)
    results = [dict(r) for r in cur.fetchall()]

    counts = {}
    for t in ["best", "partial", "unreliable", "multimatch"]:
        cur.execute("SELECT count(*) FROM results WHERE type = ?", (t,))
        counts[t] = cur.fetchone()[0]

    cur.execute("SELECT * FROM unmatched")
    unmatched = [dict(r) for r in cur.fetchall()]

    conn.close()

    return {
        "config": config_info,
        "counts": counts,
        "total_matches": len(results),
        "unmatched_count": len(unmatched),
        "results": results[:500],
        "truncated": len(results) > 500,
        "unmatched": unmatched[:100],
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
    err1 = check_db(db1_path)
    if err1:
        return json.dumps({"error": err1})
    err2 = check_db(db2_path)
    if err2:
        return json.dumps({"error": err2})

    if not output_path:
        b1 = os.path.splitext(os.path.basename(db1_path))[0]
        b2 = os.path.splitext(os.path.basename(db2_path))[0]
        output_path = os.path.join(
            os.path.dirname(db1_path), f"{b1}_vs_{b2}.diaphora"
        )

    desc = f"Diff {os.path.basename(db1_path)} vs {os.path.basename(db2_path)}"
    log = OperationLogger(desc, tag="diff")
    log.__enter__()
    log.info(f"  db1: {db1_path}")
    log.info(f"  db2: {db2_path}")
    log.info(f"  out: {output_path}")

    try:
        start = time.time()
        proc = subprocess.run(
            [PYTHON, DIAPHORA_SCRIPT, db1_path, db2_path, "-o", output_path],
            cwd=DIAPHORA_DIR,
            capture_output=True,
            text=True,
            timeout=600,
        )
        elapsed = time.time() - start
        log.info(f"diaphora.py exit code: {proc.returncode} ({elapsed:.0f}s)")
        log.log_subprocess_output(proc.stdout or "", proc.stderr or "")
    except subprocess.TimeoutExpired:
        log.error("Diaphora diff timed out after 600 s")
        log.__exit__(None, None, None)
        return json.dumps({"error": "Diaphora diff timed out after 600 s"})
    except FileNotFoundError:
        log.error(f"diaphora.py not found at {DIAPHORA_SCRIPT}")
        log.__exit__(None, None, None)
        return json.dumps({"error": f"diaphora.py not found at {DIAPHORA_SCRIPT}"})
    except Exception as exc:
        log.error(f"Failed to launch Diaphora: {exc}")
        log.__exit__(None, None, None)
        return json.dumps({"error": f"Failed to launch Diaphora: {exc}"})

    if not os.path.isfile(output_path):
        log.error("No output file produced")
        log.__exit__(None, None, None)
        return json.dumps(
            {
                "error": "Diaphora completed but did not produce an output file",
                "stdout": (proc.stdout or "")[-3000:],
                "stderr": (proc.stderr or "")[-3000:],
            }
        )

    out_size = os.path.getsize(output_path)
    log.info(f"Output created: {out_size} bytes")

    # Read result stats for the log
    try:
        conn = sqlite3.connect(output_path)
        cur = conn.cursor()
        cur.execute("SELECT type, count(*) FROM results GROUP BY type")
        counts = dict(cur.fetchall())
        log.info(f"Matches: {counts}")
        cur.execute("SELECT count(*) FROM unmatched")
        log.info(f"Unmatched: {cur.fetchone()[0]}")
        conn.close()
    except Exception:
        pass

    log.__exit__(None, None, None)
    return json.dumps(read_results(output_path), indent=2, default=str)


def get_diff_results(
    results_path: str,
    match_type: str = "all",
    min_ratio: float = 0.0,
) -> str:
    """Return matches from a .diaphora results file, optionally filtered."""
    if not os.path.isfile(results_path):
        return json.dumps({"error": f"Results file not found: {results_path}"})

    try:
        return json.dumps(
            read_results(results_path, match_type, min_ratio), indent=2, default=str
        )
    except Exception as exc:
        return json.dumps({"error": f"Error reading results: {exc}"})


def get_diff_summary(results_path: str) -> str:
    """Return match statistics, top matches, and unmatched counts."""
    if not os.path.isfile(results_path):
        return json.dumps({"error": f"Results file not found: {results_path}"})

    conn = sqlite3.connect(results_path)
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

    conn.close()

    return json.dumps(
        {
            "config": config_info,
            "match_statistics": type_stats,
            "unmatched": unmatched,
            "top_best_matches": top_best,
            "top_partial_matches": top_partial,
        },
        indent=2,
        default=str,
    )
