"""
Diaphora MCP — importance ranking of changed functions.

Composite scoring across match type, security keywords, CFG changes,
pseudocode diff size, and heuristics.
"""

import json
import os
import sqlite3

from ..utils.sqlite import get_func, get_underlying_db_paths
from ..utils.format import pseudocode_simple_diff
from ..core.security import match_security_keywords


def score_change(result_row: dict, sec_match: bool, complexity_chg: int,
                 pseudo_diff_len: int) -> float:
    """Compute a single importance score for a changed function. 0–100."""
    score = 0.0
    mtype = result_row.get("type", "")
    ratio = float(result_row.get("ratio", 0) or 0)

    type_w = {"best": 10, "partial": 30, "unreliable": 20, "multimatch": 25}
    score += type_w.get(mtype, 15)

    if mtype == "partial":
        score += (1.0 - ratio) * 40 if ratio > 0 else 20
    elif mtype == "unreliable":
        score += 15

    if sec_match:
        score += 50

    score += min(complexity_chg * 3, 40)
    score += min(pseudo_diff_len * 0.5, 30)

    n1 = int(result_row.get("nodes1", 0) or 0)
    n2 = int(result_row.get("nodes2", 0) or 0)
    if n1 and n2:
        delta = abs(n2 - n1) / max(n1, 1)
        score += min(delta * 20, 20)

    return round(min(score, 100), 1)


def rank_changes(
    results_path: str,
    top_n: int = 30,
) -> str:
    """Analyse a .diaphora results file and rank every match by a composite
    importance score (0–100)."""
    if not os.path.isfile(results_path):
        return json.dumps({"error": f"Results file not found: {results_path}"})

    db1_path, db2_path = get_underlying_db_paths(results_path)

    conn = sqlite3.connect(results_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT * FROM results")
    all_rows = [dict(r) for r in cur.fetchall()]

    cur.execute("SELECT * FROM config")
    config_info = dict(cur.fetchone() or {})
    conn.close()

    ranked = []
    for row in all_rows:
        addr1 = row.get("address", "")
        addr2 = row.get("address2", "")
        name1 = row.get("name", "")
        name2 = row.get("name2", "")

        pseudo1 = pseudo2 = ""
        complexity_chg = 0
        if db1_path and addr1:
            f1 = get_func(db1_path, address=addr1)
            if f1:
                pseudo1 = f1.get("pseudocode", "") or ""
        if db2_path and addr2:
            f2 = get_func(db2_path, address=addr2)
            if f2:
                pseudo2 = f2.get("pseudocode", "") or ""
                complexity = f2.get("cyclomatic_complexity", 0) or 0
                complexity1 = f1.get("cyclomatic_complexity", 0) if f1 else 0
                complexity_chg = abs(complexity - complexity1)

        sec_old = match_security_keywords(name1, pseudo1, "")
        sec_new = match_security_keywords(name2, pseudo2, "")
        sec_match = sec_old["matched"] or sec_new["matched"]

        pseudo_diff = pseudocode_simple_diff(pseudo1, pseudo2)
        score = score_change(row, sec_match, complexity_chg, len(pseudo_diff))

        ranked.append({
            "score": score,
            "type": row.get("type", ""),
            "ratio": row.get("ratio", 0),
            "name_old": name1,
            "name_new": name2,
            "address_old": addr1,
            "address_new": addr2,
            "security_relevant": sec_match,
            "security_categories": sorted(set(sec_old["categories"] + sec_new["categories"])),
            "complexity_change": complexity_chg,
            "pseudo_diff_lines": len(pseudo_diff),
            "ida_pro_mcp": {
                "db1": db1_path,
                "db2": db2_path,
                "addr1": addr1,
                "addr2": addr2,
            },
        })

    ranked.sort(key=lambda x: -x["score"])

    return json.dumps({
        "config": config_info,
        "total_matches": len(ranked),
        "top_n": min(top_n, len(ranked)),
        "ranked": ranked[:top_n],
        "categories": {
            "high_interest": sum(1 for r in ranked if r["score"] >= 70),
            "medium_interest": sum(1 for r in ranked if 40 <= r["score"] < 70),
            "low_interest": sum(1 for r in ranked if r["score"] < 40),
        },
    }, indent=2, default=str)
