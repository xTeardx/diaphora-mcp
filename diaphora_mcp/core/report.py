"""
Diaphora MCP — patch report generation.

Orchestrates data from multiple sources to produce a comprehensive
patch analysis report.  Standalone module so core/analysis.py stays
under 800 lines.
"""

import json
import os
import sqlite3

from ..utils.sqlite import get_func, get_funcs_batch, get_underlying_db_paths
from ..core.security import match_security_keywords
from ..utils.format import dumps, err_json


def summarize_patch(
    results_path: str,
) -> str:
    """Create a full patch analysis report from a .diaphora results file."""
    if not os.path.isfile(results_path):
        return err_json(f"Results file not found: {results_path}")

    db1_path, db2_path = get_underlying_db_paths(results_path)

    with sqlite3.connect(results_path) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("SELECT * FROM config")
        config_info = dict(cur.fetchone() or {})

        cur.execute("SELECT * FROM results")
        results = [dict(r) for r in cur.fetchall()]

        cur.execute("SELECT * FROM unmatched")
        unmatched = [dict(r) for r in cur.fetchall()]

    # Statistics
    total = len(results)
    by_type = {}
    for r in results:
        t = r.get("type", "unknown")
        by_type[t] = by_type.get(t, 0) + 1

    ratios = [float(r.get("ratio", 0) or 0) for r in results]
    avg_ratio = round(sum(ratios) / max(len(ratios), 1), 3)

    # Security analysis (batch-load functions)
    sec_count = 0
    sec_categories: set = set()

    addrs1 = [r.get("address", "") for r in results]
    addrs2 = [r.get("address2", "") for r in results]
    funcs1 = get_funcs_batch(db1_path, addrs1) if db1_path else {}
    funcs2 = get_funcs_batch(db2_path, addrs2) if db2_path else {}

    for r in results:
        addr1 = r.get("address", "")
        addr2 = r.get("address2", "")
        name1 = r.get("name", "")
        name2 = r.get("name2", "")
        f1 = funcs1.get(addr1) if addr1 else None
        f2 = funcs2.get(addr2) if addr2 else None
        pseudo1 = (f1.get("pseudocode", "") or "") if f1 else ""
        pseudo2 = (f2.get("pseudocode", "") or "") if f2 else ""
        so = match_security_keywords(name1, pseudo1, "")
        sn = match_security_keywords(name2, pseudo2, "")
        if so["matched"] or sn["matched"]:
            sec_count += 1
            sec_categories.update(so["categories"] + sn["categories"])

    # Program info
    prog1 = prog2 = {}
    if db1_path:
        try:
            with sqlite3.connect(db1_path) as conn1:
                cur1 = conn1.cursor()
                cur1.execute("SELECT * FROM program")
                row = cur1.fetchone()
                if row:
                    prog1 = dict(zip([d[0] for d in cur1.description], row))
        except Exception:
            pass
    if db2_path:
        try:
            with sqlite3.connect(db2_path) as conn2:
                cur2 = conn2.cursor()
                cur2.execute("SELECT * FROM program")
                row = cur2.fetchone()
                if row:
                    prog2 = dict(zip([d[0] for d in cur2.description], row))
        except Exception:
            pass

    unmatched_primary = [u for u in unmatched if u.get("type") == "primary"]
    unmatched_secondary = [u for u in unmatched if u.get("type") == "secondary"]

    return dumps({
        "report_title": "Diaphora Patch Analysis Report",
        "binaries": {
            "primary": {
                "path": db1_path or config_info.get("main_db", ""),
                "md5": prog1.get("md5sum", ""),
                "processor": prog1.get("processor", ""),
            },
            "secondary": {
                "path": db2_path or config_info.get("diff_db", ""),
                "md5": prog2.get("md5sum", ""),
                "processor": prog2.get("processor", ""),
            },
        },
        "config": config_info,
        "match_statistics": {
            "total_matches": total,
            "by_type": by_type,
            "average_ratio": avg_ratio,
            "ratio_distribution": {
                "exact (1.0)": sum(1 for r in ratios if r == 1.0),
                "high (0.9–0.99)": sum(1 for r in ratios if 0.9 <= r < 1.0),
                "medium (0.7–0.89)": sum(1 for r in ratios if 0.7 <= r < 0.9),
                "low (< 0.7)": sum(1 for r in ratios if 0.0 < r < 0.7),
            },
        },
        "security_analysis": {
            "security_relevant_matches": sec_count,
            "categories_found": sorted(sec_categories) if sec_categories else [],
            "pct_of_total": round(sec_count / max(total, 1) * 100, 1),
        },
        "unmatched": {
            "primary_only": len(unmatched_primary),
            "secondary_only": len(unmatched_secondary),
            "primary_examples": [
                {"address": u.get("address", ""), "name": u.get("name", "")}
                for u in unmatched_primary[:20]
            ],
            "secondary_examples": [
                {"address": u.get("address", ""), "name": u.get("name", "")}
                for u in unmatched_secondary[:20]
            ],
        },
        "recommendations": [
            f"Found {by_type.get('best', 0)} best, {by_type.get('partial', 0)} partial, "
            f"{by_type.get('unreliable', 0)} unreliable matches.",
            f"{sec_count} function(s) have security-relevant changes ({sorted(sec_categories) if sec_categories else 'none'}).",
            f"{len(unmatched_primary)} function(s) removed, {len(unmatched_secondary)} added.",
            "Use rank_changes for a sorted priority list, find_patch_root for root cause candidates, "
            "or analyze_diff_results for detailed security filtering.",
        ],
    })
