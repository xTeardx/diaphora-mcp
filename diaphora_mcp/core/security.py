"""
Diaphora MCP — security analysis.

Keyword-based security relevance filtering and security-patch heuristics.
"""

import json
import os
import sqlite3

from ..models import SECURITY_KEYWORDS, SECURITY_KEYWORD_CATEGORIES
from ..utils.sqlite import get_underlying_db_paths, get_func


# ---------------------------------------------------------------------------
# Keyword matching
# ---------------------------------------------------------------------------
def match_security_keywords(name: str, pseudo: str, assembly: str) -> dict:
    """Check a function against security keyword lists.

    Returns a dict with matched categories and the specific keywords found.
    """
    name_lower = name.lower() if name else ""
    pseudo_lower = pseudo.lower() if pseudo else ""
    assembly_lower = assembly.lower() if assembly else ""
    haystack = f"{name_lower} {pseudo_lower} {assembly_lower}"

    matched_keywords = []
    categories = set()

    for kw in SECURITY_KEYWORDS:
        if kw in haystack:
            matched_keywords.append(kw)
            for cat_name, cat_kws in SECURITY_KEYWORD_CATEGORIES.items():
                if kw in cat_kws:
                    categories.add(cat_name)
                    break
            else:
                categories.add("other")

    return {
        "matched": len(matched_keywords) > 0,
        "keywords": matched_keywords[:20],
        "categories": sorted(categories),
    }


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
def analyze_diff_results(
    results_path: str,
    security_only: bool = True,
) -> str:
    """Analyse diff results for security-relevant changes.

    Uses keyword matching against function names, pseudocode, and assembly.
    Returns a structured report with matched categories, severity indicators,
    and full context (address, database path) for IDA Pro MCP drill-down.
    """
    if not os.path.isfile(results_path):
        return json.dumps({"error": f"Results file not found: {results_path}"})

    conn = sqlite3.connect(results_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT * FROM config")
    config_info = dict(cur.fetchone() or {})

    cur.execute("SELECT * FROM matching_databases")
    databases = [dict(r) for r in cur.fetchall()]

    db1_path = config_info.get("primary_database", "")
    db2_path = config_info.get("secondary_database", "")

    cur.execute(
        """SELECT r.*, m1.pseudocode as pseudo1, m2.pseudocode as pseudo2,
                  m1.assembly as asm1, m2.assembly as asm2,
                  m1.name as name1, m2.name as name2,
                  m1.address as addr1, m2.address as addr2
           FROM results r
           LEFT JOIN functions m1 ON r.address1 = m1.address
           LEFT JOIN functions m2 ON r.address2 = m2.address"""
    )
    all_results = [dict(r) for r in cur.fetchall()]

    matches = []
    security_count = 0

    for row in all_results:
        name1 = row.get("name1") or row.get("name", "")
        name2 = row.get("name2") or ""
        pseudo1 = row.get("pseudo1") or ""
        pseudo2 = row.get("pseudo2") or ""
        asm1 = row.get("asm1") or ""
        asm2 = row.get("asm2") or ""
        ratio = row.get("ratio", 0) or 0
        match_type = row.get("type", "unknown")

        sec_old = match_security_keywords(name1 or "", pseudo1, asm1)
        sec_new = match_security_keywords(name2 or "", pseudo2, asm2)

        is_security_relevant = sec_old["matched"] or sec_new["matched"]

        complexity_change = abs(
            (row.get("cyclomatic_complexity1") or 0)
            - (row.get("cyclomatic_complexity2") or 0)
        )

        entry = {
            "type": match_type,
            "ratio": ratio,
            "name_old": name1,
            "name_new": name2,
            "address_old": row.get("addr1") or row.get("address1", ""),
            "address_new": row.get("addr2") or row.get("address2", ""),
            "security_relevant": is_security_relevant,
            "security_categories": sorted(
                set(sec_old["categories"] + sec_new["categories"])
            ) if is_security_relevant else [],
            "security_keywords": sorted(
                set(sec_old["keywords"] + sec_new["keywords"])
            ) if is_security_relevant else [],
            "complexity_change": complexity_change,
            "suspicious": (
                complexity_change >= 5 and ratio < 0.7
            ),
            "ida_pro_mcp": {
                "db1": db1_path,
                "db2": db2_path,
                "addr1": row.get("addr1") or row.get("address1", ""),
                "addr2": row.get("addr2") or row.get("address2", ""),
            },
        }

        if is_security_relevant:
            security_count += 1

        if security_only and not is_security_relevant:
            continue

        matches.append(entry)

    cur.execute(
        """SELECT type, count(*) as cnt
           FROM results GROUP BY type"""
    )
    type_counts = {r["type"]: r["cnt"] for r in cur.fetchall()}

    cur.execute("SELECT * FROM unmatched")
    unmatched = [dict(r) for r in cur.fetchall()]

    conn.close()

    return json.dumps(
        {
            "config": {
                "primary_database": db1_path,
                "secondary_database": db2_path,
            },
            "total_matches": len(all_results),
            "total_matches_analyzed": len(matches),
            "security_relevant_matches": security_count,
            "match_type_counts": type_counts,
            "unmatched": len(unmatched),
            "matches": matches,
            "databases": databases,
            "recommendation": (
                f"Found {security_count} security-relevant match(es). "
                "Use IDA Pro MCP tools (decompile_function, "
                "get_function_by_address, etc.) on the addresses above "
                "for deeper analysis."
            ),
        },
        indent=2,
        default=str,
    )


def detect_security_patches(
    results_path: str,
) -> str:
    """Analyse diff results for security patch patterns.

    Heuristics:
    - New comparison / bounds checks (if x >= limit)
    - Added null-pointer checks
    - Added error handling (goto cleanup, return -1)
    - Cryptographic algorithm changes
    - Memory safety pattern changes (memcpy → memmove, added size checks)
    - Added anti-debug / integrity checks
    - Functions where complexity barely changed but pseudocode diff is large
      (logic rewrite without structural change)
    """
    if not os.path.isfile(results_path):
        return json.dumps({"error": f"Results file not found: {results_path}"})

    db1_path, db2_path = get_underlying_db_paths(results_path)

    conn = sqlite3.connect(results_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM results")
    results = [dict(r) for r in cur.fetchall()]
    conn.close()

    from ..utils.format import pseudocode_simple_diff

    security_patches = []

    for row in results:
        addr1 = row.get("address", "")
        addr2 = row.get("address2", "")
        name1 = row.get("name", "")
        name2 = row.get("name2", "")
        ratio = row.get("ratio", 0) or 0
        mtype = row.get("type", "")

        pseudo1 = pseudo2 = ""
        f1 = get_func(db1_path, address=addr1) if db1_path and addr1 else None
        f2 = get_func(db2_path, address=addr2) if db2_path and addr2 else None

        if f1:
            pseudo1 = f1.get("pseudocode", "") or ""
        if f2:
            pseudo2 = f2.get("pseudocode", "") or ""

        match_indicators = []

        diff_lines = pseudocode_simple_diff(pseudo1, pseudo2)
        added_lines = [d["line"] for d in diff_lines if d["type"] == "added"]
        removed_lines = [d["line"] for d in diff_lines if d["type"] == "removed"]

        added_text = " ".join(added_lines)

        # 1. New bounds checks
        if any(kw in added_text for kw in [">= ", "<= ", "> ", "< "]):
            match_indicators.append("new_bounds_check")

        # 2. New null/error checks
        if "NULL" in added_text or "nullptr" in added_text or "null" in added_text.lower():
            match_indicators.append("new_null_check")

        # 3. New error handling
        if "return -1" in added_text or "return false" in added_text or "goto" in added_text:
            match_indicators.append("new_error_handling")

        # 4. New validation / sanitization
        if any(kw in added_text.lower() for kw in ["validate", "sanitize", "verify", "check"]):
            match_indicators.append("new_validation")

        # 5. Memory safety patterns
        if any(kw in added_text.lower() for kw in ["sizeof", "memcpy_s", "memmove",
                                                     "strncpy", "strncat", "snprintf"]):
            match_indicators.append("memory_safety")
        if any(kw in removed_lines or kw in added_lines for kw in ["memcpy", "strcpy", "sprintf", "gets", "scanf"]):
            match_indicators.append("unsafe_func_removed")

        # 6. Crypto changes
        if any(kw in added_text.lower() for kw in ["aes", "rsa", "sha", "hash", "hmac",
                                                     "encrypt", "decrypt", "cipher"]):
            match_indicators.append("crypto_change")

        # 7. Logic rewrite
        cc1 = (f1.get("cyclomatic_complexity", 0) or 0) if f1 else 0
        cc2 = (f2.get("cyclomatic_complexity", 0) or 0) if f2 else 0
        if abs(cc2 - cc1) <= 3 and len(diff_lines) > 10 and ratio > 0.7:
            match_indicators.append("logic_rewrite")

        # 8. Anti-debug / integrity
        if any(kw in added_text.lower() for kw in ["ptrace", "debugger", "isdebug",
                                                     "antidebug", "tamper", "integrity",
                                                     "checksum", "self_check"]):
            match_indicators.append("anti_debug_integrity")

        # 9. Exception handling changes
        if any(kw in added_text for kw in ["__try", "__except", "try {", "catch ", "throw"]):
            match_indicators.append("exception_handling")

        # 10. New parameter checks
        if "if (" in added_text and any(p in added_text for p in ["argc", "argv", "param", "arg"]):
            match_indicators.append("parameter_validation")

        if match_indicators:
            security_patches.append({
                "address_old": addr1,
                "address_new": addr2,
                "name_old": name1,
                "name_new": name2,
                "type": mtype,
                "ratio": ratio,
                "indicators": match_indicators,
                "severity": (
                    "high" if any(i in match_indicators for i in
                                  ["memory_safety", "crypto_change", "anti_debug_integrity"])
                    else "medium" if "new_bounds_check" in match_indicators
                    else "low"
                ),
                "pseudo_diff_lines": len(diff_lines),
                "complexity_change": abs(cc2 - cc1),
                "ida_pro_mcp": {
                    "db1": db1_path,
                    "db2": db2_path,
                    "addr1": addr1,
                    "addr2": addr2,
                },
            })

    security_patches.sort(key=lambda x: (
        {"high": 0, "medium": 1, "low": 2}[x["severity"]],
        -len(x["indicators"]),
    ))

    return json.dumps({
        "total_matches_analysed": len(results),
        "security_patches_found": len(security_patches),
        "severity_summary": {
            "high": sum(1 for s in security_patches if s["severity"] == "high"),
            "medium": sum(1 for s in security_patches if s["severity"] == "medium"),
            "low": sum(1 for s in security_patches if s["severity"] == "low"),
        },
        "detection_heuristics_applied": [
            "new_bounds_check", "new_null_check", "new_error_handling",
            "new_validation", "memory_safety", "unsafe_func_removed",
            "crypto_change", "logic_rewrite", "anti_debug_integrity",
            "exception_handling", "parameter_validation",
        ],
        "security_patches": security_patches,
        "recommendation": (
            "Review high-severity items first. Use compare_functions or "
            "IDA Pro MCP (decompile_function) on the addresses above."
        ),
    }, indent=2, default=str)
