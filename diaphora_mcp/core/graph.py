"""
Diaphora MCP — callgraph analysis.

BFS call-path traversal, comparison of callers/callees across versions,
and root-cause detection via dependency-chain analysis.
"""

import json
import os
import sqlite3

from ..utils.sqlite import check_db, get_func, get_callgraph, resolve_func_names, get_underlying_db_paths


def build_call_path(db_path: str, start_addr: str, depth: int,
                    direction: str = "callees") -> list:
    """BFS walk callgraph from *start_addr* up to *depth* levels.

    *direction* is "callees" (down) or "callers" (up).
    """
    visited = set()
    result = []
    queue = [(start_addr, 0)]

    while queue:
        addr, level = queue.pop(0)
        if addr in visited or level > depth:
            continue
        visited.add(addr)

        cg = get_callgraph(db_path, addr)
        targets = cg.get(direction, [])
        resolved = resolve_func_names(db_path, targets)

        entry = {
            "address": addr,
            "level": level,
            "direction": direction,
            "calls": len(targets),
            "functions": {tgt: resolved.get(tgt, "?") for tgt in sorted(targets)[:20]},
        }
        result.append(entry)

        for tgt in targets[:50]:
            queue.append((tgt, level + 1))

    return result


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
def get_changed_callgraph(
    db1_path: str,
    db2_path: str,
    address: str = "",
    name: str = "",
) -> str:
    """Compare the callers and callees of a function across two databases."""
    err1 = check_db(db1_path)
    if err1:
        return json.dumps({"error": err1})
    err2 = check_db(db2_path)
    if err2:
        return json.dumps({"error": err2})

    if not address and not name:
        return json.dumps({"error": "Provide either address or name"})

    if not address and name:
        f1 = get_func(db1_path, name=name)
        if not f1:
            return json.dumps({"error": f"Function '{name}' not found in db1"})
        address = f1["address"]

    func1 = get_func(db1_path, address=address)
    func2 = get_func(db2_path, address=address)

    if not func1 and not func2:
        return json.dumps({"error": f"Function at 0x{address} not found in either database"})

    name1 = func1["name"] if func1 else "(not in db1)"
    name2 = func2["name"] if func2 else "(not in db2)"

    cg1 = get_callgraph(db1_path, address) if func1 else {"callers": [], "callees": []}
    cg2 = get_callgraph(db2_path, address) if func2 else {"callers": [], "callees": []}

    set_c1 = set(cg1["callers"])
    set_c2 = set(cg2["callers"])
    set_ce1 = set(cg1["callees"])
    set_ce2 = set(cg2["callees"])

    added_callers = list(set_c2 - set_c1)
    removed_callers = list(set_c1 - set_c2)
    kept_callers = list(set_c1 & set_c2)

    added_callees = list(set_ce2 - set_ce1)
    removed_callees = list(set_ce1 - set_ce2)
    kept_callees = list(set_ce1 & set_ce2)

    all_addrs = set(added_callers + removed_callers + kept_callers +
                    added_callees + removed_callees + kept_callees)
    names1 = resolve_func_names(db1_path, list(all_addrs))
    names2 = resolve_func_names(db2_path, list(all_addrs))
    combined_names = {a: names1.get(a) or names2.get(a) or "?" for a in all_addrs}

    def _format_list(addrs):
        items = [{"address": a, "name": combined_names.get(a, "?")} for a in addrs]
        return sorted(items, key=lambda x: x.get("address", ""))

    return json.dumps({
        "function_name_old": name1,
        "function_name_new": name2,
        "address": address,
        "callers": {
            "total_old": len(set_c1),
            "total_new": len(set_c2),
            "added": _format_list(added_callers),
            "removed": _format_list(removed_callers),
            "unchanged": len(kept_callers),
        },
        "callees": {
            "total_old": len(set_ce1),
            "total_new": len(set_ce2),
            "added": _format_list(added_callees),
            "removed": _format_list(removed_callees),
            "unchanged": len(kept_callees),
        },
        "summary": (
            f"{name2}: +{len(added_callers)}/–{len(removed_callers)} callers, "
            f"+{len(added_callees)}/–{len(removed_callees)} callees"
        ),
    }, indent=2, default=str)


def compare_call_path(
    db1_path: str,
    db2_path: str,
    address: str = "",
    name: str = "",
    depth: int = 2,
    direction: str = "callees",
) -> str:
    """Walk the callgraph from a starting function and compare the call trees
    between old and new binaries."""
    err1 = check_db(db1_path)
    if err1:
        return json.dumps({"error": err1})
    err2 = check_db(db2_path)
    if err2:
        return json.dumps({"error": err2})

    if not address and not name:
        return json.dumps({"error": "Provide either address or name"})

    if not address and name:
        f1 = get_func(db1_path, name=name)
        if not f1:
            return json.dumps({"error": f"Function '{name}' not found in db1"})
        address = f1["address"]

    depth = min(depth, 5)
    path1 = build_call_path(db1_path, address, depth, direction)
    path2 = build_call_path(db2_path, address, depth, direction)

    def _flatten(path):
        return {(e["address"], l) for e in path for l in [e["level"]]}

    set1 = _flatten(path1)
    set2 = _flatten(path2)
    added = [e for e in path2 if (e["address"], e["level"]) not in set1]
    removed = [e for e in path1 if (e["address"], e["level"]) not in set2]

    return json.dumps({
        "function_address": address,
        "direction": direction,
        "depth": depth,
        "total_nodes_old": len(set1),
        "total_nodes_new": len(set2),
        "added_nodes": len(added),
        "removed_nodes": len(removed),
        "call_path_old": path1,
        "call_path_new": path2,
        "added": added[:20],
        "removed": removed[:20],
        "summary": (
            f"Call {direction} for 0x{address}: "
            f"{len(set1)}→{len(set2)} nodes, "
            f"+{len(added)}/–{len(removed)}"
        ),
    }, indent=2, default=str)


def find_patch_root(
    results_path: str,
) -> str:
    """Analyse the diff to identify which functions are probable root causes.

    Strategy:
    1. Find changed functions that call many other changed functions.
    2. Find functions high in the call chain whose callees also changed.
    3. Cross-reference with security keywords and complexity jumps.
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

    if not db1_path or not db2_path:
        return json.dumps({
            "note": "Underlying databases not found — limited analysis",
            "results": [r for r in results],
        }, indent=2, default=str)

    changed_addrs = set()
    addr_to_result = {}
    for r in results:
        a2 = r.get("address2", "")
        if a2:
            a2n = a2.strip().lower()
            changed_addrs.add(a2n)
            if a2n not in addr_to_result:
                addr_to_result[a2n] = r

    conn2 = sqlite3.connect(db2_path)
    cur2 = conn2.cursor()
    candidates = []
    for addr in changed_addrs:
        cur2.execute(
            "SELECT id, name, instructions, cyclomatic_complexity FROM functions WHERE address = ?",
            (addr,)
        )
        row = cur2.fetchone()
        if not row:
            continue
        fid, fname, insns, cc = row

        cur2.execute(
            "SELECT address FROM callgraph WHERE func_id = ? AND type = 'callee'",
            (fid,)
        )
        callee_addrs = {r[0].strip().lower() for r in cur2.fetchall()}

        callees_changed = callee_addrs & changed_addrs
        pct = len(callees_changed) / max(len(callee_addrs), 1)

        root_score = round(
            (len(callees_changed) * 15)
            + (pct * 30)
            + min(insns or 0, 200) * 0.1
            + (20 if (cc or 0) > 10 else 0),
            1,
        )

        cur2.execute(
            "SELECT address FROM callgraph WHERE func_id = ? AND type = 'caller'",
            (fid,)
        )
        caller_addrs = {r[0].strip().lower() for r in cur2.fetchall()}
        callers_changed = caller_addrs & changed_addrs

        candidates.append({
            "address": addr,
            "name": fname or f"sub_{addr}",
            "instructions": insns,
            "complexity": cc,
            "callees_total": len(callee_addrs),
            "callees_changed": len(callees_changed),
            "callees_changed_pct": round(pct, 2),
            "callers_total": len(caller_addrs),
            "callers_changed": len(callers_changed),
            "root_score": root_score,
            "is_root_candidate": root_score >= 30 and pct > 0.3,
        })

    conn2.close()

    candidates.sort(key=lambda x: -x["root_score"])
    root_candidates = [c for c in candidates if c["is_root_candidate"]]

    return json.dumps({
        "total_changed_functions": len(changed_addrs),
        "root_candidates_found": len(root_candidates),
        "analysis_method": "callgraph-cascade (changed callees / total callees)",
        "root_candidates": root_candidates[:20],
        "all_candidates_ranked": candidates[:50],
        "recommendation": (
            "Functions flagged as root candidates are high in the call chain: "
            "they changed AND their callees also changed disproportionately. "
            "Investigate these first with compare_functions / IDA Pro MCP."
        ),
    }, indent=2, default=str)
