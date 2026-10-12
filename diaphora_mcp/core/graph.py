"""
Diaphora MCP — callgraph analysis.

BFS call-path traversal, comparison of callers/callees across versions,
and root-cause detection via dependency-chain analysis.
"""

import os
import sqlite3

from ..utils.sqlite import check_db, check_results_db, get_func, get_callgraph, resolve_func_names, get_underlying_db_paths, norm_addr, read_adaptive_table, _RESULTS_COLUMN_MAP, _UNMATCHED_COLUMN_MAP, _detect_decimal
from ..utils.connection import get_connection, get_cache_manager
from ..utils.format import dumps, err_json
from .repository import IndexedDatabase, CallGraphEngine
from .mapping import FunctionMapping, canonical_address, resolve_pair, compare_neighbors


def build_call_path(db_path: str, start_addr: str, depth: int,
                    direction: str = "callees") -> list:
    """BFS walk callgraph from *start_addr* up to *depth* levels.

    Uses in-memory CallGraphEngine and IndexedDatabase — zero SQL
    queries after the initial (lazy) load.
    """
    cache_mgr = get_cache_manager()
    indexed = cache_mgr.get_indexed(db_path)
    cg_engine = cache_mgr.get_callgraph(db_path)
    # Lazy loads happen on first access below

    raw = cg_engine.bfs_traverse(start_addr, depth, direction)
    result = []
    for entry in raw:
        addr = entry["address"]
        targets = entry.get("targets", [])
        functions = {}
        for tgt in targets:
            name = indexed.get_name("0x" + canonical_address(tgt)) or "?"
            functions[tgt] = name

        result.append({
            "address": addr,
            "level": entry["level"],
            "direction": direction,
            "calls": len(targets),
            "functions": functions,
        })

    return result


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
def get_changed_callgraph(
    db1_path: str,
    db2_path: str,
    address: str = "",
    name: str = "",
    match_results_path: str = "",
    address2: str = "",
    name2: str = "",
) -> str:
    """Compare the callers and callees of a function across two databases."""
    err1 = check_db(db1_path)
    if err1:
        return err_json(err1)
    err2 = check_db(db2_path)
    if err2:
        return err_json(err2)

    if not address and not name:
        return err_json("Provide either address or name")

    try:
        func1, func2, identity, mapping = resolve_pair(db1_path, db2_path, address, name, address2, name2, match_results_path)
    except ValueError as exc:
        return err_json(str(exc))
    if not func1:
        return err_json("Primary function selector is missing or ambiguous")
    if not func2:
        return dumps({"change_type": "unknown", "identity": identity, "warning": "Secondary identity is unresolved; no edge changes are inferred"})
    address = func1["address"]
    address2 = func2["address"]
    name1, name2 = func1["name"], func2["name"]
    cg1 = get_callgraph(db1_path, address)
    cg2 = get_callgraph(db2_path, address2)
    callers = compare_neighbors(db1_path, db2_path, cg1["callers"], cg2["callers"], mapping)
    callees = compare_neighbors(db1_path, db2_path, cg1["callees"], cg2["callees"], mapping)

    def _format_list(addrs, db_path):
        names = resolve_func_names(db_path, ["0x" + a for a in addrs])
        return [{"address": a, "name": names.get(a, names.get("0x" + a, "?"))} for a in addrs]

    def _output(delta, kind):
        return {"total_old": len(cg1[kind]), "total_new": len(cg2[kind]),
                "added": _format_list(delta["added"], db2_path),
                "removed": _format_list(delta["removed"], db1_path),
                "unchanged": delta["unchanged"],
                "unknown_old": _format_list(delta["unknown_old"], db1_path),
                "unknown_new": _format_list(delta["unknown_new"], db2_path)}

    return dumps({
        "function_name_old": name1,
        "function_name_new": name2,
        "address": address,
        "address_old": func1.get("address", "") if func1 else "",
        "address_new": func2.get("address", "") if func2 else "",
        "identity": identity,
        "callers": _output(callers, "callers"),
        "callees": _output(callees, "callees"),
        "summary": "Edges compared through resolved identity; unresolved neighbors remain unknown",
    }, indent=2, default=str)


def compare_call_path(
    db1_path: str,
    db2_path: str,
    address: str = "",
    name: str = "",
    depth: int = 2,
    direction: str = "callees",
    match_results_path: str = "",
) -> str:
    """Walk the callgraph from a starting function and compare the call trees
    between old and new binaries."""
    err1 = check_db(db1_path)
    if err1:
        return err_json(err1)
    err2 = check_db(db2_path)
    if err2:
        return err_json(err2)

    if not address and not name:
        return err_json("Provide either address or name")

    try:
        old, new, identity, mapping = resolve_pair(db1_path, db2_path, address, name, match_results_path=match_results_path)
    except ValueError as exc:
        return err_json(str(exc))
    if not old:
        return err_json("Primary function selector is missing or ambiguous")
    if not new:
        return dumps({"change_type": "unknown", "identity": identity, "warning": "Secondary identity is unresolved"})
    address, address2 = old["address"], new["address"]
    depth = min(depth, 5)

    path1 = build_call_path(db1_path, address, depth, direction)
    path2 = build_call_path(db2_path, address2, depth, direction)

    translated = {}
    unknown_old, unknown_new = [], []
    for entry in path1:
        old_address = entry["address"]
        if mapping is not None:
            match = mapping.by_old("0x" + old_address)
            target = match.new_address if match else None
        else:
            _, counterpart, _, _ = resolve_pair(db1_path, db2_path, "0x" + old_address)
            target = canonical_address(counterpart["address"], decimal_database=_detect_decimal(get_connection(db2_path))) if counterpart else None
        if target:
            translated[(old_address, entry["level"])] = (target, entry["level"])
        else:
            unknown_old.append(entry)
    set1 = set(translated.values())
    set2 = {(canonical_address(e["address"]), e["level"]) for e in path2}
    added = []
    for entry in path2:
        new_address = canonical_address(entry["address"])
        if (new_address, entry["level"]) in set1:
            continue
        if mapping is not None:
            known = mapping.by_new("0x" + new_address) is not None or mapping.is_added(new_address)
        else:
            _, counterpart, _, _ = resolve_pair(db2_path, db1_path, "0x" + new_address)
            known = counterpart is not None
        (added if known else unknown_new).append(entry)
    removed = [e for e in path1 if (e["address"], e["level"]) in translated and translated[(e["address"], e["level"])] not in set2]

    return dumps({
        "identity": identity,
        "unknown_old": unknown_old[:20],
        "unknown_new": unknown_new[:20],
        "function_address": address,
        "function_address_new": address2,
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
        return err_json(f"Results file not found: {results_path}")
    if (err := check_results_db(results_path)):
        return err_json(err)

    db1_path, db2_path = get_underlying_db_paths(results_path)

    try:
        mapping = FunctionMapping.from_results(results_path)
    except (FileNotFoundError, ValueError):
        mapping = None

    results_data = read_adaptive_table(
        results_path, _RESULTS_COLUMN_MAP, "results",
        row_factory=sqlite3.Row,
    )

    unmatched = read_adaptive_table(
        results_path, _UNMATCHED_COLUMN_MAP, "unmatched",
        row_factory=sqlite3.Row,
    )

    if not db1_path or not db2_path:
        return dumps({
            "note": "Underlying databases not found — limited analysis",
            "results": [dict(r) for r in results_data],
        })

    changed_addrs = set()
    addr_to_result = {}
    for r in results_data:
        a2 = r.get("address2", "")
        if a2:
            a2n = canonical_address(a2)
            changed_addrs.add(a2n)
            if a2n not in addr_to_result:
                addr_to_result[a2n] = r

    # Include newly added functions (secondary unmatched) as changed addresses
    for u in unmatched:
        if u.get("type") == "secondary":
            addr = u.get("address", "")
            if addr:
                changed_addrs.add(
                    canonical_address(addr)
                )

    candidates = []
    try:
        cache_mgr = get_cache_manager()
        indexed_db2 = cache_mgr.get_indexed(db2_path)
        cg_engine2 = cache_mgr.get_callgraph(db2_path)
        cg_engine2._ensure_loaded()
        
        for addr in changed_addrs:
            meta = indexed_db2.get_metadata("0x" + canonical_address(addr))
            if not meta:
                continue
            fname = indexed_db2.get_name("0x" + canonical_address(addr)) or f"sub_{addr}"
            insns = meta.get("instructions", 0)
            cc = meta.get("cyclomatic_complexity", 0)

            # Get in-memory caller/callee sets
            callee_addrs = set(cg_engine2.adjacency.get(addr, []))
            caller_addrs = set(cg_engine2.callers.get(addr, []))

            callees_changed = callee_addrs & changed_addrs
            pct = len(callees_changed) / max(len(callee_addrs), 1)

            # Cap the changed callees bonus at 75 points (5 changed callees)
            root_score = round(
                (min(len(callees_changed), 5) * 15)
                + (pct * 30)
                + min(insns or 0, 200) * 0.1
                + (20 if (cc or 0) > 10 else 0),
                1,
            )

            callers_changed = caller_addrs & changed_addrs

            candidates.append({
                "address": addr,
                "name": fname,
                "instructions": insns,
                "complexity": cc,
                "callees_total": len(callee_addrs),
                "callees_changed": len(callees_changed),
                "callees_changed_pct": round(pct, 2),
                "callers_total": len(caller_addrs),
                "callers_changed": len(callers_changed),
                "root_score": root_score,
                # Filter out wrappers/leaves by requiring at least 3 callees to be a root candidate
                "is_root_candidate": root_score >= 30 and pct > 0.3 and len(callee_addrs) >= 3,
            })
    except Exception as e:
        print(f"Error in optimized find_patch_root: {e}")
        pass

    candidates.sort(key=lambda x: -x["root_score"])
    root_candidates = [c for c in candidates if c["is_root_candidate"]]

    return dumps({
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
    })
