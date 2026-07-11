"""
Diaphora MCP — function-level analysis.

Search, compare, and explain individual functions across databases.
"""

import json
import os
import sqlite3

from ..utils.sqlite import check_db, get_func, get_funcs_batch, get_callgraph, resolve_func_names, norm_addr, _detect_decimal, get_query_addresses
from ..utils.connection import get_connection
from ..utils.format import pseudocode_simple_diff, func_features, dumps, err_json


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
def search_export_db(
    db_path: str,
    name_pattern: str = "",
    min_instructions: int = 0,
    max_instructions: int = 0,
    min_complexity: int = 0,
    max_complexity: int = 0,
    limit: int = 100,
) -> str:
    """Query functions in an exported Diaphora .sqlite database."""
    err = check_db(db_path)
    if err:
        return err_json(err)

    conn = get_connection(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    conditions = []
    params = []

    if name_pattern:
        conditions.append("name LIKE ?")
        params.append(name_pattern)
    if min_instructions > 0:
        conditions.append("instructions >= ?")
        params.append(min_instructions)
    if max_instructions > 0:
        conditions.append("instructions <= ?")
        params.append(max_instructions)
    if min_complexity > 0:
        conditions.append("cyclomatic_complexity >= ?")
        params.append(min_complexity)
    if max_complexity > 0:
        conditions.append("cyclomatic_complexity <= ?")
        params.append(max_complexity)

    where = " AND ".join(conditions) if conditions else "1=1"

    cur.execute(f"SELECT count(*) FROM functions WHERE {where}", params)
    total = cur.fetchone()[0]

    cur.execute(
        f"""SELECT name, address, nodes, edges, instructions,
                   cyclomatic_complexity, prototype, bytes_hash
            FROM functions
            WHERE {where}
            ORDER BY instructions DESC
            LIMIT ?""",
        params + [limit],
    )
    functions = [dict(r) for r in cur.fetchall()]

    cur.execute("SELECT count(*) FROM functions")
    total_funcs = cur.fetchone()[0]

    cur.execute(
        "SELECT id, callgraph_primes, callgraph_all_primes, "
        "processor, md5sum "
        "FROM program"
    )
    program = [dict(r) for r in cur.fetchall()]

    return dumps(
        {
            "program": program,
            "total_functions_in_db": total_funcs,
            "matching_functions": total,
            "truncated": total > limit,
            "functions": functions,
        }
    )


def get_function_pseudocode(
    db_path: str,
    address: str = "",
    name: str = "",
) -> str:
    """Retrieve pseudocode + metadata for a function.

    When *address* contains commas it is treated as a comma-separated list
    of addresses and handled as a bulk query via get_funcs_batch.
    """
    err = check_db(db_path)
    if err:
        return err_json(err)

    # Bulk mode: comma-separated addresses
    if address and "," in address:
        addrs = [a.strip() for a in address.split(",") if a.strip()]
        batch = get_funcs_batch(db_path, addrs)
        if not batch:
            return err_json(f"No functions found for addresses: {address}")
        return dumps({"functions": batch, "count": len(batch)})

    conn = get_connection(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    if address:
        addrs = get_query_addresses(conn, address)
        placeholders = ",".join("?" for _ in addrs)
        cur.execute(
            f"""SELECT name, address, pseudocode, assembly, prototype,
                       instructions, cyclomatic_complexity
                FROM functions WHERE address IN ({placeholders})""",
            addrs,
        )
    elif name:
        cur.execute(
            """SELECT name, address, pseudocode, assembly, prototype,
                      instructions, cyclomatic_complexity
               FROM functions WHERE name = ?""",
            (name,),
        )
    else:
        return err_json("Provide either address or name")

    row = cur.fetchone()

    if not row:
        return err_json(f"Function not found (address={address}, name={name})")

    return dumps(dict(row))


def get_export_info(db_path: str) -> str:
    """Show metadata from a Diaphora export database."""
    err = check_db(db_path)
    if err:
        return err_json(err)

    conn = get_connection(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT count(*) FROM functions")
    func_count = cur.fetchone()[0]

    cur.execute(
        "SELECT id, callgraph_primes, callgraph_all_primes, "
        "processor, md5sum "
        "FROM program"
    )
    program = [dict(r) for r in cur.fetchall()]

    # SUM(instructions) is much faster than SELECT count(*) FROM instructions
    # on large databases (instructions can have 10M+ rows)
    cur.execute("SELECT COALESCE(SUM(instructions), 0) FROM functions")
    insn_count = cur.fetchone()[0]

    return dumps(
        {
            "database": os.path.basename(db_path),
            "size_bytes": os.path.getsize(db_path),
            "program": program,
            "function_count": func_count,
            "instruction_count": insn_count,
        }
    )


def compare_functions(
    db1_path: str,
    db2_path: str,
    address: str = "",
    name: str = "",
    address2: str = "",
    name2: str = "",
) -> str:
    """Retrieve a function's data from both databases for side-by-side comparison."""
    err1 = check_db(db1_path)
    if err1:
        return err_json(err1)
    err2 = check_db(db2_path)
    if err2:
        return err_json(err2)

    if not address and not name:
        return err_json("Provide either address or name")

    def _lookup(db_path, lookup_addr, lookup_name):
        conn = get_connection(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        if lookup_addr:
            addrs = get_query_addresses(conn, lookup_addr)
            placeholders = ",".join("?" for _ in addrs)
            cur.execute(
                f"""SELECT name, address, pseudocode, assembly, prototype,
                           instructions, cyclomatic_complexity, nodes, edges,
                           bytes_hash, constants
                    FROM functions WHERE address IN ({placeholders})""",
                addrs,
            )
        elif lookup_name:
            cur.execute(
                """SELECT name, address, pseudocode, assembly, prototype,
                          instructions, cyclomatic_complexity, nodes, edges,
                          bytes_hash, constants
                   FROM functions WHERE name = ?""",
                (lookup_name,),
            )

        row = cur.fetchone()
        return dict(row) if row else None

    func1 = _lookup(db1_path, address, name)
    if not func1:
        return err_json(f"Function not found in primary database (address={address}, name={name})")

    func2 = _lookup(db2_path, address2 or address, name2 or name)
    if not func2:
        return dumps(
            {
                "warning": "Function not found in secondary database",
                "primary": func1,
                "secondary": None,
            }
        )

    def _short(row):
        return {
            "name": row.get("name", ""),
            "address": row.get("address", ""),
            "prototype": row.get("prototype", ""),
            "instructions": row.get("instructions", 0),
            "cyclomatic_complexity": row.get("cyclomatic_complexity", 0),
            "nodes": row.get("nodes", 0),
            "edges": row.get("edges", 0),
            "pseudocode": row.get("pseudocode", ""),
            "assembly": row.get("assembly", ""),
            "bytes_hash": row.get("bytes_hash", ""),
        }

    return dumps(
        {
            "function_old": _short(func1),
            "function_new": _short(func2),
            "comparison": {
                "name_changed": func1.get("name") != func2.get("name"),
                "instructions_added": (func2.get("instructions") or 0)
                - (func1.get("instructions") or 0),
                "complexity_change": (func2.get("cyclomatic_complexity") or 0)
                - (func1.get("cyclomatic_complexity") or 0),
                "hash_changed": func1.get("bytes_hash") != func2.get("bytes_hash"),
            },
            "ida_pro_mcp": {
                "db1": db1_path,
                "db2": db2_path,
                "address_old": func1.get("address", ""),
                "address_new": func2.get("address", ""),
            },
        }
    )


def find_function_match(
    db1_path: str,
    db2_path: str,
    address: str = "",
    name: str = "",
) -> str:
    """Locate the matching function in the second (new) binary given a
    reference in the first (old) binary."""
    err1 = check_db(db1_path)
    if err1:
        return err_json(err1)
    err2 = check_db(db2_path)
    if err2:
        return err_json(err2)

    if not address and not name:
        return err_json("Provide either address or name")

    func1 = get_func(db1_path, address, name)
    if not func1:
        return err_json(f"Function not found in primary database (addr={address}, name={name})")

    addr = func1["address"]
    fname = func1["name"]
    candidates = []
    strategies = []

    # 1. Exact address match
    func2 = get_func(db2_path, address=addr)
    if func2:
        candidates.append((func2, 1.0, "exact_address"))
        strategies.append("exact_address")

    # 2. Exact name match
    if fname and not fname.startswith("sub_"):
        func2 = get_func(db2_path, name=fname)
        if func2:
            if not any(c["address"] == func2["address"] for c, _, _ in candidates):
                candidates.append((func2, 0.95, "exact_name"))
                strategies.append("exact_name")

    # 3. Bytes hash match
    bh = func1.get("bytes_hash", "")
    if bh:
        conn2 = get_connection(db2_path)
        conn2.row_factory = sqlite3.Row
        cur2 = conn2.cursor()
        cur2.execute(
            "SELECT address, name, pseudocode, assembly, prototype, "
            "instructions, nodes, edges, cyclomatic_complexity, bytes_hash, "
            "constants, mnemonics, loops, strongly_connected, names, "
            "pseudocode_hash1, pseudocode_hash2 "
            "FROM functions WHERE bytes_hash = ?", (bh,)
        )
        for row in cur2.fetchall():
            fd = dict(row)
            if not any(c["address"] == fd["address"] for c, _, _ in candidates):
                candidates.append((fd, 0.9, "bytes_hash"))
                strategies.append("bytes_hash")

    # 4. Prototype match
    proto = func1.get("prototype", "")
    if proto and len(proto) > 5:
        conn2 = get_connection(db2_path)
        conn2.row_factory = sqlite3.Row
        cur2 = conn2.cursor()
        cur2.execute(
            "SELECT address, name, pseudocode, assembly, prototype, "
            "instructions, nodes, edges, cyclomatic_complexity, bytes_hash, "
            "constants, mnemonics, loops, strongly_connected, names, "
            "pseudocode_hash1, pseudocode_hash2 "
            "FROM functions WHERE prototype = ?", (proto,)
        )
        for row in cur2.fetchall():
            fd = dict(row)
            if not any(c["address"] == fd["address"] for c, _, _ in candidates):
                candidates.append((fd, 0.7, "prototype"))
                strategies.append("prototype")

    # 5. Heuristic: closest by feature vector
    feat1 = func_features(func1)
    conn2 = get_connection(db2_path)
    conn2.row_factory = sqlite3.Row
    cur2 = conn2.cursor()
    cur2.execute(
        "SELECT address, name, pseudocode, assembly, prototype, "
        "instructions, nodes, edges, cyclomatic_complexity, bytes_hash, "
        "constants, mnemonics, loops, strongly_connected, names, "
        "pseudocode_hash1, pseudocode_hash2 "
        "FROM functions WHERE instructions BETWEEN ? AND ?",
        (max(0, feat1["instructions"] - 10), feat1["instructions"] + 10),
    )
    heuristic_candidates = []
    for row in cur2.fetchall():
        fd = dict(row)
        if any(c["address"] == fd["address"] for c, _, _ in candidates):
            continue
        feat2 = func_features(fd)
        score = 0.0
        if feat1["nodes"] == feat2["nodes"]:
            score += 0.15
        elif abs(feat1["nodes"] - feat2["nodes"]) <= 2:
            score += 0.08
        if feat1["edges"] == feat2["edges"]:
            score += 0.15
        elif abs(feat1["edges"] - feat2["edges"]) <= 2:
            score += 0.08
        if feat1["cyclomatic_complexity"] == feat2["cyclomatic_complexity"]:
            score += 0.10
        if feat1["loops"] == feat2["loops"]:
            score += 0.05
        if feat1["mnemonics"] and feat1["mnemonics"] == feat2["mnemonics"]:
            score += 0.20
        if feat1["constants"] and feat1["constants"] == feat2["constants"]:
            score += 0.15
        if feat1["prototype"] and feat1["prototype"] == feat2["prototype"]:
            score += 0.20
        heuristic_candidates.append((fd, score))

    heuristic_candidates.sort(key=lambda x: -x[1])
    for fd, sc in heuristic_candidates[:3]:
        if sc >= 0.5:
            if not any(c["address"] == fd["address"] for c, _, _ in candidates):
                candidates.append((fd, round(sc, 2), "heuristic_features"))
                if "heuristic" not in strategies:
                    strategies.append("heuristic")
                break

    if not candidates:
        if fname:
            conn2 = get_connection(db2_path)
            cur2 = conn2.cursor()
            cur2.execute("SELECT name, address FROM functions WHERE name LIKE ?",
                         (f"%{fname[:16]}%",))
            similar = [{"name": r[0], "address": r[1]} for r in cur2.fetchall()[:10]]
        else:
            similar = []
        return dumps({
            "matched": False,
            "primary_function": {
                "name": func1["name"],
                "address": func1["address"],
            },
            "similar_named_in_secondary": similar,
            "strategies_tried": strategies,
        })

    candidates.sort(key=lambda x: -x[1])
    func2, confidence, method = candidates[0]

    feat1 = func_features(func1)
    feat2 = func_features(func2)

    return dumps({
        "matched": True,
        "confidence": confidence,
        "method": method,
        "strategies_tried": strategies,
        "primary_function": {
            "name": func1["name"],
            "address": func1["address"],
            "prototype": func1.get("prototype", ""),
            "instructions": func1.get("instructions", 0),
            "cyclomatic_complexity": func1.get("cyclomatic_complexity", 0),
        },
        "matched_function": {
            "name": func2["name"],
            "address": func2["address"],
            "prototype": func2.get("prototype", ""),
            "instructions": func2.get("instructions", 0),
            "cyclomatic_complexity": func2.get("cyclomatic_complexity", 0),
        },
        "comparison": {
            "nodes": (feat1["nodes"], feat2["nodes"]),
            "edges": (feat1["edges"], feat2["edges"]),
            "instructions": (feat1["instructions"], feat2["instructions"]),
            "complexity": (feat1["cyclomatic_complexity"], feat2["cyclomatic_complexity"]),
            "hash_match": feat1["bytes_hash"] == feat2["bytes_hash"],
            "prototype_match": feat1["prototype"] == feat2["prototype"],
        },
        "evidence": (
            f"Primary: {func1['name']} @ 0x{func1['address']} "
            f"({func1.get('instructions', 0)} insns, "
            f"CC={func1.get('cyclomatic_complexity', 0)})\n"
            f"Match:  {func2['name']} @ 0x{func2['address']} "
            f"({func2.get('instructions', 0)} insns, "
            f"CC={func2.get('cyclomatic_complexity', 0)})\n"
            f"Method: {method} (confidence {confidence:.0%})"
        ),
        "ida_pro_mcp": {
            "db1": db1_path,
            "db2": db2_path,
            "addr1": func1["address"],
            "addr2": func2["address"],
        },
    })


def explain_similarity(
    db1_path: str,
    db2_path: str,
    address: str = "",
    name: str = "",
    address2: str = "",
    name2: str = "",
) -> str:
    """Compare two matched functions and explain the similarity score."""
    err1 = check_db(db1_path)
    if err1:
        return json.dumps({"error": err1})
    err2 = check_db(db2_path)
    if err2:
        return json.dumps({"error": err2})

    if not address and not name:
        return json.dumps({"error": "Provide either address or name"})

    # Resolve address1 (primary database)
    address1 = address
    if not address1 and name:
        f1 = get_func(db1_path, name=name)
        if f1:
            address1 = f1["address"]

    if not address1:
        return json.dumps({"error": "Could not resolve address in primary database"})

    # Resolve address2 (secondary database)
    address2_resolved = address2
    if not address2_resolved:
        if name2:
            f2 = get_func(db2_path, name=name2)
            if f2:
                address2_resolved = f2["address"]
        else:
            if name:
                f2 = get_func(db2_path, name=name)
                if f2:
                    address2_resolved = f2["address"]
            if not address2_resolved:
                address2_resolved = address1

    f1 = get_func(db1_path, address=address1)
    if not f1:
        return json.dumps({"error": f"Function at 0x{address1} not found in db1"})

    f2 = get_func(db2_path, address=address2_resolved)
    if not f2:
        return json.dumps({"error": f"Function at 0x{address2_resolved} not found in db2"})

    features1 = func_features(f1)
    features2 = func_features(f2)

    factors = []

    # 1. Mnemonics
    mne1 = features1["mnemonics"]
    mne2 = features2["mnemonics"]
    mne_match = mne1 == mne2 if mne1 and mne2 else False
    factors.append({
        "factor": "mnemonics",
        "weight": 25,
        "match": mne_match,
        "detail": f"{'identical' if mne_match else 'different'} mnemonic sequences",
        "value_old": mne1[:100] if mne1 else "",
        "value_new": mne2[:100] if mne2 else "",
    })

    # 2. Nodes
    n1, n2 = features1["nodes"], features2["nodes"]
    node_match = n1 == n2
    node_sim = min(n1, n2) / max(n1, n2, 1)
    factors.append({
        "factor": "cfg_nodes",
        "weight": 15,
        "match": node_match,
        "detail": f"basic blocks {n1} vs {n2} ({'same' if node_match else f'{node_sim:.0%} similar'})" if not node_match else f"same ({n1})",
        "values": (n1, n2),
    })

    # 3. Edges
    e1, e2 = features1["edges"], features2["edges"]
    edge_match = e1 == e2
    factors.append({
        "factor": "cfg_edges",
        "weight": 10,
        "match": edge_match,
        "detail": f"edges {e1} vs {e2} ({'same' if edge_match else 'different'})",
        "values": (e1, e2),
    })

    # 4. Constants
    cs1 = features1["constants"]
    cs2 = features2["constants"]
    const_match = cs1 == cs2 if cs1 and cs2 else False
    factors.append({
        "factor": "constants",
        "weight": 15,
        "match": const_match,
        "detail": f"{'identical' if const_match else 'different'} constant pools",
        "value_old": cs1[:100] if cs1 else "",
        "value_new": cs2[:100] if cs2 else "",
    })

    # 5. Callgraph similarity
    cg1 = get_callgraph(db1_path, address1)
    cg2 = get_callgraph(db2_path, address2_resolved)
    ce1 = set(cg1["callees"])
    ce2 = set(cg2["callees"])
    callee_sim = len(ce1 & ce2) / max(len(ce1 | ce2), 1) if (ce1 or ce2) else 0
    cr1 = set(cg1["callers"])
    cr2 = set(cg2["callers"])
    caller_sim = len(cr1 & cr2) / max(len(cr1 | cr2), 1) if (cr1 or cr2) else 0
    callgraph_score = round((callee_sim * 0.6 + caller_sim * 0.4) * 100, 1)
    factors.append({
        "factor": "callgraph",
        "weight": 10,
        "match": callgraph_score >= 80,
        "detail": f"callees: {len(ce1)}→{len(ce2)} ({callee_sim:.0%}), callers: {len(cr1)}→{len(cr2)} ({caller_sim:.0%})",
        "callee_similarity": round(callee_sim, 2),
        "caller_similarity": round(caller_sim, 2),
        "overall_score": callgraph_score,
    })

    # 6. Prototype
    p1 = features1["prototype"]
    p2 = features2["prototype"]
    proto_match = p1 == p2 if p1 and p2 else False
    factors.append({
        "factor": "prototype",
        "weight": 10,
        "match": proto_match,
        "detail": f"{'identical' if proto_match else 'different'} signatures" if p1 or p2 else "no prototype data",
    })

    # 7. Bytes / hash
    bh1 = features1["bytes_hash"]
    bh2 = features2["bytes_hash"]
    hash_match = bh1 == bh2 if bh1 and bh2 else False
    factors.append({
        "factor": "bytes_hash",
        "weight": 5,
        "match": hash_match,
        "detail": f"{'identical' if hash_match else 'different'} byte hashes",
    })

    # 8. Pseudocode hashes
    ph1 = f1.get("pseudocode_hash1", "") or ""
    ph2 = f2.get("pseudocode_hash1", "") or ""
    ph_match = ph1 == ph2 if ph1 and ph2 else False
    factors.append({
        "factor": "pseudocode_hash",
        "weight": 10,
        "match": ph_match,
        "detail": f"{'identical' if ph_match else 'different'} pseudocode hashes",
    })

    matched_weight = sum(f["weight"] for f in factors if f.get("match"))
    total_weight = sum(f["weight"] for f in factors)
    estimated_similarity = round(matched_weight / max(total_weight, 1) * 100, 1)

    return dumps({
        "primary_function": {
            "name": f1.get("name", ""),
            "address": f1.get("address", ""),
        },
        "secondary_function": {
            "name": f2.get("name", ""),
            "address": f2.get("address", ""),
        },
        "estimated_similarity": estimated_similarity,
        "note": (
            "This is an approximation based on feature comparison. "
            "Diaphora's actual ratio uses internal heuristics and "
            "pseudocode comparison." if estimated_similarity else ""
        ),
        "factors": factors,
        "matching_factors": [f["factor"] for f in factors if f.get("match")],
        "differing_factors": [f["factor"] for f in factors if not f.get("match")],
    })


def detect_behavior_change(
    db1_path: str,
    db2_path: str,
    address: str = "",
    name: str = "",
    address2: str = "",
    name2: str = "",
) -> str:
    """Analyse a single function across two versions and describe what behaviour changed."""
    err1 = check_db(db1_path)
    if err1:
        return err_json(err1)
    err2 = check_db(db2_path)
    if err2:
        return err_json(err2)

    if not address and not name:
        return err_json("Provide either address or name")

    # Resolve address1 (primary database)
    address1 = address
    if not address1 and name:
        f1 = get_func(db1_path, name=name)
        if f1:
            address1 = f1["address"]
        else:
            return err_json(f"Function '{name}' not found in db1")

    # Resolve address2 (secondary database)
    address2_resolved = address2
    if not address2_resolved:
        if name2:
            f2 = get_func(db2_path, name=name2)
            if f2:
                address2_resolved = f2["address"]
        else:
            if name:
                f2 = get_func(db2_path, name=name)
                if f2:
                    address2_resolved = f2["address"]
            if not address2_resolved:
                address2_resolved = address1

    f1 = get_func(db1_path, address=address1)
    f2 = get_func(db2_path, address=address2_resolved)

    if not f1 and not f2:
        return err_json(f"Function 0x{address1} / 0x{address2_resolved} not found in either database")

    if not f1:
        return dumps({
            "change_type": "new_function",
            "address": address2_resolved,
            "function_new": {
                "name": f2.get("name", ""),
                "instructions": f2.get("instructions", 0),
                "complexity": f2.get("cyclomatic_complexity", 0),
            },
            "description": f"Function NEW in the update — not present in the old binary",
        })

    if not f2:
        return dumps({
            "change_type": "deleted_function",
            "address": address1,
            "function_old": {
                "name": f1.get("name", ""),
                "instructions": f1.get("instructions", 0),
                "complexity": f1.get("cyclomatic_complexity", 0),
            },
            "description": f"Function REMOVED in the update — present only in the old binary",
        })

    name1 = f1.get("name", "")
    name2 = f2.get("name", "")
    pseudo1 = f1.get("pseudocode", "") or ""
    pseudo2 = f2.get("pseudocode", "") or ""

    pseudo_diff = pseudocode_simple_diff(pseudo1, pseudo2)
    added_count = sum(1 for d in pseudo_diff if d["type"] == "added")
    removed_count = sum(1 for d in pseudo_diff if d["type"] == "removed")

    cg1 = get_callgraph(db1_path, address1)
    cg2 = get_callgraph(db2_path, address2_resolved)
    added_callees = set(cg2["callees"]) - set(cg1["callees"])
    removed_callees = set(cg1["callees"]) - set(cg2["callees"])

    consts1_str = f1.get("constants", "") or ""
    consts2_str = f2.get("constants", "") or ""
    consts1 = set(consts1_str.split(",")) if consts1_str else set()
    consts2 = set(consts2_str.split(",")) if consts2_str else set()
    added_consts = list(consts2 - consts1)[:10]
    removed_consts = list(consts1 - consts2)[:10]

    nodes1 = f1.get("nodes", 0) or 0
    nodes2 = f2.get("nodes", 0) or 0
    edges1 = f1.get("edges", 0) or 0
    edges2 = f2.get("edges", 0) or 0
    insns1 = f1.get("instructions", 0) or 0
    insns2 = f2.get("instructions", 0) or 0
    cc1 = f1.get("cyclomatic_complexity", 0) or 0
    cc2 = f2.get("cyclomatic_complexity", 0) or 0
    loops1 = f1.get("loops", 0) or 0
    loops2 = f2.get("loops", 0) or 0

    changes = []
    if name1 != name2:
        changes.append(f"renamed from '{name1}' to '{name2}'")
    proto1 = f1.get("prototype", "") or ""
    proto2 = f2.get("prototype", "") or ""
    if proto1 != proto2:
        changes.append("prototype changed")

    delta_insns = insns2 - insns1
    if abs(delta_insns) > 3:
        changes.append(f"{'grew' if delta_insns > 0 else 'shrunk'} by {abs(delta_insns)} instructions ({insns1}→{insns2})")
    elif delta_insns != 0:
        changes.append(f"instructions {insns1}→{insns2}")

    delta_cc = cc2 - cc1
    if delta_cc > 0:
        changes.append(f"complexity increased by {delta_cc} (CC {cc1}→{cc2})")
    elif delta_cc < 0:
        changes.append(f"complexity decreased by {abs(delta_cc)} (CC {cc1}→{cc2})")

    if nodes1 != nodes2 or edges1 != edges2:
        changes.append(f"CFG: {nodes1}→{nodes2} blocks, {edges1}→{edges2} edges")
    if loops1 != loops2:
        changes.append(f"loops: {loops1}→{loops2}")

    if added_callees:
        names = resolve_func_names(db2_path, list(added_callees))
        call_names = [names.get(a, f"0x{a}") for a in sorted(added_callees)[:5]]
        changes.append(f"now calls: {', '.join(call_names)}")
    if removed_callees:
        names = resolve_func_names(db1_path, list(removed_callees))
        call_names = [names.get(a, f"0x{a}") for a in sorted(removed_callees)[:5]]
        changes.append(f"no longer calls: {', '.join(call_names)}")

    if added_consts:
        changes.append(f"new constants: {', '.join(added_consts[:5])}")
    if removed_consts:
        changes.append(f"removed constants: {', '.join(removed_consts[:5])}")

    pseudo_change_pct = 0
    if pseudo1 and pseudo2:
        total = max(len(pseudo1.splitlines()), len(pseudo2.splitlines()), 1)
        pseudo_change_pct = round(((added_count + removed_count) / total) * 100, 1)

    if pseudo_change_pct > 50:
        changes.append(f"pseudocode heavily rewritten ({pseudo_change_pct}% changed)")
    elif pseudo_change_pct > 10:
        changes.append(f"pseudocode moderately changed ({pseudo_change_pct}% changed, +{added_count}/–{removed_count} lines)")

    return dumps({
        "function_name_old": name1,
        "function_name_new": name2,
        "address": address1,
        "change_type": "modified",
        "changes": changes,
        "description": "; ".join(changes) if changes else "Minor or no detectable change",
        "metrics": {
            "instructions": (insns1, insns2),
            "cyclomatic_complexity": (cc1, cc2),
            "nodes": (nodes1, nodes2),
            "edges": (edges1, edges2),
            "loops": (loops1, loops2),
            "pseudo_changed_pct": pseudo_change_pct,
        },
        "callgraph_delta": {
            "added_callees": sorted(added_callees)[:10],
            "removed_callees": sorted(removed_callees)[:10],
        },
        "pseudo_diff": pseudo_diff[:50],
        "pseudo_diff_truncated": len(pseudo_diff) > 50,
        "ida_pro_mcp": {
            "db1": db1_path,
            "db2": db2_path,
            "addr1": address1,
            "addr2": address2_resolved,
        },
    })
