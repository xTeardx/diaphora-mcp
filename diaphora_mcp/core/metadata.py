"""
Diaphora MCP — metadata transfer between databases.

Selectively transfer names, comments, prototypes, and type definitions
from a source export database to a target database, optionally using
a .diaphora match file for address mapping.
"""

import json
import os
import sqlite3

from ..utils.sqlite import check_db, norm_addr
from ..utils.format import dumps, err_json


def transfer_metadata(
    source_db_path: str,
    target_db_path: str,
    transfer_names: bool = True,
    transfer_comments: bool = True,
    transfer_prototypes: bool = True,
    transfer_types: bool = True,
    match_results_path: str = "",
) -> str:
    """Read metadata from the *source* database that can be applied to the
    *target* database.

    When *match_results_path* (a .diaphora file) is provided, only transfer
    metadata for functions that were matched, mapping addresses from old→new.
    """
    err1 = check_db(source_db_path)
    if err1:
        return err_json(f"source: {err1}")
    err2 = check_db(target_db_path)
    if err2:
        return err_json(f"target: {err2}")

    # Build address mapping
    addr_map = {}
    if match_results_path and os.path.isfile(match_results_path):
        with sqlite3.connect(match_results_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT address, address2 FROM results")
            for src, tgt in cur.fetchall():
                addr_map[norm_addr(src)] = norm_addr(tgt)

    items = []

    with sqlite3.connect(source_db_path) as conn_src:
        conn_src.row_factory = sqlite3.Row
        cur_src = conn_src.cursor()

        # 1. Function names
        if transfer_names:
            # Some Diaphora schemas have "true_name" (user-assigned name); fall
            # back to plain "name" when the column doesn't exist.
            try:
                cur_src.execute(
                    "SELECT address, name, true_name FROM functions "
                    "WHERE name NOT LIKE 'sub_%' AND name != ''"
                )
                use_true_name = True
            except (sqlite3.OperationalError, sqlite3.DatabaseError):
                cur_src.execute(
                    "SELECT address, name FROM functions "
                    "WHERE name NOT LIKE 'sub_%' AND name != ''"
                )
                use_true_name = False
            for row in cur_src.fetchall():
                src_addr = norm_addr(row["address"])
                tgt_addr = addr_map.get(src_addr, src_addr)
                new_name = (row["true_name"] if use_true_name else None) or row["name"]
                items.append({
                    "type": "function_name",
                    "source_address": row["address"],
                    "target_address": tgt_addr,
                    "value": new_name,
                    "auto_apply": f"rename_function(0x{tgt_addr}, {json.dumps(new_name)})",
                })

        # 2. Comments
        if transfer_comments:
            cur_src.execute(
                "SELECT address, comment FROM functions WHERE comment != '' AND comment IS NOT NULL"
            )
            for row in cur_src.fetchall():
                src_addr = norm_addr(row["address"])
                tgt_addr = addr_map.get(src_addr, src_addr)
                items.append({
                    "type": "comment",
                    "source_address": row["address"],
                    "target_address": tgt_addr,
                    "value": row["comment"][:500],
                    "auto_apply": f"set_comment(0x{tgt_addr}, {json.dumps(row['comment'][:100])})",
                })

        # 3. Prototypes
        if transfer_prototypes:
            cur_src.execute(
                "SELECT address, name, prototype FROM functions "
                "WHERE prototype != '' AND prototype IS NOT NULL"
            )
            for row in cur_src.fetchall():
                src_addr = norm_addr(row["address"])
                tgt_addr = addr_map.get(src_addr, src_addr)
                items.append({
                    "type": "prototype",
                    "source_address": row["address"],
                    "target_address": tgt_addr,
                    "value": row["prototype"],
                    "auto_apply": f"set_function_prototype(0x{tgt_addr}, {json.dumps(row['prototype'][:120])})",
                })

        # 4. Types (structs, enums, unions)
        if transfer_types:
            cur_src.execute(
                "SELECT name, type, value FROM program_data "
                "WHERE type IN ('structure', 'struct', 'enum', 'union')"
            )
            for row in cur_src.fetchall():
                items.append({
                    "type": row["type"],
                    "source_address": "",
                    "target_address": "",
                    "name": row["name"],
                    "value": (row["value"] or "")[:1000],
                    "auto_apply": f"declare_c_type(\"{row['name']}: {row['value'][:80]}\")",
                })

    return dumps({
        "total_items": len(items),
        "summary": {
            "names": sum(1 for i in items if i["type"] == "function_name"),
            "comments": sum(1 for i in items if i["type"] == "comment"),
            "prototypes": sum(1 for i in items if i["type"] == "prototype"),
            "types": sum(1 for i in items if i["type"] in ("structure", "struct", "enum", "union")),
        },
        "items": items[:200],
        "truncated": len(items) > 200,
        "instruction": (
            "Use the items above with IDA Pro MCP tools, or generate an IDAPython script "
            "to apply them in bulk."
        ),
    })
