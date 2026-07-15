"""
Diaphora MCP — metadata transfer between databases.

Selectively transfer names, comments, prototypes, and type definitions
from a source export database to a target database, optionally using
a .diaphora match file for address mapping.
"""

import json
import os
import sqlite3

from ..utils.sqlite import check_db, norm_addr, read_adaptive_table, _RESULTS_COLUMN_MAP, _detect_decimal
from ..utils.connection import get_connection
from ..utils.format import dumps, err_json
from .mapping import FunctionMapping, canonical_address


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

    conn_src = get_connection(source_db_path)
    use_dec_src = _detect_decimal(conn_src)

    # Build address mapping
    mapping = None
    if match_results_path and os.path.isfile(match_results_path):
        try:
            mapping = FunctionMapping.from_results(match_results_path)
        except (FileNotFoundError, ValueError) as exc:
            return err_json(f"Invalid match results: {exc}")

    items = []

    conn_src.row_factory = sqlite3.Row
    cur_src = conn_src.cursor()

    def target_for(source_address):
        if mapping:
            match = mapping.by_old(source_address)
            return match.new_address if match else None
        return canonical_address(source_address, decimal_database=use_dec_src)

    skipped_unmapped = 0

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
            src_addr = norm_addr(row["address"], use_dec_src)
            tgt_addr = target_for(row["address"])
            if not tgt_addr:
                skipped_unmapped += 1
                continue
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
            src_addr = norm_addr(row["address"], use_dec_src)
            tgt_addr = target_for(row["address"])
            if not tgt_addr:
                skipped_unmapped += 1
                continue
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
            src_addr = norm_addr(row["address"], use_dec_src)
            tgt_addr = target_for(row["address"])
            if not tgt_addr:
                skipped_unmapped += 1
                continue
            items.append({
                "type": "prototype",
                "source_address": row["address"],
                "target_address": tgt_addr,
                "value": row["prototype"],
                "auto_apply": f"set_function_prototype(0x{tgt_addr}, {json.dumps(row['prototype'][:120])})",
            })

    # 4. Types (structs, enums, unions)
    if transfer_types:
        try:
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
        except (sqlite3.OperationalError, sqlite3.DatabaseError):
            pass

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
        "unmapped_skipped": skipped_unmapped,
        "instruction": (
            "Use the items above with IDA Pro MCP tools, or generate an IDAPython script "
            "to apply them in bulk."
        ),
    })
