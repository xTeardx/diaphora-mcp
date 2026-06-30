"""
Diaphora MCP — SQLite database helpers.

Shared low-level functions for reading Diaphora-exported databases and
.diaphora diff results files.
"""

import os
import sqlite3


def check_db(path: str) -> str | None:
    """Return an error string if *path* is not a readable Diaphora SQLite file, else None."""
    if not os.path.isfile(path):
        return f"File not found: {path}"
    try:
        with sqlite3.connect(path) as c:
            c.execute("SELECT count(*) FROM functions")
    except Exception as exc:
        return f"Not a valid Diaphora export database: {path}\n{exc}"
    return None


def get_func(db_path: str, address: str = "", name: str = "") -> dict | None:
    """Return the full function row from an export .sqlite database.

    Returns a dict, or None if not found / DB invalid.
    """
    err = check_db(db_path)
    if err:
        return None
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    if address:
        addr = address.lower().removeprefix("0x")
        cur.execute("SELECT * FROM functions WHERE address = ?", (addr,))
    elif name:
        cur.execute("SELECT * FROM functions WHERE name = ?", (name,))
    else:
        conn.close()
        return None
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def get_underlying_db_paths(results_path: str) -> tuple:
    """Return (primary_db, secondary_db) paths from a .diaphora config table."""
    conn = sqlite3.connect(results_path)
    cur = conn.cursor()
    try:
        cur.execute("SELECT main_db, diff_db FROM config")
        row = cur.fetchone()
        return (row[0], row[1]) if row else ("", "")
    except Exception:
        return ("", "")
    finally:
        conn.close()


def get_callgraph(db_path: str, func_address: str) -> dict:
    """Get callers and callees for a function from the callgraph table.

    Returns {"callers": [addr, ...], "callees": [addr, ...]}.
    """
    err = check_db(db_path)
    if err:
        return {"callers": [], "callees": []}
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    addr = func_address.lower().removeprefix("0x")
    cur.execute("SELECT id FROM functions WHERE address = ?", (addr,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return {"callers": [], "callees": []}
    fid = row[0]

    callers = []
    callees = []
    cur.execute(
        "SELECT address, type FROM callgraph WHERE func_id = ?", (fid,)
    )
    for addr_str, ctype in cur.fetchall():
        if ctype == "caller":
            callers.append(addr_str)
        else:
            callees.append(addr_str)
    conn.close()
    return {"callers": callers, "callees": callees}


def resolve_func_names(db_path: str, addresses: list[str]) -> dict:
    """Resolve a list of addresses to {addr: name} in one query."""
    if not addresses:
        return {}
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    norm = {a.lower().removeprefix("0x"): a for a in addresses}
    placeholders = ",".join("?" for _ in norm)
    cur.execute(
        f"SELECT address, name FROM functions WHERE address IN ({placeholders})",
        list(norm.keys()),
    )
    result = {}
    for row in cur.fetchall():
        orig = norm.get(row[0], row[0])
        result[orig] = row[1]
    conn.close()
    return result
