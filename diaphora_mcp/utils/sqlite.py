"""
Diaphora MCP — SQLite database helpers.

Shared low-level functions for reading Diaphora-exported databases and
.diaphora diff results files.
"""

import os
import sqlite3
import subprocess
import time


def norm_addr(addr: str) -> str:
    """Normalize a hex address: strip whitespace, lowercase, remove 0x prefix."""
    return addr.strip().lower().removeprefix("0x")


def force_delete_file(path: str, retries: int = 3) -> bool:
    """Safely delete a file on Windows, killing idat.exe if locked."""
    if not os.path.exists(path):
        return True
    for attempt in range(retries):
        try:
            os.remove(path)
            return True
        except OSError as e:
            # WinError 32: Sharing violation
            if getattr(e, "winerror", 0) == 32 or "busy" in str(e).lower():
                subprocess.run(
                    ["taskkill", "/f", "/im", "idat.exe"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                time.sleep(0.5)
            else:
                raise
    return not os.path.exists(path)



def check_db(path: str) -> str | None:
    """Return an error string if *path* is not a readable Diaphora SQLite file, else None."""
    if not os.path.isfile(path):
        return f"File not found: {path}"
    try:
        with sqlite3.connect(path) as c:
            # Force checkpoint so WAL data is visible in the main file
            c.execute("PRAGMA wal_checkpoint(PASSIVE)")
            c.execute("SELECT count(*) FROM functions")
    except Exception as exc:
        return f"Not a valid Diaphora export database: {path}\n{exc}"
    return None


def check_db_for_diff(path: str) -> str | None:
    """Strict check: DB must have data AND filled program table (for diff).

    Diff requires callgraph_primes in the program table, which is only
    written at the very end of a successful headless export.  If the
    program table is empty, the export likely crashed during
    finalization (see problem #3 in Problems.md).
    """
    err = check_db(path)
    if err:
        return err

    with sqlite3.connect(path) as conn:
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM functions")
        funcs = cur.fetchone()[0]
        if funcs == 0:
            return f"Database has 0 functions (export incomplete or empty)"

        cur.execute("SELECT count(*) FROM program")
        prog_rows = cur.fetchone()[0]
        if prog_rows == 0:
            return (
                f"Database export incomplete: program table is empty "
                f"(export likely crashed before finalization). "
                f"Found {funcs} functions but missing callgraph metadata."
            )

        cur.execute(
            "SELECT callgraph_primes FROM program "
            "WHERE callgraph_primes IS NOT NULL AND callgraph_primes != ''"
        )
        if cur.fetchone() is None:
            return f"Database export incomplete: callgraph_primes is empty in program table"

        return None


def get_funcs_batch(db_path: str, addresses: list[str]) -> dict[str, dict]:
    """Load multiple functions by address in ONE query.

    Args:
        db_path: Path to a Diaphora .sqlite database.
        addresses: List of address strings (hex, with or without 0x prefix).

    Returns:
        {address_normalized: func_dict, ...}
        Only addresses that exist in the database are returned.
    """
    if not addresses or not os.path.isfile(db_path):
        return {}

    norm = {}
    for a in addresses:
        key = norm_addr(a)
        norm[key] = a

    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            placeholders = ",".join("?" for _ in norm)
            cur.execute(
                f"SELECT * FROM functions WHERE address IN ({placeholders})",
                list(norm.keys()),
            )
            result = {}
            for row in cur.fetchall():
                fd = dict(row)
                addr = fd.get("address", "")
                if addr:
                    result[addr] = fd
            return result
    except Exception:
        return {}


def get_func(db_path: str, address: str = "", name: str = "") -> dict | None:
    """Return the full function row from an export .sqlite database.

    Returns a dict, or None if not found / DB invalid.
    """
    err = check_db(db_path)
    if err:
        return None
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        if address:
            addr = norm_addr(address)
            cur.execute("SELECT * FROM functions WHERE address = ?", (addr,))
        elif name:
            cur.execute("SELECT * FROM functions WHERE name = ?", (name,))
        else:
            return None
        row = cur.fetchone()
        return dict(row) if row else None


def get_underlying_db_paths(results_path: str) -> tuple:
    """Return (primary_db, secondary_db) paths from a .diaphora config table."""
    try:
        with sqlite3.connect(results_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT main_db, diff_db FROM config")
            row = cur.fetchone()
            return (row[0], row[1]) if row else ("", "")
    except Exception:
        return ("", "")



def get_callgraph(db_path: str, func_address: str) -> dict:
    """Get callers and callees for a function from the callgraph table.

    Returns {"callers": [addr, ...], "callees": [addr, ...]}.
    """
    err = check_db(db_path)
    if err:
        return {"callers": [], "callees": []}
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()

        addr = norm_addr(func_address)
        cur.execute("SELECT id FROM functions WHERE address = ?", (addr,))
        row = cur.fetchone()
        if not row:
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
        return {"callers": callers, "callees": callees}


def resolve_func_names(db_path: str, addresses: list[str]) -> dict:
    """Resolve a list of addresses to {addr: name} in one query."""
    if not addresses:
        return {}
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        norm = {norm_addr(a): a for a in addresses}
        placeholders = ",".join("?" for _ in norm)
        cur.execute(
            f"SELECT address, name FROM functions WHERE address IN ({placeholders})",
            list(norm.keys()),
        )
        result = {}
        for row in cur.fetchall():
            orig = norm.get(row[0], row[0])
            result[orig] = row[1]
        return result
