"""
Diaphora MCP — SQLite database helpers.

Shared low-level functions for reading Diaphora-exported databases and
.diaphora diff results files.
"""

import os
import sqlite3
import subprocess
import time

from .connection import get_connection


# ---------------------------------------------------------------------------
# Schema-adaptive column resolution for .diaphora diff results
# ---------------------------------------------------------------------------

# Known column name variants across Diaphora versions
_RESULTS_COLUMN_MAP = {
    # (standard_name, [variants...])
    "address": ["address", "addr1", "address1"],
    "name": ["name", "name1", "func_name"],
    "address2": ["address2", "addr2", "target_address", "address_2"],
    "name2": ["name2", "target_name", "name_2", "func_name_2"],
    "ratio": ["ratio", "similarity", "match_ratio", "confidence"],
    "type": ["type", "match_type"],
    "nodes1": ["nodes1", "nodes_old", "nodes_primary"],
    "nodes2": ["nodes2", "nodes_new", "nodes_secondary"],
    "description": ["description", "desc", "notes"],
}

_UNMATCHED_COLUMN_MAP = {
    "address": ["address", "addr"],
    "name": ["name"],
    "address2": ["address2", "addr2", "target_address"],
    "name2": ["name2", "target_name"],
    "type": ["type", "match_type"],
    "address_new": ["address_new", "addr_new"],
}


def get_table_columns(db_path: str, table: str) -> set:
    """Return the set of column names for *table* in the given database."""
    try:
        conn = get_connection(db_path)
        cur = conn.execute(f"PRAGMA table_info({table})")
        return {row[1].lower() for row in cur.fetchall()}
    except Exception:
        return set()


def resolve_columns(available: set, column_map: dict) -> list:
    """Return the best column names available, in standard order.

    *available* is a set of lowercase actual column names from the DB.
    *column_map* maps standard names to their known variant lists.
    Returns a list of (standard_name, actual_column_name) tuples.
    """
    resolved = []
    for standard, variants in column_map.items():
        for variant in variants:
            if variant.lower() in available:
                resolved.append((standard, variant))
                break
        else:
            resolved.append((standard, None))
    return resolved


def safe_results_query(
    db_path: str,
    column_map: dict,
    table: str = "results",
    extra_where: str = "",
) -> tuple:
    """Build a safe SELECT query for a .diaphora results table.

    Returns (sql, resolved_columns) where *resolved_columns* is a list of
    (standard_name, actual_name) tuples.  Callers iterate over *resolved_columns*
    to populate dicts with standardised keys.
    """
    available = get_table_columns(db_path, table)
    resolved = resolve_columns(available, column_map)
    actual_names = [name for _, name in resolved if name is not None]

    if not actual_names:
        # Fallback: SELECT * and let the caller handle missing columns
        sql = f"SELECT * FROM {table}"
        return sql, resolved

    select_clause = ", ".join(actual_names)
    sql = f"SELECT {select_clause} FROM {table}"
    if extra_where:
        sql += f" WHERE {extra_where}"
    return sql, resolved


def row_to_standard_dict(row: dict, resolved: list) -> dict:
    """Convert a row dict (actual column names) to standardised keys."""
    result = {}
    for standard, actual in resolved:
        if actual and actual in row:
            result[standard] = row[actual]
        else:
            result[standard] = None
    return result


def read_adaptive_table(
    db_path: str,
    column_map: dict,
    table: str = "results",
    extra_where: str = "",
    params: tuple = (),
    row_factory=None,
) -> list:
    """Read rows from *table* in *db_path* using schema-adaptive queries.

    Returns a list of dicts with standardised keys (from *column_map*).
    Numeric-typed standard names (``ratio``) are coerced to float.
    """
    import sqlite3
    conn = get_connection(db_path)
    if row_factory:
        conn.row_factory = row_factory
    cur = conn.cursor()

    sql, resolved = safe_results_query(db_path, column_map, table, extra_where)
    try:
        cur.execute(sql, params)
    except Exception as exc:
        # Last-resort fallback: try SELECT *
        try:
            cur.execute(f"SELECT * FROM {table}")
        except Exception:
            raise exc

    rows = []
    for raw in cur.fetchall():
        d = dict(raw) if isinstance(raw, sqlite3.Row) else dict(zip([d[0] for d in cur.description], raw))

        # Coerce known numeric columns to float
        if "ratio" in d and d["ratio"] is not None:
            try:
                d["ratio"] = float(d["ratio"])
            except (ValueError, TypeError):
                pass

        rows.append(row_to_standard_dict(d, resolved))
    return rows


# ---------------------------------------------------------------------------


def norm_addr(addr: str, use_decimal: bool = False) -> str:
    """Normalize a hex or decimal address to a lowercase hex string (no 0x prefix)."""
    s = addr.strip().lower()
    if use_decimal and s.isdigit() and int(s) > 1000000:
        return hex(int(s)).removeprefix("0x")
    return s.removeprefix("0x")


def _detect_decimal(conn) -> bool:
    try:
        cur = conn.cursor()
        cur.execute("SELECT address FROM functions LIMIT 1")
        row = cur.fetchone()
        if row and row[0]:
            s = row[0]
            if s.isdigit() and int(s) > 1000000:
                return True
    except Exception:
        pass
    return False


def force_delete_file(path: str, retries: int = 3) -> bool:
    """Safely delete a file on Windows, killing idat.exe if locked."""
    if not os.path.exists(path):
        return True
    from .connection import close_connection
    close_connection(path)
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
        conn = get_connection(path)
        # Force checkpoint so WAL data is visible in the main file
        conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
        conn.execute("SELECT count(*) FROM functions")
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

    conn = get_connection(path)
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
    """Load multiple functions by address in batched queries.

    Automatically splits into chunks of 500 addresses to avoid SQLite's
    SQLITE_MAX_VARIABLE_NUMBER limit (default ~999 on most builds).

    Args:
        db_path: Path to a Diaphora .sqlite database.
        addresses: List of address strings (hex, with or without 0x prefix).

    Returns:
        {address_normalized: func_dict, ...}
        Only addresses that exist in the database are returned.
    """
    if not addresses or not os.path.isfile(db_path):
        return {}

    try:
        conn = get_connection(db_path)
        use_decimal = _detect_decimal(conn)

        norm = {}
        for a in addresses:
            key = norm_addr(a, False)
            norm[key] = a

        result: dict[str, dict] = {}

        # Build a list of (db_key, original_key) pairs
        keys = []
        for k, orig in norm.items():
            if use_decimal:
                keys.append((k, orig))
                try:
                    dec = str(int(k, 16))
                    if dec != k:
                        keys.append((dec, orig))
                except ValueError:
                    pass
            else:
                keys.append((k, orig))

        # Process in chunks of 500 to avoid parameter-count limits
        chunk_size = 500
        for i in range(0, len(keys), chunk_size):
            chunk = keys[i:i + chunk_size]
            db_keys = [k for k, _ in chunk]
            placeholders = ",".join("?" for _ in db_keys)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(
                f"SELECT address, name, nodes, edges, cyclomatic_complexity, "
                f"instructions, pseudocode, assembly, prototype, bytes_hash "
                f"FROM functions WHERE address IN ({placeholders})",
                db_keys,
            )
            for row in cur.fetchall():
                fd = dict(row)
                addr = fd.get("address", "")
                orig = next((o for k, o in chunk if k == addr), addr)
                if orig:
                    result[orig] = fd
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
    conn = get_connection(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    if address:
        use_decimal = _detect_decimal(conn)
        addr = norm_addr(address, False)
        if use_decimal:
            addr_dec = None
            try:
                addr_dec = str(int(addr, 16))
            except ValueError:
                pass
            if addr_dec and addr_dec != addr:
                cur.execute(
                    "SELECT address, name, nodes, edges, instructions, "
                    "cyclomatic_complexity, pseudocode, assembly, prototype, "
                    "bytes_hash, constants, mnemonics, loops, strongly_connected, "
                    "names, pseudocode_hash1, pseudocode_hash2 "
                    "FROM functions WHERE address = ? OR address = ?", (addr_dec, addr)
                )
            else:
                cur.execute(
                    "SELECT address, name, nodes, edges, instructions, "
                    "cyclomatic_complexity, pseudocode, assembly, prototype, "
                    "bytes_hash, constants, mnemonics, loops, strongly_connected, "
                    "names, pseudocode_hash1, pseudocode_hash2 "
                    "FROM functions WHERE address = ?", (addr,)
                )
        else:
            cur.execute(
                "SELECT address, name, nodes, edges, instructions, "
                "cyclomatic_complexity, pseudocode, assembly, prototype, "
                "bytes_hash, constants, mnemonics, loops, strongly_connected, "
                "names, pseudocode_hash1, pseudocode_hash2 "
                "FROM functions WHERE address = ?", (addr,)
            )
    elif name:
        cur.execute(
            "SELECT address, name, nodes, edges, instructions, "
            "cyclomatic_complexity, pseudocode, assembly, prototype, "
            "bytes_hash, constants, mnemonics, loops, strongly_connected, "
            "names, pseudocode_hash1, pseudocode_hash2 "
            "FROM functions WHERE name = ?", (name,)
        )
    else:
        return None
    row = cur.fetchone()
    return dict(row) if row else None


def get_underlying_db_paths(results_path: str) -> tuple:
    """Return (primary_db, secondary_db) paths from a .diaphora config table."""
    try:
        conn = get_connection(results_path)
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
    conn = get_connection(db_path)
    cur = conn.cursor()

    use_decimal = _detect_decimal(conn)
    addr = norm_addr(func_address, False)
    if use_decimal:
        addr_dec = None
        try:
            addr_dec = str(int(addr, 16))
        except ValueError:
            pass
        if addr_dec and addr_dec != addr:
            cur.execute("SELECT id FROM functions WHERE address = ? OR address = ?", (addr_dec, addr))
        else:
            cur.execute("SELECT id FROM functions WHERE address = ?", (addr,))
    else:
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
        norm_addr_str = norm_addr(addr_str, use_decimal)
        if ctype == "caller":
            callers.append(norm_addr_str)
        else:
            callees.append(norm_addr_str)
    return {"callers": callers, "callees": callees}


def resolve_func_names(db_path: str, addresses: list[str]) -> dict:
    """Resolve a list of addresses to {addr: name} in one query."""
    if not addresses:
        return {}
    conn = get_connection(db_path)
    cur = conn.cursor()
    use_decimal = _detect_decimal(conn)
    norm = {norm_addr(a, False): a for a in addresses}
    db_keys = []
    db_to_orig = {}
    for k, orig in norm.items():
        if use_decimal:
            db_keys.append(k)
            db_to_orig[k] = orig
            try:
                dec = str(int(k, 16))
                if dec != k:
                    db_keys.append(dec)
                    db_to_orig[dec] = orig
            except ValueError:
                pass
        else:
            db_keys.append(k)
            db_to_orig[k] = orig

    placeholders = ",".join("?" for _ in db_keys)
    cur.execute(
        f"SELECT address, name FROM functions WHERE address IN ({placeholders})",
        db_keys,
    )
    result = {}
    for row in cur.fetchall():
        addr = row[0]
        orig = db_to_orig.get(addr, addr)
        result[orig] = row[1]
    return result
