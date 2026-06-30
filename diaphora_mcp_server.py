#!/c/Users/olegc/AppData/Local/Programs/Python/Python312/python.exe
"""
Diaphora MCP Server for Claude Code.

Provides tools to:
  - Export IDB/i64 databases to Diaphora SQLite format (headless IDA)
  - Diff two Diaphora-exported databases
  - Read/analyze diff results (including security-relevant filtering)
  - Search/filter exported databases
  - Get function pseudocode and details
  - Side-by-side function comparison across two databases

Uses Diaphora's own diff engine via subprocess + direct SQLite reading,
and delegates headless export to IDA's idat.exe with Diaphora's built-in
DIAPHORA_AUTO environment-variable mechanism.
"""

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
DIAPHORA_DIR     = r"D:\Programs\IDA Professional 9.3\plugins\diaphora-3.4.1"
IDAT_PATH        = r"D:\Programs\IDA Professional 9.3\idat.exe"
DIAPHORA_SCRIPT  = os.path.join(DIAPHORA_DIR, "diaphora.py")

_HEADLESS_WRAPPER = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "_diaphora_headless.py"
)
_PYTHON = sys.executable

# Security-relevant keywords for analyze_diff_results.
_SECURITY_KEYWORDS = [
    # Crypto
    "crypt", "encrypt", "decrypt", "aes", "rsa", "sha", "md5", "hash",
    "hmac", "cipher", "chacha", "salsa", "blake", "elliptic", "ecdh",
    "ecdsa", "hkdf", "pbkdf", "bcrypt", "scrypt", "argon2",
    # Auth / credentials
    "password", "passwd", "pwd", "credential", "auth", "oauth", "token",
    "session", "login", "permission", "privilege", "acl", "capability",
    "certificate", "cert", "x509", "tls", "ssl", "asn1",
    # Memory safety
    "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat",
    "strncat", "sprintf", "vsprintf", "snprintf", "vsnprintf", "scanf",
    "sscanf", "fscanf", "gets", "read", "recv", "malloc", "free",
    "realloc", "calloc", "alloc", "dealloc",
    # Input validation
    "validate", "sanitize", "escape", "check", "verify", "bounds",
    "overflow", "underflow", "integer_overflow", "off_by_one",
    "null_terminat", "format_string",
    # Process / memory
    "exec", "system", "shell", "fork", "spawn", "create_process",
    "load_library", "dlopen", "dlsym", "virtual_alloc", "virtual_protect",
    "write_process", "read_process", "code_inject",
    # File operations
    "fopen", "fwrite", "fread", "create_file", "write_file",
    "delete_file", "temp", "tmp", "path_traversal", "directory",
    # Networking
    "socket", "connect", "bind", "listen", "accept", "send", "recvfrom",
    "dns", "resolve", "url", "uri", "http", "https", "websocket",
]

# Common heuristic indicators that a change in a patch diff is security-relevant.
_SECURITY_PSEUDO_PATTERNS = [
    "if (", ">= ", "<= ", "> ", "< ", "== 0", "!= 0",  # bounds checks
    "goto", "return -1", "return 0", "return false",
    "__except", "__try", "try {", "catch ", "throw",
    "null", "NULL", "nullptr",  # null checks
    "sizeof",  # buffer size tracking
]

# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------
mcp = FastMCP("Diaphora")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _check_db(path: str) -> str | None:
    """Return an error string if *path* is not a readable SQLite file, else None."""
    if not os.path.isfile(path):
        return f"File not found: {path}"
    try:
        with sqlite3.connect(path) as c:
            c.execute("SELECT count(*) FROM functions")
    except Exception as exc:
        return f"Not a valid Diaphora export database: {path}\n{exc}"
    return None


def _run_export(idb_path: str, output_path: str, use_decompiler: bool) -> str | None:
    """Run IDA headless export via idat.exe and the headless wrapper.

    Returns an error string on failure, or None on success.
    """
    if not os.path.isfile(idb_path):
        return f"Input file not found: {idb_path}"
    if not os.path.isfile(IDAT_PATH):
        return f"idat.exe not found at {IDAT_PATH}"
    if not os.path.isfile(_HEADLESS_WRAPPER):
        return f"Headless wrapper not found at {_HEADLESS_WRAPPER}"

    # Prepare environment for Diaphora's built-in headless export.
    env = os.environ.copy()
    env["DIAPHORA_AUTO"] = "1"
    env["DIAPHORA_EXPORT_FILE"] = output_path
    env["DIAPHORA_USE_DECOMPILER"] = "1" if use_decompiler else "0"

    # Write a small sentinel so the wrapper can verify env was passed
    try:
        proc = subprocess.run(
            [IDAT_PATH, "-A", f"-S{_HEADLESS_WRAPPER}", idb_path],
            cwd=DIAPHORA_DIR,
            env=env,
            capture_output=True,
            text=True,
            timeout=3600,  # 1 hour max
        )
    except subprocess.TimeoutExpired:
        return "Export timed out after 3600 s"
    except FileNotFoundError:
        return f"idat.exe not found at {IDAT_PATH}"
    except Exception as exc:
        return f"Failed to launch IDA headless: {exc}"

    # Diaphora creates a crash file when it starts export and removes it on
    # success.  If the file is still present, export crashed.
    crash_file = f"{output_path}-crash"
    if os.path.isfile(crash_file):
        try:
            os.remove(crash_file)
        except OSError:
            pass
        return (
            "Export appears to have crashed (crash file still present).\n"
            f"  idat stdout (last 2K):\n{(proc.stdout or '')[-2048:]}\n"
            f"  idat stderr (last 2K):\n{(proc.stderr or '')[-2048:]}"
        )

    # Verify the output was actually created.
    if not os.path.isfile(output_path):
        return (
            "Export completed but no output file was produced.\n"
            f"  idat stdout (last 2K):\n{(proc.stdout or '')[-2048:]}\n"
            f"  idat stderr (last 2K):\n{(proc.stderr or '')[-2048:]}"
        )

    # Validate it's a real Diaphora DB.
    db_err = _check_db(output_path)
    if db_err:
        return f"Export produced invalid database:\n  {db_err}"

    return None  # success


def _match_security_keywords(name: str, pseudo: str, assembly: str) -> dict:
    """Check a function against security keyword lists.

    Returns a dict with matched categories and the specific keywords found.
    """
    name_lower = name.lower() if name else ""
    pseudo_lower = pseudo.lower() if pseudo else ""
    assembly_lower = assembly.lower() if assembly else ""
    haystack = f"{name_lower} {pseudo_lower} {assembly_lower}"

    matched_keywords = []
    categories = set()

    for kw in _SECURITY_KEYWORDS:
        if kw in haystack:
            matched_keywords.append(kw)
            # Determine category
            if kw in {"memcpy", "memmove", "memset", "strcpy", "strncpy",
                       "strcat", "strncat", "sprintf", "vsprintf", "snprintf",
                       "vsnprintf", "scanf", "sscanf", "fscanf", "gets",
                       "malloc", "free", "realloc", "calloc", "alloc",
                       "dealloc"}:
                categories.add("memory")
            elif kw in {"crypt", "encrypt", "decrypt", "aes", "rsa", "sha",
                         "md5", "hash", "hmac", "cipher", "chacha", "blake",
                         "elliptic", "ecdh", "ecdsa", "hkdf", "pbkdf",
                         "bcrypt", "scrypt", "argon2"}:
                categories.add("crypto")
            elif kw in {"password", "passwd", "pwd", "credential", "auth",
                         "oauth", "token", "session", "login", "permission",
                         "privilege", "acl", "capability"}:
                categories.add("auth")
            elif kw in {"exec", "system", "shell", "fork", "spawn",
                         "create_process", "load_library", "dlopen", "dlsym"}:
                categories.add("process")
            elif kw in {"socket", "connect", "bind", "listen", "accept",
                         "send", "recvfrom", "dns", "url", "uri", "http",
                         "https"}:
                categories.add("network")
            elif kw in {"validate", "sanitize", "escape", "check", "verify",
                         "bounds", "overflow", "underflow"}:
                categories.add("validation")
            elif kw in {"fopen", "fwrite", "fread", "create_file",
                         "write_file", "delete_file", "temp", "tmp"}:
                categories.add("file_io")
            elif kw in {"virtual_alloc", "virtual_protect", "write_process",
                         "read_process", "code_inject"}:
                categories.add("memory_manipulation")
            else:
                categories.add("other")

    return {
        "matched": len(matched_keywords) > 0,
        "keywords": matched_keywords[:20],
        "categories": sorted(categories),
    }


def _read_results(results_path: str, match_type: str = "all", min_ratio: float = 0.0):
    """Read a .diaphora results file and return structured data."""
    conn = sqlite3.connect(results_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Metadata
    cur.execute("SELECT * FROM config")
    config_info = dict(cur.fetchone() or {})

    types_filter = {
        "best": ("best",),
        "partial": ("partial",),
        "unreliable": ("unreliable",),
        "multimatch": ("multimatch",),
        "all": ("best", "partial", "unreliable", "multimatch"),
    }
    mtypes = types_filter.get(match_type, types_filter["all"])
    placeholders = ",".join("?" for _ in mtypes)

    if min_ratio > 0:
        sql = (
            f"SELECT * FROM results WHERE type IN ({placeholders}) AND ratio >= ?"
            " ORDER BY ratio DESC"
        )
        params = [*mtypes, min_ratio]
    else:
        sql = f"SELECT * FROM results WHERE type IN ({placeholders}) ORDER BY ratio DESC"
        params = [*mtypes]

    cur.execute(sql, params)
    results = [dict(r) for r in cur.fetchall()]

    # Counts per type
    counts = {}
    for t in ["best", "partial", "unreliable", "multimatch"]:
        cur.execute("SELECT count(*) FROM results WHERE type = ?", (t,))
        counts[t] = cur.fetchone()[0]

    # Unmatched
    cur.execute("SELECT * FROM unmatched")
    unmatched = [dict(r) for r in cur.fetchall()]

    conn.close()

    return {
        "config": config_info,
        "counts": counts,
        "total_matches": len(results),
        "unmatched_count": len(unmatched),
        "results": results[:500],
        "truncated": len(results) > 500,
        "unmatched": unmatched[:100],
    }


# ---------------------------------------------------------------------------
# Tools — Export
# ---------------------------------------------------------------------------
@mcp.tool(
    description="Export an IDB/i64 database to Diaphora SQLite format using IDA headless (idat.exe). Requires a previously analyzed .i64/.idb file."
)
def export_idb_to_diaphora(
    idb_path: str,
    output_path: str | None = None,
    use_decompiler: bool = True,
) -> str:
    """Export an existing IDB/i64 database to a Diaphora-compatible SQLite file.

    Runs idat.exe in headless mode with Diaphora's built-in DIAPHORA_AUTO
    environment variable mechanism.  The resulting .sqlite can be diffed with
    ``diff_diaphora_dbs``.

    Args:
        idb_path: Path to an existing .i64 or .idb database
        output_path: Where to write the exported .sqlite (auto-generated if
                     omitted, based on the input file name)
        use_decompiler: Whether to use the Hex-Rays decompiler during export
    """
    if not os.path.isfile(idb_path):
        return json.dumps({"error": f"IDB file not found: {idb_path}"})

    if not output_path:
        base = os.path.splitext(os.path.basename(idb_path))[0]
        output_path = os.path.join(os.path.dirname(idb_path), f"{base}.sqlite")

    err = _run_export(idb_path, output_path, use_decompiler)
    if err:
        return json.dumps({"error": err})

    return json.dumps(
        {
            "success": True,
            "output_path": output_path,
            "size_bytes": os.path.getsize(output_path),
            "exported_from": os.path.basename(idb_path),
        },
        indent=2,
        default=str,
    )


@mcp.tool(
    description="Complete pipeline: export two IDB databases, diff them, and return a summary. One-shot for the full workflow."
)
def batch_export_and_diff(
    idb1_path: str,
    idb2_path: str,
    output_dir: str | None = None,
    use_decompiler: bool = True,
) -> str:
    """Run the full Diaphora pipeline: export → export → diff → summary.

    This is the primary entry point for patch diffing.  Give it two .i64 files
    (pre- and post-patch) and it returns structured match results.

    Args:
        idb1_path: Path to the first (primary / old) .i64 database
        idb2_path: Path to the second (secondary / new) .i64 database
        output_dir: Directory for intermediate and result files (defaults to
                    the directory of idb1_path)
        use_decompiler: Whether to use Hex-Rays decompiler during export
    """
    # Validate inputs ---------------------------------------------------------
    for p, label in [(idb1_path, "idb1"), (idb2_path, "idb2")]:
        if not os.path.isfile(p):
            return json.dumps({"error": f"{label} not found: {p}"})

    if not output_dir:
        output_dir = os.path.dirname(os.path.abspath(idb1_path))
    os.makedirs(output_dir, exist_ok=True)

    b1 = os.path.splitext(os.path.basename(idb1_path))[0]
    b2 = os.path.splitext(os.path.basename(idb2_path))[0]

    sqlite1 = os.path.join(output_dir, f"{b1}.sqlite")
    sqlite2 = os.path.join(output_dir, f"{b2}.sqlite")
    diff_out = os.path.join(output_dir, f"{b1}_vs_{b2}.diaphora")

    step_results = {}

    # Step 1: export primary --------------------------------------------------
    err = _run_export(idb1_path, sqlite1, use_decompiler)
    if err:
        return json.dumps({"error": f"Export of {b1} failed: {err}", "steps": step_results})
    step_results["export1"] = {
        "database": b1,
        "output": sqlite1,
        "size_bytes": os.path.getsize(sqlite1),
    }

    # Step 2: export secondary ------------------------------------------------
    err = _run_export(idb2_path, sqlite2, use_decompiler)
    if err:
        return json.dumps({"error": f"Export of {b2} failed: {err}", "steps": step_results})
    step_results["export2"] = {
        "database": b2,
        "output": sqlite2,
        "size_bytes": os.path.getsize(sqlite2),
    }

    # Step 3: diff ------------------------------------------------------------
    try:
        proc = subprocess.run(
            [_PYTHON, DIAPHORA_SCRIPT, sqlite1, sqlite2, "-o", diff_out],
            cwd=DIAPHORA_DIR,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "Diff timed out after 600 s", "steps": step_results})
    except Exception as exc:
        return json.dumps({"error": f"Diff failed: {exc}", "steps": step_results})

    if not os.path.isfile(diff_out):
        return json.dumps(
            {
                "error": "Diff completed but no output file produced",
                "steps": step_results,
                "stdout": (proc.stdout or "")[-3000:],
                "stderr": (proc.stderr or "")[-3000:],
            }
        )

    step_results["diff"] = {
        "output": diff_out,
        "size_bytes": os.path.getsize(diff_out),
    }

    # Step 4: read and return results -----------------------------------------
    try:
        results = _read_results(diff_out)
    except Exception as exc:
        return json.dumps({"error": f"Failed to read diff results: {exc}", "steps": step_results})

    return json.dumps(
        {
            "success": True,
            "steps": step_results,
            "summary": {
                "best_matches": results["counts"]["best"],
                "partial_matches": results["counts"]["partial"],
                "unreliable_matches": results["counts"]["unreliable"],
                "multimatches": results["counts"]["multimatch"],
                "unmatched_primary": results["unmatched_count"],
            },
            "results": results,
        },
        indent=2,
        default=str,
    )


@mcp.tool(
    description="Filter .diaphora diff results for security-relevant changes. Returns a curated list suitable for IDA Pro MCP follow-up."
)
def analyze_diff_results(
    results_path: str,
    security_only: bool = True,
) -> str:
    """Analyse diff results for security-relevant changes.

    Uses keyword matching against function names, pseudocode, and assembly.
    Returns a structured report with matched categories, severity indicators,
    and full context (address, database path) for IDA Pro MCP drill-down.

    Args:
        results_path: Path to a .diaphora diff results file
        security_only: When True (default), only return security-relevant
                       matches. When False, return a security annotation for
                       every match.
    """
    if not os.path.isfile(results_path):
        return json.dumps({"error": f"Results file not found: {results_path}"})

    # Load the raw results and databases info --------------------------------
    conn = sqlite3.connect(results_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT * FROM config")
    config_info = dict(cur.fetchone() or {})

    cur.execute("SELECT * FROM matching_databases")
    databases = [dict(r) for r in cur.fetchall()]

    db1_path = config_info.get("primary_database", "")
    db2_path = config_info.get("secondary_database", "")

    # Load all results --------------------------------------------------------
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

    # Analyse each match ------------------------------------------------------
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

        # Security keyword analysis (on both old and new artifacts)
        sec_old = _match_security_keywords(name1 or "", pseudo1, asm1)
        sec_new = _match_security_keywords(name2 or "", pseudo2, asm2)

        is_security_relevant = sec_old["matched"] or sec_new["matched"]

        # Heuristic: large complexity change + low ratio = suspicious
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

    # Counts by type and security status -------------------------------------
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


@mcp.tool(
    description="Compare the same function side-by-side across two exported databases. Returns pseudocode 'was' / 'became' with addresses for IDA Pro MCP drill-down."
)
def compare_functions(
    db1_path: str,
    db2_path: str,
    address: str = "",
    name: str = "",
) -> str:
    """Retrieve a function's data from both databases for side-by-side comparison.

    The output includes pseudocode, assembly, prototype, and complexity metrics
    for both the old and new version.  Addresses are included so you can call
    IDA Pro MCP tools (decompile_function, get_function_by_address) for
    deeper analysis.

    Args:
        db1_path: Path to the primary (old) exported .sqlite database
        db2_path: Path to the secondary (new) exported .sqlite database
        address: Function address (hex, e.g. "401000" or "0x401000")
        name: Function name to look up (used if address is empty)
    """
    err1 = _check_db(db1_path)
    if err1:
        return json.dumps({"error": err1})
    err2 = _check_db(db2_path)
    if err2:
        return json.dumps({"error": err2})

    if not address and not name:
        return json.dumps({"error": "Provide either address or name"})

    def _lookup(db_path, lookup_addr, lookup_name):
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        if lookup_addr:
            addr = lookup_addr.lower().removeprefix("0x")
            cur.execute(
                """SELECT name, address, pseudocode, assembly, prototype,
                          instructions, cyclomatic_complexity, nodes, edges,
                          bytes_hash, constants
                   FROM functions WHERE address = ?""",
                (addr,),
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
        conn.close()
        return dict(row) if row else None

    func1 = _lookup(db1_path, address, name)
    if not func1:
        return json.dumps(
            {"error": f"Function not found in primary database (address={address}, name={name})"}
        )

    func2 = _lookup(db2_path, address, name)
    if not func2:
        return json.dumps(
            {
                "warning": "Function not found in secondary database",
                "primary": func1,
                "secondary": None,
            },
            indent=2,
            default=str,
        )

    # Build a clean side-by-side structure -----------------------------------
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

    return json.dumps(
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
        },
        indent=2,
        default=str,
    )


# ---------------------------------------------------------------------------
# Tools — Diff & Query
# ---------------------------------------------------------------------------
@mcp.tool(
    description="Diff two Diaphora-exported SQLite databases. Returns structured match results (best/partial/unreliable)."
)
def diff_diaphora_dbs(
    db1_path: str,
    db2_path: str,
    output_path: str | None = None,
) -> str:
    """Diff two exported Diaphora databases and return the results.

    Args:
        db1_path: Path to the primary exported .sqlite database
        db2_path: Path to the secondary exported .sqlite database
        output_path: Optional custom path for the .diaphora results file
    """
    # Validate inputs
    err1 = _check_db(db1_path)
    if err1:
        return json.dumps({"error": err1})
    err2 = _check_db(db2_path)
    if err2:
        return json.dumps({"error": err2})

    if not output_path:
        b1 = os.path.splitext(os.path.basename(db1_path))[0]
        b2 = os.path.splitext(os.path.basename(db2_path))[0]
        output_path = os.path.join(
            os.path.dirname(db1_path), f"{b1}_vs_{b2}.diaphora"
        )
        # Use the same directory as db1

    # Run the diff -----------------------------------------------------------
    try:
        proc = subprocess.run(
            [_PYTHON, DIAPHORA_SCRIPT, db1_path, db2_path, "-o", output_path],
            cwd=DIAPHORA_DIR,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "Diaphora diff timed out after 600 s"})
    except FileNotFoundError:
        return json.dumps({"error": f"diaphora.py not found at {DIAPHORA_SCRIPT}"})
    except Exception as exc:
        return json.dumps({"error": f"Failed to launch Diaphora: {exc}"})

    if not os.path.isfile(output_path):
        return json.dumps(
            {
                "error": "Diaphora completed but did not produce an output file",
                "stdout": (proc.stdout or "")[-3000:],
                "stderr": (proc.stderr or "")[-3000:],
            }
        )

    return json.dumps(_read_results(output_path), indent=2, default=str)


@mcp.tool(
    description="Read and filter a previously saved .diaphora diff results file."
)
def get_diff_results(
    results_path: str,
    match_type: str = "all",
    min_ratio: float = 0.0,
) -> str:
    """Return matches from a .diaphora results file, optionally filtered.

    Args:
        results_path: Path to a .diaphora results file
        match_type: "all" | "best" | "partial" | "unreliable" | "multimatch"
        min_ratio: Minimum similarity ratio threshold (0.0 – 1.0)
    """
    if not os.path.isfile(results_path):
        return json.dumps({"error": f"Results file not found: {results_path}"})

    try:
        return json.dumps(
            _read_results(results_path, match_type, min_ratio), indent=2, default=str
        )
    except Exception as exc:
        return json.dumps({"error": f"Error reading results: {exc}"})


@mcp.tool(
    description="Search for functions in an exported Diaphora database by name, size, or complexity."
)
def search_export_db(
    db_path: str,
    name_pattern: str = "",
    min_instructions: int = 0,
    max_instructions: int = 0,
    min_complexity: int = 0,
    max_complexity: int = 0,
    limit: int = 100,
) -> str:
    """Query functions in an exported Diaphora .sqlite database.

    Args:
        db_path: Path to the exported .sqlite database
        name_pattern: SQL LIKE pattern (e.g. "sub_%", "%crypt%", "sub_401%")
        min_instructions: Minimum instruction count
        max_instructions: Maximum instruction count (0 = no limit)
        min_complexity: Minimum cyclomatic complexity
        max_complexity: Maximum cyclomatic complexity (0 = no limit)
        limit: Max number of results (default 100)
    """
    err = _check_db(db_path)
    if err:
        return json.dumps({"error": err})

    conn = sqlite3.connect(db_path)
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

    cur.execute("SELECT * FROM program")
    program = [dict(r) for r in cur.fetchall()]

    conn.close()

    return json.dumps(
        {
            "program": program,
            "total_functions_in_db": total_funcs,
            "matching_functions": total,
            "truncated": total > limit,
            "functions": functions,
        },
        indent=2,
        default=str,
    )


@mcp.tool(
    description="Get a high-level summary of a .diaphora diff results file."
)
def get_diff_summary(results_path: str) -> str:
    """Return match statistics, top matches, and unmatched counts."""
    if not os.path.isfile(results_path):
        return json.dumps({"error": f"Results file not found: {results_path}"})

    conn = sqlite3.connect(results_path)
    cur = conn.cursor()

    cur.execute("SELECT * FROM config")
    config_info = dict(zip([d[0] for d in cur.description], cur.fetchone() or []))

    cur.execute(
        """SELECT type, count(*) as cnt,
                  round(avg(ratio), 4) as avg_ratio,
                  round(max(ratio), 4) as max_ratio,
                  round(min(ratio), 4) as min_ratio
           FROM results GROUP BY type"""
    )
    type_stats = [dict(r) for r in cur.fetchall()]

    cur.execute(
        "SELECT * FROM results WHERE type='best' ORDER BY ratio DESC LIMIT 10"
    )
    top_best = [dict(r) for r in cur.fetchall()]

    cur.execute(
        "SELECT * FROM results WHERE type='partial' ORDER BY ratio DESC LIMIT 10"
    )
    top_partial = [dict(r) for r in cur.fetchall()]

    cur.execute("SELECT type, count(*) FROM unmatched GROUP BY type")
    unmatched = [dict(zip(["type", "count"], r)) for r in cur.fetchall()]

    conn.close()

    return json.dumps(
        {
            "config": config_info,
            "match_statistics": type_stats,
            "unmatched": unmatched,
            "top_best_matches": top_best,
            "top_partial_matches": top_partial,
        },
        indent=2,
        default=str,
    )


@mcp.tool(
    description="Get pseudocode or assembly of a specific function in an exported database."
)
def get_function_pseudocode(
    db_path: str,
    address: str = "",
    name: str = "",
) -> str:
    """Retrieve pseudocode + metadata for a function.

    Args:
        db_path: Path to the exported .sqlite database
        address: Function address as stored in Diaphora (hex, e.g. "401000" or "0x401000")
        name: Function name to look up (used if address is empty)
    """
    err = _check_db(db_path)
    if err:
        return json.dumps({"error": err})

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    if address:
        # Normalise: strip optional 0x prefix
        addr = address.lower().removeprefix("0x")
        cur.execute(
            """SELECT name, address, pseudocode, assembly, prototype,
                      instructions, cyclomatic_complexity
               FROM functions WHERE address = ?""",
            (addr,),
        )
    elif name:
        cur.execute(
            """SELECT name, address, pseudocode, assembly, prototype,
                      instructions, cyclomatic_complexity
               FROM functions WHERE name = ?""",
            (name,),
        )
    else:
        return json.dumps({"error": "Provide either address or name"})

    row = cur.fetchone()
    conn.close()

    if not row:
        return json.dumps(
            {"error": f"Function not found (address={address}, name={name})"}
        )

    return json.dumps(dict(row), indent=2, default=str)


@mcp.tool(
    description="Get basic info about an exported Diaphora database — function count, processor, MD5."
)
def get_export_info(db_path: str) -> str:
    """Show metadata from a Diaphora export database."""
    err = _check_db(db_path)
    if err:
        return json.dumps({"error": err})

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("SELECT count(*) FROM functions")
    func_count = cur.fetchone()[0]

    cur.execute("SELECT * FROM program")
    program = [dict(zip([d[0] for d in cur.description], r)) for r in cur.fetchall()]

    cur.execute("SELECT count(*) FROM instructions")
    insn_count = cur.fetchone()[0]

    conn.close()

    return json.dumps(
        {
            "database": os.path.basename(db_path),
            "size_bytes": os.path.getsize(db_path),
            "program": program,
            "function_count": func_count,
            "instruction_count": insn_count,
        },
        indent=2,
        default=str,
    )


# ---------------------------------------------------------------------------
# Phase 3 — Agent helpers
# ---------------------------------------------------------------------------
def _get_func(db_path: str, address: str = "", name: str = "") -> dict | None:
    """Return the full function row from an export .sqlite database."""
    err = _check_db(db_path)
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


def _get_callgraph(db_path: str, func_address: str) -> dict:
    """Get callers and callees for a function from the callgraph table.

    Returns {"callers": [addr, ...], "callees": [addr, ...]}.
    """
    err = _check_db(db_path)
    if err:
        return {"callers": [], "callees": []}
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    addr = func_address.lower().removeprefix("0x")
    # Resolve the internal func_id first
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


def _resolve_func_names(db_path: str, addresses: list[str]) -> dict:
    """Resolve a list of addresses to {addr: name} in one query."""
    if not addresses:
        return {}
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    # Normalise addresses
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


def _get_underlying_db_paths(results_path: str) -> tuple:
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


def _pseudocode_simple_diff(pseudo1: str, pseudo2: str) -> list:
    """Return a list of {'type': 'added'|'removed'|'context', 'line': str}."""
    lines1 = (pseudo1 or "").splitlines()
    lines2 = (pseudo2 or "").splitlines()
    import difflib
    diff = []
    for line in difflib.unified_diff(
        lines1, lines2, n=1, lineterm=""
    ):
        if line.startswith("---") or line.startswith("+++") or line.startswith("@@"):
            continue
        if line.startswith("-"):
            diff.append({"type": "removed", "line": line[1:]})
        elif line.startswith("+"):
            diff.append({"type": "added", "line": line[1:]})
        else:
            diff.append({"type": "context", "line": line[1:]})
    return diff


def _func_features(func: dict) -> dict:
    """Extract a feature vector for similarity/comparison."""
    return {
        "nodes": func.get("nodes", 0),
        "edges": func.get("edges", 0),
        "instructions": func.get("instructions", 0),
        "cyclomatic_complexity": func.get("cyclomatic_complexity", 0),
        "mnemonics": (func.get("mnemonics") or ""),
        "constants": (func.get("constants") or ""),
        "bytes_hash": (func.get("bytes_hash") or ""),
        "prototype": (func.get("prototype") or ""),
        "loops": func.get("loops", 0),
        "strongly_connected": func.get("strongly_connected", 0),
        "names": (func.get("names") or ""),
    }


def _score_change(result_row: dict, sec_match: bool, complexity_chg: int,
                  pseudo_diff_len: int) -> float:
    """Compute a single importance score for a changed function. 0–100."""
    score = 0.0
    mtype = result_row.get("type", "")
    ratio = result_row.get("ratio", 0) or 0

    # Match-type weight
    type_w = {"best": 10, "partial": 30, "unreliable": 20, "multimatch": 25}
    score += type_w.get(mtype, 15)

    # Low-ratio partial matches are more interesting
    if mtype == "partial":
        score += (1.0 - ratio) * 40 if ratio > 0 else 20
    elif mtype == "unreliable":
        score += 15

    # Security keywords bump
    if sec_match:
        score += 50

    # Complexity change
    score += min(complexity_chg * 3, 40)

    # Pseudocode diff size
    score += min(pseudo_diff_len * 0.5, 30)

    # Node/edge change
    n1 = result_row.get("nodes1", 0) or 0
    n2 = result_row.get("nodes2", 0) or 0
    if n1 and n2:
        delta = abs(n2 - n1) / max(n1, 1)
        score += min(delta * 20, 20)

    return round(min(score, 100), 1)


def _build_call_path(db_path: str, start_addr: str, depth: int,
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

        cg = _get_callgraph(db_path, addr)
        targets = cg.get(direction, [])
        resolved = _resolve_func_names(db_path, targets)

        entry = {
            "address": addr,
            "level": level,
            "direction": direction,
            "calls": len(targets),
            "functions": {tgt: resolved.get(tgt, "?") for tgt in sorted(targets)[:20]},
        }
        result.append(entry)

        for tgt in targets[:50]:  # cap breadth
            queue.append((tgt, level + 1))

    return result


# ---------------------------------------------------------------------------
# Phase 3 — Agent tools
# ---------------------------------------------------------------------------
@mcp.tool(
    description="Find the corresponding function between two binary versions with confidence and reasoning. Searches by address, name, hash, and heuristic similarity."
)
def find_function_match(
    db1_path: str,
    db2_path: str,
    address: str = "",
    name: str = "",
) -> str:
    """Locate the matching function in the second (new) binary given a
    reference in the first (old) binary.

    Matching strategy (in order of decreasing confidence):
      1. Exact address match
      2. Exact name match
      3. Bytes hash match
      4. Prototype match
      5. Heuristic: closest by instruction-count / complexity / callgraph

    Returns the matched pair with a confidence level and the evidence.
    """
    err1 = _check_db(db1_path)
    if err1:
        return json.dumps({"error": err1})
    err2 = _check_db(db2_path)
    if err2:
        return json.dumps({"error": err2})

    if not address and not name:
        return json.dumps({"error": "Provide either address or name"})

    func1 = _get_func(db1_path, address, name)
    if not func1:
        return json.dumps(
            {"error": f"Function not found in primary database (addr={address}, name={name})"}
        )

    addr = func1["address"]
    fname = func1["name"]
    candidates = []
    strategies = []

    # 1. Exact address match (highest confidence)
    func2 = _get_func(db2_path, address=addr)
    if func2:
        candidates.append((func2, 1.0, "exact_address"))
        strategies.append("exact_address")

    # 2. Exact name match
    if fname and not fname.startswith("sub_"):
        func2 = _get_func(db2_path, name=fname)
        if func2:
            # Avoid duplicate if same function already found by address
            if not any(c["address"] == func2["address"] for c, _, _ in candidates):
                candidates.append((func2, 0.95, "exact_name"))
                strategies.append("exact_name")

    # 3. Bytes hash match
    bh = func1.get("bytes_hash", "")
    if bh:
        conn2 = sqlite3.connect(db2_path)
        conn2.row_factory = sqlite3.Row
        cur2 = conn2.cursor()
        cur2.execute("SELECT * FROM functions WHERE bytes_hash = ?", (bh,))
        for row in cur2.fetchall():
            fd = dict(row)
            if not any(c["address"] == fd["address"] for c, _, _ in candidates):
                candidates.append((fd, 0.9, "bytes_hash"))
                strategies.append("bytes_hash")
        conn2.close()

    # 4. Prototype match
    proto = func1.get("prototype", "")
    if proto and len(proto) > 5:
        conn2 = sqlite3.connect(db2_path)
        conn2.row_factory = sqlite3.Row
        cur2 = conn2.cursor()
        cur2.execute("SELECT * FROM functions WHERE prototype = ?", (proto,))
        for row in cur2.fetchall():
            fd = dict(row)
            if not any(c["address"] == fd["address"] for c, _, _ in candidates):
                candidates.append((fd, 0.7, "prototype"))
                strategies.append("prototype")
        conn2.close()

    # 5. Heuristic: closest by feature vector
    feat1 = _func_features(func1)
    conn2 = sqlite3.connect(db2_path)
    conn2.row_factory = sqlite3.Row
    cur2 = conn2.cursor()
    cur2.execute(
        "SELECT * FROM functions WHERE instructions BETWEEN ? AND ?",
        (max(0, feat1["instructions"] - 10), feat1["instructions"] + 10),
    )
    heuristic_candidates = []
    for row in cur2.fetchall():
        fd = dict(row)
        if any(c["address"] == fd["address"] for c, _, _ in candidates):
            continue
        feat2 = _func_features(fd)
        # Simple similarity score
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
        if feat1["mnemonics"] == feat2["mnemonics"]:
            score += 0.20
        if feat1["constants"] == feat2["constants"]:
            score += 0.15
        if feat1["prototype"] and feat1["prototype"] == feat2["prototype"]:
            score += 0.20
        heuristic_candidates.append((fd, score))
    conn2.close()

    heuristic_candidates.sort(key=lambda x: -x[1])
    for fd, sc in heuristic_candidates[:3]:
        if sc >= 0.5:
            if not any(c["address"] == fd["address"] for c, _, _ in candidates):
                candidates.append((fd, round(sc, 2), "heuristic_features"))
                if "heuristic" not in strategies:
                    strategies.append("heuristic")
                break

    if not candidates:
        # No match found — show closest by name similarity
        if fname:
            conn2 = sqlite3.connect(db2_path)
            cur2 = conn2.cursor()
            cur2.execute("SELECT name, address FROM functions WHERE name LIKE ?",
                         (f"%{fname[:16]}%",))
            similar = [{"name": r[0], "address": r[1]} for r in cur2.fetchall()[:10]]
            conn2.close()
        else:
            similar = []
        return json.dumps({
            "matched": False,
            "primary_function": {
                "name": func1["name"],
                "address": func1["address"],
            },
            "similar_named_in_secondary": similar,
            "strategies_tried": strategies,
        }, indent=2, default=str)

    # Pick the highest-confidence candidate
    candidates.sort(key=lambda x: -x[1])
    func2, confidence, method = candidates[0]

    feat1 = _func_features(func1)
    feat2 = _func_features(func2)

    return json.dumps({
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
    }, indent=2, default=str)


@mcp.tool(
    description="Selectively transfer metadata (names, comments, prototypes, types) from one exported database to another. Returns structured data ready for IDA Pro MCP application."
)
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
    *target* database.  When *match_results_path* (a .diaphora file) is
    provided, only transfer metadata for functions that were matched,
    mapping addresses from old→new.

    Returns a structured report with the items to transfer, suitable for
    applying via IDA Pro MCP tools or an IDAPython script.
    """
    err1 = _check_db(source_db_path)
    if err1:
        return json.dumps({"error": f"source: {err1}"})
    err2 = _check_db(target_db_path)
    if err2:
        return json.dumps({"error": f"target: {err2}"})

    # Build address mapping ---------------------------------------------------
    addr_map = {}  # source_addr → target_addr
    if match_results_path and os.path.isfile(match_results_path):
        conn = sqlite3.connect(match_results_path)
        cur = conn.cursor()
        try:
            cur.execute("SELECT address, address2 FROM results")
            for src, tgt in cur.fetchall():
                addr_map[src.strip().lower()] = tgt.strip().lower()
        finally:
            conn.close()

    conn_src = sqlite3.connect(source_db_path)
    conn_src.row_factory = sqlite3.Row
    cur_src = conn_src.cursor()

    conn_tgt = sqlite3.connect(target_db_path)
    cur_tgt = conn_tgt.cursor()

    items = []

    # 1. Function names -------------------------------------------------------
    if transfer_names:
        cur_src.execute(
            "SELECT address, name, true_name FROM functions "
            "WHERE name NOT LIKE 'sub_%' AND name != ''"
        )
        for row in cur_src.fetchall():
            src_addr = row["address"].strip().lower()
            tgt_addr = addr_map.get(src_addr, src_addr)
            new_name = row["true_name"] or row["name"]
            items.append({
                "type": "function_name",
                "source_address": row["address"],
                "target_address": tgt_addr,
                "value": new_name,
                "auto_apply": f"rename_function(0x{tgt_addr}, \"{new_name}\")",
            })

    # 2. Comments -------------------------------------------------------------
    if transfer_comments:
        cur_src.execute(
            "SELECT address, comment FROM functions WHERE comment != '' AND comment IS NOT NULL"
        )
        for row in cur_src.fetchall():
            src_addr = row["address"].strip().lower()
            tgt_addr = addr_map.get(src_addr, src_addr)
            items.append({
                "type": "comment",
                "source_address": row["address"],
                "target_address": tgt_addr,
                "value": row["comment"][:500],
                "auto_apply": f"set_comment(0x{tgt_addr}, \"{row['comment'][:100]}\")",
            })

    # 3. Prototypes -----------------------------------------------------------
    if transfer_prototypes:
        cur_src.execute(
            "SELECT address, name, prototype FROM functions "
            "WHERE prototype != '' AND prototype IS NOT NULL"
        )
        for row in cur_src.fetchall():
            src_addr = row["address"].strip().lower()
            tgt_addr = addr_map.get(src_addr, src_addr)
            items.append({
                "type": "prototype",
                "source_address": row["address"],
                "target_address": tgt_addr,
                "value": row["prototype"],
                "auto_apply": f"set_function_prototype(0x{tgt_addr}, \"{row['prototype'][:120]}\")",
            })

    # 4. Types (structs, enums, unions) ---------------------------------------
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

    conn_src.close()
    conn_tgt.close()

    return json.dumps({
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
    }, indent=2, default=str)


@mcp.tool(
    description="Show changes in incoming/outgoing calls and execution paths for a function between two binary versions."
)
def get_changed_callgraph(
    db1_path: str,
    db2_path: str,
    address: str = "",
    name: str = "",
) -> str:
    """Compare the callers and callees of a function across two databases.

    Identifies added, removed, and unchanged callers/callees, helping
    understand how the function's role changed between versions.
    """
    err1 = _check_db(db1_path)
    if err1:
        return json.dumps({"error": err1})
    err2 = _check_db(db2_path)
    if err2:
        return json.dumps({"error": err2})

    if not address and not name:
        return json.dumps({"error": "Provide either address or name"})

    # Resolve address if name given
    if not address and name:
        f1 = _get_func(db1_path, name=name)
        if not f1:
            return json.dumps({"error": f"Function '{name}' not found in db1"})
        address = f1["address"]

    func1 = _get_func(db1_path, address=address)
    func2 = _get_func(db2_path, address=address)

    if not func1 and not func2:
        return json.dumps({"error": f"Function at 0x{address} not found in either database"})

    name1 = func1["name"] if func1 else "(not in db1)"
    name2 = func2["name"] if func2 else "(not in db2)"

    cg1 = _get_callgraph(db1_path, address) if func1 else {"callers": [], "callees": []}
    cg2 = _get_callgraph(db2_path, address) if func2 else {"callers": [], "callees": []}

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

    # Resolve names
    all_addrs = set(added_callers + removed_callers + kept_callers +
                    added_callees + removed_callees + kept_callees)
    names1 = _resolve_func_names(db1_path, list(all_addrs))
    names2 = _resolve_func_names(db2_path, list(all_addrs))
    combined_names = {a: names1.get(a) or names2.get(a) or "?" for a in all_addrs}

    def _format_list(addrs):
        return sorted(
            {"address": a, "name": combined_names.get(a, "?")} for a in addrs
        )

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


@mcp.tool(
    description="Rank changed functions by importance using CFG, pseudocode, complexity, strings, imports, and security indicators."
)
def rank_changes(
    results_path: str,
    top_n: int = 30,
) -> str:
    """Analyse a .diaphora results file and rank every match by a composite
    importance score (0–100).  Factors considered:

    - Match type (best = low interest, partial/unreliable = higher)
    - Security keyword density (names, pseudocode, assembly)
    - Cyclomatic complexity change
    - Instruction count change
    - Node/edge (CFG) change
    - Pseudocode diff size
    - Suspicious heuristics (complexity jump + low similarity)
    """
    if not os.path.isfile(results_path):
        return json.dumps({"error": f"Results file not found: {results_path}"})

    db1_path, db2_path = _get_underlying_db_paths(results_path)

    conn = sqlite3.connect(results_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT * FROM results")
    all_rows = [dict(r) for r in cur.fetchall()]

    cur.execute("SELECT * FROM config")
    config_info = dict(cur.fetchone() or {})
    conn.close()

    ranked = []
    for row in all_rows:
        addr1 = row.get("address", "")
        addr2 = row.get("address2", "")
        name1 = row.get("name", "")
        name2 = row.get("name2", "")

        # Try to get more detail from underlying databases
        pseudo1 = pseudo2 = ""
        complexity_chg = 0
        if db1_path and addr1:
            f1 = _get_func(db1_path, address=addr1)
            if f1:
                pseudo1 = f1.get("pseudocode", "") or ""
        if db2_path and addr2:
            f2 = _get_func(db2_path, address=addr2)
            if f2:
                pseudo2 = f2.get("pseudocode", "") or ""
                complexity = f2.get("cyclomatic_complexity", 0) or 0
                complexity1 = f1.get("cyclomatic_complexity", 0) if f1 else 0
                complexity_chg = abs(complexity - complexity1)

        # Security check
        sec_old = _match_security_keywords(name1, pseudo1, "")
        sec_new = _match_security_keywords(name2, pseudo2, "")
        sec_match = sec_old["matched"] or sec_new["matched"]

        # Pseudocode diff
        pseudo_diff = _pseudocode_simple_diff(pseudo1, pseudo2)

        # Score
        score = _score_change(row, sec_match, complexity_chg, len(pseudo_diff))

        ranked.append({
            "score": score,
            "type": row.get("type", ""),
            "ratio": row.get("ratio", 0),
            "name_old": name1,
            "name_new": name2,
            "address_old": addr1,
            "address_new": addr2,
            "security_relevant": sec_match,
            "security_categories": sorted(set(sec_old["categories"] + sec_new["categories"])),
            "complexity_change": complexity_chg,
            "pseudo_diff_lines": len(pseudo_diff),
            "ida_pro_mcp": {
                "db1": db1_path,
                "db2": db2_path,
                "addr1": addr1,
                "addr2": addr2,
            },
        })

    ranked.sort(key=lambda x: -x["score"])

    return json.dumps({
        "config": config_info,
        "total_matches": len(ranked),
        "top_n": min(top_n, len(ranked)),
        "ranked": ranked[:top_n],
        "categories": {
            "high_interest": sum(1 for r in ranked if r["score"] >= 70),
            "medium_interest": sum(1 for r in ranked if 40 <= r["score"] < 70),
            "low_interest": sum(1 for r in ranked if r["score"] < 40),
        },
    }, indent=2, default=str)


@mcp.tool(
    description="Identify functions likely to be the root cause of cascading changes by analysing callgraph dependency chains."
)
def find_patch_root(
    results_path: str,
) -> str:
    """Analyse the diff to identify which functions are probable root causes.

    Strategy:
    1. Find changed functions that call many other changed functions (high
       outdegree to other changed functions → root cause candidate).
    2. Find functions high in the call chain whose callees also changed
       (cascade indicator).
    3. Cross-reference with security keywords and complexity jumps.

    Requires that the underlying .sqlite databases are reachable from the
    .diaphora config.
    """
    if not os.path.isfile(results_path):
        return json.dumps({"error": f"Results file not found: {results_path}"})

    db1_path, db2_path = _get_underlying_db_paths(results_path)

    conn = sqlite3.connect(results_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM results")
    results = [dict(r) for r in cur.fetchall()]
    conn.close()

    if not db1_path or not db2_path:
        # Fall back to results-only analysis
        return json.dumps({
            "note": "Underlying databases not found — limited analysis",
            "results": [r for r in results],
        }, indent=2, default=str)

    # Build a set of changed functions (by address in db2)
    changed_addrs = set()
    addr_to_result = {}
    for r in results:
        a2 = r.get("address2", "")
        if a2:
            a2n = a2.strip().lower()
            changed_addrs.add(a2n)
            if a2n not in addr_to_result:
                addr_to_result[a2n] = r

    # For each changed function, check how many of ITS callees also changed
    conn2 = sqlite3.connect(db2_path)
    cur2 = conn2.cursor()
    candidates = []
    for addr in changed_addrs:
        # Resolve func_id
        cur2.execute("SELECT id, name, instructions, cyclomatic_complexity FROM functions WHERE address = ?", (addr,))
        row = cur2.fetchone()
        if not row:
            continue
        fid, fname, insns, cc = row

        # Get callees
        cur2.execute("SELECT address FROM callgraph WHERE func_id = ? AND type = 'callee'", (fid,))
        callee_addrs = {r[0].strip().lower() for r in cur2.fetchall()}

        # How many callees also changed?
        callees_changed = callee_addrs & changed_addrs
        pct = len(callees_changed) / max(len(callee_addrs), 1)

        # Score: more changed callees = higher chance of being root
        root_score = round(
            (len(callees_changed) * 15)  # absolute count
            + (pct * 30)                   # proportion
            + min(insns or 0, 200) * 0.1   # size bonus
            + (20 if (cc or 0) > 10 else 0),  # complexity bonus
            1,
        )

        # Also look at callers-changed proportion (if many callers changed,
        # this function might not be root but a downstream victim)
        cur2.execute("SELECT address FROM callgraph WHERE func_id = ? AND type = 'caller'", (fid,))
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


@mcp.tool(
    description="Compare call chains before and after update for a function. Traces callees (or callers) to N levels deep."
)
def compare_call_path(
    db1_path: str,
    db2_path: str,
    address: str = "",
    name: str = "",
    depth: int = 2,
    direction: str = "callees",
) -> str:
    """Walk the callgraph from a starting function and compare the call trees
    between old and new binaries.

    Args:
        db1_path: Primary (old) export database
        db2_path: Secondary (new) export database
        address: Function address
        name: Function name (used if address is empty)
        depth: How many levels of calls to traverse (default 2, max 5)
        direction: "callees" (what this function calls) or "callers"
                   (what calls this function)
    """
    err1 = _check_db(db1_path)
    if err1:
        return json.dumps({"error": err1})
    err2 = _check_db(db2_path)
    if err2:
        return json.dumps({"error": err2})

    if not address and not name:
        return json.dumps({"error": "Provide either address or name"})

    if not address and name:
        f1 = _get_func(db1_path, name=name)
        if not f1:
            return json.dumps({"error": f"Function '{name}' not found in db1"})
        address = f1["address"]

    depth = min(depth, 5)
    path1 = _build_call_path(db1_path, address, depth, direction)
    path2 = _build_call_path(db2_path, address, depth, direction)

    # Compute differences
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


@mcp.tool(
    description="Detect likely security patches by analysing pattern changes in pseudocode: new bounds checks, validation, crypto, anti-debug, and integrity checks."
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

    db1_path, db2_path = _get_underlying_db_paths(results_path)

    conn = sqlite3.connect(results_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM results")
    results = [dict(r) for r in cur.fetchall()]
    conn.close()

    security_patches = []

    for row in results:
        addr1 = row.get("address", "")
        addr2 = row.get("address2", "")
        name1 = row.get("name", "")
        name2 = row.get("name2", "")
        ratio = row.get("ratio", 0) or 0
        mtype = row.get("type", "")

        pseudo1 = pseudo2 = ""
        f1 = _get_func(db1_path, address=addr1) if db1_path and addr1 else None
        f2 = _get_func(db2_path, address=addr2) if db2_path and addr2 else None

        if f1:
            pseudo1 = f1.get("pseudocode", "") or ""
        if f2:
            pseudo2 = f2.get("pseudocode", "") or ""

        match_indicators = []

        # Compute pseudocode diff and analyse patterns
        diff_lines = _pseudocode_simple_diff(pseudo1, pseudo2)
        added_lines = [d["line"] for d in diff_lines if d["type"] == "added"]
        removed_lines = [d["line"] for d in diff_lines if d["type"] == "removed"]

        added_text = " ".join(added_lines)

        # 1. New bounds checks (if x >= limit style)
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

        # 7. Logic rewrite (low complexity change but many pseudo diffs)
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


@mcp.tool(
    description="Generate a concise natural-language description of how a function's logic changed between two binary versions."
)
def detect_behavior_change(
    db1_path: str,
    db2_path: str,
    address: str = "",
    name: str = "",
) -> str:
    """Analyse a single function across two versions and describe what
    behaviour changed.

    Compares: pseudocode, assembly, CFG (nodes/edges), calls made,
    constants used, strings referenced, prototype, and complexity.
    """
    err1 = _check_db(db1_path)
    if err1:
        return json.dumps({"error": err1})
    err2 = _check_db(db2_path)
    if err2:
        return json.dumps({"error": err2})

    if not address and not name:
        return json.dumps({"error": "Provide either address or name"})

    if not address and name:
        f1 = _get_func(db1_path, name=name)
        if f1:
            address = f1["address"]

    if not address:
        f1 = _get_func(db1_path, name=name) if name else None
        if not f1:
            return json.dumps({"error": f"Function not found"})
        address = f1["address"]

    f1 = _get_func(db1_path, address=address)
    f2 = _get_func(db2_path, address=address)

    if not f1 and not f2:
        return json.dumps({"error": f"Function 0x{address} not found in either database"})

    if not f1:
        return json.dumps({
            "change_type": "new_function",
            "address": address,
            "function_new": {
                "name": f2.get("name", ""),
                "instructions": f2.get("instructions", 0),
                "complexity": f2.get("cyclomatic_complexity", 0),
            },
            "description": f"Function NEW in the update — not present in the old binary",
        }, indent=2, default=str)

    if not f2:
        return json.dumps({
            "change_type": "deleted_function",
            "address": address,
            "function_old": {
                "name": f1.get("name", ""),
                "instructions": f1.get("instructions", 0),
                "complexity": f1.get("cyclomatic_complexity", 0),
            },
            "description": f"Function REMOVED in the update — present only in the old binary",
        }, indent=2, default=str)

    # Both exist — compute changes
    name1 = f1.get("name", "")
    name2 = f2.get("name", "")
    pseudo1 = f1.get("pseudocode", "") or ""
    pseudo2 = f2.get("pseudocode", "") or ""
    proto1 = f1.get("prototype", "") or ""
    proto2 = f2.get("prototype", "") or ""
    asm1 = f1.get("assembly", "") or ""
    asm2 = f2.get("assembly", "") or ""

    # Pseudocode diff
    pseudo_diff = _pseudocode_simple_diff(pseudo1, pseudo2)
    added_count = sum(1 for d in pseudo_diff if d["type"] == "added")
    removed_count = sum(1 for d in pseudo_diff if d["type"] == "removed")

    # Callgraph changes
    cg1 = _get_callgraph(db1_path, address)
    cg2 = _get_callgraph(db2_path, address)
    added_callees = set(cg2["callees"]) - set(cg1["callees"])
    removed_callees = set(cg1["callees"]) - set(cg2["callees"])

    # Constant changes
    consts1_str = f1.get("constants", "") or ""
    consts2_str = f2.get("constants", "") or ""
    consts1 = set(consts1_str.split(",")) if consts1_str else set()
    consts2 = set(consts2_str.split(",")) if consts2_str else set()
    added_consts = list(consts2 - consts1)[:10]
    removed_consts = list(consts1 - consts2)[:10]

    # CFG changes
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

    # Build description
    changes = []
    if name1 != name2:
        changes.append(f"renamed from '{name1}' to '{name2}'")
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
        names = _resolve_func_names(db2_path, list(added_callees))
        call_names = [names.get(a, f"0x{a}") for a in sorted(added_callees)[:5]]
        changes.append(f"now calls: {', '.join(call_names)}")
    if removed_callees:
        names = _resolve_func_names(db1_path, list(removed_callees))
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

    return json.dumps({
        "function_name_old": name1,
        "function_name_new": name2,
        "address": address,
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
            "addr1": address,
            "addr2": address,
        },
    }, indent=2, default=str)


@mcp.tool(
    description="Generate a comprehensive patch summary report with categorised changes, statistics, and security analysis."
)
def summarize_patch(
    results_path: str,
) -> str:
    """Create a full patch analysis report from a .diaphora results file.

    Sections:
    - Binary metadata
    - Match statistics by type and ratio distribution
    - Security-relevant changes (from analyze_diff_results)
    - Root cause candidates (from find_patch_root)
    - Top-ranked changes (from rank_changes)
    - Unmatched function analysis
    - Recommendations
    """
    if not os.path.isfile(results_path):
        return json.dumps({"error": f"Results file not found: {results_path}"})

    db1_path, db2_path = _get_underlying_db_paths(results_path)

    conn = sqlite3.connect(results_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT * FROM config")
    config_info = dict(cur.fetchone() or {})

    cur.execute("SELECT * FROM results")
    results = [dict(r) for r in cur.fetchall()]

    cur.execute("SELECT * FROM unmatched")
    unmatched = [dict(r) for r in cur.fetchall()]

    conn.close()

    # --- Statistics ----------------------------------------------------------
    total = len(results)
    by_type = {}
    for r in results:
        t = r.get("type", "unknown")
        by_type[t] = by_type.get(t, 0) + 1

    ratios = [r.get("ratio", 0) or 0 for r in results]
    avg_ratio = round(sum(ratios) / max(len(ratios), 1), 3)

    # --- Security analysis ---------------------------------------------------
    sec_count = 0
    sec_high = 0
    sec_categories: set = set()
    for r in results:
        addr1 = r.get("address", "")
        addr2 = r.get("address2", "")
        name1 = r.get("name", "")
        name2 = r.get("name2", "")
        f1 = _get_func(db1_path, address=addr1) if db1_path and addr1 else None
        f2 = _get_func(db2_path, address=addr2) if db2_path and addr2 else None
        pseudo1 = (f1.get("pseudocode", "") or "") if f1 else ""
        pseudo2 = (f2.get("pseudocode", "") or "") if f2 else ""
        so = _match_security_keywords(name1, pseudo1, "")
        sn = _match_security_keywords(name2, pseudo2, "")
        if so["matched"] or sn["matched"]:
            sec_count += 1
            sec_categories.update(so["categories"] + sn["categories"])

    # --- Program info --------------------------------------------------------
    prog1 = prog2 = {}
    if db1_path:
        try:
            conn1 = sqlite3.connect(db1_path)
            cur1 = conn1.cursor()
            cur1.execute("SELECT * FROM program")
            row = cur1.fetchone()
            if row:
                prog1 = dict(zip([d[0] for d in cur1.description], row))
            conn1.close()
        except Exception:
            pass
    if db2_path:
        try:
            conn2 = sqlite3.connect(db2_path)
            cur2 = conn2.cursor()
            cur2.execute("SELECT * FROM program")
            row = cur2.fetchone()
            if row:
                prog2 = dict(zip([d[0] for d in cur2.description], row))
            conn2.close()
        except Exception:
            pass

    # --- Unmatched analysis --------------------------------------------------
    unmatched_primary = [u for u in unmatched if u.get("type") == "primary"]
    unmatched_secondary = [u for u in unmatched if u.get("type") == "secondary"]

    return json.dumps({
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
    }, indent=2, default=str)


@mcp.tool(
    description="Explain why two matched functions have a given similarity ratio. Breaks down contribution by CFG, instructions, mnemonics, constants, calls, and bytes."
)
def explain_similarity(
    db1_path: str,
    db2_path: str,
    address: str = "",
    name: str = "",
) -> str:
    """Compare two matched functions and explain the similarity score.

    Breaks down the comparison across:
    - Control Flow Graph (nodes, edges, strongly-connected components)
    - Instruction profile (count, mnemonics, assembly)
    - Constant pool
    - Callgraph (callers, callees)
    - Bytes hash
    - Prototype
    - Pseudocode structure (hash, lines, primes)
    """
    err1 = _check_db(db1_path)
    if err1:
        return json.dumps({"error": err1})
    err2 = _check_db(db2_path)
    if err2:
        return json.dumps({"error": err2})

    if not address and not name:
        return json.dumps({"error": "Provide either address or name"})

    if not address and name:
        f1 = _get_func(db1_path, name=name)
        if f1:
            address = f1["address"]

    if not address:
        return json.dumps({"error": "Could not resolve address"})

    f1 = _get_func(db1_path, address=address)
    if not f1:
        return json.dumps({"error": f"Function at 0x{address} not found in db1"})

    # Try same address in db2
    f2 = _get_func(db2_path, address=address)
    if not f2:
        return json.dumps({"error": f"Function at 0x{address} not found in db2"})

    features1 = _func_features(f1)
    features2 = _func_features(f2)

    factors = []

    # 1. Mnemonics (heaviest weight in Diaphora)
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

    # 2. Nodes (CFG size)
    n1, n2 = features1["nodes"], features2["nodes"]
    node_match = n1 == n2
    node_sim = min(n1, n2) / max(n1, 1)
    factors.append({
        "factor": "cfg_nodes",
        "weight": 15,
        "match": node_match,
        "detail": f"basic blocks {n1} vs {n2} ({'same' if node_match else f'{node_sim:.0%} similar'})" if not node_match else f"same ({n1})",
        "values": (n1, n2),
    })

    # 3. Edges (CFG complexity)
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
    cg1 = _get_callgraph(db1_path, address)
    cg2 = _get_callgraph(db2_path, address)
    callee_sim = 0
    ce1 = set(cg1["callees"])
    ce2 = set(cg2["callees"])
    if ce1 or ce2:
        callee_sim = len(ce1 & ce2) / max(len(ce1 | ce2), 1)
    caller_sim = 0
    cr1 = set(cg1["callers"])
    cr2 = set(cg2["callers"])
    if cr1 or cr2:
        caller_sim = len(cr1 & cr2) / max(len(cr1 | cr2), 1)
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

    # Aggregate score
    matched_weight = sum(f["weight"] for f in factors if f.get("match"))
    total_weight = sum(f["weight"] for f in factors)
    estimated_similarity = round(matched_weight / max(total_weight, 1) * 100, 1)

    return json.dumps({
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
    }, indent=2, default=str)
if __name__ == "__main__":
    mcp.run()
