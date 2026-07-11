"""
Diaphora MCP — caching repository layer and in-memory call graph engine.

Provides LRU-cached access to function metadata, pseudocode, and callgraph,
plus a preloaded in-memory adjacency list for O(1) BFS traversals.
"""
import sqlite3
from functools import lru_cache
from typing import Dict, List, Optional, Any, Tuple

from ..utils.sqlite import norm_addr, _detect_decimal, get_query_addresses
from ..utils.connection import get_connection


# ---------------------------------------------------------------------------
# DatabaseRepository — LRU-cached data access
# ---------------------------------------------------------------------------

class DatabaseRepository:
    """Thread-safe (per-connection) cached reader for a single .sqlite database.

    Each MCP tool should create its own instance (or share one within a
    single tool call).  LRU caches are bounded so memory stays predictable.
    """

    __slots__ = ("db_path",)

    def __init__(self, db_path: str):
        self.db_path = db_path

    # -- Metadata (lightweight, excludes pseudocode/assembly) ---------------

    @lru_cache(maxsize=2000)
    def get_function_metadata(self, address: str) -> Optional[Dict[str, Any]]:
        """Return a lightweight function row (no pseudocode)."""
        conn = get_connection(self.db_path)
        addrs = get_query_addresses(conn, address)
        placeholders = ",".join("?" for _ in addrs)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            f"SELECT address, name, nodes, edges, instructions, "
            f"cyclomatic_complexity, prototype, bytes_hash "
            f"FROM functions WHERE address IN ({placeholders})",
            addrs,
        )
        row = cur.fetchone()
        return dict(row) if row else None

    # -- Pseudocode (separate cache so metadata stays lightweight) ----------

    @lru_cache(maxsize=500)
    def get_pseudocode(self, address: str) -> str:
        """Return the pseudocode blob for *address* (cached)."""
        conn = get_connection(self.db_path)
        addrs = get_query_addresses(conn, address)
        placeholders = ",".join("?" for _ in addrs)
        cur = conn.cursor()
        cur.execute(
            f"SELECT pseudocode FROM functions WHERE address IN ({placeholders})",
            addrs,
        )
        row = cur.fetchone()
        return row[0] if row and row[0] else ""

    # -- Callgraph (cached) -------------------------------------------------

    @lru_cache(maxsize=500)
    def get_cached_callgraph(self, address: str) -> Dict[str, List[str]]:
        """Return {"callers": [...], "callees": [...]} for *address*."""
        conn = get_connection(self.db_path)
        use_decimal = _detect_decimal(conn)
        addrs = get_query_addresses(use_decimal, address)
        placeholders = ",".join("?" for _ in addrs)
        cur = conn.cursor()
        cur.execute(f"SELECT id FROM functions WHERE address IN ({placeholders})", addrs)
        row = cur.fetchone()
        if not row:
            return {"callers": [], "callees": []}
        fid = row[0]

        callers: List[str] = []
        callees: List[str] = []
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


# ---------------------------------------------------------------------------
# IndexedDatabase — in-memory O(1) lookup indexes
# ---------------------------------------------------------------------------

class IndexedDatabase:
    """Preloaded or lazy hash maps for lookups by address, name, or hash.

    Indexes are built lazily on first access — constructing the object is O(1).
    For large databases (> 50,000 functions), it operates in a lazy/on-demand mode
    to prevent memory bloat.
    """

    __slots__ = (
        "addr_to_metadata", "addr_to_name", "db_path",
        "hash_to_addr", "name_to_addr", "_loaded",
        "use_decimal", "_use_lazy",
    )

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._loaded = False
        self.use_decimal = False
        self._use_lazy = False
        self.addr_to_name: Dict[str, str] = {}
        self.name_to_addr: Dict[str, str] = {}
        self.hash_to_addr: Dict[str, str] = {}
        self.addr_to_metadata: Dict[str, Tuple[int, int, int, int, str]] = {}

    def _ensure_loaded(self):
        """Load indexes on first use if not already loaded."""
        if self._loaded:
            return
        self._preload_indexes()
        self._loaded = True

    def _preload_indexes(self):
        """Build in-memory lookup indexes from the functions table, or run lazily if large."""
        conn = get_connection(self.db_path)
        self.use_decimal = _detect_decimal(conn)
        cur = conn.cursor()

        # Check size first to avoid memory bloat
        cur.execute("SELECT count(*) FROM functions")
        func_count = cur.fetchone()[0]

        if func_count > 50000:
            self._use_lazy = True
            return

        self._use_lazy = False
        cur.execute(
            "SELECT address, name, bytes_hash, "
            "nodes, edges, instructions, cyclomatic_complexity, prototype "
            "FROM functions"
        )
        for row in cur.fetchall():
            addr, name, bhash = row[0], row[1], row[2]
            n_addr = norm_addr(addr, self.use_decimal)
            if name:
                self.name_to_addr[name] = n_addr
                self.addr_to_name[n_addr] = name
            if bhash:
                self.hash_to_addr[bhash] = n_addr
            self.addr_to_metadata[n_addr] = (
                row[3] or 0,  # nodes
                row[4] or 0,  # edges
                row[5] or 0,  # instructions
                row[6] or 0,  # cyclomatic_complexity
                row[7] or "",  # prototype
            )

    def get_name(self, address: str) -> Optional[str]:
        self._ensure_loaded()
        n_addr = norm_addr(address, self.use_decimal)
        if not self._use_lazy:
            return self.addr_to_name.get(n_addr)

        # Lazy query
        conn = get_connection(self.db_path)
        addrs = get_query_addresses(self.use_decimal, address)
        placeholders = ",".join("?" for _ in addrs)
        cur = conn.cursor()
        cur.execute(f"SELECT name FROM functions WHERE address IN ({placeholders}) LIMIT 1", addrs)
        row = cur.fetchone()
        return row[0] if row else None

    def get_address(self, name: str) -> Optional[str]:
        self._ensure_loaded()
        if not self._use_lazy:
            return self.name_to_addr.get(name)

        # Lazy query
        conn = get_connection(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT address FROM functions WHERE name = ? LIMIT 1", (name,))
        row = cur.fetchone()
        return norm_addr(row[0], self.use_decimal) if row else None

    def get_by_hash(self, bytes_hash: str) -> Optional[str]:
        self._ensure_loaded()
        if not self._use_lazy:
            return self.hash_to_addr.get(bytes_hash)

        # Lazy query
        conn = get_connection(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT address FROM functions WHERE bytes_hash = ? LIMIT 1", (bytes_hash,))
        row = cur.fetchone()
        return norm_addr(row[0], self.use_decimal) if row else None

    def get_metadata(self, address: str) -> Optional[Dict[str, Any]]:
        self._ensure_loaded()
        n_addr = norm_addr(address, self.use_decimal)
        if not self._use_lazy:
            meta = self.addr_to_metadata.get(n_addr)
            if meta is None:
                return None
            return {
                "nodes": meta[0],
                "edges": meta[1],
                "instructions": meta[2],
                "cyclomatic_complexity": meta[3],
                "prototype": meta[4],
            }

        # Lazy query
        conn = get_connection(self.db_path)
        addrs = get_query_addresses(self.use_decimal, address)
        placeholders = ",".join("?" for _ in addrs)
        cur = conn.cursor()
        cur.execute(
            f"SELECT nodes, edges, instructions, cyclomatic_complexity, prototype "
            f"FROM functions WHERE address IN ({placeholders}) LIMIT 1",
            addrs,
        )
        row = cur.fetchone()
        if not row:
            return None
        return {
            "nodes": row[0] or 0,
            "edges": row[1] or 0,
            "instructions": row[2] or 0,
            "cyclomatic_complexity": row[3] or 0,
            "prototype": row[4] or "",
        }


# ---------------------------------------------------------------------------
# Lazy-loading Call Graph helper classes
# ---------------------------------------------------------------------------

def _query_callgraph_lazy(db_path: str, use_decimal: bool, addr: str, direction: str) -> List[str]:
    conn = get_connection(db_path)
    cur = conn.cursor()

    addrs = get_query_addresses(use_decimal, addr)
    placeholders = ",".join("?" for _ in addrs)

    # Query 1: relationships defined by the function itself (we first find the function ID)
    cur.execute(f"SELECT id FROM functions WHERE address IN ({placeholders})", addrs)
    fid_row = cur.fetchone()

    results = set()

    if fid_row:
        fid = fid_row[0]
        cur.execute("SELECT address, type FROM callgraph WHERE func_id = ?", (fid,))
        for target_addr_str, ctype in cur.fetchall():
            target_addr = norm_addr(target_addr_str, use_decimal)
            if direction == "callees":
                if ctype != "caller":
                    results.add(target_addr)
            else:
                if ctype == "caller":
                    results.add(target_addr)

    # Query 2: relationships pointing to the function from other functions
    for a in addrs:
        cur.execute(
            "SELECT f.address, c.type FROM callgraph c "
            "JOIN functions f ON c.func_id = f.id "
            "WHERE c.address = ?", (a,)
        )
        for source_addr_str, ctype in cur.fetchall():
            source_addr = norm_addr(source_addr_str, use_decimal)
            if direction == "callees":
                if ctype == "caller":
                    results.add(source_addr)
            else:
                if ctype != "caller":
                    results.add(source_addr)

    return list(results)


class LazyAdjacencyDict:
    def __init__(self, db_path: str, use_decimal: bool):
        self.db_path = db_path
        self.use_decimal = use_decimal
        self._cache: Dict[str, List[str]] = {}

    def get(self, addr: str, default=None) -> List[str]:
        if addr in self._cache:
            return self._cache[addr]
        callees = _query_callgraph_lazy(self.db_path, self.use_decimal, addr, "callees")
        self._cache[addr] = callees
        return callees

    def __getitem__(self, addr: str) -> List[str]:
        return self.get(addr, [])


class LazyCallersDict:
    def __init__(self, db_path: str, use_decimal: bool):
        self.db_path = db_path
        self.use_decimal = use_decimal
        self._cache: Dict[str, List[str]] = {}

    def get(self, addr: str, default=None) -> List[str]:
        if addr in self._cache:
            return self._cache[addr]
        callers = _query_callgraph_lazy(self.db_path, self.use_decimal, addr, "callers")
        self._cache[addr] = callers
        return callers

    def __getitem__(self, addr: str) -> List[str]:
        return self.get(addr, [])


# ---------------------------------------------------------------------------
# CallGraphEngine — in-memory or lazy adjacency list for O(1) graph traversals
# ---------------------------------------------------------------------------

class CallGraphEngine:
    """Preloaded or lazy directed callgraph stored as adjacency lists.

    Graph is loaded lazily on first BFS traversal — constructing the object
    is O(1) and hits no database.
    """

    __slots__ = ("adjacency", "callers", "db_path", "_loaded", "use_decimal", "_use_lazy")

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._loaded = False
        self.use_decimal = False
        self._use_lazy = False
        # parent -> [children]  (a function → its callees)
        self.adjacency: Dict[str, List[str]] = {}
        # child -> [parents]   (a function → its callers)
        self.callers: Dict[str, List[str]] = {}

    def _ensure_loaded(self):
        """Load graph on first use if not already loaded."""
        if self._loaded:
            return
        self._load_graph()
        self._loaded = True

    def _load_graph(self):
        """Load all edges from the callgraph table into memory, or configure lazy loaders if large."""
        conn = get_connection(self.db_path)
        self.use_decimal = _detect_decimal(conn)
        cur = conn.cursor()

        # Check edge count first to avoid memory bloat
        cur.execute("SELECT count(*) FROM callgraph")
        edge_count = cur.fetchone()[0]

        if edge_count > 100000:
            self._use_lazy = True
            # Use custom dictionary wrappers that query SQLite on demand
            self.adjacency = LazyAdjacencyDict(self.db_path, self.use_decimal)
            self.callers = LazyCallersDict(self.db_path, self.use_decimal)
            return

        self._use_lazy = False
        # Map function IDs to their normalised addresses
        cur.execute("SELECT id, address FROM functions")
        id_to_addr = {
            row[0]: norm_addr(row[1], self.use_decimal) for row in cur.fetchall()
        }

        cur.execute("SELECT func_id, address, type FROM callgraph")
        for fid, target_addr_str, ctype in cur.fetchall():
            source_addr = id_to_addr.get(fid)
            if not source_addr:
                continue
            target_addr = norm_addr(target_addr_str, self.use_decimal)

            if ctype == "caller":
                # target_addr is a caller of source_addr
                self.callers.setdefault(source_addr, []).append(target_addr)
                self.adjacency.setdefault(target_addr, []).append(source_addr)
            else:
                # target_addr is a callee of source_addr
                self.adjacency.setdefault(source_addr, []).append(target_addr)
                self.callers.setdefault(target_addr, []).append(source_addr)

    def bfs_traverse(
        self, start_addr: str, depth: int, direction: str = "callees"
    ) -> List[Dict[str, Any]]:
        """Traverse the graph from *start_addr* up to *depth* levels.

        *direction* is ``"callees"`` (down) or ``"callers"`` (up).
        """
        self._ensure_loaded()
        visited: set = set()
        result: List[Dict[str, Any]] = []
        queue: List[Tuple[str, int]] = [(norm_addr(start_addr, self.use_decimal), 0)]
        graph = self.adjacency if direction == "callees" else self.callers

        while queue:
            addr, level = queue.pop(0)
            if addr in visited or level > depth:
                continue
            visited.add(addr)

            targets = graph.get(addr, [])
            result.append({
                "address": addr,
                "level": level,
                "direction": direction,
                "calls": len(targets),
                "targets": targets[:20],
            })

            for t in targets[:50]:
                queue.append((t, level + 1))
        return result
