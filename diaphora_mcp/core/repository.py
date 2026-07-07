"""
Diaphora MCP — caching repository layer and in-memory call graph engine.

Provides LRU-cached access to function metadata, pseudocode, and callgraph,
plus a preloaded in-memory adjacency list for O(1) BFS traversals.
"""
import sqlite3
from functools import lru_cache
from typing import Dict, List, Optional, Any, Tuple

from ..utils.sqlite import norm_addr, _detect_decimal
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
        use_decimal = _detect_decimal(conn)
        addr = norm_addr(address, False)
        if use_decimal:
            try:
                addr = str(int(addr, 16))
            except ValueError:
                pass
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            "SELECT address, name, nodes, edges, instructions, "
            "cyclomatic_complexity, prototype, bytes_hash "
            "FROM functions WHERE address = ?",
            (addr,),
        )
        row = cur.fetchone()
        return dict(row) if row else None

    # -- Pseudocode (separate cache so metadata stays lightweight) ----------

    @lru_cache(maxsize=500)
    def get_pseudocode(self, address: str) -> str:
        """Return the pseudocode blob for *address* (cached)."""
        conn = get_connection(self.db_path)
        use_decimal = _detect_decimal(conn)
        addr = norm_addr(address, False)
        if use_decimal:
            try:
                addr = str(int(addr, 16))
            except ValueError:
                pass
        cur = conn.cursor()
        cur.execute(
            "SELECT pseudocode FROM functions WHERE address = ?", (addr,)
        )
        row = cur.fetchone()
        return row[0] if row and row[0] else ""

    # -- Callgraph (cached) -------------------------------------------------

    @lru_cache(maxsize=500)
    def get_cached_callgraph(self, address: str) -> Dict[str, List[str]]:
        """Return {"callers": [...], "callees": [...]} for *address*."""
        conn = get_connection(self.db_path)
        use_decimal = _detect_decimal(conn)
        addr = norm_addr(address, False)
        if use_decimal:
            try:
                addr = str(int(addr, 16))
            except ValueError:
                pass
        cur = conn.cursor()
        cur.execute("SELECT id FROM functions WHERE address = ?", (addr,))
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
    """Preloaded hash maps for instant lookups by address, name, or hash.

    Indexes are built lazily on first access — constructing the object is O(1).
    """

    __slots__ = (
        "addr_to_metadata", "addr_to_name", "db_path",
        "hash_to_addr", "name_to_addr", "_loaded",
    )

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._loaded = False
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
        """Build in-memory lookup indexes from the functions table."""
        conn = get_connection(self.db_path)
        use_decimal = _detect_decimal(conn)
        cur = conn.cursor()
        cur.execute(
            "SELECT address, name, bytes_hash, "
            "nodes, edges, instructions, cyclomatic_complexity, prototype "
            "FROM functions"
        )
        for row in cur.fetchall():
            addr, name, bhash = row[0], row[1], row[2]
            n_addr = norm_addr(addr, use_decimal)
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
        return self.addr_to_name.get(norm_addr(address, False))

    def get_address(self, name: str) -> Optional[str]:
        self._ensure_loaded()
        return self.name_to_addr.get(name)

    def get_by_hash(self, bytes_hash: str) -> Optional[str]:
        self._ensure_loaded()
        return self.hash_to_addr.get(bytes_hash)

    def get_metadata(self, address: str) -> Optional[Dict[str, Any]]:
        self._ensure_loaded()
        n_addr = norm_addr(address, False)
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


# ---------------------------------------------------------------------------
# CallGraphEngine — in-memory adjacency list for O(1) graph traversals
# ---------------------------------------------------------------------------

class CallGraphEngine:
    """Preloaded directed callgraph stored as adjacency lists.

    Graph is loaded lazily on first BFS traversal — constructing the object
    is O(1) and hits no database.
    """

    __slots__ = ("adjacency", "callers", "db_path", "_loaded")

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._loaded = False
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
        """Load all edges from the callgraph table into memory."""
        conn = get_connection(self.db_path)
        use_decimal = _detect_decimal(conn)
        cur = conn.cursor()
        # Map function IDs to their normalised addresses
        cur.execute("SELECT id, address FROM functions")
        id_to_addr = {
            row[0]: norm_addr(row[1], use_decimal) for row in cur.fetchall()
        }

        cur.execute("SELECT func_id, address, type FROM callgraph")
        for fid, target_addr_str, ctype in cur.fetchall():
            source_addr = id_to_addr.get(fid)
            if not source_addr:
                continue
            target_addr = norm_addr(target_addr_str, use_decimal)

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
        Every step is an O(1) dict lookup.
        """
        self._ensure_loaded()
        visited: set = set()
        result: List[Dict[str, Any]] = []
        queue: List[Tuple[str, int]] = [(norm_addr(start_addr, False), 0)]
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
