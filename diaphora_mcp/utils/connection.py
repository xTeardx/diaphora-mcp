"""
Diaphora MCP — database connection manager with thread-local caching.

Provides long-lived SQLite connections with automatic PRAGMA tuning:
- mmap_size = file size (capped at 2 GB) for faster reads
- cache_size = -256000 (256 MB page cache)

Thread-safe via threading.local() — each thread gets its own connection
per database path, avoiding shared-state issues.
"""

import os
import sqlite3
import threading
from collections import OrderedDict
from contextlib import contextmanager
from typing import Optional

# ---------------------------------------------------------------------------
# Thread-local storage
# ---------------------------------------------------------------------------

_local = threading.local()


def get_connection(db_path: str) -> sqlite3.Connection:
    """Return a cached SQLite connection for *db_path* in the current thread.

    The connection is created on first access, configured with performance
    PRAGMAs, and reused for subsequent calls within the same thread.
    """
    db_path = os.path.abspath(os.path.normpath(db_path))
    if not hasattr(_local, "connections"):
        _local.connections = {}

    cache = _local.connections
    if db_path in cache:
        return cache[db_path]

    conn = sqlite3.connect(db_path, timeout=10, check_same_thread=False)
    _configure_connection(conn, db_path)
    cache[db_path] = conn
    return conn


def _configure_connection(conn: sqlite3.Connection, db_path: str):
    """Apply performance PRAGMAs to a freshly opened connection."""
    file_size = os.path.getsize(db_path)
    # mmap_size = file size, capped at 2 GB
    mmap_size = min(file_size, 2 * 1024 * 1024 * 1024)
    # cache_size = 256 MB (negative = kibibytes)
    cache_size = -256000

    conn.execute(f"PRAGMA mmap_size = {mmap_size}")
    conn.execute(f"PRAGMA cache_size = {cache_size}")

    # NOTE: WAL and synchronous = NORMAL are NOT set here.
    # This server only reads from Diaphora-exported databases.
    # WAL would risk leaving -wal files around, and the default
    # synchronous=FULL (or NORMAL with WAL) is fine for read-only use.


def close_connection(db_path: str):
    """Explicitly close and remove a cached connection."""
    db_path = os.path.abspath(os.path.normpath(db_path))
    if not hasattr(_local, "connections"):
        return
    conn = _local.connections.pop(db_path, None)
    if conn:
        conn.close()


def close_all():
    """Close every cached connection in the current thread."""
    if not hasattr(_local, "connections"):
        return
    for conn in _local.connections.values():
        conn.close()
    _local.connections.clear()


# ---------------------------------------------------------------------------
# Convenience wrappers
# ---------------------------------------------------------------------------

@contextmanager
def using_connection(db_path: str):
    """Context manager yielding a configured connection for *db_path*.

    Usage::

        with using_connection("/path/to/db.sqlite") as conn:
            cur = conn.cursor()
            ...
    """
    conn = get_connection(db_path)
    try:
        yield conn
    finally:
        pass  # connection is cached, not closed


@contextmanager
def using_cursor(db_path: str):
    """Context manager yielding a cursor from the cached connection.

    Usage::

        with using_cursor("/path/to/db.sqlite") as cur:
            cur.execute("SELECT ...")
    """
    conn = get_connection(db_path)
    try:
        yield conn.cursor()
    finally:
        pass


# ---------------------------------------------------------------------------
# DatabaseCacheManager — LRU for in-memory database state
# ---------------------------------------------------------------------------

class DatabaseCacheManager:
    """LRU cache for in-memory database state (IndexedDatabase + CallGraphEngine).

    Holds at most *max_databases* entries (default 2).  When a new database
    is accessed and the cache is full, the least recently used entry is
    evicted — its dicts are cleared so the GC can reclaim the memory.
    """

    __slots__ = ("_cache", "_max")

    def __init__(self, max_databases: int = 2):
        self._max = max_databases
        # db_path -> {"indexed": IndexedDatabase|None, "cg": CallGraphEngine|None}
        self._cache: OrderedDict = OrderedDict()

    def get_indexed(self, db_path: str):
        """Return an IndexedDatabase for *db_path*, creating it if needed."""
        entry = self._get_or_create(db_path)
        return entry["indexed"]

    def get_callgraph(self, db_path: str):
        """Return a CallGraphEngine for *db_path*, creating it if needed."""
        entry = self._get_or_create(db_path)
        return entry["cg"]

    def _get_or_create(self, db_path: str) -> dict:
        """Access or create a cache entry, applying LRU eviction."""
        if db_path in self._cache:
            self._cache.move_to_end(db_path)
            return self._cache[db_path]

        # Evict LRU entry if at capacity
        if len(self._cache) >= self._max:
            self._evict_lru()

        from ..core.repository import IndexedDatabase, CallGraphEngine
        entry = {
            "indexed": IndexedDatabase(db_path),
            "cg": CallGraphEngine(db_path),
        }
        self._cache[db_path] = entry
        return entry

    def _evict_lru(self):
        """Remove the least recently used entry and release its memory."""
        if not self._cache:
            return
        db_path, entry = self._cache.popitem(last=False)  # FIFO = LRU

        # Close the SQLite connection to release file handles
        close_connection(db_path)

        # Clear dicts so the GC can reclaim memory
        indexed = entry.get("indexed")
        if indexed:
            indexed.addr_to_name.clear()
            indexed.name_to_addr.clear()
            indexed.hash_to_addr.clear()
            indexed.addr_to_metadata.clear()

        cg = entry.get("cg")
        if cg:
            cg.adjacency.clear()
            cg.callers.clear()

    def evict(self, db_path: str):
        """Explicitly remove a specific database from the cache."""
        if db_path not in self._cache:
            return
        self._cache.pop(db_path)
        close_connection(db_path)
        # Since the entry is no longer referenced by us, the GC will
        # reclaim it as long as no one else holds a reference.

    def clear(self):
        """Evict all cached entries."""
        while self._cache:
            self._evict_lru()

    @property
    def size(self) -> int:
        return len(self._cache)


# Module-level singleton for the MCP server
_cache_manager = DatabaseCacheManager(max_databases=2)


def get_cache_manager() -> DatabaseCacheManager:
    """Return the module-level DatabaseCacheManager singleton."""
    return _cache_manager
