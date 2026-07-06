# Implementation Plan: diaphora-mcp Performance Optimization

This plan outlines the architecture and step-by-step changes required to transform the `diaphora-mcp` server from a direct SQLite wrapper into a high-performance backend. It is designed to handle very large databases (150k–1M functions) while remaining responsive for LLM agents.

These phases correspond to the requirements in [Problems.md](file:///D:/scripts/AntigravityProjects/diaphora-mcp/Fixes/Problems.md) and [Roadmap.md](file:///D:/scripts/AntigravityProjects/diaphora-mcp/Fixes/Roadmap.md).

---

## Analysis: Current Codebase vs. Fixes/Problems.md

Yes, the problems described in the `Fixes/` directory are highly relevant to our current codebase. Specifically:
1. **Direct SQLite Access**: Every MCP tool directly opens connections and queries SQLite. There is no caching or repository layer, causing redundant I/O.
2. **`SELECT *` Usage**: The code frequently uses `SELECT *` on the `functions` table, which automatically retrieves heavy text blobs (`pseudocode`, `assembly`) even when only basic metadata (like `nodes`, `complexity`) is needed.
3. **Missing Collection Limits**: Many queries (e.g. `SELECT * FROM results`) do not apply a `LIMIT` at the SQL level, loading tens of thousands of rows into Python memory when only a small page is displayed.
4. **Repeated Callgraph Queries**: BFS traversal of callgraphs performs a SQL query for every single node, resulting in $O(N)$ database round-trips.

---

## Proposed Changes

### Phase 1 — Performance Instrumentation (Baseline)

#### [NEW] [metrics.py](file:///D:/scripts/AntigravityProjects/diaphora-mcp/diaphora_mcp/utils/metrics.py)
Create a lightweight instrumentation module to track execution time, SQL query count, and memory/data transfer.

```python
import time
import os
import psutil
from contextlib import contextmanager

class MetricsTracker:
    def __init__(self):
        self.sql_queries = 0
        self.rows_fetched = 0
        self.start_time = 0
        self.elapsed = 0
        self.start_memory = 0
        self.memory_used = 0

    def record_query(self, rows: int = 1):
        self.sql_queries += 1
        self.rows_fetched += rows

@contextmanager
def track_metrics(tool_name: str):
    tracker = MetricsTracker()
    tracker.start_time = time.perf_counter()
    process = psutil.Process(os.getpid())
    tracker.start_memory = process.memory_info().rss
    
    # Store tracker in thread-local storage or context var if needed,
    # or just yield it for manual invocation.
    yield tracker
    
    tracker.elapsed = time.perf_counter() - tracker.start_time
    tracker.memory_used = process.memory_info().rss - tracker.start_memory
    print(
        f"[METRICS] Tool: {tool_name} | "
        f"Time: {tracker.elapsed:.3f}s | "
        f"SQL Queries: {tracker.sql_queries} | "
        f"Rows: {tracker.rows_fetched} | "
        f"Memory Delta: {tracker.memory_used / 1024 / 1024:.2f} MB"
    )
```

---

### Phase 2 — SQL Cleanup (SELECT * & LIMIT)

Modify database queries to explicitly select columns and enforce defensive limits.

#### [MODIFY] [sqlite.py](file:///D:/scripts/AntigravityProjects/diaphora-mcp/diaphora_mcp/utils/sqlite.py)

1. Modify `get_funcs_batch` to avoid `SELECT *`. The caller `ranking.py` only needs `nodes`, `cyclomatic_complexity`, and `pseudocode`.
   * **Old SQL**: `SELECT * FROM functions WHERE address IN ({placeholders})`
   * **New SQL**: `SELECT address, name, nodes, edges, cyclomatic_complexity, pseudocode, assembly, prototype FROM functions WHERE address IN ({placeholders})`

2. Modify `get_func` to select only required columns unless full data is requested:
   * **New SQL**: `SELECT address, name, nodes, edges, cyclomatic_complexity, pseudocode, assembly, prototype FROM functions WHERE address = ?`

#### [MODIFY] [diff.py](file:///D:/scripts/AntigravityProjects/diaphora-mcp/diaphora_mcp/core/diff.py)

1. Enforce query-level `LIMIT` in `read_results`.
   * **Old SQL**: `SELECT * FROM results WHERE type IN ({placeholders}) ORDER BY ratio DESC`
   * **New SQL**: `SELECT address, name, address2, name2, ratio, type FROM results WHERE type IN ({placeholders}) ORDER BY ratio DESC LIMIT ?` (pass the `limit` argument directly to SQLite instead of slicing the python list).

---

### Phase 3 — Repository Layer & LRU Caching

#### [NEW] [repository.py](file:///D:/scripts/AntigravityProjects/diaphora-mcp/diaphora_mcp/core/repository.py)
Introduce a caching data access layer.

```python
import sqlite3
from functools import lru_cache
from typing import Dict, Any, List, Optional
from ..utils.sqlite import norm_addr

class DatabaseRepository:
    def __init__(self, db_path: str):
        self.db_path = db_path

    @lru_cache(maxsize=1000)
    def get_function_metadata(self, address: str) -> Optional[Dict[str, Any]]:
        """Cache function metadata queries (excludes heavy pseudocode/assembly)."""
        addr = norm_addr(address)
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(
                "SELECT address, name, nodes, edges, instructions, cyclomatic_complexity "
                "FROM functions WHERE address = ?", (addr,)
            )
            row = cur.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    @lru_cache(maxsize=500)
    def get_pseudocode(self, address: str) -> str:
        """Cache pseudocode requests separately to keep metadata cache lightweight."""
        addr = norm_addr(address)
        conn = sqlite3.connect(self.db_path)
        try:
            cur = conn.cursor()
            cur.execute("SELECT pseudocode FROM functions WHERE address = ?", (addr,))
            row = cur.fetchone()
            return row[0] if row and row[0] else ""
        finally:
            conn.close()

    @lru_cache(maxsize=200)
    def get_cached_callgraph(self, address: str) -> Dict[str, List[str]]:
        """Cache callers and callees for a function."""
        addr = norm_addr(address)
        conn = sqlite3.connect(self.db_path)
        try:
            cur = conn.cursor()
            cur.execute("SELECT id FROM functions WHERE address = ?", (addr,))
            row = cur.fetchone()
            if not row:
                return {"callers": [], "callees": []}
            fid = row[0]
            
            callers = []
            callees = []
            cur.execute("SELECT address, type FROM callgraph WHERE func_id = ?", (fid,))
            for addr_str, ctype in cur.fetchall():
                if ctype == "caller":
                    callers.append(addr_str)
                else:
                    callees.append(addr_str)
            return {"callers": callers, "callees": callees}
        finally:
            conn.close()
```

---

### Phase 4 — In-Memory Indexes & Preloading (Warm-up)

On database initialization, build lightweight in-memory hash maps of all function addresses, names, and hashes to support instant $O(1)$ lookups.

#### [MODIFY] [repository.py](file:///D:/scripts/AntigravityProjects/diaphora-mcp/diaphora_mcp/core/repository.py)

Add initialization indexes:

```python
class IndexedDatabase:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.addr_to_name: Dict[str, str] = {}
        self.name_to_addr: Dict[str, str] = {}
        self.hash_to_addr: Dict[str, str] = {}
        self.preload_indexes()

    def preload_indexes(self):
        """Build instant in-memory lookup indexes for metadata columns."""
        conn = sqlite3.connect(self.db_path)
        try:
            cur = conn.cursor()
            # Fast index query: avoids loading large text blocks
            cur.execute("SELECT address, name, bytes_hash FROM functions")
            for addr, name, bhash in cur.fetchall():
                n_addr = norm_addr(addr)
                if name:
                    self.name_to_addr[name] = n_addr
                    self.addr_to_name[n_addr] = name
                if bhash:
                    self.hash_to_addr[bhash] = n_addr
        finally:
            conn.close()
```

---

### Phase 5 — In-Memory Call Graph Engine

Rather than querying the `callgraph` table sequentially during BFS, load the entire callgraph relationships into an adjacency list in memory on startup.

#### [MODIFY] [repository.py](file:///D:/scripts/AntigravityProjects/diaphora-mcp/diaphora_mcp/core/repository.py)

Add the callgraph builder and traversal helpers:

```python
class CallGraphEngine:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.adjacency_list: Dict[str, List[str]] = {} # parent -> [children]
        self.caller_list: Dict[str, List[str]] = {}    # child -> [parents]
        self.load_graph()

    def load_graph(self):
        """Loads all edges from database to build the in-memory graph."""
        conn = sqlite3.connect(self.db_path)
        try:
            cur = conn.cursor()
            # Get function IDs to address mapping
            cur.execute("SELECT id, address FROM functions")
            id_to_addr = {row[0]: norm_addr(row[1]) for row in cur.fetchall()}
            
            cur.execute("SELECT func_id, address, type FROM callgraph")
            for fid, target_addr, ctype in cur.fetchall():
                source_addr = id_to_addr.get(fid)
                if not source_addr:
                    continue
                target_addr = norm_addr(target_addr)
                
                if ctype == "caller":
                    # target_addr is the caller, source_addr is the callee
                    self.caller_list.setdefault(source_addr, []).append(target_addr)
                    self.adjacency_list.setdefault(target_addr, []).append(source_addr)
                else:
                    # target_addr is the callee, source_addr is the caller
                    self.adjacency_list.setdefault(source_addr, []).append(target_addr)
                    self.caller_list.setdefault(target_addr, []).append(source_addr)
        finally:
            conn.close()

    def bfs_traverse(self, start_addr: str, depth: int, direction: str = "callees") -> List[Dict[str, Any]]:
        """Traverse the in-memory graph with O(1) step operations."""
        visited = set()
        result = []
        queue = [(norm_addr(start_addr), 0)]
        graph = self.adjacency_list if direction == "callees" else self.caller_list

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
                "targets": targets[:20] # Limit response payload size
            })

            for t in targets[:50]:
                queue.append((t, level + 1))
        return result
```

---

## Verification Plan

### Automated Benchmarks
1. Write a test script in `D:\scripts\AntigravityProjects\diaphora-mcp\Fixes\benchmark.py` that opens a test SQLite database and runs:
   * 100 random function metadata queries.
   * 10 distinct BFS callgraph traversals (up to 3 levels deep).
2. Measure database open time and query execution time.
3. Compare the time taken under direct SQLite queries vs. the newly implemented Caching Repository.

### Manual Verification
1. Verify that `explain_similarity` and `rank_changes` return identical outputs as before, but with decreased latency.
2. Verify that total peak memory usage of the MCP server stays within reasonable bounds (e.g. less than 150MB) even when preloading indexes on a 100k function database.
