#!/usr/bin/env python
"""
Diaphora MCP — performance benchmark suite.

Measures time, SQL queries, memory, and connection overhead for all key
operations.  Designed to run before and after optimisations so you can
compare results side-by-side.

Usage:
    python -m diaphora_mcp.scratch.run_benchmark         # runs all benchmarks
    python -m diaphora_mcp.scratch.run_benchmark --save   # saves as before.json
    python -m diaphora_mcp.scratch.run_benchmark --compare before.json  # vs baseline
"""

import argparse
import json
import os
import sys
import time
import sqlite3
from contextlib import contextmanager
from pathlib import Path

# Ensure the package root is importable
_SCRIPT_DIR = Path(__file__).resolve().parent  # .../diaphora_mcp/scratch/
_PROJECT = _SCRIPT_DIR.parent.parent  # .../diaphora-mcp (project root)
sys.path.insert(0, str(_PROJECT))  # project root

import psutil

from diaphora_mcp.utils.sqlite import (
    norm_addr,
    check_db,
    get_funcs_batch,
    resolve_func_names,
    get_func,
)
from diaphora_mcp.utils.connection import get_connection
from diaphora_mcp.core.repository import (
    DatabaseRepository,
    IndexedDatabase,
    CallGraphEngine,
)
from diaphora_mcp.core.graph import build_call_path
from diaphora_mcp.core.analysis import search_export_db, get_function_pseudocode

# ---------------------------------------------------------------------------
# Paths — use the test databases bundled in Fixes/Tests/
# ---------------------------------------------------------------------------
_PROJECT = _PROJECT
_DEFAULT_DB1 = str(_PROJECT / "Fixes" / "Tests" / "sqlite3_aimp.dll.diaphora.sqlite")
_DEFAULT_DB2 = str(_PROJECT / "Fixes" / "Tests" / "sqlite3_python.dll.diaphora.sqlite")

# ---------------------------------------------------------------------------
# Metrics collector
# ---------------------------------------------------------------------------

class QueryCountingCursor:
    """Wraps sqlite3.Cursor to count queries and rows for a single connection."""

    def __init__(self, cur, metrics: "BenchmarkMetrics"):
        self._cur = cur
        self._metrics = metrics

    def execute(self, sql, *args):
        self._metrics.sql_count += 1
        self._cur.execute(sql, *args)
        return self

    def fetchone(self):
        row = self._cur.fetchone()
        self._metrics.rows_fetched += 1 if row else 0
        return row

    def fetchall(self):
        rows = self._cur.fetchall()
        self._metrics.rows_fetched += len(rows)
        return rows

    def __getattr__(self, name):
        return getattr(self._cur, name)


class QueryCountingConnection:
    """Wraps sqlite3.Connection to return QueryCountingCursor."""

    def __init__(self, conn, metrics: "BenchmarkMetrics"):
        self._conn = conn
        self._metrics = metrics

    def cursor(self):
        return QueryCountingCursor(self._conn.cursor(), self._metrics)

    def execute(self, sql, *args):
        self._metrics.sql_count += 1
        self._conn.execute(sql, *args)
        return self

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __getattr__(self, name):
        return getattr(self._conn, name)


class BenchmarkMetrics:
    """Holds counters for a single benchmark run."""

    __slots__ = (
        "name", "elapsed", "sql_count", "rows_fetched",
        "mem_before", "mem_after", "conn_time",
    )

    def __init__(self, name: str):
        self.name = name
        self.elapsed = 0.0
        self.sql_count = 0
        self.rows_fetched = 0
        self.mem_before = 0
        self.mem_after = 0
        self.conn_time = 0.0

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "elapsed_s": round(self.elapsed, 4),
            "sql_queries": self.sql_count,
            "rows_fetched": self.rows_fetched,
            "mem_before_mb": round(self.mem_before / 1048576, 2),
            "mem_after_mb": round(self.mem_after / 1048576, 2),
            "mem_delta_mb": round((self.mem_after - self.mem_before) / 1048576, 2),
            "conn_time_s": round(self.conn_time, 4),
        }


@contextmanager
def measure(name: str, metrics_list: list):
    """Context manager that records a benchmark run into *metrics_list*."""
    m = BenchmarkMetrics(name)
    process = psutil.Process(os.getpid())
    m.mem_before = process.memory_info().rss
    start = time.perf_counter()
    yield m
    m.elapsed = time.perf_counter() - start
    m.mem_after = process.memory_info().rss
    metrics_list.append(m)

    _print_metrics(m)


def _print_metrics(m: BenchmarkMetrics):
    print(
        f"  [{m.name:35s}] {m.elapsed:8.4f}s  "
        f"SQL:{m.sql_count:5d}  Rows:{m.rows_fetched:6d}  "
        f"Mem:{round((m.mem_after - m.mem_before)/1048576, 2):+6.2f}MB  "
        f"Conn:{m.conn_time:.4f}s"
    )


# ---------------------------------------------------------------------------
# Benchmark implementations
# ---------------------------------------------------------------------------

def _track_sqlite(metrics: BenchmarkMetrics) -> QueryCountingConnection:
    """Create a QueryCountingConnection, measuring both connection overhead and queries."""
    t0 = time.perf_counter()
    raw = sqlite3.connect(":memory:")
    raw.close()
    # measure pure connection cost to isolate it
    return None  # we'll track inline


def benchmark_open(db_path: str, metrics_list: list):
    """Measure time and memory to open a database and build in-memory indexes."""
    desc = f"open+index ({os.path.basename(db_path)})"

    with measure(desc, metrics_list) as m:
        # Warm up the connection cache so connect time isn't in the load
        _ = get_connection(db_path)

        # Measure IndexedDatabase lazy load
        indexed = IndexedDatabase(db_path)
        t0 = time.perf_counter()
        indexed._ensure_loaded()
        indexed_elapsed = time.perf_counter() - t0
        m.sql_count += 1  # _preload_indexes runs one SELECT
        m.rows_fetched += len(indexed.addr_to_metadata)

        # Measure CallGraphEngine lazy load
        cg_engine = CallGraphEngine(db_path)
        t0 = time.perf_counter()
        cg_engine._ensure_loaded()
        cg_elapsed = time.perf_counter() - t0
        total_edges = sum(len(v) for v in cg_engine.adjacency)
        m.sql_count += 2  # _load_graph runs 2 SELECTs
        m.rows_fetched += total_edges
        print(
            f"    |-- IndexedDatabase: {indexed_elapsed:.4f}s "
            f"({len(indexed.addr_to_metadata)} functions, "
            f"{len(indexed.name_to_addr)} names, "
            f"{len(indexed.hash_to_addr)} hashes)"
        )
        print(
            f"    '-- CallGraphEngine:  {cg_elapsed:.4f}s "
            f"({total_edges} edges)"
        )


def benchmark_lookup(db_path: str, metrics_list: list):
    """Measure point lookups by address and name."""
    indexed = IndexedDatabase(db_path)
    indexed._ensure_loaded()

    # Pick a handful of sample addresses
    sample_addrs = list(indexed.addr_to_metadata.keys())[:50]
    sample_names = [n for n in indexed.name_to_addr.keys() if n][:50]

    with measure(f"lookup-by-addr (50x) [{os.path.basename(db_path)}]", metrics_list) as m:
        for addr in sample_addrs:
            meta = indexed.get_metadata(addr)
            _ = meta

    with measure(f"lookup-by-name (50x) [{os.path.basename(db_path)}]", metrics_list) as m:
        for name in sample_names:
            addr = indexed.get_address(name)
            _ = addr


def benchmark_graph(db_path: str, metrics_list: list):
    """Measure BFS call-graph traversal up to depth 3."""
    indexed = IndexedDatabase(db_path)
    cg_engine = CallGraphEngine(db_path)
    # Force-load both so only BFS traversal time is measured
    indexed._ensure_loaded()
    cg_engine._ensure_loaded()

    roots = list(indexed.addr_to_metadata.keys())[:5]
    if not roots:
        return

    with measure(f"graph-bfs-callees (d=3) [{os.path.basename(db_path)}]", metrics_list) as m:
        for root in roots:
            result = cg_engine.bfs_traverse(root, depth=3, direction="callees")
            m.rows_fetched += len(result)


def benchmark_pseudocode(db_path: str, metrics_list: list, use_bulk: bool = False):
    """Measure pseudocode retrieval — both single and bulk."""
    indexed = IndexedDatabase(db_path)
    indexed._ensure_loaded()
    sample_addrs = list(indexed.addr_to_metadata.keys())[:20]

    if use_bulk:
        with measure(f"pseudocode-bulk (20x) [{os.path.basename(db_path)}]", metrics_list) as m:
            batch = get_funcs_batch(db_path, sample_addrs)
            m.sql_count += 1
            m.rows_fetched += len(batch)
    else:
        with measure(f"pseudocode-single (20x) [{os.path.basename(db_path)}]", metrics_list) as m:
            repo = DatabaseRepository(db_path)
            for addr in sample_addrs:
                pc = repo.get_pseudocode(addr)


def benchmark_search(db_path: str, metrics_list: list):
    """Measure search_export_db (the tool that was profiled at 91% SQLite)."""
    with measure(f"search-by-complexity [{os.path.basename(db_path)}]", metrics_list) as m:
        result = search_export_db(
            db_path,
            min_complexity=5,
            max_complexity=50,
            limit=500,
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_all(db1: str, db2: str, save_path: str | None = None) -> list:
    """Run every benchmark and return results as a list of dicts."""
    # Validate
    for p in (db1, db2):
        err = check_db(p)
        if err:
            print(f"ERROR: {p}: {err}", file=sys.stderr)
            sys.exit(1)

    results = []
    process = psutil.Process(os.getpid())

    print(f"\n{'='*80}")
    print(f"  Diaphora MCP Benchmark Suite")
    print(f"  Process PID: {os.getpid()}")
    print(f"  RSS before:  {process.memory_info().rss / 1048576:.1f} MB")
    print(f"  db1:         {db1} ({os.path.getsize(db1) / 1048576:.0f} MB)")
    print(f"  db2:         {db2} ({os.path.getsize(db2) / 1048576:.0f} MB)")
    print(f"{'='*80}\n")

    # -- Open/index --
    print("--- Benchmark: Open & Index ---")
    benchmark_open(db1, results)
    benchmark_open(db2, results)

    # -- Lookups --
    print("\n--- Benchmark: Lookups ---")
    benchmark_lookup(db1, results)

    # -- Graph --
    print("\n--- Benchmark: Call Graph ---")
    benchmark_graph(db1, results)

    # -- Pseudocode --
    print("\n--- Benchmark: Pseudocode ---")
    benchmark_pseudocode(db1, results, use_bulk=False)
    benchmark_pseudocode(db1, results, use_bulk=True)

    # -- Search --
    print("\n--- Benchmark: Search ---")
    benchmark_search(db1, results)

    # Summary table
    print(f"\n{'='*80}")
    print(f"  SUMMARY")
    print(f"{'='*80}")
    print(f"  {'Benchmark':35s} {'Time':>9s}  {'SQL':>5s}  {'Rows':>6s}  {'MemΔ':>7s}")
    print(f"  {'─'*35} {'─'*9}  {'─'*5}  {'─'*6}  {'─'*7}")
    for r in results:
        d = r if isinstance(r, dict) else r.as_dict()
        delta = d["mem_after_mb"] - d["mem_before_mb"]
        print(
            f"  {d['name']:35s} {d['elapsed_s']:8.4f}s  "
            f"{d['sql_queries']:5d}  {d['rows_fetched']:6d}  "
            f"{delta:+6.2f}MB"
        )
    print(f"{'='*80}\n")

    if save_path:
        _save_results(results, save_path)
        print(f"  Results saved to: {save_path}")

    return results


def _save_results(results: list, path: str):
    """Write results as JSON, keyed by benchmark name."""
    data = {
        "timestamp": time.time(),
        "platform": sys.platform,
        "python": sys.version,
        "benchmarks": {r.as_dict()["name"]: r.as_dict() for r in results},
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def compare(before_path: str, after_list: list):
    """Print a regression comparison between a saved baseline and current run."""
    with open(before_path) as f:
        before = json.load(f)

    before_map = before.get("benchmarks", {})

    print(f"\n{'='*80}")
    print(f"  PERFORMANCE REGRESSION CHECK")
    print(f"{'='*80}")
    print(f"  {'Benchmark':35s} {'Before':>9s}  {'After':>9s}  {'Δ':>9s}  {'Δ%':>7s}")
    print(f"  {'─'*35} {'─'*9}  {'─'*9}  {'─'*9}  {'─'*7}")

    for r in after_list:
        d = r if isinstance(r, dict) else r.as_dict()
        name = d["name"]
        before_r = before_map.get(name)
        if not before_r:
            continue
        b_time = before_r["elapsed_s"]
        a_time = d["elapsed_s"]
        delta = a_time - b_time
        pct = (delta / b_time * 100) if b_time else 0
        arrow = "WORSE" if delta > 0.05 else "BETTER" if delta < -0.05 else "SAME"
        print(
            f"  {name:35s} {b_time:8.4f}s  {a_time:8.4f}s  "
            f"{arrow}{delta:+7.4f}s  {pct:+6.1f}%"
        )

    print(f"{'='*80}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Diaphora MCP benchmark suite")
    parser.add_argument("--db1", default=_DEFAULT_DB1, help="Primary test database")
    parser.add_argument("--db2", default=_DEFAULT_DB2, help="Secondary test database")
    parser.add_argument("--save", nargs="?", const="before.json", metavar="PATH",
                        help="Save results to JSON (default: before.json)")
    parser.add_argument("--compare", metavar="BASELINE",
                        help="Compare current run against a saved baseline")
    args = parser.parse_args()

    results = run_all(args.db1, args.db2, save_path=args.save)

    if args.compare:
        compare(args.compare, results)


if __name__ == "__main__":
    main()
