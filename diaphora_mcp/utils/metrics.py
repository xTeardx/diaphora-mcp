"""
Diaphora MCP — lightweight performance instrumentation.

Tracks execution time, SQL query count, row counts, and memory delta
for each MCP tool invocation.  Designed as a context manager so any
caller can wrap a code block with zero boilerplate changes to the
business logic.
"""
import os
import time
import psutil
from contextlib import contextmanager


class MetricsTracker:
    """Holds counters and timestamps for one instrumented operation."""

    __slots__ = (
        "sql_queries", "rows_fetched",
        "start_time", "elapsed",
        "start_memory", "memory_used",
    )

    def __init__(self):
        self.sql_queries = 0
        self.rows_fetched = 0
        self.start_time = 0.0
        self.elapsed = 0.0
        self.start_memory = 0
        self.memory_used = 0

    def record_query(self, rows: int = 1):
        self.sql_queries += 1
        self.rows_fetched += rows


@contextmanager
def track_metrics(tool_name: str):
    """Wrap an MCP tool invocation and print a METRICS line on exit.

    Usage::

        with track_metrics("rank_changes") as metrics:
            ...
            metrics.record_query(len(results))
    """
    tracker = MetricsTracker()
    tracker.start_time = time.perf_counter()
    process = psutil.Process(os.getpid())
    tracker.start_memory = process.memory_info().rss
    yield tracker

    tracker.elapsed = time.perf_counter() - tracker.start_time
    tracker.memory_used = process.memory_info().rss - tracker.start_memory
    print(
        f"[METRICS] {tool_name} | "
        f"{tracker.elapsed:.3f}s | "
        f"SQL:{tracker.sql_queries} | "
        f"Rows:{tracker.rows_fetched} | "
        f"Mem:{tracker.memory_used / 1024 / 1024:.2f}MB"
    )
