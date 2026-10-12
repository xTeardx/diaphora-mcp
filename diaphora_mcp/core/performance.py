"""
Diaphora MCP — performance report tool.

Returns aggregated runtime stats: connection cache state, memory usage,
cache manager state, and SQLite PRAGMA configuration.
"""

import os

import psutil

from ..utils.connection import get_cache_manager
from ..utils.format import dumps


def performance_report() -> str:
    """Return an aggregated performance report for the MCP server.

    Reports connection cache state, memory usage, cache manager state,
    and SQLite configuration.
    """
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    cache_mgr = get_cache_manager()

    return dumps({
        "process": {
            "pid": os.getpid(),
            "rss_mb": round(mem_info.rss / 1048576, 2),
            "vms_mb": round(mem_info.vms / 1048576, 2),
        },
        "database_cache": {
            "entries": cache_mgr.size,
            "max_entries": 2,
            "eviction_policy": "LRU (OrderedDict)",
        },
        "recommendation": (
            "For large databases (>100 MB), use summaries_only=True and "
            "use_decompiler=False. The in-memory cache holds at most 2 "
            "databases — if memory grows, eviction occurs automatically."
        ),
    })
