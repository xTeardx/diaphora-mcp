"""
Diaphora MCP — logging utilities for long-running operations.

Writes structured timestamped log entries so users can monitor
progress of exports, diffs, and other background tasks.
"""

import os
import sys
import time
from datetime import datetime


_LOG_DIR = None


def set_log_dir(path: str):
    """Override the default log directory."""
    global _LOG_DIR
    _LOG_DIR = path


def get_log_dir() -> str:
    """Return the log directory, creating it if needed."""
    global _LOG_DIR
    if _LOG_DIR:
        d = _LOG_DIR
    else:
        # Project root = diaphora_mcp/../  (two levels up from utils/log.py)
        d = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "logs",
        )
    os.makedirs(d, exist_ok=True)
    return d


def _ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_path(tag: str = "export") -> str:
    """Return a path like logs/export_2025-06-30_15-30-00.log."""
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return os.path.join(get_log_dir(), f"{tag}_{ts}.log")


def write_log(path: str, level: str, message: str):
    """Append a single structured log line."""
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"[{_ts()}] [{level}] {message}\n")
    except OSError:
        pass  # best-effort


def write_log_lines(path: str, level: str, lines: list[str]):
    """Append multiple lines under a single timestamp header."""
    if not lines:
        return
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"[{_ts()}] [{level}] --- begin ---\n")
            for line in lines:
                # Strip trailing newlines, re-indent
                clean = line.rstrip("\n\r")
                f.write(f"  | {clean}\n")
            f.write(f"[{_ts()}] [{level}] --- end ({len(lines)} lines) ---\n")
    except OSError:
        pass


class ExportLogger:
    """Context manager that writes a structured log for one export operation."""

    def __init__(self, idb_path: str, output_path: str, tag: str = "export"):
        self.idb_path = idb_path
        self.output_path = output_path
        self.log_path = log_path(tag)
        self.start_time = time.time()

    def __enter__(self):
        write_log(
            self.log_path, "START",
            f"Export {os.path.basename(self.idb_path)} → {os.path.basename(self.output_path)}",
        )
        write_log(self.log_path, "INFO", f"  Full IDB path: {self.idb_path}")
        write_log(self.log_path, "INFO", f"  Output path:   {self.output_path}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        elapsed = time.time() - self.start_time
        if exc_type:
            write_log(self.log_path, "ERROR", f"Failed after {elapsed:.0f}s: {exc_val}")
        else:
            write_log(self.log_path, "DONE", f"Completed in {elapsed:.0f}s")
        return False

    def info(self, message: str):
        write_log(self.log_path, "INFO", message)

    def warn(self, message: str):
        write_log(self.log_path, "WARN", message)

    def error(self, message: str):
        write_log(self.log_path, "ERROR", message)

    def log_subprocess_output(self, stdout: str, stderr: str):
        if stdout and stdout.strip():
            write_log_lines(self.log_path, "STDOUT", stdout.splitlines()[-50:])
        if stderr and stderr.strip():
            write_log_lines(self.log_path, "STDERR", stderr.splitlines()[-50:])

    def log_file_growth(self, path: str, label: str = "WAL"):
        try:
            sz = os.path.getsize(path)
            self.info(f"  {label}: {sz // 1024 // 1024} MB ({sz} bytes)")
        except OSError:
            pass
