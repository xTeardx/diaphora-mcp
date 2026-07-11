"""Регрессионные тесты подтверждённых audit findings."""

import asyncio
import importlib.util
import json
import sqlite3
import subprocess
import sys
import types
from pathlib import Path

import pytest

from diaphora_mcp.core import export as export_module
from diaphora_mcp.core import diff as diff_module
from diaphora_mcp.utils.connection import close_all
from diaphora_mcp.utils.sqlite import check_db_for_diff, get_callgraph


@pytest.mark.parametrize(
    "module_name, function_name",
    [
        ("diaphora_mcp.core.security", "analyze_diff_results"),
        ("diaphora_mcp.core.security", "detect_security_patches"),
        ("diaphora_mcp.core.graph", "find_patch_root"),
        ("diaphora_mcp.core.diff", "get_diff_summary"),
        ("diaphora_mcp.core.ranking", "rank_changes"),
        ("diaphora_mcp.core.report", "summarize_patch"),
    ],
)
def test_results_tools_reject_non_sqlite_input_as_json_error(
    module_name, function_name
):
    """Results tools must not leak sqlite.DatabaseError for an IDA .i64 file."""
    import importlib

    module = importlib.import_module(module_name)
    function = getattr(module, function_name)
    input_path = Path(__file__).parents[1] / "Fixes" / "Tests" / "sqlite3_aimp.dll.i64"

    result = json.loads(function(str(input_path)))

    assert "error" in result
    assert "database" in result["error"].lower()


@pytest.fixture(autouse=True)
def close_cached_connections():
    close_all()
    yield
    close_all()


def make_callgraph_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE functions (id INTEGER PRIMARY KEY, address TEXT, name TEXT);
        CREATE TABLE callgraph (func_id INTEGER, address TEXT, type TEXT);
        INSERT INTO functions VALUES (1, '401000', 'root');
        INSERT INTO functions VALUES (2, '402000', 'callee');
        INSERT INTO callgraph VALUES (1, '402000', 'callee');
        """
    )
    conn.commit()
    conn.close()


def make_partial_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE functions (id INTEGER PRIMARY KEY, address TEXT)")
    conn.execute("INSERT INTO functions VALUES (1, '401000')")
    conn.commit()
    conn.close()


def test_get_callgraph_returns_callees_for_official_minimal_schema(tmp_path):
    path = tmp_path / "graph.sqlite"
    make_callgraph_db(path)

    assert get_callgraph(str(path), "401000") == {
        "callers": [],
        "callees": ["402000"],
    }


def test_diff_rejects_partial_schema_as_json_error(tmp_path):
    first = tmp_path / "first.sqlite"
    second = tmp_path / "second.sqlite"
    make_partial_db(first)
    make_partial_db(second)

    result = json.loads(diff_module.diff_diaphora_dbs(str(first), str(second)))

    assert "error" in result
    assert "program" in result["error"]
    assert "OperationalError" not in result["error"]


def test_schema_error_evicts_cached_connection(tmp_path):
    path = tmp_path / "partial.sqlite"
    make_partial_db(path)

    assert check_db_for_diff(str(path)) is not None
    path.unlink()


def test_export_rejects_path_outside_configured_root(tmp_path, monkeypatch):
    root = tmp_path / "allowed"
    outside = tmp_path / "outside" / "result.sqlite"
    root.mkdir()
    outside.parent.mkdir()
    idb = root / "sample.i64"
    idb.write_bytes(b"idb")
    monkeypatch.setenv("DIAPHORA_OUTPUT_ROOT", str(root))

    result = json.loads(
        asyncio.run(
            export_module.export_idb_to_diaphora(str(idb), str(outside))
        )
    )

    assert "error" in result
    assert "output root" in result["error"].lower()


def test_export_does_not_overwrite_target_created_after_validation(tmp_path, monkeypatch):
    root = tmp_path / "allowed"
    root.mkdir()
    idb = root / "sample.i64"
    idb.write_bytes(b"idb")
    target = root / "result.sqlite"
    target_contents = b"attacker-owned target"

    def fake_plugin(_idb_path, _output_path, _use_decompiler, _summaries_only):
        target.write_bytes(target_contents)
        return None

    monkeypatch.setenv("DIAPHORA_OUTPUT_ROOT", str(root))
    monkeypatch.setattr(export_module, "_try_via_plugin", fake_plugin)

    result = json.loads(
        asyncio.run(export_module.export_idb_to_diaphora(str(idb), str(target)))
    )

    assert "error" in result
    assert "overwrite" in result["error"].lower()
    assert target.read_bytes() == target_contents


def test_export_rejects_target_symlink_created_after_validation(tmp_path, monkeypatch):
    root = tmp_path / "allowed"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    idb = root / "sample.i64"
    idb.write_bytes(b"idb")
    target = root / "result.sqlite"
    escaped = outside / "escaped.sqlite"

    def fake_plugin(_idb_path, output_path, _use_decompiler, _summaries_only):
        target.symlink_to(escaped)
        Path(output_path).write_bytes(b"staged export")
        return None

    monkeypatch.setenv("DIAPHORA_OUTPUT_ROOT", str(root))
    monkeypatch.setattr(export_module, "_try_via_plugin", fake_plugin)

    result = json.loads(
        asyncio.run(export_module.export_idb_to_diaphora(str(idb), str(target)))
    )

    assert "error" in result
    assert "overwrite" in result["error"].lower()
    assert not escaped.exists()


def load_gui_listener(monkeypatch, idb_path: Path):
    fake_idaapi = types.ModuleType("idaapi")
    fake_idaapi.PLUGIN_UNL = 0
    fake_idaapi.PLUGIN_KEEP = 1
    fake_idaapi.MFF_WRITE = 2
    fake_idaapi.get_idb_path = lambda: str(idb_path)
    fake_idaapi.execute_sync = lambda callback, _flags: callback()
    fake_idaapi.plugin_t = type("plugin_t", (), {})
    monkeypatch.setitem(sys.modules, "idaapi", fake_idaapi)

    module_name = "diaphora_gui_listener_regression"
    spec = importlib.util.spec_from_file_location(
        module_name, Path(__file__).parents[1] / "diaphora_gui_listener.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module, fake_idaapi


def test_gui_listener_does_not_overwrite_target_created_after_validation(
    tmp_path, monkeypatch
):
    root = tmp_path / "allowed"
    root.mkdir()
    idb = root / "sample.i64"
    idb.write_bytes(b"idb")
    target = root / "result.sqlite"

    listener, fake_idaapi = load_gui_listener(monkeypatch, idb)
    monkeypatch.setenv("DIAPHORA_OUTPUT_ROOT", str(root))

    def execute_sync(_callback, _flags):
        target.write_bytes(b"attacker-owned target")
        return True

    monkeypatch.setattr(fake_idaapi, "execute_sync", execute_sync)

    result = listener.DiaphoraGuiAPI().export_current_db(
        str(target), use_decompiler=False
    )

    assert isinstance(result, str)
    assert "overwrite" in result.lower()
    assert target.read_bytes() == b"attacker-owned target"


class FakeTimeoutProcess:
    def __init__(self):
        self.returncode = None
        self.stdout = []
        self.stderr = []
        self.events = []

    def wait(self, timeout=None):
        self.events.append(("wait", timeout))
        if self.returncode is None and timeout is not None:
            raise subprocess.TimeoutExpired("fake", timeout)
        self.returncode = -9

    def kill(self):
        self.events.append(("kill",))
        self.returncode = -9

    def poll(self):
        return self.returncode


def test_diff_timeout_reaps_child_process(monkeypatch, tmp_path):
    process = FakeTimeoutProcess()
    monkeypatch.setattr(diff_module, "check_db_for_diff", lambda _path: None)
    monkeypatch.setattr(diff_module.subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(diff_module, "read_results", lambda _path: {})
    first = tmp_path / "first.sqlite"
    second = tmp_path / "second.sqlite"
    first.touch()
    second.touch()

    result = json.loads(diff_module.diff_diaphora_dbs(str(first), str(second)))

    assert "timed out" in result["error"]
    assert [event[0] for event in process.events] == ["wait", "kill", "wait"]


def test_documented_tool_count_matches_registry():
    import diaphora_mcp

    registered = diaphora_mcp.mcp._tool_manager._tools
    assert len(registered) == 21
    assert "performance_report" in registered
