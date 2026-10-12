import asyncio
import json
from pathlib import Path

import pytest

from diaphora_mcp.core import export, diff


@pytest.mark.parametrize('existing', ['old.diaphora.sqlite', 'new.diaphora.sqlite', 'old_vs_new.diaphora'])
def test_batch_preflights_all_outputs_and_preserves_existing(tmp_path, monkeypatch, existing):
    old, new = tmp_path / 'old.i64', tmp_path / 'new.i64'
    old.touch()
    new.touch()
    target = tmp_path / existing
    target.write_bytes(b'precious')
    async def fail(*args, **kwargs):
        pytest.fail('export began before all targets were checked')
    monkeypatch.setattr(export, 'run_export', fail)
    result = json.loads(asyncio.run(export.batch_export_and_diff(str(old), str(new), cleanup=True)))
    assert 'error' in result
    assert target.read_bytes() == b'precious'


def test_same_basename_exports_are_distinct_and_cleanup_owned_only(tmp_path, monkeypatch):
    old_dir, new_dir = tmp_path / 'old', tmp_path / 'new'
    old_dir.mkdir()
    new_dir.mkdir()
    old, new = old_dir / 'app.i64', new_dir / 'app.i64'
    old.touch()
    new.touch()
    monkeypatch.setenv('DIAPHORA_OUTPUT_ROOT', str(tmp_path))
    unrelated = tmp_path / 'unrelated.sqlite'
    unrelated.write_bytes(b'keep')
    outputs = []
    async def export_fake(source, target, *args, **kwargs):
        assert kwargs['export_mode'] == 'headless'
        Path(target).write_bytes(source.encode())
        outputs.append(target)
        return json.dumps({'ok': True})
    async def diff_fake(db1, db2, target, *args):
        assert db1 != db2
        assert Path(db1).read_bytes() == str(old).encode()
        assert Path(db2).read_bytes() == str(new).encode()
        Path(target).write_bytes(b'diff')
        return {'counts': dict(best=1, partial=0, unreliable=0, multimatch=0), 'unmatched_count': 0}
    monkeypatch.setattr(export, 'export_idb_to_diaphora', export_fake)
    monkeypatch.setattr(diff, '_diff_diaphora_dbs_async', diff_fake)
    result = json.loads(asyncio.run(export.batch_export_and_diff(str(old), str(new), cleanup=True)))
    assert result['success']
    assert len(set(outputs)) == 2
    assert all(not Path(path).exists() for path in outputs)
    assert Path(result['steps']['diff']['output']).exists()
    assert unrelated.read_bytes() == b'keep'


def test_async_diff_cancellation_kills_and_reaps_child(tmp_path, monkeypatch):
    import threading
    started, stopped = threading.Event(), threading.Event()
    class Child:
        returncode = None
        killed = False
        waited = False
        def communicate(self):
            started.set()
            stopped.wait(5)
            return '', ''
        def poll(self):
            return self.returncode
        def kill(self):
            self.killed = True
            self.returncode = -9
            stopped.set()
        def wait(self, timeout):
            self.waited = True
    child = Child()
    monkeypatch.setattr(diff, 'check_db_for_diff', lambda p: None)
    monkeypatch.setattr(diff.subprocess, 'Popen', lambda *a, **k: child)
    async def run():
        task = asyncio.create_task(diff._diff_diaphora_dbs_async(str(tmp_path / 'old.sqlite'), str(tmp_path / 'new.sqlite'), str(tmp_path / 'out.diaphora')))
        while not started.is_set():
            await asyncio.sleep(.001)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    asyncio.run(run())
    assert child.killed and child.waited
    assert not list(tmp_path.glob('*.tmp'))


def test_diff_nonzero_exit_does_not_publish_partial_output(tmp_path, monkeypatch):
    class Child:
        returncode = 3
        stdout = []
        stderr = []
        def wait(self, timeout):
            return self.returncode
        def poll(self):
            return self.returncode
    def launch(command, **kwargs):
        Path(command[-1]).write_bytes(b'partial')
        return Child()
    monkeypatch.setattr(diff, 'check_db_for_diff', lambda p: None)
    monkeypatch.setattr(diff.subprocess, 'Popen', launch)
    target = tmp_path / 'out.diaphora'
    result = json.loads(diff.diff_diaphora_dbs(str(tmp_path / 'old.sqlite'), str(tmp_path / 'new.sqlite'), str(target)))
    assert 'exit code 3' in result['error']
    assert not target.exists()
    assert not list(tmp_path.glob('*.tmp'))


def test_single_export_cancellation_removes_staged_output(tmp_path, monkeypatch):
    old = tmp_path / 'old.i64'
    old.touch()
    async def cancelled(source, staged, *args):
        Path(staged).write_bytes(b'partial')
        raise asyncio.CancelledError
    monkeypatch.setattr(export, 'run_export', cancelled)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(export.export_idb_to_diaphora(str(old), export_mode='headless'))
    assert list(tmp_path.iterdir()) == [old]


def test_second_export_failure_cleanup_preserves_unowned_target(tmp_path, monkeypatch):
    old, new = tmp_path / 'old.i64', tmp_path / 'new.i64'
    old.touch()
    new.touch()
    async def export_fake(source, target, *args, **kwargs):
        if source == str(old):
            Path(target).write_bytes(b'owned')
            return json.dumps({'ok': True})
        # Another operation wins publication after preflight.
        Path(target).write_bytes(b'other operation')
        return json.dumps({'error': 'Refusing to overwrite existing output'})
    monkeypatch.setattr(export, 'export_idb_to_diaphora', export_fake)
    result = json.loads(asyncio.run(export.batch_export_and_diff(str(old), str(new), cleanup=True)))
    assert 'error' in result
    assert not (tmp_path / 'old.diaphora.sqlite').exists()
    assert (tmp_path / 'new.diaphora.sqlite').read_bytes() == b'other operation'


def test_diff_rejects_output_outside_configured_root(tmp_path, monkeypatch):
    root = tmp_path / 'root'
    root.mkdir()
    monkeypatch.setenv('DIAPHORA_OUTPUT_ROOT', str(root))
    monkeypatch.setattr(diff, 'check_db_for_diff', lambda p: None)
    monkeypatch.setattr(diff.subprocess, 'Popen', lambda *a, **k: pytest.fail('must preflight root'))
    result = json.loads(diff.diff_diaphora_dbs(str(root / 'old.sqlite'), str(root / 'new.sqlite'), str(tmp_path / 'out.diaphora')))
    assert 'output root' in result['error']


@pytest.mark.parametrize('value', [0, -1, True, '5', None])
def test_batch_rejects_bad_page_size_before_exports(tmp_path, monkeypatch, value):
    old, new = tmp_path / 'old.i64', tmp_path / 'new.i64'
    old.touch()
    new.touch()
    async def fail(*args, **kwargs):
        pytest.fail('invalid limit started expensive exports')
    monkeypatch.setattr(export, 'export_idb_to_diaphora', fail)
    result = json.loads(asyncio.run(export.batch_export_and_diff(str(old), str(new), limit=value)))
    assert 'limit' in result['error']


def test_diff_relative_paths_resolved_before_child_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(diff, 'check_db_for_diff', lambda p: None)
    class Child:
        returncode = 2
        stdout = []
        stderr = ['x' * 5000 + 'useful failure']
        def wait(self, timeout):
            return self.returncode
        def poll(self):
            return self.returncode
    def launch(command, **kwargs):
        assert all(Path(path).is_absolute() for path in (command[2], command[3], command[5]))
        return Child()
    monkeypatch.setattr(diff.subprocess, 'Popen', launch)
    result = json.loads(diff.diff_diaphora_dbs('old.sqlite', 'new.sqlite', 'out.diaphora'))
    assert 'exit code 2' in result['error']
    assert result['stderr_tail'].endswith('useful failure')
    assert len(result['stderr_tail']) <= 3000


def test_finished_diff_counts_unmatched_types_beyond_display_page(tmp_path, monkeypatch):
    import sqlite3
    staged = tmp_path / 'stage.tmp'
    with sqlite3.connect(staged) as conn:
        conn.execute('CREATE TABLE unmatched(type TEXT)')
        conn.executemany('INSERT INTO unmatched VALUES (?)', [('primary',), ('secondary',), ('secondary',)])
    conn.close()
    monkeypatch.setattr(diff, 'check_results_db', lambda p: None)
    monkeypatch.setattr(diff, 'read_results', lambda *a, **k: {'unmatched_count': 3, 'unmatched': [{'type': 'primary'}]})
    result = diff._finish_diff(0, str(staged), str(tmp_path / 'out.diaphora'))
    assert result['unmatched_counts'] == {'primary': 1, 'secondary': 2}


def test_locked_database_copy_preserves_existing_fixed_temp(tmp_path, monkeypatch):
    import builtins
    old = tmp_path / 'old.i64'
    old.write_bytes(b'input')
    lock = tmp_path / 'old.id0'
    lock.touch()
    fixed = tmp_path / 'old_diaphora_tmp.i64'
    fixed.write_bytes(b'precious')
    original_open = builtins.open
    def locked_open(path, *args, **kwargs):
        if str(path) == str(lock):
            raise OSError('locked')
        return original_open(path, *args, **kwargs)
    async def fail(source, staged, *args):
        assert source != str(fixed)
        return 'export failed'
    monkeypatch.setattr(builtins, 'open', locked_open)
    monkeypatch.setattr(export, 'run_export', fail)
    result = json.loads(asyncio.run(export.export_idb_to_diaphora(str(old), export_mode='headless')))
    assert 'error' in result
    assert fixed.read_bytes() == b'precious'


def test_headless_nonzero_exit_rejected_even_with_valid_schema(tmp_path, monkeypatch):
    source = tmp_path / 'old.i64'
    source.touch()
    output = tmp_path / 'stage.tmp'
    output.write_bytes(b'valid schema placeholder')
    class Child:
        returncode = 3
        stdout = []
        stderr = []
        def poll(self):
            return self.returncode
    monkeypatch.setattr(export, 'IDAT_PATH', str(source))
    monkeypatch.setattr(export, 'HEADLESS_WRAPPER', str(source))
    monkeypatch.setattr(export, 'check_db', lambda p: None)
    monkeypatch.setattr(export, 'check_db_for_diff', lambda p: None)
    monkeypatch.setattr(export.subprocess, 'Popen', lambda *a, **k: Child())
    result = asyncio.run(export.run_export(str(source), str(output), False))
    assert result and 'exit code 3' in result


def test_batch_rejects_root_escape_before_export(tmp_path, monkeypatch):
    root = tmp_path / 'root'
    root.mkdir()
    old, new = root / 'old.i64', root / 'new.i64'
    old.touch()
    new.touch()
    monkeypatch.setenv('DIAPHORA_OUTPUT_ROOT', str(root))
    async def fail(*args, **kwargs):
        pytest.fail('export outside root')
    monkeypatch.setattr(export, 'run_export', fail)
    result = json.loads(asyncio.run(export.batch_export_and_diff(str(old), str(new), str(tmp_path / 'outside'))))
    assert 'error' in result
    assert not (tmp_path / 'outside').exists()


def test_diff_preserves_existing_target(tmp_path, monkeypatch):
    target = tmp_path / 'result.diaphora'
    target.write_bytes(b'precious')
    monkeypatch.setattr(diff, 'check_db_for_diff', lambda p: None)
    monkeypatch.setattr(diff.subprocess, 'Popen', lambda *a, **k: pytest.fail('must preflight'))
    result = json.loads(diff.diff_diaphora_dbs(str(tmp_path / 'old.sqlite'), str(tmp_path / 'new.sqlite'), str(target)))
    assert 'error' in result
    assert target.read_bytes() == b'precious'
