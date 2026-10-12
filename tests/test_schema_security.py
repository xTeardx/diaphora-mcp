import json
import sqlite3
import pytest
from diaphora_mcp.utils.sqlite import check_db, check_db_for_diff
from diaphora_mcp.core import security

def test_basic_export_is_not_diff_ready(tmp_path):
    path=str(tmp_path / "weak.sqlite")
    with sqlite3.connect(path) as c:
        c.executescript("CREATE TABLE functions(address TEXT); INSERT INTO functions VALUES('1'); CREATE TABLE program(callgraph_primes TEXT); INSERT INTO program VALUES('2');")
    assert check_db(path) is None
    assert check_db_for_diff(path) is not None

@pytest.mark.parametrize("old,new,removed", [("return 0;", "memcpy(a,b,n);",False),("memcpy(a,b,n);","return 0;",True),("memcpy(a,b,n);","memcpy(a,b,m);",False),("return 0;","memcpy_s(a,b,n);",False)])
def test_unsafe_removal_requires_removed_call(tmp_path,monkeypatch,old,new,removed):
    path=tmp_path / "results.diaphora"
    path.touch()
    monkeypatch.setattr(security,"check_results_db",lambda _:None)
    monkeypatch.setattr(security,"get_underlying_db_paths",lambda _:("old","new"))
    monkeypatch.setattr(security,"read_adaptive_table",lambda *a,**kw:[dict(address="1",address2="2",ratio=0.8,type="partial")])
    monkeypatch.setattr(security,"get_funcs_batch",lambda db,addrs,**kw:{("1" if db=="old" else "2"):dict(pseudocode=old if db=="old" else new)})
    report=json.loads(security.detect_security_patches(str(path)))
    indicators=[i for p in report["security_patches"] for i in p["indicators"]]
    assert ("unsafe_func_removed" in indicators) == removed


def official_export(tmp_path):
    from diaphora_mcp.utils.sqlite import DIFF_REQUIRED_COLUMNS
    path = str(tmp_path / "official.sqlite")
    with sqlite3.connect(path) as c:
        for table, columns in DIFF_REQUIRED_COLUMNS.items():
            c.execute(f'CREATE TABLE "{table}" (' + ", ".join(f'"{col}" TEXT' for col in columns) + ")")
        c.execute("INSERT INTO functions(address) VALUES('1')")
        c.execute("INSERT INTO program(callgraph_primes) VALUES('2')")
        c.execute("INSERT INTO version(value) VALUES('3.4.1')")
    return path

def test_complete_official_schema_is_diff_ready(tmp_path):
    assert check_db_for_diff(official_export(tmp_path)) is None

@pytest.mark.parametrize("table,column", [("functions","microcode_spp"),("program","processor"),("version","value"),("compilation_unit_functions","cu_id")])
def test_missing_upstream_columns_are_rejected(tmp_path,table,column):
    path=official_export(tmp_path)
    with sqlite3.connect(path) as c:
        if table == "version":
            c.execute("ALTER TABLE version ADD COLUMN extra TEXT")
        c.execute(f'ALTER TABLE "{table}" DROP COLUMN "{column}"')
    assert "missing columns" in check_db_for_diff(path)


def test_diff_requires_populated_version_metadata(tmp_path):
    path=official_export(tmp_path)
    with sqlite3.connect(path) as c:
        c.execute("DELETE FROM version")
    assert check_db_for_diff(path) is not None


def batch_export(tmp_path, addresses):
    path=str(tmp_path / "batch.sqlite")
    with sqlite3.connect(path) as c:
        c.executescript("CREATE TABLE version(value TEXT); INSERT INTO version VALUES('3.4.1'); CREATE TABLE functions(address TEXT,name TEXT,nodes INTEGER,edges INTEGER,cyclomatic_complexity INTEGER,instructions INTEGER,pseudocode TEXT,assembly TEXT,prototype TEXT,bytes_hash TEXT);")
        c.executemany("INSERT INTO functions(address,name) VALUES(?,?)",addresses)
    return path

@pytest.mark.parametrize("address", ["01234567","1234567"])
def test_results_hex_address_avoids_decimal_collision(tmp_path,address):
    from diaphora_mcp.utils.sqlite import get_funcs_batch
    path=batch_export(tmp_path,[("19088743","target"),("1234567","collision")])
    rows=get_funcs_batch(path,[address],addresses_are_hex=True)
    assert rows[address]["name"] == "target"

def test_low_official_decimal_addresses_are_detected(tmp_path):
    from diaphora_mcp.utils.sqlite import get_funcs_batch,_detect_decimal
    from diaphora_mcp.utils.connection import get_connection
    path=batch_export(tmp_path,[("16","target"),("10","collision")])
    assert _detect_decimal(get_connection(path)) is True
    rows=get_funcs_batch(path,["00000010"],addresses_are_hex=True)
    assert rows["00000010"]["name"] == "target"

def test_hex_aliases_preserve_all_input_keys(tmp_path):
    from diaphora_mcp.utils.sqlite import get_funcs_batch
    path=batch_export(tmp_path,[("16","target")])
    rows=get_funcs_batch(path,["00000010","0x10","10"],addresses_are_hex=True)
    assert set(rows) == {"00000010","0x10","10"}


def test_low_decimal_callgraph_neighbors_normalize_to_hex(tmp_path):
    from diaphora_mcp.utils.sqlite import get_callgraph,norm_addr
    path=batch_export(tmp_path,[("16","root"),("4096","child")])
    with sqlite3.connect(path) as c:
        c.execute("ALTER TABLE functions ADD COLUMN id INTEGER")
        c.execute("UPDATE functions SET id=1 WHERE address='16'")
        c.execute("UPDATE functions SET id=2 WHERE address='4096'")
        c.executescript("CREATE TABLE callgraph(func_id INTEGER,address TEXT,type TEXT); INSERT INTO callgraph VALUES(1,'4096','callee');")
    assert norm_addr("4096", True) == "1000"
    assert norm_addr("0x1000", True) == "1000"
    assert "1000" in get_callgraph(path,"0x10")["callees"]


@pytest.mark.parametrize("selector", ["0x01234567","0x1234567"])
def test_explicit_hex_selector_never_uses_decimal_collision(tmp_path,selector):
    from diaphora_mcp.utils.sqlite import get_query_addresses,get_func,get_callgraph
    path=official_export(tmp_path)
    with sqlite3.connect(path) as c:
        c.execute("DELETE FROM functions")
        c.execute("INSERT INTO functions(id,address,name,pseudocode) VALUES(1,'1234567','collision','wrong')")
        c.execute("INSERT INTO functions(id,address,name,pseudocode) VALUES(2,'19088743','target','correct')")
        c.execute("INSERT INTO functions(id,address,name) VALUES(3,'4096','child')")
        c.execute("INSERT INTO callgraph(func_id,address,type) VALUES(2,'4096','callee')")
    assert get_query_addresses(True,selector) == ["19088743"]
    assert get_func(path,address=selector)["name"] == "target"
    assert get_callgraph(path,selector)["callees"] == ["1000"]

@pytest.mark.parametrize("address", ["0x00001000","0x1000"])
def test_explicit_hex_legacy_selectors_use_safe_padding_aliases(tmp_path,address):
    from diaphora_mcp.utils.sqlite import get_query_addresses
    assert get_query_addresses(False,address)[0] == "1000"
    assert all(int(candidate,16) == 4096 for candidate in get_query_addresses(False,address))
