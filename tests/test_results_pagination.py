import json
import sqlite3
import pytest
from diaphora_mcp.core.diff import read_results, get_diff_results, get_diff_summary
from diaphora_mcp.utils.connection import get_connection

def fixture(tmp_path, count=5107, aliases=False):
    path = str(tmp_path / "results.diaphora")
    with sqlite3.connect(path) as c:
        c.executescript("CREATE TABLE config(main_db TEXT); CREATE TABLE unmatched(type TEXT,address TEXT,name TEXT);")
        cols = "match_type TEXT,addr1 TEXT,name1 TEXT,addr2 TEXT,name2 TEXT,similarity REAL" if aliases else "type TEXT,address TEXT,name TEXT,address2 TEXT,name2 TEXT,ratio REAL"
        c.execute(f"CREATE TABLE results({cols})")
        c.executemany("INSERT INTO results VALUES(?,?,?,?,?,?)", [("partial",str(i),"f",str(i+1),"g",0.5) for i in range(count)])
        c.executemany("INSERT INTO unmatched VALUES(?,?,?)", [("primary",str(i),"u") for i in range(count)])
    return path

@pytest.mark.parametrize("aliases", [False, True])
def test_every_row_reachable_in_sql_pages(tmp_path, aliases):
    path = fixture(tmp_path, aliases=aliases)
    queries=[]
    get_connection(path).set_trace_callback(queries.append)
    first = read_results(path,limit=5000,unmatched_limit=5000)
    second = read_results(path,limit=5000,unmatched_limit=5000,offset=first["next_offset"],unmatched_offset=first["next_unmatched_offset"])
    assert len(first["results"]) == 5000
    assert len(second["results"]) == 107
    assert len({r["address"] for r in first["results"]+second["results"]}) == 5107
    assert second["next_offset"] is None
    assert first["total_matches"] == 5107
    assert len(second["unmatched"]) == 107
    assert all("LIMIT" in q.upper() for q in queries if q.upper().startswith("SELECT ") and " FROM RESULTS" in q.upper() and "COUNT(" not in q.upper())

@pytest.mark.parametrize("kwargs", [{"offset":-1},{"limit":0},{"unmatched_offset":-1},{"sort_by":"SQL"},{"sort_order":"bad"},{"match_type":"bad"},{"min_ratio":2}])
def test_invalid_page_arguments(tmp_path, kwargs):
    assert "error" in json.loads(get_diff_results(fixture(tmp_path, 2), **kwargs))

def test_ratio_order_filter_and_summary_are_bounded(tmp_path):
    path=fixture(tmp_path,3)
    get_connection(path).execute("UPDATE results SET ratio=0.9 WHERE address='0'")
    get_connection(path).execute("UPDATE results SET ratio=0.1 WHERE address='2'")
    assert read_results(path,limit=1)["results"][0]["address"] == "2"
    assert read_results(path,min_ratio=0.8)["total_matches"] == 1
    assert read_results(path,limit=1,sort_order="desc")["results"][0]["address"] == "0"
    queries=[]
    get_connection(path).set_trace_callback(queries.append)
    assert len(json.loads(get_diff_summary(path))["top_partial_matches"]) == 3
    assert all("LIMIT" in q.upper() for q in queries if q.upper().startswith("SELECT ") and " FROM RESULTS" in q.upper() and "COUNT(" not in q.upper())


def test_offsets_past_end_return_empty_terminal_page(tmp_path):
    page=read_results(fixture(tmp_path,2),offset=5,unmatched_offset=5)
    assert page["results"] == page["unmatched"] == []
    assert page["next_offset"] is page["next_unmatched_offset"] is None
    assert page["total_matches"] == page["unmatched_count"] == 2


def test_unfiltered_page_keeps_matches_without_ratio(tmp_path):
    path=fixture(tmp_path,2)
    get_connection(path).execute("UPDATE results SET ratio=NULL WHERE address='0'")
    assert read_results(path)["total_matches"] == 2
    assert read_results(path,min_ratio=0.1)["total_matches"] == 1
