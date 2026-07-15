import sqlite3
import json

from diaphora_mcp.core.mapping import FunctionMapping
from diaphora_mcp.core.analysis import compare_functions
from diaphora_mcp.core.graph import get_changed_callgraph
from diaphora_mcp.core.metadata import transfer_metadata


def _make_function_db(path, address, child_address):
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE functions (
            id INTEGER PRIMARY KEY, address TEXT, name TEXT, nodes INTEGER,
            edges INTEGER, instructions INTEGER, cyclomatic_complexity INTEGER,
            prototype TEXT, bytes_hash TEXT, pseudocode TEXT, assembly TEXT,
            constants TEXT, mnemonics TEXT, loops INTEGER,
            strongly_connected INTEGER, names TEXT,
            pseudocode_hash1 TEXT, pseudocode_hash2 TEXT
        );
        CREATE TABLE program (id INTEGER, callgraph_primes TEXT,
            callgraph_all_primes TEXT, processor TEXT, md5sum TEXT);
        CREATE TABLE callgraph (func_id INTEGER, address TEXT, type TEXT);
        """
    )
    conn.executemany(
        "INSERT INTO functions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (1, address, "root", 1, 0, 3, 1, "int root()", "h1", "old()", "", "", "", 0, 0, "", "", ""),
            (2, child_address, "child", 1, 0, 2, 1, "int child()", "h2", "child()", "", "", "", 0, 0, "", "", ""),
        ],
    )
    conn.execute("INSERT INTO program VALUES (1, 'x', 'x', 'x', 'x')")
    conn.execute("INSERT INTO callgraph VALUES (1, ?, 'callee')", (child_address,))
    conn.commit()
    conn.close()


def _make_results(path, old_db, new_db, rows=None):
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE config (main_db TEXT, diff_db TEXT);
        CREATE TABLE results (address TEXT, name TEXT, address2 TEXT,
            name2 TEXT, ratio REAL, type TEXT);
        CREATE TABLE unmatched (address TEXT, name TEXT, type TEXT);
        """
    )
    conn.execute("INSERT INTO config VALUES (?, ?)", (str(old_db), str(new_db)))
    for row in rows or [
        ("401000", "root", "501000", "root"),
        ("401010", "child", "501010", "child"),
    ]:
        conn.execute(
            "INSERT INTO results VALUES (?, ?, ?, ?, 1.0, 'best')", row
        )
    conn.commit()
    conn.close()


def test_mapping_resolves_rebased_function_and_preserves_match_metadata():
    mapping = FunctionMapping.from_rows(
        [
            {
                "address": "401000",
                "address2": "501000",
                "name": "old_name",
                "name2": "new_name",
                "type": "partial",
                "ratio": "0.82",
            }
        ],
        source_decimal=False,
        target_decimal=False,
    )

    match = mapping.by_old("0x401000")

    assert match is not None
    assert match.new_address == "501000"
    assert match.match_type == "partial"
    assert match.ratio == 0.82
    assert mapping.by_new("0x501000").old_address == "401000"


def test_mapping_normalizes_decimal_database_addresses_to_hex_keys():
    mapping = FunctionMapping.from_rows(
        [
            {
                "address": "4198400",
                "address2": "5246976",
                "type": "best",
                "ratio": 1.0,
            }
        ],
        source_decimal=True,
        target_decimal=True,
    )

    assert mapping.by_old("0x401000").new_address == "501000"


def test_mapping_normalizes_low_decimal_addresses_when_schema_is_known():
    mapping = FunctionMapping.from_rows(
        [{"address": "4096", "address2": "8192", "type": "best", "ratio": 1.0}],
        source_decimal=True,
        target_decimal=True,
    )

    assert mapping.by_old("0x1000").new_address == "2000"


def test_mapping_reports_unmapped_old_and_new_addresses():
    mapping = FunctionMapping.from_rows(
        [
            {"address": "401000", "address2": "501000", "type": "best", "ratio": 1},
        ],
        source_decimal=False,
        target_decimal=False,
        unmatched_primary=[{"address": "402000", "name": "removed"}],
        unmatched_secondary=[{"address": "502000", "name": "added"}],
    )

    assert mapping.is_removed("402000")
    assert mapping.is_added("502000")
    assert not mapping.is_removed("401000")


def test_compare_functions_uses_diaphora_mapping_for_rebased_binary(tmp_path):
    old_db = tmp_path / "old.sqlite"
    new_db = tmp_path / "new.sqlite"
    results = tmp_path / "diff.diaphora"
    _make_function_db(old_db, "401000", "401010")
    _make_function_db(new_db, "501000", "501010")
    _make_results(results, old_db, new_db)

    report = json.loads(
        compare_functions(
            str(old_db),
            str(new_db),
            address="401000",
            match_results_path=str(results),
        )
    )

    assert report["function_new"]["address"] == "501000"


def test_changed_callgraph_uses_mapped_function_address(tmp_path):
    old_db = tmp_path / "old.sqlite"
    new_db = tmp_path / "new.sqlite"
    results = tmp_path / "diff.diaphora"
    _make_function_db(old_db, "401000", "401010")
    _make_function_db(new_db, "501000", "501010")
    _make_results(results, old_db, new_db)

    report = json.loads(
        get_changed_callgraph(
            str(old_db),
            str(new_db),
            address="401000",
            match_results_path=str(results),
        )
    )

    assert report["function_name_new"] == "root"
    assert report["address_new"] == "501000"


def test_compare_call_path_translates_old_nodes_before_comparison(tmp_path):
    from diaphora_mcp.core.graph import compare_call_path

    old_db = tmp_path / "old.sqlite"
    new_db = tmp_path / "new.sqlite"
    results = tmp_path / "diff.diaphora"
    _make_function_db(old_db, "401000", "401010")
    _make_function_db(new_db, "501000", "501010")
    _make_results(results, old_db, new_db)

    report = json.loads(
        compare_call_path(
            str(old_db),
            str(new_db),
            address="401000",
            depth=2,
            match_results_path=str(results),
        )
    )

    assert report["function_address_new"] == "501000"
    assert report["added_nodes"] == 0
    assert report["removed_nodes"] == 0


def test_metadata_transfer_maps_decimal_source_to_rebased_decimal_target(tmp_path):
    old_db = tmp_path / "old.sqlite"
    new_db = tmp_path / "new.sqlite"
    results = tmp_path / "diff.diaphora"
    _make_function_db(old_db, "4198400", "4198416")
    _make_function_db(new_db, "5246976", "5246992")
    _make_results(
        results,
        old_db,
        new_db,
        rows=[
            ("4198400", "root", "5246976", "root"),
            ("4198416", "child", "5246992", "child"),
        ],
    )

    report = json.loads(
        transfer_metadata(
            str(old_db),
            str(new_db),
            transfer_comments=False,
            transfer_prototypes=False,
            transfer_types=False,
            match_results_path=str(results),
        )
    )

    root_item = next(i for i in report["items"] if i["source_address"] == "4198400")
    assert root_item["target_address"] == "501000"
