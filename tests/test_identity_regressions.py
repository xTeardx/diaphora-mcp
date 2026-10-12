import json
import sqlite3

from test_mapping_regressions import _make_function_db, _make_results
from diaphora_mcp.core.analysis import compare_functions, find_function_match, detect_behavior_change
from diaphora_mcp.core.graph import get_changed_callgraph
from diaphora_mcp.core.mapping import FunctionMapping


def pair(tmp_path, rebased=True):
    old, new, results = (tmp_path / n for n in ('old.sqlite', 'new.sqlite', 'diff.diaphora'))
    _make_function_db(old, '401000', '401010')
    _make_function_db(new, '501000' if rebased else '401000', '501010' if rebased else '401010')
    _make_results(results, old, new)
    return str(old), str(new), str(results)


def test_equal_address_is_not_identity(tmp_path):
    old, new, _ = pair(tmp_path, False)
    with sqlite3.connect(new) as conn:
        conn.execute("UPDATE functions SET name='unrelated', bytes_hash='different'")
    report = json.loads(find_function_match(old, new, address='401000'))
    assert report['matched'] is False


def test_name_selector_uses_resolved_old_address_for_mapping(tmp_path):
    old, new, results = pair(tmp_path)
    with sqlite3.connect(new) as conn:
        conn.execute("UPDATE functions SET name='renamed' WHERE id=1")
    report = json.loads(compare_functions(old, new, name='root', match_results_path=results))
    assert report['function_new']['name'] == 'renamed'


def test_rebased_neighbors_are_unchanged(tmp_path):
    old, new, results = pair(tmp_path)
    report = json.loads(get_changed_callgraph(old, new, address='401000', match_results_path=results))
    assert report['callees']['unchanged'] == 1
    assert report['callees']['added'] == report['callees']['removed'] == []


def test_moved_function_is_not_deleted(tmp_path):
    old, new, _ = pair(tmp_path)
    report = json.loads(detect_behavior_change(old, new, address='401000'))
    assert report['change_type'] != 'deleted_function'
    assert report['function_name_new'] == 'root'


def test_invalid_mapping_does_not_fall_back(tmp_path):
    old, new, _ = pair(tmp_path, False)
    report = json.loads(compare_functions(old, new, address='401000', match_results_path=str(tmp_path / 'missing.diaphora')))
    assert 'error' in report or report.get('secondary') is None
    assert 'function_new' not in report


def test_multimatches_are_not_overwritten():
    mapping = FunctionMapping.from_rows([
        {'address': '401000', 'address2': '501000'},
        {'address': '401000', 'address2': '502000'},
    ])
    assert mapping.by_old('401000') is None
    assert mapping.by_new('501000') is None


def test_unmatched_results_do_not_mean_deleted(tmp_path):
    old, new, results = pair(tmp_path)
    with sqlite3.connect(results) as conn:
        conn.execute("DELETE FROM results WHERE address='401000'")
        conn.execute("INSERT INTO unmatched VALUES ('401000', 'root', 'primary')")
    report = json.loads(detect_behavior_change(old, new, address='401000', match_results_path=results))
    assert report['change_type'] == 'unknown'

def test_legacy_similarity_uses_mapped_edges(tmp_path):
    from diaphora_mcp.core.analysis import explain_similarity
    old, new, results = pair(tmp_path)
    report = json.loads(explain_similarity(old, new, name='root', match_results_path=results))
    factor = next(f for f in report['factors'] if f['factor'] == 'callgraph')
    assert factor['callee_similarity'] == 1


def test_call_path_invalid_mapping_does_not_fall_back(tmp_path):
    from diaphora_mcp.core.graph import compare_call_path
    old, new, _ = pair(tmp_path, False)
    report = json.loads(compare_call_path(old, new, address='401000', match_results_path=str(tmp_path / 'missing.diaphora')))
    assert 'error' in report


def test_metadata_transfer_requires_identity(tmp_path):
    from diaphora_mcp.core.metadata import transfer_metadata
    old, new, _ = pair(tmp_path, False)
    with sqlite3.connect(new) as conn:
        conn.execute("UPDATE functions SET name='unrelated', bytes_hash='different'")
    report = json.loads(transfer_metadata(old, new, transfer_comments=False, transfer_prototypes=False, transfer_types=False))
    assert report['items'] == []

def test_rebased_decimal_neighbors_are_unchanged(tmp_path):
    old, new, results = (tmp_path / n for n in ('old.sqlite', 'new.sqlite', 'diff.diaphora'))
    _make_function_db(old, '4198400', '4198416')
    _make_function_db(new, '5246976', '5246992')
    _make_results(results, old, new, rows=[('00401000', 'root', '00501000', 'root'), ('00401010', 'child', '00501010', 'child')])
    report = json.loads(get_changed_callgraph(str(old), str(new), address='0x401000', match_results_path=str(results)))
    assert report['callees']['unchanged'] == 1

def test_explicit_target_keeps_authoritative_neighbor_mapping(tmp_path):
    old, new, results = pair(tmp_path)
    with sqlite3.connect(new) as conn:
        conn.execute("UPDATE functions SET name='sub_501010', bytes_hash='changed' WHERE id=2")
    report = json.loads(get_changed_callgraph(old, new, address='401000', address2='501000', match_results_path=results))
    assert report['callees']['unchanged'] == 1


def test_duplicate_primary_evidence_does_not_assign_same_new_identity(tmp_path):
    old, new, _ = pair(tmp_path)
    with sqlite3.connect(old) as conn:
        conn.execute("UPDATE functions SET name='root', bytes_hash='h1'")
    report = json.loads(find_function_match(old, new, address='401010'))
    assert report['matched'] is False

def test_official_padded_hex_results_map_decimal_export_addresses(tmp_path):
    old, new, results = (tmp_path / n for n in ('old.sqlite', 'new.sqlite', 'diff.diaphora'))
    _make_function_db(old, '4198400', '4198416')
    _make_function_db(new, '5246976', '5246992')
    _make_results(results, old, new, rows=[('00401000', 'root', '00501000', 'root'), ('00401010', 'child', '00501010', 'child')])
    report = json.loads(compare_functions(str(old), str(new), name='root', match_results_path=str(results)))
    assert report['function_new']['address'] == '5246976'
    graph = json.loads(get_changed_callgraph(str(old), str(new), name='root', match_results_path=str(results)))
    assert graph['callees']['unchanged'] == 1

def test_official_hex_results_keep_decimal_call_path_unchanged(tmp_path):
    from diaphora_mcp.core.graph import compare_call_path
    old, new, results = (tmp_path / n for n in ('old.sqlite', 'new.sqlite', 'diff.diaphora'))
    _make_function_db(old, '4198400', '4198416')
    _make_function_db(new, '5246976', '5246992')
    _make_results(results, old, new, rows=[('00401000', 'root', '00501000', 'root'), ('00401010', 'child', '00501010', 'child')])
    report = json.loads(compare_call_path(str(old), str(new), name='root', match_results_path=str(results)))
    assert report['added_nodes'] == report['removed_nodes'] == 0
    assert report['unknown_old'] == report['unknown_new'] == []

def test_decimal_graph_index_lookups_preserve_hex_identity(tmp_path):
    from diaphora_mcp.core.graph import compare_call_path, find_patch_root
    old, new, results = (tmp_path / n for n in ('old.sqlite', 'new.sqlite', 'diff.diaphora'))
    _make_function_db(old, '4198400', '4198416')
    _make_function_db(new, '5246976', '5246992')
    _make_results(results, old, new, rows=[('00401000', 'root', '00501000', 'root'), ('00401010', 'child', '00501010', 'child')])
    path = json.loads(compare_call_path(str(old), str(new), name='root', match_results_path=str(results)))
    roots = json.loads(find_patch_root(str(results)))
    assert roots['total_changed_functions'] == 2
    assert len(roots['all_candidates_ranked']) == 2
    assert {candidate['name'] for candidate in roots['all_candidates_ranked']} == {'root', 'child'}
    assert path['call_path_new'][0]['functions']['501010'] == 'child'
