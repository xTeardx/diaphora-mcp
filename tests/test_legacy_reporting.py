import json
import runpy
import sqlite3
from pathlib import Path

from diaphora_mcp.core.ranking import rank_changes
from diaphora_mcp.core.report import summarize_patch
from diaphora_mcp.utils.connection import close_all


def make_pair(tmp_path):
    helpers = runpy.run_path(str(Path(__file__).with_name("test_mapping_regressions.py")))
    old, new, results = (tmp_path / name for name in ("old.sqlite", "new.sqlite", "diff.diaphora"))
    helpers["_make_function_db"](old, "401000", "401010")
    helpers["_make_function_db"](new, "501000", "501010")
    helpers["_make_results"](results, old, new)
    return old, new, results


def test_patch_report_does_not_claim_unmatched_means_added_or_deleted(tmp_path):
    _, _, results = make_pair(tmp_path)
    conn = sqlite3.connect(results)
    conn.execute("INSERT INTO unmatched VALUES ('402000', 'unknown', 'primary')")
    conn.commit()
    conn.close()
    try:
        report = json.loads(summarize_patch(str(results)))
        assert report["heuristic_only"] is True
        assert "unmatched" in " ".join(report["recommendations"]).lower()
        assert "function(s) removed" not in " ".join(report["recommendations"])
        assert "security-relevant changes" not in " ".join(report["recommendations"])
    finally:
        close_all()


def test_legacy_ranking_labels_scores_as_arbitrary_heuristics(tmp_path):
    _, _, results = make_pair(tmp_path)
    try:
        report = json.loads(rank_changes(str(results)))
        assert report["heuristic_only"] is True
        assert report["score_kind"] == "review_priority_heuristic"
        assert "calibrated" in report["note"]
    finally:
        close_all()


def test_legacy_report_does_not_read_decimal_address_collision(tmp_path):
    helpers = runpy.run_path(str(Path(__file__).with_name("test_mapping_regressions.py")))
    old, new, results = (tmp_path / name for name in ("old.sqlite", "new.sqlite", "diff.diaphora"))
    helpers["_make_function_db"](old, str(int("140001000", 16)), str(int("140001010", 16)))
    helpers["_make_function_db"](new, str(int("150001000", 16)), str(int("150001010", 16)))
    helpers["_make_results"](results, old, new, rows=[("140001000", "root", "150001000", "root")])
    conn = sqlite3.connect(old)
    conn.execute("INSERT INTO functions SELECT 3, '140001000', 'memcpy', nodes, edges, instructions, cyclomatic_complexity, prototype, 'poison', 'memcpy(dst, src, n);', assembly, constants, mnemonics, loops, strongly_connected, names, pseudocode_hash1, pseudocode_hash2 FROM functions WHERE id=1")
    conn.commit()
    conn.close()
    try:
        report = json.loads(summarize_patch(str(results)))
        assert report["security_analysis"]["security_relevant_matches"] == 0
        ranking = json.loads(rank_changes(str(results)))
        assert ranking["ranked"][0]["security_relevant"] is False
    finally:
        close_all()
