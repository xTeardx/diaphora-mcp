import json
import sqlite3

from diaphora_mcp.core.security import match_security_keywords


def test_security_keyword_matching_avoids_substring_false_positive():
    assert not match_security_keywords("author", "", "")["matched"]
    assert match_security_keywords("authenticate_user", "", "")["matched"]


def test_integrity_keywords_are_classified_explicitly():
    result = match_security_keywords("verify_checksum", "", "")

    assert result["matched"]
    assert "integrity" in result["categories"]


def test_security_report_marks_keyword_results_as_heuristic(tmp_path):
    path = tmp_path / "results.diaphora"
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE config (main_db TEXT, diff_db TEXT);
        CREATE TABLE results (address TEXT, name TEXT, address2 TEXT,
            name2 TEXT, ratio REAL, type TEXT);
        CREATE TABLE unmatched (address TEXT, name TEXT, type TEXT);
        INSERT INTO results VALUES ('401000', 'authenticate_user',
            '501000', 'authenticate_user', 1.0, 'best');
        """
    )
    conn.commit()
    conn.close()

    from diaphora_mcp.core.security import analyze_diff_results

    report = json.loads(analyze_diff_results(str(path)))

    assert report["heuristic_only"] is True
    assert report["confirmed"] is False
    assert report["matches"][0]["heuristic_confidence"] == "low"
