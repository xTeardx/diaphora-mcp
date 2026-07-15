# Diaphora MCP Remediation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Correct cross-version identity handling, improve result reliability, and make the repository publishable and reproducible.

**Architecture:** Diaphora remains the matching authority. A shared `FunctionMapping` translates old database addresses to new database addresses; graph, metadata, ranking, and reports consume that mapping. Address parsing and schema adaptation stay centralized in SQLite utilities.

**Tech Stack:** Python 3.10+, SQLite, pytest, FastMCP, GitHub Actions.

---

### Task 1: Canonical mapping model

**Files:**
- Create: `diaphora_mcp/core/mapping.py`
- Modify: `diaphora_mcp/utils/sqlite.py`
- Test: `tests/test_mapping_regressions.py`

Steps:
1. Add failing tests for old-to-new lookup, reverse lookup, decimal/hex normalization, and added/removed entries.
2. Run the focused tests and verify they fail for the missing mapping API.
3. Implement the smallest mapping model and loader from adaptive Diaphora results.
4. Run focused tests, then the existing suite.

### Task 2: Cross-version analysis and graph mapping

**Files:**
- Modify: `diaphora_mcp/core/analysis.py`
- Modify: `diaphora_mcp/core/graph.py`
- Test: `tests/test_mapping_regressions.py`

Steps:
1. Add failing tests for rebased `compare_functions`, changed callgraphs, and call-path comparison.
2. Run focused tests and verify the old same-address behavior fails them.
3. Resolve explicit mapping first, preserve safe fallback behavior, and compare graph identities through mapping.
4. Run focused and full tests.

### Task 3: Metadata transfer and decimal addresses

**Files:**
- Modify: `diaphora_mcp/core/metadata.py`
- Modify: `diaphora_mcp/utils/sqlite.py`
- Test: `tests/test_mapping_regressions.py`

Steps:
1. Add failing decimal-address metadata mapping tests.
2. Run them to verify the mismatch.
3. Use canonical source and target keys and reject ambiguous unmapped targets when a results file is provided.
4. Run the suite.

### Task 4: Result statistics and reproducible fixtures

**Files:**
- Modify: `diaphora_mcp/core/diff.py`
- Modify: `tests/test_remediation_regressions.py`
- Create: `tests/helpers.py` or synthetic fixture helpers in tests.

Steps:
1. Add a failing test showing `total_matches` must exceed the display limit.
2. Replace ignored fixture dependency in unit tests with tracked synthetic data.
3. Compute counts before limiting rows and distinguish display truncation from total count.
4. Run unit and full tests.

### Task 5: Security triage semantics

**Files:**
- Modify: `diaphora_mcp/core/security.py`
- Modify: `diaphora_mcp/models.py`
- Test: `tests/test_security_regressions.py`

Steps:
1. Add failing tests for token-boundary matching and explicit heuristic confidence/evidence.
2. Implement bounded matching and triage labels without claiming vulnerability confirmation.
3. Run focused and full tests.

### Task 6: GitHub project health

**Files:**
- Create: `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`
- Create: `.github/workflows/tests.yml`, `.github/dependabot.yml`, `.github/pull_request_template.md`
- Create: `.github/ISSUE_TEMPLATE/bug_report.yml`, `.github/ISSUE_TEMPLATE/feature_request.yml`
- Modify: `README.md`, `README.ru.md`, `pyproject.toml`

Steps:
1. Add CI and documentation files with pinned, minimal tooling.
2. Document IDA/Diaphora external dependencies and licensing boundaries.
3. Validate YAML, package metadata, and clean-clone test behavior.

### Task 7: Final verification

Run:

```powershell
python -m pytest -q
python -m compileall -q .
python -m pip check
git diff --check
```

Review changed files for generated binaries, secrets, and untracked fixtures before reporting completion.
