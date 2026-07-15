# GitHub-Ready MCP Documentation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Publish an English-first, agent-friendly GitHub presentation of Diaphora MCP with accurate setup, workflow, limitations, examples, and contribution guidance.

**Architecture:** Keep `README.md` as the canonical entry point and move detailed operational material into focused `docs/` pages. Add small configuration/workflow examples that contain placeholders rather than local paths or proprietary fixtures. Validate documentation through repository checks and a link/path consistency script.

**Tech Stack:** Markdown, JSON, GitHub Actions YAML, Python pytest/compileall, existing setuptools/pyproject configuration.

---

### Task 1: Build the canonical English README

**Files:**
- Modify: `README.md`
- Reference: `pyproject.toml`, `diaphora_mcp/diaphora_mcp_server.py`, `AGENTS.md`

**Step 1: Inventory public commands and tool groups**

Run `rg -n` against the server registrations, pyproject entry points, and current docs. Record only commands and parameters that exist in the code.

**Step 2: Rewrite the README sections**

Include project value proposition, prerequisites, installation, MCP client configuration, quick-start workflow, export mode table, tool-group table, examples, development commands, security/data handling, limitations, and links to detailed docs. Keep the first screen concise and make the recommended path explicit: `batch_export_and_diff(..., export_mode="headless")`.

**Step 3: Verify references**

Run `rg` to ensure every documented file and entry point exists. Do not include IDB/SQLite fixtures or machine-specific paths.

### Task 2: Add focused operational documentation

**Files:**
- Create: `docs/CONFIGURATION.md`
- Create: `docs/WORKFLOWS.md`
- Create: `docs/TOOLS.md`
- Create: `docs/LIMITATIONS.md`

**Step 1: Document configuration**

Explain `IDAT_PATH`, `DIAPHORA_DIR`, `DIAPHORA_OUTPUT_ROOT`, stdio startup, Windows path quoting, and restart behavior.

**Step 2: Document workflows**

Show single export, recommended batch diff, result inspection, address mapping, GUI-only export, and recovery from locks/schema failures.

**Step 3: Document tools and limitations**

Group tools by export, diff, analysis, graph, ranking/security, metadata, and performance. State that `.i64` is not a results SQLite database, matching is heuristic, GUI bridge is optional, and IDA/Diaphora licensing remains external.

### Task 3: Make the Russian companion useful

**Files:**
- Modify: `README.ru.md`
- Reference: `docs/CONFIGURATION.md`, `docs/WORKFLOWS.md`, `docs/LIMITATIONS.md`

**Step 1: Align Russian quick start**

Translate the essential setup, recommended headless workflow, export modes, matching example, and limitations. Link to English detailed pages for the canonical reference.

**Step 2: Check parity**

Confirm that Russian instructions do not mention removed flags, stale ports, or old GUI behavior.

### Task 4: Add agent and contributor guidance

**Files:**
- Modify: `AGENTS.md`
- Modify: `CONTRIBUTING.md`
- Modify: `SECURITY.md`
- Create: `.github/PULL_REQUEST_TEMPLATE.md`
- Create: `.github/ISSUE_TEMPLATE/bug_report.md`
- Create: `.github/ISSUE_TEMPLATE/feature_request.md`

**Step 1: Clarify agent rules**

Add repository map, safe fixture policy, validation commands, source-of-truth rules, and an instruction to prepare a plan before broad changes.

**Step 2: Clarify contributions and security**

Document supported Python/IDA assumptions, test expectations, binary fixture handling, responsible disclosure, and required PR evidence.

**Step 3: Add templates**

Ensure bug reports collect OS, IDA/Diaphora versions, backend/mode, sanitized logs, and reproduction steps without encouraging proprietary uploads.

### Task 5: Add examples and CI

**Files:**
- Create: `examples/mcp-config.windows.json`
- Create: `examples/mcp-config.generic.json`
- Create: `examples/batch-workflow.md`
- Create: `.github/workflows/ci.yml`

**Step 1: Add safe client examples**

Use placeholders and stdio commands. Mark Windows `cmd /c` quoting and environment overrides clearly.

**Step 2: Add workflow example**

Show tool-call-shaped JSON and expected result categories without embedding real user paths or binaries.

**Step 3: Add CI**

Run on supported pushes/PRs: Python setup, dependency installation from project metadata, pytest, compileall, diff-check, and a check that prohibited binary fixtures are absent from tracked files.

### Task 6: Verify and commit

**Files:**
- Test: repository-wide checks and documentation path checks

**Step 1: Run automated checks**

Run `python -m pytest -q`, `python -m compileall -q .`, `git diff --check`, and a PowerShell path/link existence check for documented local files.

**Step 2: Inspect the final diff**

Confirm no IDB, SQLite, log, generated, or machine-specific files were staged.

**Step 3: Commit**

Use a focused commit such as `docs: publish GitHub-ready MCP documentation`.
