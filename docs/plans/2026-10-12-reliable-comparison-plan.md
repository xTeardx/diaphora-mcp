# Reliable comparison implementation plan

**Goal:** Make two-version comparison safe and evidence-based, with a compact default MCP interface.

**Scope approved:** The user's request to fix all findings in the preceding audit. Preserve export modes and old-primary/new-secondary order. Work on `codex/reliable-comparison`; no push, merge, or upstream IDA integration edits.

## Task 1: Safe export/diff pipeline
- [x] Add and reproduce regression tests for pre-existing output preservation, root escape, identical basenames, failure/cleanup ownership, and async cancellation.
- [x] Route batch exports through the validated staged single-export implementation. Use separate old/new output names; validate all targets before starting. Diff into a unique staged file; publish exclusively and reject nonzero subprocess exits. Keep timeout and cancellation cleanup bounded.
- [x] Test a successful mocked pipeline and failures. Never delete artifacts not created by this operation.

## Task 2: Authoritative identity and mapped graph edges
- [x] Reproduce same-address false match, renamed name-only lookup, rebased edge false changes, and moved-as-deleted behavior in synthetic tests.
- [x] Centralize pair resolution: explicit second selector or Diaphora mapping first, then unambiguous non-generated name/hash evidence. Equal addresses alone are not identity. Invalid/missing mappings must not silently fall back.
- [x] Translate old neighbors before graph comparison. Preserve ambiguity and match evidence; make legacy behavior/similarity tools accept mapping and avoid unsupported deleted/semantic claims.
- [x] Verify hex/decimal mapping and existing tests.

## Task 3: Bounded results and schema validation
- [x] Reproduce inaccessible later results, full-table loading, weak schema acceptance, and added memcpy mislabeled removed.
- [x] Implement SQL pagination (`offset`, `unmatched_offset`, deterministic sort) and counts without loading entire tables. Preserve existing arguments and add next offsets.
- [x] Validate actual upstream diff-required tables/columns using available official source; distinguish basic inspection from diff readiness. Fix unsafe-call removal indicators to require actual removal.
- [x] Verify filtering, alias schemas, pagination beyond 5000 and invalid arguments.

## Task 4: Focused MCP and docs
- [x] Add registry tests: 10 default tools, legacy extras only with `DIAPHORA_ENABLE_LEGACY_TOOLS=1`.
- [x] Keep export, batch, diff, results, summary, export info, search, code, compare and mapped callgraph public by default. Clearly label legacy scoring as heuristic evidence, not calibrated confidence or semantic proof.
- [x] Remove unused hashing/metrics placeholders and unused repository/context helpers only after reference search.
- [x] Update English/Russian README, tool/config/workflow/limitations docs and changelog.

## Verification and review
- [x] Run focused regression tests after each patch and request independent code review for the combined changes.
- [x] Run `python -m pytest -q`, `python -m compileall -q .`, `git diff --check`; inspect status and final diff.
- [x] Record completed tasks and decisions here. Report exact validation and IDA integration limitations.

**Coordination:** Tasks 1/2/3 own disjoint production files and separate new test files. Task 4 owns registration/docs. Shared interface changes must be communicated before use. Regression tests precede implementation. No commits from worker agents.

**Decision:** Keep legacy tool implementations opt-in to preserve integrations while removing misleading default tool choices. No worktree is required for these reversible in-place edits on a dedicated branch.

## Completion record

- All four tasks implemented with failing regression reproduction before patches. Dedicated test modules cover output ownership, relative paths, cancellation/nonzero exits, authoritative identity/ambiguity, official padded hexadecimal results with decimal exports, mapped edges/cache lookups, pagination and strict schema, legacy labels and registration.
- Independent review found five additional identity/export defects; all corrected, plus the introduced decimal cache-call boundary regression. Final scoped review and full checks recorded in the delivery message.
- Real installed Diaphora 3.4.1 diff engine smoke: two synthetic exports created from upstream schema, one best match, actual generated padded-hex result resolves old decimal 4198400 to new decimal 5246976. Real IDA export was not run.
- Removed unused hashing/metrics modules, DatabaseRepository and connection context wrappers after reference searches. No upstream ida_mcp.py edits or generated databases committed.
- Compatibility decisions: legacy tools require startup opt-in; result limits must be positive (capped 5000); lowest-ratio-first sorting; unambiguous evidence required on both sides. Strict schema baseline is 3.4.1, excluding export-only fields. Branch remains local; changes are left reviewable in the working tree.
