# Changelog

## Unreleased

- Reduced the default MCP surface to 10 comparison tools; the previous 21 tools remain opt-in through `DIAPHORA_ENABLE_LEGACY_TOOLS=1`.
- Protected batch/diff outputs with preflight validation, staging, exclusive publication and ownership-based cleanup; preserved cancellation and rejected failed subprocess results.
- Removed address-only identity guesses and made cross-version function/graph resolution use authoritative mappings, with explicit ambiguity handling.
- Added bounded SQL result pagination and change-oriented deterministic sorting.
- Strengthened official diff-schema validation and corrected unsafe-call removal signals.
- Removed unused placeholder/instrumentation/repository wrappers and clarified legacy heuristic limitations.

- Added authoritative Diaphora old-to-new function mapping for rebased
  cross-version analysis.
- Fixed decimal-address metadata transfer and complete diff statistics.
- Marked security outputs as heuristic triage signals.
- Added reproducible unit fixtures and GitHub CI/community files.
