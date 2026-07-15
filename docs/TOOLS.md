# Tool reference

The server registers tools through `diaphora_mcp/diaphora_mcp_server.py`. Clients should discover the exact JSON schemas through MCP `tools/list`; this page explains selection by task.

## Export

- `export_idb_to_diaphora`: export one IDB; choose `export_mode` explicitly.
- `batch_export_and_diff`: headless export of both inputs, Diaphora diff, and a bounded summary.

## Diff and results

- `diff_diaphora_dbs`: run a diff over two existing official exports.
- `get_diff_summary`: compact statistics and top matches.
- `get_diff_results`: filtered match/unmatched rows.

## Database inspection

- `get_export_info`: function count and export metadata.
- `search_export_db`: search names, instruction counts, or complexity.
- `get_function_pseudocode`: retrieve pseudocode/assembly for a known function.

## Matching and behavior

- `find_function_match`: locate a likely counterpart with confidence and evidence.
- `compare_functions`: compare both sides; provide `match_results_path` when rebasing is present.
- `explain_similarity`: break down similarity signals.
- `detect_behavior_change`: summarize likely logic changes.

## Graph and change prioritization

- `get_changed_callgraph`: compare callers/callees, preferably with result mapping.
- `compare_call_path`: compare call paths to a bounded depth.
- `find_patch_root`: identify likely upstream causes in changed dependency chains.
- `rank_changes`: prioritize functions for review.
- `summarize_patch`: produce a higher-level report.

## Security and metadata

- `analyze_diff_results` and `detect_security_patches`: heuristic security triage only.
- `transfer_metadata`: prepare selective metadata transfer; review before applying it in IDA.
- `performance_report`: inspect cache/performance state.

## Input contract

Database/results tools expect files produced by Diaphora. Do not pass `.i64` directly to results tools. Keep old/new order consistent: the primary database is the old version, and the secondary database is the new version.
