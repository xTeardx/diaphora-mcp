# Tool reference

The server exposes 10 core tools by default. Discover exact JSON schemas through MCP `tools/list`.

| Tool | Purpose |
| --- | --- |
| `export_idb_to_diaphora` | Export one IDB; explicit `headless`, `auto`, or `gui` backend |
| `batch_export_and_diff` | Validated headless export of old/new IDBs, diff, bounded first page |
| `diff_diaphora_dbs` | Compare existing official exports, preserving existing outputs |
| `get_diff_summary` | Aggregated match/unmatched counts and bounded examples |
| `get_diff_results` | Filtered and sorted SQL pages of matches and unmatched rows |
| `get_export_info` | Export metadata and function/instruction counts |
| `search_export_db` | Search function names, instruction counts, complexity |
| `get_function_pseudocode` | Retrieve available pseudocode/assembly and metadata |
| `compare_functions` | Code and measured differences for a resolved old/new pair |
| `get_changed_callgraph` | Compare mapped neighbors; unresolved edges remain separate |

## Results pagination

`get_diff_results(results_path, match_type="all", min_ratio=0.0, limit=500, unmatched_limit=100, offset=0, unmatched_offset=0, sort_by="ratio", sort_order="asc")`

- Page sizes must be positive integers and are capped at 5000; offsets must be nonnegative integers.
- `sort_by`: `ratio`, `address`, `address2`, `name`, `name2`, or `type`; `sort_order`: `asc` or `desc`.
- Lower ratios come first by default, followed by a stable row tie-breaker.
- Follow `next_offset` and `next_unmatched_offset` independently until null. Counts cover complete sets; `total_matches` respects the match filter, `counts` gives all categories, and unmatched rows have their own total.
- Retain the same filter/sort arguments between pages. Result files must remain unchanged while paging.

## Function identity

Pass `match_results_path` for cross-version comparisons. An explicit second selector can identify the pair directly; otherwise supplied Diaphora mappings take precedence. Without a mapping, only unambiguous name/hash evidence can establish a candidate. Equal addresses alone do not identify corresponding functions. Missing or ambiguous matches are reported as unresolved; invalid match files return errors.

For code analysis, export with `use_decompiler=true` and `summaries_only=false`. Missing pseudocode is unavailable evidence, not proof that behavior stayed unchanged.

## Optional legacy tools

Set `DIAPHORA_ENABLE_LEGACY_TOOLS=1` before starting the server to expose the previous 21-tool interface. The additional tools are:

`find_function_match`, `explain_similarity`, `detect_behavior_change`, `compare_call_path`, `find_patch_root`, `rank_changes`, `summarize_patch`, `analyze_diff_results`, `detect_security_patches`, `transfer_metadata`, and `performance_report`.

These are compatibility and triage aids. Feature/ranking/root scores use arbitrary weights, do not explain Diaphora's internal ratio, and do not measure calibrated confidence, importance, exploitability or causation. Behavior summaries describe measured differences; security flags indicate patterns requiring inspection. Unmatched functions are not confirmed additions/deletions. Metadata transfer prepares data for review and does not apply changes to IDA.

## Input/output contract

Inspection tools accept Diaphora exports; diff tools require the supported official Diaphora 3.4.1 schema baseline. Results tools expect `.diaphora` SQLite results, never an `.i64`/`.idb`. Old is primary; new is secondary. Newly generated exports/results must stay below `DIAPHORA_OUTPUT_ROOT` (or the documented input-directory fallback) and cannot replace an existing target.
