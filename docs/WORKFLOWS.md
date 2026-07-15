# Workflows

## Recommended: export and diff two IDBs

1. Analyze both inputs in IDA and save `.i64`/`.idb` databases.
2. Call `batch_export_and_diff` with `export_mode="headless"`, `use_decompiler=false`, and `summaries_only=true` for large databases.
3. Keep the returned `.diaphora.sqlite` files and `.diaphora` result file together.
4. Call `get_diff_summary` first, then use `get_diff_results` with a suitable `min_ratio` or `match_type`.
5. Use `find_function_match` and `compare_functions` for a specific old address.
6. Pass `match_results_path` to address-aware comparison and graph tools when old/new image bases differ.
7. Use `ida-pro-mcp`/`idalib-mcp` for low-level validation in the original IDA databases.

## Example

```text
batch_export_and_diff(
  idb1_path="C:/analysis/v1.i64",
  idb2_path="C:/analysis/v2.i64",
  output_dir="C:/diaphora-outputs/v1-v2",
  export_mode="headless",
  summaries_only=true,
  use_decompiler=false
)
```

Then:

```text
get_diff_summary(results_path=RESULTS)
find_function_match(db1_path=OLD_SQLITE, db2_path=NEW_SQLITE, address="1800d6b80")
compare_functions(
  db1_path=OLD_SQLITE,
  db2_path=NEW_SQLITE,
  address="1800d6b80",
  match_results_path=RESULTS
)
```

## Single export

Use `export_idb_to_diaphora` when you need one database for later analysis. Prefer `headless` when the file will be compared later. `auto` is convenient for an active GUI session but still validates the resulting schema.

## GUI export

Use `export_mode="gui"` only for an intentionally open IDA session. The session must have the requested IDB open. If no matching GUI bridge exists, the call fails instead of silently launching headless IDA. This makes backend selection visible and avoids unexpected process or lock behavior.

## Failure recovery

- **Output outside root:** choose a path below `DIAPHORA_OUTPUT_ROOT`.
- **Target already exists:** choose a new output path; the server does not overwrite exports.
- **IDB lock or process conflict:** close the IDA session, use a copy, or use the active GUI backend.
- **Missing `program`/`callgraph_primes`:** discard the incomplete export and rerun headless.
- **No matches:** verify that both inputs are official Diaphora exports and that the intended old/new order was used.

## Interpreting matching

`best`, `partial`, and `multimatch` are Diaphora result categories. Ratios and confidence are evidence for prioritization, not proof of semantic equivalence. Always inspect assembly, pseudocode where available, CFG, and call sites before making a security claim.
