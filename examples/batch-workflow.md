# Batch workflow example

This example uses placeholders. Replace them with paths below your configured output root.

## 1. Export and diff

```text
batch_export_and_diff(
  idb1_path="C:/analysis/old.i64",
  idb2_path="C:/analysis/new.i64",
  output_dir="C:/diaphora-outputs/old-new",
  export_mode="headless",
  use_decompiler=false,
  summaries_only=true,
  cleanup=false,
  limit=100,
  unmatched_limit=50
)
```

Keep the returned paths:

```text
OLD_SQLITE  = <steps.export1.output>
NEW_SQLITE  = <steps.export2.output>
RESULTS     = <steps.diff.output>
```

## 2. Inspect the result

```text
get_diff_summary(results_path=RESULTS)
get_diff_results(results_path=RESULTS, match_type="best", limit=20)
```

## 3. Follow one function

```text
find_function_match(
  db1_path=OLD_SQLITE,
  db2_path=NEW_SQLITE,
  address="1800d6b80"
)

compare_functions(
  db1_path=OLD_SQLITE,
  db2_path=NEW_SQLITE,
  address="1800d6b80",
  match_results_path=RESULTS
)

get_changed_callgraph(
  db1_path=OLD_SQLITE,
  db2_path=NEW_SQLITE,
  address="1800d6b80",
  match_results_path=RESULTS
)
```

If a tool reports an unmatched function, verify the old/new order, the input schema, and whether the function was actually present in both builds.
