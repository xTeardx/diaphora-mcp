## Example: Cross-Binary Function Matching with Diaphora + idalib-mcp

**Goal:** Compare two differently-compiled versions of the same library (`sqlite3.dll` — one built for Python, another for AIMP), find identical and changed functions, and transfer reverse-engineering metadata (function names) from the already-annotated Python build to the unannotated AIMP build.

**Why:** When you have RE'd one binary and need to analyze a sister build (different compiler flags, different consumer, newer/older version), Diaphora automates the comparison. idalib-mcp lets you script the result application without touching the GUI.

---

## Tools Used

| Tool | Purpose |
|---|---|
| `idalib-mcp` | Headless IDA Pro session management, binary analysis, renaming |
| `Diaphora MCP` | Binary diffing — function matching by hash/CFG/mnemonics/etc. |
| `SQLite` | Direct query of `.diaphora` results database for precise address pairs |

---

## Step 1: Open Both Binaries

```json
// Open Python build
{
  "input_path": "sqlite3_python.dll.i64",
  "mode": "force_headless",
  "idle_ttl_sec": 1200
}
// → session_id: "8a831e30"

// Open AIMP build
{
  "input_path": "sqlite3_aimp.dll.i64",
  "mode": "force_headless",
  "idle_ttl_sec": 1200
}
// → session_id: "93b75ebe"
```

## Step 2: Survey Each Binary

**Python build:** 2,532 functions, 439 named, 44 library
**AIMP build:**  3,362 functions, 611 named, 437 library

Key finding: the Python version already has 20+ internal functions manually named (vdbe_exec, sqlite3Malloc, win_utf8_conv, etc.). The AIMP version has only export-table names.

## Step 3: Export Both to Diaphora SQLite

```json
// Export Python → .diaphora.sqlite (64 MB)
export_idb_to_diaphora(idb_path: "sqlite3_python.dll.i64", use_decompiler: false, summaries_only: true)
// → output_path: "sqlite3_python.dll.diaphora.sqlite"

// Export AIMP → .diaphora.sqlite (51 MB)
export_idb_to_diaphora(idb_path: "sqlite3_aimp.dll.i64", use_decompiler: false, summaries_only: true)
// → output_path: "sqlite3_aimp.dll.diaphora.sqlite"
```

## Step 4: Diff the Databases

```json
diff_diaphora_dbs(
  db1: "sqlite3_python.dll.diaphora.sqlite",
  db2: "sqlite3_aimp.dll.diaphora.sqlite",
  output_path: "diff_results.diaphora"
)
```

**Results summary:**

| Match Type | Count | Avg Ratio |
|---|---|---|
| **Best** (perfect) | 42 | 1.000 |
| **Partial** | 847 | 0.576 |
| **Multimatch** | 54 | 0.746 |

**Unmatched:** 1,619 (Python-only) + 1,388 (AIMP-only)

Total: **943 matched** out of ~5,800 functions across both databases.

## Step 5: Security & Root Cause Analysis

```json
detect_security_patches(results_path: "diff_results.diaphora")
// → No security patches found
// Differences are from compiler optimization/configuration, not fixes

find_patch_root(results_path: "diff_results.diaphora")
// → No root-cause cascade detected
```

## Step 6: Extract Mapped Address Pairs (the tricky part)

The `transfer_metadata` tool returns source addresses, not properly mapped target addresses. We bypass it by querying the SQLite results database directly:

```sql
-- Query .diaphora file to get proper Python→AIMP address pairs
SELECT type, address, name, address2, name2, ratio
FROM results
WHERE name NOT LIKE 'sub_%'
ORDER BY ratio DESC;
```

This yields pairs like:

```
vdbe_exec:        Python 0x180081DF0  →  AIMP 0x1800BEB20  (ratio: 0.49)
sqlite3Malloc:    Python 0x180005930  →  AIMP 0x180002EB0  (ratio: 0.36)
win_shm_connect:  Python 0x18000E380  →  AIMP 0x180082B10  (ratio: 0.68)
```

## Step 7: Rename Functions in Target Database

Use the `rename` batch tool with correct AIMP addresses:

```json
{
  "database": "4d8b12b0",  // AIMP session
  "batch": {
    "func": [
      {"addr": "0x1800beb20", "name": "vdbe_exec"},
      {"addr": "0x18005bea0", "name": "vdbe_exec_common"},
      {"addr": "0x1800ced80", "name": "vdbe_prep_check"},
      {"addr": "0x1800e13b0", "name": "sqlite3Parser"},
      {"addr": "0x180002eb0", "name": "sqlite3Malloc"},
      {"addr": "0x18002b2a0", "name": "sqlite3MallocSize"},
      {"addr": "0x180034210", "name": "sqlite3ErrorCheck"},
      {"addr": "0x180082b10", "name": "win_shm_connect"},
      // ... 15 more
    ]
  }
}
```

**Note:** addresses must have `0x` prefix or parsing fails.

## Step 8: Save and Verify

```json
// Save the updated .i64
idb_save(database: "4d8b12b0")
// → sqlite3_aimp.dll.i64

// Verify: named functions increased from 611 → 640 (+29)
survey_binary(database: "4d8b12b0")
```

## Step 9: Clean Up Lock Files

Headless workers leave `.id0`, `.id1`, `.nam` files that prevent the GUI from opening the `.i64`:

```bash
# Kill the worker process first
taskkill /F /PID 26264
# Then delete loose working files
rm "sqlite3_aimp.dll.id0" "sqlite3_aimp.dll.id1" "sqlite3_aimp.dll.nam"
```

---

## Results

**23 internal sqlite3 functions transferred**, including:

| Function | Description |
|---|---|
| `vdbe_exec` | Main VDBE execution loop — the heart of SQL execution |
| `sqlite3Malloc` | Internal memory allocator |
| `sqlite3Parser` | Lemon-generated SQL parser |
| `btree_cursor` | B-tree cursor operations |
| `win_utf8_conv` | Windows UTF-8 conversion |
| `where_loop_search` | Query planner WHERE loop search |
| `pager_write_page` | Pager page writing |
| `vdbe_dispatch` | VDBE opcode dispatch |

Plus **8 sqlite3_* export names** that were still `sub_*` in the AIMP version.

**7 names skipped** due to export-table name conflicts — the internal implementation at a different address shares a name with the real export stub.

**Named functions total:** 611 → 640 (+4.7%).

## Key Lessons

1. **Don't use `transfer_metadata`** — query the `.diaphora` SQLite directly for correct address pairs
2. **Always add `0x` prefix** to addresses in idalib-mcp tools
3. **Set `idle_ttl_sec` high enough** or the worker dies mid-session
4. **Clean up `.id0`/`.id1`/`.nam`** after headless work or IDA GUI can't open the file
5. **Use `use_decompiler: false` and `summaries_only: true`** for large binaries to keep export fast
