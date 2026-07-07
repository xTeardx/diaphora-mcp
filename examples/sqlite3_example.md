[Read in Russian](sqlite3_example.ru.md)

# Diaphora MCP — SQLite3 DLL Binary Diffing Example

This example compares two Windows DLLs based on SQLite3 using **Diaphora MCP** (IDA Pro + Diaphora integration via the MCP protocol).

## 📂 Source Files

| File | Size | SQLite Version | Hash |
|---|---|---|---|
| `sqlite3_aimp.dll` | 1.6 MB | **2015** (2015-10-16) | `767c1727fec4ce11b83f25b3f1bfcfe68a2c8b02` |
| `sqlite3_python.dll` | 1.5 MB | **2023** (2023-05-16) | `831d0fb2836b71c9bc51067c49fee4b8f18047814f2ff22d817d25195cf350b0` |

Both DLLs export the SQLite3 API, but:

- **aimp** — older build (2015) with custom naming (`_0` suffix, many `sub_*`)
- **python** — newer build (2023) with canonical function names

Source IDB/i64 files: `sqlite3_aimp.dll.i64` (62 MB), `sqlite3_python.dll.i64` (77 MB).

---

## 🛠️ MCP Tools Used

### 1. Full Pipeline (batch_export_and_diff)

```json
{
  "idb1_path": "sqlite3_aimp.dll.i64",
  "idb2_path": "sqlite3_python.dll.i64",
  "use_decompiler": false
}
```

Executes:
- Export both .i64 to Diaphora SQLite
- Run the diffing algorithm
- Return structured results

### 2. Summary (get_diff_summary)

Overall match statistics, top best/partial matches.

### 3. Ranking (rank_changes)

Sort functions by importance with security classification.

### 4. Function Comparison (compare_functions)

Side-by-side assembly and pseudocode for matched function pairs.

### 5. Behaviour Change Detection (detect_behavior_change)

Analysis: added/removed calls, constants, CFG changes.

### 6. Call Graph (get_changed_callgraph)

Who called and what the function called — before and after.

### 7. Pseudocode via IDA MCP (decompile)

Real Hex-Rays C-like pseudocode for selected functions.

### 8. Security Analysis (detect_security_patches)

Find security patches: bounds checks, null checks, validation, etc.

### 9. Component Analysis (analyze_component)

Group analysis of related functions.

---

## 📊 Output Format

Diaphora MCP returns **structured JSON**, including:

### Diff Summary

```json
{
  "best_matches": 60,
  "partial_matches": 993,
  "unreliable_matches": 0,
  "multimatches": 52,
  "unmatched_primary": 2647,
  "total_matches": 1105
}
```

### Each Matched Pair

```json
{
  "type": "partial",
  "address": "1800beb20",
  "name": "sub_1800BEB20",
  "address2": "180081df0",
  "name2": "vdbe_exec",
  "ratio": "0.4897823",
  "nodes1": 18,
  "nodes2": 40,
  "description": "assembly changed"
}
```

### Ranked Changes

```json
{
  "score": 100,
  "type": "partial",
  "ratio": "0.4805652",
  "name_old": "sqlite3MallocSize",
  "name_new": "sqlite3MallocSize",
  "security_relevant": true,
  "security_categories": ["memory"],
  "complexity_change": 0,
  "ida_pro_mcp": {
    "db1": "aimp.diaphora.sqlite",
    "db2": "python.diaphora.sqlite",
    "addr1": "18002b2a0",
    "addr2": "180005dc0"
  }
}
```

---

## 🔬 Key Results

### Overall Statistics

| Match Type | Count | Average Similarity |
|---|---|---|
| ✅ Best (100% identical) | 60 | 1.000 |
| 🔶 Partial (partially changed) | 993 | 0.591 |
| 🔷 Multimatch (1→N) | 52 | 0.761 |
| ❌ Unmatched (aimp only) | 1,282 | — |
| ❌ Unmatched (python only) | 1,365 | — |
| **Total** | **1,105** | — |

### Security-Relevant Changes (23 found)

| Function (old → new) | Category | Similarity | What Changed |
|---|---|---|---|
| `sub_18002B070` → `sqlite3_realloc64` | memory | 0.50 | New allocator with checks |
| `sub_1800BEB20` → `vdbe_exec` | process | 0.49 | +50 instructions, retry loop |
| `sub_18002B2A0` → `sqlite3MallocSize` | memory | 0.48 | Multi-level freelist buckets |
| `sub_18002AB40` → `sqlite3_malloc64` | memory | 0.45 | New malloc implementation |
| `sub_1800CED80` → `vdbe_prep_check` | validation | 0.43 | Strengthened validation |

---

## 🧬 Example: `vdbe_exec` Comparison

### AIMP (old, 2015) — 94 instructions, 18 blocks

```c
__int64 __fastcall sub_1800BEB20(a1, a2, a3, a4, a5, a6, a7) {
    *a6 = 0;
    if (!a1) { sqlite3_log(…); return 21; }
    // Check via DWORD magic numbers
    v13 = *(DWORD *)(a1 + 92);
    if (v13 != 0xA029A697) { /* unopened/invalid */ }
    // mutex_enter
    sub_180032720(a1);           // prepare
    v15 = sub_1800BE120(a1, …);  // exec (single pass)
    if (v15 == 17) {             // SQLITE_OK?
        sqlite3_finalize(*a6);
        v15 = sub_1800BE120(a1, …); // retry
    }
    sub_18000A790(a1);           // cleanup
    return v15;
}
```

### Python (new, 2023) — 144 instructions, 40 blocks

```c
__int64 __fastcall vdbe_exec(a1, a2, a3, a4, a5, a6, a7) {
    v7 = 0;  // retry counter
    *a6 = 0;
    if (!a1) { sqlite3_log(…); goto misuse; }
    v14 = *(BYTE *)(a1 + 113);   // enum-based check
    if (v14 != 118) { /* unopened/invalid */ }
    // mutex_enter
    if (!*(BYTE *)(a1 + 111))
        sub_18001E740(a1);       // check cancel
    while (1) {
        v17 = sub_180081850(a1, …); // execute step
        if (!v17) break;
        if (*(a1 + 103)) break;  // cancel requested
        if (v17 == 513) {        // SQLITE_SCHEMA
            if (v7++ >= 25) break;  // max 25 retries
        } else if (v17 == 17) {
            // iterate statements → cancel VDBE on schema change
            for (v23=0; v23 < *(a1+40); v23++) {
                v25 = stmt[v23];
                if (v25->flags & 8) sub_180067CB0(v25);
            }
            if (v7++) break;
        }
    }
    // sqlite3ApiExit, cleanup
    return v27;
}
```

### Key Differences

| Change | Old | New |
|---|---|---|
| **Retry loop** | None | Up to 25 attempts on lock |
| **SQLITE_SCHEMA** | Ignored | Automatic restart |
| **Cancel** | None | Cancel flag check |
| **Connection check** | DWORD magic (0xA029A697) | Enum byte (118) |
| **Error handling** | Direct return | Via sqlite3ApiExit |

---

## 🧬 Example: `sqlite3MallocSize`

### AIMP (old) — single freelist bucket

```c
if (!a1) goto alloc;
if (*(a1+81)) return 0;          // OOM guard
if (!*(a1+338)) goto alloc;      // freelist disabled
if (size > *(a1+336)) {          // too big
    (*(a1+352))++; goto alloc;   // miss counter
}
result = *(a1+360);              // one freelist
if (result) { *(a1+360) = *result; }
else { (*(a1+356))++; }
```

### Python (new) — 4 freelist buckets (by size)

```c
if (size > *(a1+420)) {
    if (*(a1+416)) { if (*(a1+103)) return 0; }
    else { (*(a1+436))++; goto sub_180005D80; }
}
// <= 128 bytes → bucket @ offset 472
// > 128 ≤ max  → bucket @ offset 464
//                 bucket @ offset 456
//                 bucket @ offset 448
// pop from linked list, hit counter, return
```

---

## ⚠️ Diaphora MCP Usage Notes

### 1. Comparison Direction Matters

```
aimp → python:  60 best + 993 partial = 1105 matches
python → aimp:  42 best + 847 partial =  943 matches
```

Diaphora is **asymmetric** — when the primary DB is less complete (aimp with `sub_*`), the algorithm finds more matches.

### 2. Decompiler Slows Export 10-30×

- `use_decompiler: false` — fast first pass (no pseudocode in SQLite)
- `use_decompiler: true` — includes C pseudocode, but 10-30× slower

### 3. .i64 Size Matters
- Files >100 MB: recommended `summaries_only: auto`
- For large binaries: limit `limit` and `unmatched_limit`

### 4. IDA MCP Complements Diaphora
- Diaphora provides **diffing** (who changed, how much)
- IDA MCP provides **deep analysis** (pseudocode, call graph, xrefs)
- The combination gives the fullest picture

---

## 📋 Complete MCP Tool Call List

### Diaphora MCP
| Tool | Purpose |
|---|---|
| `batch_export_and_diff` | Full pipeline export + diff |
| `get_diff_summary` | Summary statistics |
| `rank_changes` | Ranking with security analysis |
| `compare_functions` | Side-by-side assembly |
| `detect_behavior_change` | Natural-language change description |
| `get_changed_callgraph` | Call graph before/after |
| `detect_security_patches` | Security patch detection |
| `explain_similarity` | Breakdown of why functions match at X% |
| `find_function_match` | Find correspondence by address/name |

### IDA MCP
| Tool | Purpose |
|---|---|
| `idb_open` | Open .i64 (.idb) |
| `decompile` | Get Hex-Rays C pseudocode |
| `analyze_component` | Analyse group of related functions |
| `survey_binary` | Quick binary overview |
| `func_profile` | Function profiling |

---

## 🏁 Conclusions

1. **Diaphora MCP successfully compares two binaries** and produces structured JSON with matched pairs, similarity percentages, and match types.

2. **Combination with IDA MCP** provides C pseudocode and detailed analysis for selected functions, compensating for the lack of a decompiler in Diaphora SQLite.

3. **SQLite3 2015 → 2023**: changes affected all key subsystems — VDBE (retries, cancel), memory manager (4-level buckets), error handling (sqlite3ApiExit).

4. **Security-relevant changes** (23 functions) — mainly memory management and process execution, but Diaphora did not flag them as explicit security patches.

5. **JSON format** with `ida_pro_mcp` references makes it easy to transition from summary to deep analysis of a specific function.

---

*Generated with Claude Code + Diaphora MCP + IDA MCP*
