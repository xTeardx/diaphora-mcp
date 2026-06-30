[Читать на русском](sqlite3_example.ru.md)

# Example: Diffing sqlite3.dll (Python vs AIMP)

This example demonstrates how to use the Diaphora MCP server to perform binary comparison (diffing) on two small, real-world native Windows DLLs that already exist on your system.

We will compare two different compiled versions of `sqlite3.dll`:
1. **Python 3.12 version**: `C:\Users\<User>\AppData\Local\Programs\Python\Python312\DLLs\sqlite3.dll` (compiled ~Oct 2023, ~1.50 MB)
2. **AIMP Player version**: `D:\Programs\AIMP\sqlite3.dll` (compiled ~Dec 2023, ~1.63 MB)

---

## 1. Preparing the IDA Pro Databases (.i64)

1. Create a workspace folder, e.g., `E:\Program Files\IdaPro_projects\test\`.
2. Copy both DLL files to this folder, renaming them for clarity:
   - Copy Python's DLL as `sqlite3_python.dll`
   - Copy AIMP's DLL as `sqlite3_aimp.dll`
3. Open both DLLs in IDA Pro to let IDA perform auto-analysis and save the databases (`sqlite3_python.dll.i64` and `sqlite3_aimp.dll.i64`). 
   *Note: Since you have `ida-pro-mcp` configured, you can simply open them in your active IDA Pro GUI sessions. Alternatively, you can generate them headless via command line:*
   ```cmd
   "C:\Program Files\IDA Pro 9.3\idat.exe" -B "E:\Program Files\IdaPro_projects\test\sqlite3_python.dll"
   "C:\Program Files\IDA Pro 9.3\idat.exe" -B "E:\Program Files\IdaPro_projects\test\sqlite3_aimp.dll"
   ```
   This will analyze both DLLs and save `sqlite3_python.dll.i64` and `sqlite3_aimp.dll.i64`.

---

## 2. Running the Diff Pipeline

Invoke the `batch_export_and_diff` tool via your MCP client (e.g., Claude Desktop, Gemini Antigravity, cursor):

```json
{
  "idb1_path": "E:\\Program Files\\IdaPro_projects\\test\\sqlite3_python.dll.i64",
  "idb2_path": "E:\\Program Files\\IdaPro_projects\\test\\sqlite3_aimp.dll.i64",
  "use_decompiler": false,
  "summaries_only": false,
  "cleanup": false
}
```

### Expected Output
The tool will export both databases to `.sqlite` format and generate a `.diaphora` diff file containing matched functions.
```json
{
  "success": true,
  "summary": {
    "best_matches": 41,
    "partial_matches": 850,
    "unreliable_matches": 0,
    "multimatches": 54,
    "unmatched_primary": 3000
  }
}
```

---

## 3. Querying Differences across Different Addresses

Because the two DLLs were compiled differently, functions shifted addresses (e.g., `sqlite3_exec` has address `6442949232` in Python and address `6443299984` in AIMP). 

You can compare them by providing both `address` (for db1) and `address2` (for db2):

### A. Side-by-Side Comparison (`compare_functions`)
```json
{
  "db1_path": "E:\\Program Files\\IdaPro_projects\\test\\sqlite3_python.dll.sqlite",
  "db2_path": "E:\\Program Files\\IdaPro_projects\\test\\sqlite3_aimp.dll.sqlite",
  "address": "6442949232",
  "address2": "6443299984"
}
```
**Returns:**
```json
{
  "function_old": {
    "name": "sqlite3_exec",
    "address": "6442949232",
    "instructions": 398,
    "cyclomatic_complexity": 246
  },
  "function_new": {
    "name": "sqlite3_exec_0",
    "address": "6443299984",
    "instructions": 387,
    "cyclomatic_complexity": 228
  },
  "comparison": {
    "name_changed": true,
    "instructions_added": -11,
    "complexity_change": -18,
    "hash_changed": true
  }
}
```

### B. Behavior Change Analysis (`detect_behavior_change`)
```json
{
  "db1_path": "E:\\Program Files\\IdaPro_projects\\test\\sqlite3_python.dll.sqlite",
  "db2_path": "E:\\Program Files\\IdaPro_projects\\test\\sqlite3_aimp.dll.sqlite",
  "address": "6442949232",
  "address2": "6443299984"
}
```
**Returns:**
```json
{
  "function_name_old": "sqlite3_exec",
  "function_name_new": "sqlite3_exec_0",
  "change_type": "modified",
  "changes": [
    "renamed from 'sqlite3_exec' to 'sqlite3_exec_0'",
    "shrunk by 11 instructions (398→387)",
    "complexity decreased by 18 (CC 246→228)",
    "CFG: 118→110 blocks, 362→336 edges",
    "loops: 2→1",
    "no longer calls: sqlite3_malloc64_0, sub_180005930, sub_180005DC0..."
  ]
}
```
