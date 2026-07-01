# Diaphora ↔ ida-pro-mcp Integration

## Для русскоязычных пользователей

Данная интеграция заменяет файл `ida_mcp.py` в установленном пакете `ida-pro-mcp` на модифицированную версию, которая добавляет HTTP-эндпоинт `/diaphora/export`. Это позволяет `diaphora-mcp` экспортировать IDB в Diaphora SQLite **без запуска второго экземпляра IDA** и, соответственно, **без конфликта лицензии Hex-Rays**.

**Что меняется:**
- Файл `ida_mcp.py` (загрузчик плагина) — заменяется на модифицированный
- Остальные файлы пакета `ida-pro-mcp` **не трогаются**
- Никакие файлы `diaphora-mcp` не меняются

**Что это даёт:**
- Экспорт работает внутри уже запущенной IDA GUI — пользователь не теряет сессию
- Экспорт включает структуры, енумы и комментарии (чего нет в экспорте через `idat64`)
- Не требуется вторая лицензия Hex-Rays

Если у вас уже установлен `ida-pro-mcp`, просто скопируйте файл `ida_mcp.py` из этой папки поверх существующего. Путь назначения см. ниже.

---

## Overview

This integration patches the **ida-pro-mcp** plugin (`ida_mcp.py`) to add a `/diaphora/export` HTTP endpoint. The **diaphora-mcp** server detects this endpoint and delegates IDB→SQLite export to the already-running IDA Pro instance, **eliminating the Hex-Rays license conflict** that occurs when a second `idat64.exe` process is spawned.

### What it adds to ida-pro-mcp

| Endpoint | Method | Purpose |
|---|---|---|
| `/diaphora/health` | GET | Health check — returns `{"ok": true}` if the plugin is live |
| `/diaphora/export` | POST | Export the currently open IDB to Diaphora-format SQLite |

### Diaphora SQLite schema (exported tables)

`functions` · `calls` · `basic_blocks` · `strings` · `constants` · `imports` · `structures` · `enums` · `comments` · `metadata`

All tables are populated by a background thread inside the running IDA process — no second instance, no license conflict.

---

## Installation Guide for AI Agent

Follow these steps to install the integration. **You must warn the user before making any changes** — see the warning template below.

### ⚠️ Pre-installation Warning (show to user)

> **This integration modifies the `ida-pro-mcp` pip package by replacing `ida_mcp.py`.**
>
> - **Required:** [ida-pro-mcp](https://pypi.org/project/ida-pro-mcp/) must already be installed (`pip install ida-pro-mcp`)
> - The file `ida_mcp.py` in the pip package will be **replaced** with a modified version
> - No other files in `ida-pro-mcp` or `diaphora-mcp` are changed
> - If you update `ida-pro-mcp` via pip later, the file will be overwritten — you'll need to re-apply this patch
> - **Backup** of the original file is created automatically during installation
>
> Proceed? (y/N)

---

### Step 1: Verify ida-pro-mcp is installed

```bash
pip show ida-pro-mcp
```

If not installed:

```bash
pip install ida-pro-mcp
```

### Step 2: Locate the pip package directory

```bash
python -c "import ida_pro_mcp; print(ida_pro_mcp.__file__)"
```

Expected output (Windows example):

```
C:\Users\<user>\AppData\Local\Programs\Python\Python312\Lib\site-packages\ida_pro_mcp\__init__.py
```

The file we need to replace is **`ida_mcp.py`** in this directory (the parent of `__init__.py`).

### Step 3: Backup the original file

```powershell
# From the directory above:
copy ida_mcp.py ida_mcp.py.backup
```

### Step 4: Copy the patched file

Copy **[idalib/ida_mcp.py](./ida_mcp.py)** from this repository into the pip package directory, **replacing** the original.

```powershell
# Example (adjust paths to match your actual pip location):
copy D:\path\to\diaphora-mcp\idalib\ida_mcp.py `
  C:\Users\<user>\AppData\Local\Programs\Python\Python312\Lib\site-packages\ida_pro_mcp\ida_mcp.py
```

### Step 5: Verify the patched file

```python
python -c "
import ast
import ida_pro_mcp
# Read and parse the patched file
with open(ida_pro_mcp.__file__.replace('__init__.py', 'ida_mcp.py')) as f:
    tree = ast.parse(f.read())
# Check that the export function exists
found = any(
    isinstance(n, ast.FunctionDef) and n.name == '_export_diaphora'
    for n in ast.walk(tree)
)
print('✓ _export_diaphora found' if found else '✗ _export_diaphora MISSING')
"
```

### Step 6: Restart IDA Pro

Close all IDA Pro instances and reopen. The MCP plugin will now serve the `/diaphora/export` and `/diaphora/health` endpoints on port `13337`.

Check the IDA Output window for:

```
[MCP] Plugin loaded, server will start automatically
...
  Diaphora: http://127.0.0.1:13337/diaphora/health
```

### Step 7: Test the integration

With IDA Pro GUI open and a database loaded:

```bash
# Health check
curl http://127.0.0.1:13337/diaphora/health

# Expected: {"ok": true, "capabilities": ["diaphora/export"]}
```

Then from diaphora-mcp:

```bash
# Export should use the plugin instead of spawning idat64
python -m diaphora_mcp call export_idb_to_diaphora --idb-path /path/to/binary.i64
```

---

## How it works (for the AI agent)

### Export flow

1. **diaphora-mcp** calls `export_idb_to_diaphora(idb_path)`
2. `run_export()` → `_try_via_plugin()` probes `GET /diaphora/health` on port 13337
3. If the endpoint responds:
   - **`POST /diaphora/export`** — returns `{"task_id": "uuid"}` immediately (async)
   - Polls **`GET /diaphora/export/<task_id>`** every 2 seconds until `done == true`
4. **ida-pro-mcp** receives the POST in its running HTTP server:
   - The export function is scheduled on the main IDA thread via **`idaapi.execute_sync(…, MFF_READ)`**
   - `MFF_READ` does not block the GUI — IDA stays responsive
   - After completion (or error), **`idaapi.process_ui_action("Refresh")`** is called to flush any pending UI events
5. Results are stored in an in-memory `EXPORT_TASKS` dict keyed by `task_id`
6. Clients poll until the result is available

### Critical implementation details

| Detail | Reason |
|---|---|
| `execute_sync(…, MFF_READ)` | Runs the export on the main IDA thread (IDAPython is not thread-safe), but does **not** hold a write lock on the IDB |
| `process_ui_action("Refresh")` | Prevents GUI freeze after export completes or on Cancel |
| Background `_worker` thread | The export runs in a daemon thread that calls `execute_sync` — this avoids blocking the HTTP server |
| `uuid` task IDs | Enables multiple concurrent exports and clean polling |
| In-memory `EXPORT_TASKS` | Results are kept until the server restarts — no filesystem pollution |

### If the plugin is not reachable

- diaphora-mcp falls through to the existing GUI listener (port 28652)
- Then checks lock files → clear error
- If any IDA process is running → clear error with instructions
- Otherwise spawns `idat64.exe` as before
