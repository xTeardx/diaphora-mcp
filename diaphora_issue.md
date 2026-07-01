# Конфликт лицензии при экспорте Diaphora и интеграция с `ida_mcp`

## Проблема

MCP-инструмент `export_idb_to_diaphora` (и `batch_export_and_diff`) для экспорта IDB в Diaphora-формат запускает отдельный процесс `idat64.exe` через `subprocess`.

Если на момент вызова уже запущена IDA Pro (в GUI или headless-режиме), возникает **конфликт лицензии Hex-Rays**:

- Лицензия однопользовательская — второй процесс не может стартовать
- `idat64.exe` либо падает с `"This copy of IDA Pro has been already started"`, либо зависает
- Пользователь теряет текущую сессию (IDA может зависнуть или закрыться)
- Несохранённые изменения (имена, комментарии, типы) рискуют пропасть
- `.i64` может остаться с повреждёнными рабочими файлами (`.id0`/`.id1`)

### Почему это происходит

Diaphora MCP работает в **отдельном процессе** от IDA. Чтобы получить доступ к IDB, ему нужно либо запустить свой `idat64.exe`, либо попросить уже запущенную IDA сделать экспорт.

IDA Pro GUI уже содержит плагин `ida_mcp.py`, который:
- Хостит HTTP-сервер на `127.0.0.1:13337`
- Имеет полный доступ к IDAPython API
- Может вызывать Hex-Rays декомпилятор
- Работает **в той же лицензии**, что и GUI

Но Diaphora MCP его не использует, а запускает второй процесс.

---

## Решение: делегировать экспорт в `ida_mcp`

### Целевая архитектура

```
До (сломано):

    diaphora-mcp ── spawn idat64.exe ── конфликт лицензии ── крах

После (чисто):

    diaphora-mcp ── HTTP POST /diaphora/export ──► ida_mcp (внутри IDA)
                        │                           та же лицензия, тот же процесс
                        ▼
                    IDAPython:                       
                        idautils.Functions()         ← функции
                        ida_gdl.FlowChart()          ← CFG
                        ida_hexrays.decompile()      ← псевдокод
                        idc.GetType()                ← прототипы
                        ida_struct.get_struc_list()  ← структуры
                        ida_enum.get_enum_qty()      ← enum'ы
                        ida_bytes.get_bytes()        ← байты
                        ↓
                    Diaphora .sqlite
```

---

## Часть 1: что добавить в `ida_mcp.py`

### 1.1. Эндпоинт

```python
@app.post("/diaphora/export")
def handle_diaphora_export(body: dict) -> dict:
    """
    Экспорт текущей IDB в Diaphora SQLite.
    Работает в фоновом потоке — не вешает GUI.
    
    Тело запроса (JSON):
    {
        "output_path": "C:/path/to/output.sqlite",  // опционально
        "use_decompiler": false,                      // опционально
        "summaries_only": false                       // опционально
    }
    
    Ответ:
    {
        "ok": true,
        "path": "C:/path/to/output.sqlite",
        "stats": {
            "functions": 2532,
            "calls": 14457,
            "structures": 45,
            "enums": 12
        }
    }
    """
```

### 1.2. Схема SQLite (Diaphora-формат с типами)

```sql
-- Основная таблица функций
CREATE TABLE functions (
    address         TEXT PRIMARY KEY,   -- hex, e.g. "0x180039690"
    name            TEXT,               -- "vdbe_codegen"
    size            INTEGER,
    complexity      INTEGER,            -- cyclomatic complexity
    instructions    INTEGER,            -- instruction count
    prototype       TEXT,               -- C prototype (e.g. "__int64 __fastcall(...)")
    pseudocode      TEXT,               -- Hex-Rays output (if use_decompiler)
    asm             TEXT,               -- disassembly listing
    bytes           TEXT,               -- hex-encoded raw bytes
    md5             TEXT,               -- instruction hash for matching
    md5_min         TEXT,               -- mnemonic-only hash
    type            TEXT                -- "thunk|leaf|wrapper|dispatcher|complex"
);

-- Call graph
CREATE TABLE calls (
    caller          TEXT,               -- caller function address
    callee          TEXT                -- callee function address
);

-- Basic blocks (CFG)
CREATE TABLE basic_blocks (
    address         TEXT,               -- parent function
    block_start     TEXT,               -- block start address
    size            INTEGER
);

-- Строки, на которые ссылается функция
CREATE TABLE strings (
    address         TEXT,               -- referencing function
    string          TEXT,               -- string value
    xref_addr       TEXT                -- address of the reference
);

-- Константы, используемые в функции
CREATE TABLE constants (
    address         TEXT,               -- referencing function
    constant        INTEGER,
    operand         INTEGER             -- operand index
);

-- Импорты, вызываемые из функции
CREATE TABLE imports (
    address         TEXT,               -- function using import
    import_name     TEXT,
    module          TEXT                -- e.g. "kernel32.dll"
);

-- Структуры (UDT) — полное описание
CREATE TABLE structures (
    name            TEXT PRIMARY KEY,    -- "sqlite3_value"
    size            INTEGER,
    members         TEXT,                -- JSON: [{"offset":0,"name":"flags","type":"int"},...]
    declaration     TEXT                 -- полное C-объявление
);

-- Enum'ы
CREATE TABLE enums (
    name            TEXT PRIMARY KEY,    -- "SQLITE_OK"
    bitfield        INTEGER,             -- 0 или 1
    members         TEXT                 -- JSON: [{"name":"SQLITE_OK","value":0},...]
);

-- Комментарии
CREATE TABLE comments (
    address         TEXT,               -- address
    comment         TEXT,               -- текст комментария
    type            TEXT                -- "regular" | "repeatable" | "function"
);

-- Метаданные бинарника
CREATE TABLE metadata (
    key             TEXT PRIMARY KEY,
    value           TEXT
);
-- ("md5", "..."), ("module", "sqlite3_python.dll"), ("base", "0x180000000")
-- ("compiler", "MSVC VCRUNTIME140"), ("arch", "x64")
```

### 1.3. Логика экспорта

```python
import sqlite3, threading, json
import idautils, idc, ida_funcs, ida_gdl, ida_nalt, ida_bytes
import ida_xref, ida_hexrays, ida_struct, ida_enum, ida_typeinf

def _export_diaphora(output_path: str, opts: dict) -> str:
    use_decompiler = opts.get("use_decompiler", False)
    summaries_only = opts.get("summaries_only", False)
    
    conn = sqlite3.connect(output_path)
    cur = conn.cursor()
    cur.executescript(SCHEMA_SQL)
    
    # ── Метаданные ──
    meta = [
        ("module",  ida_nalt.get_root_filename()),
        ("md5",     idc.GetInputMD5()),
        ("base",    hex(ida_ida.get_imagebase())),
        ("arch",    "x64" if ida_ida.inf_is_64bit() else "x86"),
        ("compiler", ida_typeinf.get_compiler_name(ida_ida.inf_get_compiler())),
    ]
    cur.executemany("INSERT INTO metadata VALUES (?, ?)", meta)
    
    # ── Структуры ──
    for idx in range(ida_struct.get_struc_qty()):
        sptr = ida_struct.get_struc_by_idx(idx)
        name = ida_struct.get_struc_name(sptr.id)
        members = []
        for m in [ida_struct.get_struc_member_by_idx(sptr, j)
                  for j in range(ida_struct.get_struc_member_qty(sptr))]:
            if m:
                members.append({
                    "offset": m.soff,
                    "name":   ida_struct.get_member_name(m.id) or "",
                    "size":   m.size,
                    "type":   ida_struct.get_member_tinfo(m).dstr() if m.tid else "",
                })
        cur.execute(
            "INSERT INTO structures VALUES (?, ?, ?, ?)",
            (name, sptr.size, json.dumps(members),
             ida_typeinf.get_type(ida_struct.get_struc_id(name)) or "")
        )
    
    # ── Enum'ы ──
    for idx in range(ida_enum.get_enum_qty()):
        eid = ida_enum.get_enum_by_idx(idx)
        name = ida_enum.get_enum_name(eid)
        bf = ida_enum.is_bf(eid)
        members = []
        for bit in range(ida_enum.get_enum_size(eid) * 8):
            cid = ida_enum.get_first_enum_member(eid, bit)
            if cid != ida_enum.DEFMASK:
                members.append({
                    "name":  ida_enum.get_enum_member_name(cid),
                    "value": ida_enum.get_enum_member_value(cid),
                })
        cur.execute(
            "INSERT INTO enums VALUES (?, ?, ?)",
            (name, 1 if bf else 0, json.dumps(members))
        )
    
    # ── Комментарии ──
    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue
        # Комментарий функции (repeatable)
        comment = idc.get_func_comment(func_ea)
        if comment:
            cur.execute("INSERT INTO comments VALUES (?, ?, ?)",
                       (hex(func_ea), comment, "function"))
        # Комментарии в строках функции
        for head in idautils.Heads(func.start_ea, func.end_ea):
            for ctype, label in [(0, "regular"), (1, "repeatable")]:
                text = idc.get_cmt(head, ctype)
                if text:
                    cur.execute("INSERT INTO comments VALUES (?, ?, ?)",
                               (hex(head), text, label))
    
    # ── Функции ──
    total = len(list(idautils.Functions()))
    
    for idx, func_ea in enumerate(idautils.Functions()):
        if idx % 100 == 0:
            print(f"[Diaphora] {idx}/{total}")
        
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue
        
        size = func.end_ea - func.start_ea
        name = idc.get_func_name(func_ea)
        
        # CFG + классификация
        complexity = 0
        ftype = "unknown"
        if not summaries_only:
            try:
                blocks = list(ida_gdl.FlowChart(func))
                complexity = len(blocks)
                for b in blocks:
                    cur.execute(
                        "INSERT INTO basic_blocks VALUES (?, ?, ?)",
                        (hex(func_ea), hex(b.start_ea), b.end_ea - b.start_ea)
                    )
                # Классификация по количеству блоков и вызовов
                callees = len(list(idautils.CodeRefsFrom(func_ea, 0)))
                if size <= 8:
                    ftype = "thunk"
                elif callees == 0:
                    ftype = "leaf"
                elif callees <= 2 and complexity <= 3:
                    ftype = "wrapper"
                elif complexity > 20:
                    ftype = "complex"
                else:
                    ftype = "dispatcher"
            except:
                pass
        
        # Псевдокод (опционально — дорого)
        pseudocode = ""
        if use_decompiler:
            try:
                cfunc = ida_hexrays.decompile(func_ea)
                pseudocode = str(cfunc)
            except:
                pass
        
        # Ассемблер
        asm = ""
        asm_count = 0
        if not summaries_only:
            lines = []
            for head in idautils.Heads(func.start_ea, func.end_ea):
                lines.append(idc.generate_disasm_line(head, 0))
                asm_count += 1
            asm = "\n".join(lines)
        
        # Байты + хеш
        raw = ""
        md5_hash = ""
        if not summaries_only:
            b = ida_bytes.get_bytes(func.start_ea, size)
            if b:
                raw = b.hex()
                import hashlib
                md5_hash = hashlib.md5(b).hexdigest()
        
        # Прототип
        proto = idc.get_type(func_ea) or ""
        
        cur.execute("""
            INSERT INTO functions 
            (address, name, size, complexity, instructions, 
             prototype, pseudocode, asm, bytes, md5, type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (hex(func_ea), name, size, complexity, asm_count,
              proto, pseudocode, asm, raw, md5_hash, ftype))
        
        # Call graph
        for ref in idautils.CodeRefsFrom(func_ea, 0):
            target = idc.get_func(ref)
            if target:
                cur.execute("INSERT INTO calls VALUES (?, ?)",
                          (hex(func_ea), hex(target.start_ea)))
        
        # Строки
        for ref in idautils.DataRefsFrom(func_ea):
            s = idc.get_strlit_contents(ref)
            if s:
                cur.execute("INSERT INTO strings VALUES (?, ?, ?)",
                          (hex(func_ea), s.decode('utf-8', errors='replace'), hex(ref)))
    
    conn.commit()
    conn.close()
    return output_path
```

---

## Часть 2: что изменить в `diaphora-mcp`

### 2.1. Новая логика `export_idb_to_diaphora`

```python
import requests, os, subprocess, psutil

def export_idb_to_diaphora(idb_path: str, use_decompiler=False, summaries_only=None):
    """
    Экспорт IDB в Diaphora SQLite.
    
    Приоритет:
    1. Если IDA GUI + ida_mcp активны → POST /diaphora/export
    2. Если нет → subprocess idat64.exe (старый путь)
    """
    if _ida_running_with_plugin():
        return _export_via_plugin(idb_path, use_decompiler, summaries_only)
    
    if _any_ida_running():
        raise RuntimeError(
            "IDA Pro is running but ida_mcp plugin is not responding. "
            "Install/activate the ida_mcp plugin or close IDA."
        )
    
    return _export_via_idat(idb_path, use_decompiler, summaries_only)


def _ida_running_with_plugin() -> bool:
    """Проверить, отвечает ли ida_mcp на :13337."""
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] in ('ida64.exe', 'idat64.exe'):
            try:
                resp = requests.get("http://127.0.0.1:13337/health", timeout=2)
                return resp.ok
            except:
                pass
    return False


def _export_via_plugin(idb_path: str, use_decompiler, summaries_only) -> str:
    """Делегировать экспорт в живую IDA через ida_mcp."""
    output = os.path.splitext(idb_path)[0] + ".diaphora.sqlite"
    
    resp = requests.post(
        "http://127.0.0.1:13337/diaphora/export",
        json={
            "output_path": output,
            "use_decompiler": use_decompiler,
            "summaries_only": summaries_only,
        },
        timeout=600,
    )
    result = resp.json()
    if result.get("ok"):
        return result["path"]
    raise RuntimeError(f"Export via ida_mcp failed: {result.get('error')}")
```

### 2.2. `batch_export_and_diff`

```python
def batch_export_and_diff(idb1_path, idb2_path, ...):
    db1 = export_idb_to_diaphora(idb1_path, ...)
    db2 = export_idb_to_diaphora(idb2_path, ...)
    return diff_diaphora_dbs(db1, db2)
```

---

## План внедрения

| Шаг | Где | Что | Строк |
|---|---|---|---|
| 1 | `ida_mcp.py` | Добавить `POST /diaphora/export` с полной схемой (функции, CFG, структуры, enum'ы, комментарии) | ~300 |
| 2 | `diaphora-mcp` | `export_idb_to_diaphora` — сначала проверка `ida_mcp`, затем idat | ~50 |
| 3 | `batch_export_and_diff` | Перевести на новый транспорт | ~10 |

### Что экспортируется (с живой IDA)

| Данные | Через `idat64` | Через `ida_mcp` |
|---|---|---|
| Функции, адреса, размеры | ✅ | ✅ |
| Call graph | ✅ | ✅ |
| Basic blocks (CFG) | ✅ | ✅ |
| Псевдокод (Hex-Rays) | ✅ | ✅ |
| **Структуры (struct / union)** | ❌ | **✅ встроено** |
| **Enum'ы** | ❌ | **✅ встроено** |
| **Комментарии** | ❌ | **✅ встроено** |
| **Типы (prototype + tinfo)** | ❌ | **✅ встроено** |

### Результат

| Сценарий | Было | Стало |
|---|---|---|
| IDA GUI + `ida_mcp` активен | Конфликт лицензии, крах | Экспорт внутри живой IDA, полные данные, пользователь не замечает |
| `batch_export_and_diff` | Два `idat64`, двойной риск | Два POST-запроса в ту же сессию |
| IDA не запущена | `idat64` (ок) | `idat64` (без изменений) |

**Пользователь никогда не теряет сессию. Экспорт не требует второй лицензии.**
