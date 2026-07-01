# Проблемы экспорта Diaphora через `ida_mcp` и их решения

## Проблема 1: Конфликт лицензии

`export_idb_to_diaphora` запускал `subprocess idat64.exe`, который требовал лицензию Hex-Rays и конфликтовал с уже запущенной IDA GUI.

### Решение

Делегировать экспорт в `ida_mcp.py` — плагин, который уже живёт внутри IDA и имеет доступ к той же лицензии.

```
diaphora-mcp ── HTTP POST /diaphora/export ──► ida_mcp (внутри IDA)
```

---

## Проблема 2: IDA зависает после экспорта

Экспорт выполняется через `idaapi.execute_sync(func, MFF_WRITE)`. Экспорт Diaphora — read-only, но `MFF_WRITE` захватывает блокировку на запись IDB, которая не отпускается после завершения.

### Решение

Использовать `MFF_READ` — не блокирует IDB на запись:

```python
idaapi.execute_sync(export, idaapi.MFF_READ)
```

---

## Проблема 3: Cancel вешает IDA

Когда пользователь нажимает Cancel — Diaphora кидает `Exception("Cancelled.")`. Если не поймать это исключение, `EXPORT_TASKS[task_id]` не заполняется, агент polling-ит вечно, прогресс-бар не закрывается.

### Решение: ловить все исключения и проверять строку

```python
try:
    path = _export_diaphora(...)
    EXPORT_TASKS[task_id] = {"ok": True, "path": path}
except BaseException as e:
    if "cancelled" in str(e).lower():
        EXPORT_TASKS[task_id] = {"ok": False, "error": "cancelled"}
    else:
        EXPORT_TASKS[task_id] = {"ok": False, "error": str(e)}
finally:
    if progress:
        progress.close()
    idaapi.process_ui_action("Refresh")
```

---

## Проблема 4: Агент ждёт вечно

Если Cancel не обработан — `EXPORT_TASKS[task_id]` не заполняется, и агент polling-ит бесконечно.

### Решение: таймаут в клиенте

```python
start = time.time()
timeout = 600

while time.time() - start < timeout:
    time.sleep(2)
    poll = requests.get(f"http://127.0.0.1:13337/diaphora/export/{task_id}")
    data = poll.json()
    if not data.get("done"):
        continue
    if data.get("ok"):
        return data["path"]
    if data.get("error") == "cancelled":
        raise RuntimeError("Export cancelled by user")
    raise RuntimeError(f"Export failed: {data.get('error')}")

raise TimeoutError(f"Export timed out after {timeout}s")
```

---

## Проблема 5: Декомпиляция слишком медленная на больших бинарниках

На бинарнике с 3400 функций декомпиляция занимает >5 минут. На 100k+ это часы.

### Решение: автоотключение при >25k функций

```python
MAX_FUNCTIONS_FOR_DECOMPILER = 25_000

def _should_use_decompiler(body: dict) -> bool:
    user_pref = body.get("use_decompiler")
    if user_pref is not None:
        return user_pref
    total = len(list(idautils.Functions()))
    return total < MAX_FUNCTIONS_FOR_DECOMPILER
```

Агент может явно передать `use_decompiler: true`.

---

## Финальный код эндпоинта

```python
import uuid, threading, idaapi

EXPORT_TASKS = {}
MAX_FUNCTIONS_FOR_DECOMPILER = 25_000


@app.post("/diaphora/export")
def start_export(body: dict) -> dict:
    task_id = str(uuid.uuid4())
    output = body.get("output_path") or _default_output()

    def worker():
        def export():
            progress = None
            try:
                progress = idaapi.timeldk_progress_t("Diaphora export")
                progress.show()
                path = _export_diaphora(output, body, progress)
                EXPORT_TASKS[task_id] = {"ok": True, "path": path}
            except BaseException as e:
                if "cancelled" in str(e).lower():
                    EXPORT_TASKS[task_id] = {"ok": False, "error": "cancelled"}
                else:
                    EXPORT_TASKS[task_id] = {"ok": False, "error": str(e)}
            finally:
                if progress:
                    progress.close()
                idaapi.process_ui_action("Refresh")
            return 0

        idaapi.execute_sync(export, idaapi.MFF_READ)

    threading.Thread(target=worker, daemon=True).start()
    return {"ok": True, "task_id": task_id}


@app.get("/diaphora/export/{task_id}")
def poll_export(task_id: str) -> dict:
    result = EXPORT_TASKS.get(task_id)
    if result is None:
        return {"ok": True, "done": False}
    return {"ok": result.get("ok", False), "done": True, **result}


def _default_output() -> str:
    return os.path.splitext(idaapi.get_idb_path())[0] + ".diaphora.sqlite"


def _should_use_decompiler(body: dict) -> bool:
    user_pref = body.get("use_decompiler")
    if user_pref is not None:
        return user_pref
    total = len(list(idautils.Functions()))
    return total < MAX_FUNCTIONS_FOR_DECOMPILER
```

---

## Сводка

| Проблема | Причина | Фикс |
|---|---|---|
| Конфликт лицензии | `subprocess idat64` | POST в `ida_mcp` |
| IDA зависла после экспорта | `MFF_WRITE` блокирует IDB | `MFF_READ` |
| Cancel вешает IDA | `Exception("Cancelled.")` не ловится | `except BaseException` + проверка строки |
| Агент ждёт вечно | Нет таймаута в клиенте | polling c `timeout=600` |
| Декомпиляция >5 мин | Hex-Rays на каждой функции | автооткл при >25k функций |
