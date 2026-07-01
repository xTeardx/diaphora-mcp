# IDA Pro не отвечает после экспорта Diaphora через ida_mcp

## Проблема

После запуска экспорта через `POST /diaphora/export` в `ida_mcp`:

1. Экспорт успешно завершается, файл `.sqlite` создаётся, но **IDA Pro перестаёт отвечать**
2. Если нажать **Cancel** во время экспорта — **IDA тоже зависает**
3. Агент (Claude Code) продолжает бесконечно polling-ить `task_id`, не зная, что экспорт отменён

## Причина

### А. `MFF_WRITE` блокирует IDB

Экспорт запускается через `idaapi.execute_sync(func, MFF_WRITE)`. Экспорт Diaphora — read-only, IDB не изменяется. Но `MFF_WRITE` захватывает блокировку на запись. После завершения экспорта блокировка не отпускается, GUI-цикл IDA зависает в ожидании.

### Б. Cancel не обрабатывается

Когда пользователь жмёт Cancel на прогресс-баре:
- `idaapi.timeldk_progress_t` прерывает итерацию
- `EXPORT_TASKS[task_id]` не заполняется — ни успехом, ни ошибкой
- Агент polling-ит вечно
- Прогресс-бар остаётся открыт, блокируя GUI

## Решение

### 1. `MFF_READ` вместо `MFF_WRITE`

Экспорт Diaphora не пишет в IDB, поэтому блокировка записи не нужна.

```python
# Неправильно — захватывает блокировку записи
idaapi.execute_sync(export, idaapi.MFF_WRITE)

# Правильно — read-only, не блокирует GUI
idaapi.execute_sync(export, idaapi.MFF_READ)
```

### 2. Ловить Cancel в `except` и закрывать прогресс-бар в `finally`

```python
def export():
    progress = None
    try:
        progress = idaapi.timeldk_progress_t("Diaphora export")
        progress.show()
        path = _export_diaphora(output, opts, progress)
        EXPORT_TASKS[task_id] = {"ok": True, "path": path}
    except idaapi.cancelled:
        EXPORT_TASKS[task_id] = {"ok": False, "error": "cancelled"}
    except Exception as e:
        EXPORT_TASKS[task_id] = {"ok": False, "error": str(e)}
    finally:
        if progress:
            progress.close()       # закрыть прогресс-бар
        idaapi.process_ui_action("Refresh")  # разблокировать GUI
    return 0

idaapi.execute_sync(export, idaapi.MFF_READ)
```

### 3. Таймаут на стороне клиента

Polling не должен длиться бесконечно:

```python
def _export_via_plugin(idb_path, use_decompiler, summaries_only):
    resp = requests.post("http://127.0.0.1:13337/diaphora/export", json={...})
    task_id = resp.json()["task_id"]

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

## Код целиком (ida_mcp.py)

```python
import uuid, threading, idaapi

EXPORT_TASKS = {}

@app.post("/diaphora/export")
def start_export(body: dict) -> dict:
    task_id = str(uuid.uuid4())
    output = body.get("output_path") or _default_output()
    use_decompiler = _should_use_decompiler(body)

    def worker():
        def export():
            progress = None
            try:
                progress = idaapi.timeldk_progress_t("Diaphora export")
                progress.show()
                path = _export_diaphora(output, body, progress)
                EXPORT_TASKS[task_id] = {"ok": True, "path": path, "stats": _stats(path)}
            except idaapi.cancelled:
                EXPORT_TASKS[task_id] = {"ok": False, "error": "cancelled"}
            except Exception as e:
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
```

## Автоотключение декомпилятора для больших бинарников

Декомпиляция (Hex-Rays) — самая дорогая операция. Для больших бинарников она выключена по умолчанию:

```python
MAX_FUNCTIONS_FOR_DECOMPILER = 25_000

def _should_use_decompiler(body: dict) -> bool:
    user_pref = body.get("use_decompiler")
    if user_pref is not None:
        return user_pref           # явный выбор агента
    total = len(list(idautils.Functions()))
    return total < MAX_FUNCTIONS_FOR_DECOMPILER  # авто
```

Агент может явно передать `use_decompiler: true` и включить декомпилятор принудительно.

## Итог

| Ситуация | До | После |
|---|---|---|
| Экспорт завершился | IDA не отвечает | GUI работает |
| Пользователь нажал Cancel | IDA зависает + polling бесконечный | Cancel логируется, прогресс закрыт, клиент получает ошибку |
| Бинарник >25k функций | Декомпиляция жрёт часы | Автоотключена |
