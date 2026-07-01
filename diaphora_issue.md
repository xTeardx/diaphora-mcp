# IDA Pro не отвечает после завершения экспорта Diaphora через `ida_mcp`

## Проблема

После перехода с `idat64.exe` на `POST /diaphora/export` через `ida_mcp` появилась новая проблема:

- Экспорт **успешно завершается**, файл `.sqlite` создан
- Но сразу после завершения **IDA Pro перестаёт отвечать** — GUI не реагирует на клики, меню не открываются
- То же самое происходит, если пользователь **нажал Cancel** во время экспорта

При этом блокировка происходит **не во время** экспорта (GUI был отзывчив), а **после** его завершения.

## Причина

Экспорт выполняется через `idaapi.execute_sync()` с флагом `MFF_WRITE`. Этот флаг захватывает **блокировку на запись** IDB. Если после завершения экспорта блокировка не отпускается корректно — IDA остаётся в состоянии "захвачено и не отпущено". GUI-цикл ждёт освобождения блокировки, но оно не происходит.

Дополнительно: если в процессе экспорта создавались UI-элементы (прогресс-бар, окно статуса), а при Cancel или штатном завершении они не были закрыты — IDA может остаться висеть в ожидании закрытия модального элемента.

## Решение

### 1. Явно указывать `MFF_READ` вместо `MFF_WRITE`

Экспорт Diaphora — read-only операция: он читает IDB, но не пишет в неё. `MFF_READ` не захватывает блокировку записи и не блокирует GUI:

```python
# Неправильно — захватывает блокировку записи
idaapi.execute_sync(export, idaapi.MFF_WRITE)

# Правильно — read-only, не блокирует
idaapi.execute_sync(export, idaapi.MFF_READ)
```

### 2. После экспорта — явно обрабатывать pending-события GUI

```python
def export():
    try:
        path = _export_diaphora(output, opts)
        EXPORT_TASKS[task_id] = {"ok": True, "path": path}
    except Exception as e:
        EXPORT_TASKS[task_id] = {"ok": False, "error": str(e)}
    finally:
        # Принудительно обработать накопившиеся события GUI
        idaapi.process_ui_action("Refresh")
    return 0
```

### 3. Если используется прогресс-бар — закрывать его в `finally`

```python
def export():
    progress = None
    try:
        progress = idaapi.timeldk_progress_t("Diaphora export")
        progress.show()
        # ... экспорт ...
    finally:
        if progress:
            progress.close()
        idaapi.execute_sync(export, idaapi.MFF_READ)
```

### 4. Автоматическое включение декомпилятора для небольших бинарников

Декомпиляция (Hex-Rays) — самое дорогое. Для бинарников с менее чем 100 000 функций её можно включить по умолчанию, для больших — принудительно отключить, чтобы не зависать на часы.

```python
def _should_use_decompiler(total_funcs: int, user_pref: bool | None) -> bool:
    """Определить, нужна ли декомпиляция."""
    if user_pref is not None:
        return user_pref          # явный выбор агента
    return total_funcs < 25_000   # авто: только для небольших БД


@app.post("/diaphora/export")
def start_export(body: dict) -> dict:
    total_funcs = len(list(idautils.Functions()))
    use_decompiler = _should_use_decompiler(
        total_funcs, body.get("use_decompiler")
    )
    
    task_id = str(uuid.uuid4())
    output = body.get("output_path") or _default_output()
    
    print(f"[Diaphora] Exporting {total_funcs} functions, "
          f"decompiler={'on' if use_decompiler else 'off'}")
    
    # ... дальше как в п.3 ...
```

### 5. Весь паттерн целиком

```python
import uuid, threading, idaapi

EXPORT_TASKS = {}

@app.post("/diaphora/export")
def start_export(body: dict) -> dict:
    task_id = str(uuid.uuid4())
    output = body.get("output_path") or _default_output()
    
    def worker():
        def export():
            try:
                path = _export_diaphora(output, body)
                EXPORT_TASKS[task_id] = {"ok": True, "path": path}
            except Exception as e:
                EXPORT_TASKS[task_id] = {"ok": False, "error": str(e)}
            finally:
                # Явно обработать накопившиеся события
                idaapi.process_ui_action("Refresh")
            return 0
        
        # MFF_READ — не блокируем IDB на запись
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

## Итог

| Ситуация | Сейчас | После фикса |
|---|---|---|
| Экспорт завершился успешно | IDA не отвечает | GUI работает, `MFF_READ` + `process_ui_action` |
| Пользователь нажал Cancel | IDA не отвечает | `finally` закрывает UI-элементы, блокировка не зависает |
