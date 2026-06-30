# Problems.md — Diaphora MCP

## Проблемы, обнаруженные при тестировании

### 1. Headless export (idat.exe) падает с error code 4

**Симптом:** idat.exe завершается с `"Failed to initialize IDA as library (error code 4)"` сразу после запуска.

**Причина:** IDA находит stale lock-файлы от предыдущей сессии (`.id0`, `.id1`, `.id2`, `.nam`, `.til`) на диске и отказывается перепаковывать базу:
```
IDA has found an unpacked version of database
It appears IDA did not close properly;
it is probably safer to restart your work from the packed database
```

**Решение:** Вручную удалить stale файлы перед экспортом:
```bash
rm -f *.id0 *.id1 *.id2 *.nam *.til
```

**Нужно:** Добавить в `run_export()` автоматическую очистку lock-файлов перед запуском idat.exe.

---

### 2. Crash-файл остаётся даже при успешном экспорте

**Симптом:** Diaphora создаёт `*-crash` файл при старте экспорта и должна удалять его при успехе. Но на практике файл часто остаётся, из-за чего `run_export()` считает экспорт упавшим:
```python
crash_file = f"{output_path}-crash"
if os.path.isfile(crash_file):
    return "Export appears to have crashed..."
```

**Реальность:** Экспорт мог успешно завершиться (в SQLite есть тысячи функций), но crash-файл не был удалён.

**Примеры:**
- `gfdgdfgkkl_diaphora.sqlite` — 1469 функций, но есть `-crash` файл
- `aces.exe.sqlite` — 3050 функций, но есть `-crash` файл

**Нужно:** Не полагаться только на crash-файл. Проверять реальное наличие функций в SQLite перед выводом ошибки.

---

### 3. SQLite WAL не контроль-поинтится

**Симптом:** Экспорт пишет данные в WAL-журнал, но при `check_db()` (который делает `SELECT count(*) FROM functions`) данные из WAL не видны, если не включён режим WAL.

**Факт:** `aces.exe.sqlite` имел main файл 77KB (пустой), но WAL был 44MB+ с данными. После `PRAGMA wal_checkpoint` данные появлялись.

**Нужно:** Использовать `PRAGMA journal_mode=WAL` при подключении к экспортированным базам, либо делать `PRAGMA wal_checkpoint` перед проверкой.

---

### 4. `true_name` column отсутствует в некоторых схемах

**Симптом:** `transfer_metadata()` падает с `sqlite3.OperationalError: no such column: true_name`

**Причина:** В старых версиях Diaphora таблица `functions` не имеет колонки `true_name`.

**Статус:** **Пофикшено** — добавлен try/except с fallback на `name`.

---

### 5. Медленный экспорт (1.2GB .i64)

**Симптом:** Экспорт `gfdgdfgkkl.exe.i64` (1.2GB) занял ~5-10 минут работы idat.exe. Всё это время процесс висит без какого-либо прогресс-бара.

**Причина:** IDA должна распаковать .i64 (создать .id0 заново), загрузить все секции, проанализировать и запустить Diaphora-скрипт на экспорт.

**Нужно:**
- Добавить логирование промежуточных стадий (начинается распаковка, загружена БД, запущен скрипт, экспортировано N функций)
- Сделать таймаут настраиваемым (сейчас 3600 сек хардкод)

---

### 6. Нет мониторинга прогресса экспорта

**Симптом:** `run_export()` запускает subprocess и ждёт. Нет способа узнать, что происходит внутри.

**Нужно:** Добавить threading-монитор, который читает stdout/stderr процесса и выводит прогресс, либо периодически проверяет размер/наличие промежуточных файлов.

---

### 7. Windows file locking мешает cleanup

**Симптом:** После падения idat.exe файлы `.id0`, `.sqlite-wal` остаются заблокированными Windows, и `os.remove()` не работает:
```
rm: cannot remove 'aces.exe.id0': Device or resource busy
rm: cannot remove 'aces.exe.sqlite-wal': Device or resource busy
```

**Решение:** Использовать `taskkill /f /im idat.exe` для гарантированного убийства процессов перед cleanup.

**Нужно:** Добавить в `run_export()` и cleanup-логику принудительное убийство процессов idat.exe.

---

### 8. Неинформативные логи при падении

**Симптом:** При ошибке idat.exe возвращает пустой stdout/stderr:
```
idat stdout (last 2K):
idat stderr (last 2K):
```

**Причина:** IDA пишет ошибки в `ida.log` в своей директории, а не в stderr.

**Нужно:** В `run_export()` читать `ida.log` или использовать флаг `-L<logfile>` для захвата лога.

---

### 9. `batch_export_and_diff` не удаляет промежуточные файлы

При падении на шаге 2 (экспорт второй БД) или шаге 3 (diff), файлы с предыдущих шагов остаются на диске. Нужна опция `--clean` для автоматической очистки.

---

### 10. `_read_results` в diff.py обрезает results до 500

```python
"results": results[:500],
```

Без предупреждения. Пользователь может не заметить, что получил не все результаты.

**Нужно:** Всегда возвращать `total_matches` и `truncated` флаг, и по умолчанию не обрезать (или обрезать только если не указан `limit`).
