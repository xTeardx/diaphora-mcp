## Пример: Кросс-бинарное сопоставление функций с Diaphora + idalib-mcp

**Цель:** Сравнить две версии одной библиотеки (`sqlite3.dll`, собранные для Python и для AIMP), идентифицировать идентичные и изменённые функции, перенести метаданные реверс-инжиниринга (имена функций) из уже размеченной Python-сборки в неразмеченную AIMP-сборку.

**Зачем:** После анализа одного бинарника нужно изучить смежную сборку (другие флаги компилятора, другой потребитель, другая версия). Diaphora автоматизирует сравнение, а `idalib-mcp` позволяет применить результаты без GUI.

---

## Используемые инструменты

| Инструмент | Назначение |
|---|---|
| `idalib-mcp` | Headless-сессии IDA Pro, анализ бинарников, переименование |
| `Diaphora MCP` | Бинарный диффинг — сопоставление функций по хешам/CFG/мнемоникам |
| `SQLite` | Прямой запрос `.diaphora`-базы для точных пар адресов |

---

## Шаг 1: Открыть оба бинарника

```json
// Открыть Python-сборку
{
  "input_path": "sqlite3_python.dll.i64",
  "mode": "force_headless",
  "idle_ttl_sec": 1200
}
// → session_id: "8a831e30"

// Открыть AIMP-сборку
{
  "input_path": "sqlite3_aimp.dll.i64",
  "mode": "force_headless",
  "idle_ttl_sec": 1200
}
// → session_id: "93b75ebe"
```

## Шаг 2: Проанализировать каждую сборку

**Python-сборка:** 2532 функции, 439 именованных, 44 библиотечные
**AIMP-сборка:**  3362 функции, 611 именованных, 437 библиотечных

Ключевое наблюдение: в Python-версии уже размечено 20+ внутренних функций (vdbe_exec, sqlite3Malloc, win_utf8_conv и т.д.). В AIMP-версии есть только имена из таблицы экспорта.

## Шаг 3: Экспортировать обе сборки в Diaphora SQLite

```json
// Экспорт Python → .diaphora.sqlite (64 MB)
export_idb_to_diaphora(idb_path: "sqlite3_python.dll.i64", use_decompiler: false, summaries_only: true)
// → output_path: "sqlite3_python.dll.diaphora.sqlite"

// Экспорт AIMP → .diaphora.sqlite (51 MB)
export_idb_to_diaphora(idb_path: "sqlite3_aimp.dll.i64", use_decompiler: false, summaries_only: true)
// → output_path: "sqlite3_aimp.dll.diaphora.sqlite"
```

## Шаг 4: Сравнить базы данных

```json
diff_diaphora_dbs(
  db1: "sqlite3_python.dll.diaphora.sqlite",
  db2: "sqlite3_aimp.dll.diaphora.sqlite",
  output_path: "diff_results.diaphora"
)
```

**Результаты сравнения:**

| Тип совпадения | Количество | Средний ratio |
|---|---|---|
| **Best** (идеальные) | 42 | 1.000 |
| **Partial** | 847 | 0.576 |
| **Multimatch** | 54 | 0.746 |

**Несопоставлено:** 1619 (только Python) + 1388 (только AIMP)

Всего: **943 совпадения** из ~5800 функций в обеих базах.

## Шаг 5: Security-анализ

```json
detect_security_patches(results_path: "diff_results.diaphora")
// → Security-патчей не найдено
// Различия вызваны оптимизациями компилятора/конфигурацией

find_patch_root(results_path: "diff_results.diaphora")
// → Каскадных изменений не обнаружено
```

## Шаг 6: Извлечь пары адресов (самый хитрый шаг)

Инструмент `transfer_metadata` возвращает адреса источника, а не правильно сопоставленные адреса цели. Обходим это прямым SQL-запросом:

```sql
-- Запрос к .diaphora для получения пар Python→AIMP
SELECT type, address, name, address2, name2, ratio
FROM results
WHERE name NOT LIKE 'sub_%'
ORDER BY ratio DESC;
```

Результат — пары вида:

```
vdbe_exec:        Python 0x180081DF0  →  AIMP 0x1800BEB20  (ratio: 0.49)
sqlite3Malloc:    Python 0x180005930  →  AIMP 0x180002EB0  (ratio: 0.36)
win_shm_connect:  Python 0x18000E380  →  AIMP 0x180082B10  (ratio: 0.68)
```

## Шаг 7: Переименовать функции в целевой базе

Используем batch-инструмент `rename` с правильными адресами AIMP:

```json
{
  "database": "4d8b12b0",  // AIMP-сессия
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
      // ... ещё 15
    ]
  }
}
```

**Важно:** адреса должны быть с префиксом `0x`, иначе парсинг не сработает.

## Шаг 8: Сохранить и проверить

```json
// Сохранить обновлённый .i64
idb_save(database: "4d8b12b0")
// → sqlite3_aimp.dll.i64

// Проверка: количество именованных функций выросло с 611 до 640 (+29)
survey_binary(database: "4d8b12b0")
```

## Шаг 9: Очистить lock-файлы

Headless-воркеры оставляют файлы `.id0`, `.id1`, `.nam`, которые мешают открытию `.i64` в GUI:

```bash
# Сначала убить процесс воркера
taskkill /F /PID 26264
# Затем удалить временные файлы
rm "sqlite3_aimp.dll.id0" "sqlite3_aimp.dll.id1" "sqlite3_aimp.dll.nam"
```

---

## Результаты

**Перенесено 23 внутренних функции sqlite3**, включая:

| Функция | Описание |
|---|---|
| `vdbe_exec` | Главный цикл исполнения VDBE — сердце SQL |
| `sqlite3Malloc` | Внутренний аллокатор памяти |
| `sqlite3Parser` | SQL-парсер (сгенерирован Lemon) |
| `btree_cursor` | Операции с B-tree курсорами |
| `win_utf8_conv` | Windows-конвертер UTF-8 |
| `where_loop_search` | Поиск циклов в планировщике WHERE |
| `pager_write_page` | Запись страниц в pager |
| `vdbe_dispatch` | Диспетчеризация opcode VDBE |

Плюс **8 экспортных имён `sqlite3_*`**, которые в AIMP-версии всё ещё были `sub_*`.

**7 имён пропущено** из-за конфликта с таблицей экспорта — внутренняя реализация по другому адресу совпадает по имени с реальным экспортным стабом.

**Именованных функций:** 611 → 640 (+4.7%).

## Ключевые выводы

1. **Не используйте `transfer_metadata`** — запрашивайте `.diaphora` SQLite напрямую для получения правильных пар адресов
2. **Всегда добавляйте префикс `0x`** к адресам в инструментах idalib-mcp
3. **Устанавливайте `idle_ttl_sec` достаточно большим**, иначе воркер умрёт посреди сессии
4. **Очищайте `.id0`/`.id1`/`.nam`** после headless-работы, иначе IDA GUI не откроет файл
5. **Используйте `use_decompiler: false` и `summaries_only: true`** для больших бинарников, чтобы ускорить экспорт
