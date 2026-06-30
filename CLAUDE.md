# Diaphora MCP — Automated Binary Diffing Pipeline

MCP-сервер для автоматизации бинарного диффинга через Diaphora + IDA Pro.

## Расположение

| Компонент | Путь |
|-----------|------|
| MCP-сервер | `diaphora_mcp_server.py` |
| Headless-wrapper | `_diaphora_headless.py` |
| Diaphora | `D:\Programs\IDA Professional 9.3\plugins\diaphora-3.4.1\` |
| IDA (idat.exe) | `D:\Programs\IDA Professional 9.3\idat.exe` |
| IDB-базы | `.i64` / `.idb` файлы (готовятся через IDA Pro GUI или IDAPython) |
| MCP-конфиг | `C:\Users\olegc\.claude\.mcp.json` |

## Доступные инструменты (MCP tools)

### Экспорт
- `export_idb_to_diaphora` — экспорт .i64/.idb в .sqlite через idat.exe (headless)
- `batch_export_and_diff` — полный пайплайн: экспорт → diff → сводка

### Diff
- `diff_diaphora_dbs` — дифф двух экспортированных .sqlite баз
- `get_diff_results` — чтение .diaphora файла с фильтрацией
- `get_diff_summary` — сводка по diff

### Анализ
- `analyze_diff_results` — security-фильтрация с keyword-матчингом и IDA Pro MCP интеграцией
- `compare_functions` — сравнение функции side-by-side из двух баз
- `search_export_db` — поиск функций по имени/размеру/сложности
- `get_function_pseudocode` — псевдокод функции из базы
- `get_export_info` — метаданные базы

### Phase 3 — Agent-first tools (высокоуровневые, LLM-ориентированные)
- `find_function_match` — поиск соответствия функции между двумя версиями с confidence и evidence
- `transfer_metadata` — подготовка данных для переноса имён/комментариев/прототипов/типов между базами
- `get_changed_callgraph` — сравнение входящих/исходящих вызовов функции
- `rank_changes` — ранжирование изменённых функций по важности (CFG, псевдокод, сложность, security)
- `find_patch_root` — определение корневых функций, вызывающих каскадные изменения
- `compare_call_path` — сравнение цепочек вызовов (BFS, до N уровней)
- `detect_security_patches` — детектирование вероятных исправлений безопасности (bounds checks, null checks, crypto, anti-debug, и др.)
- `detect_behavior_change` — NL-описание изменения логики функции
- `summarize_patch` — полный отчёт по обновлению с категоризацией
- `explain_similarity` — разбор факторов сходства (mnemonics, CFG, константы, callgraph, prototype, hash)

### IDA Pro MCP интеграция

Инструменты `analyze_diff_results`, `compare_functions`, `find_function_match`, `detect_security_patches`,
`detect_behavior_change` и другие возвращают поля `ida_pro_mcp`
с адресами и путями к базам. Используйте их с IDA Pro MCP инструментами:
- `decompile_function(address)` — декомпиляция подозрительной функции
- `get_function_by_address(address)` — инфо о функции
- `disassemble_function(address)` — листинг ассемблера

## Типовой workflow

```
# 1. Быстрый diff (если базы уже экспортированы)
diff_diaphora_dbs(db1="old.sqlite", db2="new.sqlite")

# 2. Полный pipeline (с headless-экспортом)
batch_export_and_diff(idb1="old.i64", idb2="new.i64")

# 3. Security-анализ результатов
analyze_diff_results(results_path="old_vs_new.diaphora")

# 4. Ранжирование по важности
rank_changes(results_path="old_vs_new.diaphora", top_n=20)

# 5. Поиск корневых изменений
find_patch_root(results_path="old_vs_new.diaphora")

# 6. Детектирование security-патчей
detect_security_patches(results_path="old_vs_new.diaphora")

# 7. Углублённое сравнение функции
compare_functions(db1="old.sqlite", db2="new.sqlite", address="401000")

# 8. Объяснение сходства
explain_similarity(db1="old.sqlite", db2="new.sqlite", address="401000")

# 9. Полный отчёт
summarize_patch(results_path="old_vs_new.diaphora")
```

## Важно

- **headless export** использует встроенный механизм Diaphora (env vars `DIAPHORA_AUTO`,
  `DIAPHORA_EXPORT_FILE`, `DIAPHORA_USE_DECOMPILER`).
- idat.exe запускается через thin wrapper `_diaphora_headless.py` (обходит проблему
  пробелов в пути `IDA Professional 9.3`).
- Для экспорта нужен скомпилированный `.i64` или `.idb` — IDA открывает его в headless
  режиме и экспортирует все функции.
- Для diff используется `diaphora.py` (system Python, не IDA).
- Таймаут экспорта: 1 час. Таймаут diff: 10 минут.
