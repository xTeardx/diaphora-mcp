# Diaphora MCP

**Diaphora MCP** — это MCP-сервер для автоматизированного бинарного диффинга. Он соединяет [Diaphora](https://github.com/joxeankoret/diaphora) (движок диффинга) и IDA Pro (дизассемблер) через протокол MCP, позволяя ИИ-агентам (Claude Code, etc.) выполнять сравнение бинарных файлов, находить security-патчи и анализировать изменения.

## Возможности

- **Экспорт**: конвертация проанализированных .i64/.idb в формат Diaphora SQLite (через idat.exe headless)
- **Диффинг**: сравнение двух экспортированных баз, фильтрация результатов по типу совпадения и ratio
- **Анализ уязвимостей**: поиск security-релевантных изменений по ключевым словам и эвристикам
- **Детектирование патчей**: автоматическое обнаружение новых проверок границ, null-checks, обработки ошибок, крипто-изменений
- **Ранжирование**: сортировка изменённых функций по важности (CFG, сложность, security-индикаторы)
- **Call Graph**: сравнение цепочек вызовов (BFS, до N уровней), поиск корневых изменений
- **Перенос метаданных**: подготовка данных для переноса имён/комментариев/прототипов между базами
- **Интеграция с IDA Pro MCP**: все инструменты возвращают адреса и пути для прямого вызова IDA Pro MCP

## Установка

### 1. Зависимости

- Python 3.10+
- [IDA Pro](https://hex-rays.com/IDA-pro/) 8.x / 9.x (для headless-экспорта через idat.exe)
- [Diaphora](https://github.com/joxeankoret/diaphora) — плагин для IDA (установлен в IDA)
- [Claude Code](https://claude.ai/code) (или любой MCP-клиент)

### 2. Установка пакета

```bash
git clone https://github.com/your-org/diaphora-mcp.git
cd diaphora-mcp
pip install -e .
```

### 3. Конфигурация путей

Пакет пытается **автоматически найти** IDA и Diaphora в стандартных местах установки. Если не находит — можно указать переменные окружения:

| Переменная | Что указывает | Пример |
|-----------|--------------|--------|
| `IDAT_PATH` | Полный путь к idat.exe | `C:\Program Files\IDA Pro 9.3\idat.exe` |
| `DIAPHORA_DIR` | Папка с diaphora.py | `C:\Program Files\IDA Pro 9.3\plugins\diaphora-3.4.1` |
| `DIAPHORA_PYTHON` | Python для diff | `/usr/bin/python3` (по умолч. sys.executable) |

В Claude Code можно задать их в `~/.claude.json`:

```json
{
  "mcpServers": {
    "diaphora": {
      "command": "python",
      "args": ["путь/к/репе/diaphora_mcp_server.py"],
      "env": {
        "IDAT_PATH": "C:\\Program Files\\IDA Pro 9.3\\idat.exe",
        "DIAPHORA_DIR": "C:\\Program Files\\IDA Pro 9.3\\plugins\\diaphora-3.4.1"
      },
      "timeout": 3600
    }
  }
}
```

### 4. Подготовка баз для диффа

IDA должна проанализировать сравниваемые бинарники (создать .i64 или .idb). После этого:

```
┃ export_idb_to_diaphora(idb_path="old_version.i64")
┃ export_idb_to_diaphora(idb_path="new_version.i64")
```

Либо одной командой:

```
┃ batch_export_and_diff(idb1="old.i64", idb2="new.i64")
```

## Использование

### Быстрый старт

```
┃ # 1. Полный пайплайн: экспорт двух .i64 → diff → отчёт
┃ batch_export_and_diff(idb1="v1.0.i64", idb2="v1.1.i64")

┃ # 2. Если базы уже экспортированы
┃ diff_diaphora_dbs(db1="v1.0.sqlite", db2="v1.1.sqlite")

┃ # 3. Security-анализ результатов
┃ analyze_diff_results(results_path="v1.0_vs_v1.1.diaphora")

┃ # 4. Ранжирование
┃ rank_changes(results_path="v1.0_vs_v1.1.diaphora", top_n=20)

┃ # 5. Поиск корневых изменений
┃ find_patch_root(results_path="v1.0_vs_v1.1.diaphora")

┃ # 6. Детектирование security-патчей
┃ detect_security_patches(results_path="v1.0_vs_v1.1.diaphora")

┃ # 7. Полный отчёт
┃ summarize_patch(results_path="v1.0_vs_v1.1.diaphora")
```

### Исследование одной базы

```
┃ # Метаданные базы
┃ get_export_info(db_path="app.sqlite")

┃ # Поиск функций
┃ search_export_db(db_path="app.sqlite", name_pattern="%crypt%", min_instructions=50)

┃ # Псевдокод
┃ get_function_pseudocode(db_path="app.sqlite", address="401000")
```

## Структура проекта

```
diaphora-mcp/
├── diaphora_mcp_server.py          # Точка входа (22 строки)
├── diaphora_mcp/
│   ├── diaphora_mcp_server.py      # Регистрация MCP-инструментов
│   ├── config.py                   # Конфигурация путей (автоопределение)
│   ├── models.py                   # Разделяемые константы
│   ├── core/
│   │   ├── export.py               # Headless-экспорт, batch pipeline
│   │   ├── diff.py                 # Диффинг и чтение .diaphora
│   │   ├── analysis.py             # Поиск, сравнение, объяснение функций
│   │   ├── security.py             # Keyword matching, детектирование патчей
│   │   ├── ranking.py              # Ранжирование по важности
│   │   ├── graph.py                # Call graph, BFS, root cause
│   │   ├── metadata.py             # Перенос имён/типов/комментариев
│   │   └── report.py               # Полный отчёт по патчу
│   └── utils/
│       ├── sqlite.py               # DB helpers
│       ├── format.py               # Pseudocode diff, feature extraction
│       └── log.py                  # Логирование экспортов
├── _diaphora_headless.py           # Wrapper для idat.exe -S
└── logs/                           # Логи экспортов (создаётся автоматически)
```

## Все MCP-инструменты (20 шт)

### Export
| Инструмент | Описание |
|-----------|----------|
| `export_idb_to_diaphora` | Экспорт .i64/.idb в .sqlite через idat.exe |
| `batch_export_and_diff` | Полный пайплайн: экспорт → экспорт → diff → сводка |

### Diff
| Инструмент | Описание |
|-----------|----------|
| `diff_diaphora_dbs` | Дифф двух экспортированных .sqlite баз |
| `get_diff_results` | Чтение .diaphora файла с фильтрацией |
| `get_diff_summary` | Сводка по diff |

### Analysis
| Инструмент | Описание |
|-----------|----------|
| `analyze_diff_results` | Security-фильтрация |
| `compare_functions` | Side-by-side сравнение двух версий функции |
| `find_function_match` | Поиск соответствия функции между версиями |
| `explain_similarity` | Разбор факторов сходства |
| `detect_behavior_change` | NL-описание изменения логики |
| `summarize_patch` | Полный отчёт по обновлению |
| `search_export_db` | Поиск функций по имени/размеру/сложности |
| `get_function_pseudocode` | Псевдокод функции из базы |
| `get_export_info` | Метаданные базы |

### Security
| Инструмент | Описание |
|-----------|----------|
| `detect_security_patches` | Детектирование вероятных исправлений безопасности |

### Ranking
| Инструмент | Описание |
|-----------|----------|
| `rank_changes` | Ранжирование изменённых функций по важности |

### Callgraph
| Инструмент | Описание |
|-----------|----------|
| `get_changed_callgraph` | Сравнение входящих/исходящих вызовов |
| `compare_call_path` | Сравнение цепочек вызовов (BFS, N уровней) |
| `find_patch_root` | Определение корневых функций |

### Metadata
| Инструмент | Описание |
|-----------|----------|
| `transfer_metadata` | Подготовка данных для переноса имён/комментариев |

## IDA Pro MCP интеграция

Инструменты `analyze_diff_results`, `compare_functions`, `find_function_match` и другие возвращают поле `ida_pro_mcp` с адресами и путями к базам. Эти данные можно передавать напрямую в IDA Pro MCP:

```
┃ # 1. Diaphora находит подозрительную функцию
┃ analyze_diff_results(results_path="diff.diaphora")
┃   → addr1="401000", db1="old.sqlite"

┃ # 2. IDA Pro MCP декомпилирует
┃ decompile_function(address="401000")
```

## Известные проблемы

См. [Problems.md](Problems.md).

## Лицензия

MIT
