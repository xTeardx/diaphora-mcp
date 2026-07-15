[Read in English](README.md)

# Diaphora MCP

Diaphora MCP — локальный MCP-сервер, который соединяет AI-агентов с IDA Pro и Diaphora. Он экспортирует проанализированные базы IDA, запускает сравнение Diaphora и предоставляет инструменты для matching, call graph, ранжирования изменений, security triage и отчётов.

> Это помощник для анализа, а не замена IDA Pro, Diaphora или ручной проверке реверс-инженером.

## Рекомендуемый workflow

Для сравнения и matching используйте headless-режим:

```text
IDB/i64
  -> batch_export_and_diff(export_mode="headless")
  -> .diaphora.sqlite + .diaphora
  -> summary/results
  -> matching, compare, graph и security tools
```

Режимы экспорта:

| Режим | Поведение |
| --- | --- |
| `headless` | Всегда использует `idat.exe`, проверяет официальную diff-схему; рекомендуется |
| `auto` | Сначала пробует активный GUI bridge, затем headless |
| `gui` | Требует активную GUI-сессию и не переходит в headless автоматически |

`batch_export_and_diff` принимает только `export_mode="headless"`, поскольку matching требует полной официальной схемы Diaphora.

## Требования

- Python 3.10+;
- установленный IDA Pro с `idat.exe`/`idat64.exe`;
- установленный в IDA плагин Diaphora;
- MCP-совместимый клиент;
- место на диске для SQLite exports и diff-файла.

IDA Pro и Diaphora не входят в этот репозиторий и устанавливаются отдельно.

## Установка

```bash
git clone https://github.com/xTeardx/diaphora-mcp.git
cd diaphora-mcp
python -m pip install -e .
```

Переменные окружения:

```text
IDAT_PATH=<absolute path to idat.exe>
DIAPHORA_DIR=<directory containing Diaphora>
DIAPHORA_OUTPUT_ROOT=<allowed output directory>
```

Подробности: [Configuration](docs/CONFIGURATION.md) и [Workflows](docs/WORKFLOWS.md).

## Первый diff

```text
batch_export_and_diff(
  idb1_path="C:/analysis/old.i64",
  idb2_path="C:/analysis/new.i64",
  output_dir="C:/diaphora-outputs/run-001",
  export_mode="headless",
  use_decompiler=false,
  summaries_only=true
)
```

В result tools передавайте только созданные `.diaphora.sqlite` и `.diaphora`. Файл `.i64` — это база IDA, а не SQLite results database.

Для сопоставления функции используйте `find_function_match`, а для сравнения — `compare_functions` с `match_results_path`, чтобы адрес новой версии был взят из результатов Diaphora.

## Ограничения

- Matching эвристический и требует ручной проверки.
- Security tools только выделяют сигналы и не доказывают наличие уязвимости или патча.
- GUI-сессия может удерживать lock базы и блокировать второй процесс IDA.
- Большие базы могут экспортироваться минуты или часы.
- IDB, бинарники, SQLite exports, логи и crash artifacts нельзя добавлять в Git.

Полный список ограничений: [docs/LIMITATIONS.md](docs/LIMITATIONS.md). Правила для AI-агентов: [AGENTS.md](AGENTS.md).

## Разработка

```powershell
python -m pytest -q
python -m compileall -q .
git diff --check
```

Подробные инструкции для contributors находятся в [CONTRIBUTING.md](CONTRIBUTING.md).
