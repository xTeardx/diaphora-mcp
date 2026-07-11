# Diaphora MCP — правила для агентов

## Назначение

Проект предоставляет MCP-сервер для экспорта IDA-баз, сравнения Diaphora SQLite-баз и анализа diff-результатов.

## Компоненты

- `diaphora_mcp_server.py` — stdio entrypoint сервера `diaphora-mcp`.
- `diaphora_mcp/` — регистрация MCP tools и основная логика.
- `diaphora_gui_listener.py` — необязательный XML-RPC мост для уже открытой GUI-сессии IDA.
- `_diaphora_headless.py` — wrapper для `idat.exe`.
- `ida-pro-mcp`/`idalib-mcp` — отдельный upstream-сервер для headless IDA inspection; он не заменяет Diaphora diff server.

## Поддерживаемый workflow

1. Получить `.i64`/`.idb` из IDA.
2. Вызвать `export_idb_to_diaphora` или `batch_export_and_diff` с `summaries_only=True` и `use_decompiler=False` для больших баз.
3. Передать только созданные `.diaphora.sqlite` и `.diaphora` в DB/results tools.
4. Для низкоуровневой проверки адресов использовать `ida-pro-mcp`/`idalib-mcp`.

`.i64` — это IDA database, а не SQLite. Не передавай `.i64` напрямую в `get_diff_summary`, `rank_changes`, `summarize_patch` и другие results tools.

## Окружение

Минимальные переменные:

```text
IDAT_PATH=D:\Programs\IDA Professional 9.3\idat.exe
DIAPHORA_DIR=D:\Programs\IDA Professional 9.3\plugins\diaphora-3.4.1
DIAPHORA_OUTPUT_ROOT=D:\diaphora-outputs
```

`DIAPHORA_OUTPUT_ROOT` ограничивает новые export targets. Уже открытый IDB нельзя одновременно экспортировать вторым `idat.exe`: сначала освободи lock или используй уже активный GUI/idalib backend.

## Проверки перед изменениями

```powershell
git status --short
git branch --show-current
git rev-parse HEAD
python -m pytest -q
python -m compileall -q .
python -m pip check
```

Для production fix сначала добавь regression test, воспроизведи failure, внеси минимальный patch и повтори полный suite. Не используй `git reset --hard`, `git clean -fd`, force-push и не удаляй пользовательские IDA fixtures.

## Git и локальные артефакты

- `Fixes/` — локальные бинарные fixtures, не публикуются.
- `audit_artifacts/`, `logs/`, `dist/`, `build/`, `uv.lock` — локальные/generated artifacts.
- Проектные тесты в `tests/` отслеживаются Git.
- Перед commit проверь `git diff --check` и отсутствие случайных бинарников.

## Ограничения

Статические проверки могут показывать существующие diagnostics для IDA-модулей, XML-RPC и adaptive SQL. Это не следует автоматически считать новым production bug: сначала сравни с baseline и добавь воспроизводимый тест.
