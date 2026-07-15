[Read in English](GUI_INSTRUCTIONS.md)

# GUI, headless и интеграция с IDA

В проекте есть три разных компонента:

| Компонент | Назначение | Транспорт/порт |
| --- | --- | --- |
| `diaphora-mcp` | Экспорт IDA-баз, Diaphora diff и анализ результатов | Локальный stdio MCP-сервер |
| `ida-pro-mcp` / `idalib-mcp` | Инспекция IDA-баз, открытие функций, decompile и проверка адресов | Upstream-сервис, обычно `127.0.0.1:8745` |
| `diaphora_gui_listener.py` | Необязательный legacy GUI fallback для экспорта | XML-RPC, `127.0.0.1:28652` |

Upstream-сервис инспекции IDA не заменяет Diaphora MCP diff-сервер. Они дополняют друг друга.

## Сначала выберите режим экспорта

У `export_idb_to_diaphora` есть явный параметр `export_mode`:

| Режим | Поведение | Когда использовать |
| --- | --- | --- |
| `headless` | Всегда запускает `idat.exe`/`idat64.exe` и проверяет официальную diff-схему | Для matching и batch diff; основной вариант |
| `auto` | HTTP GUI integration → legacy listener → headless | Для удобного одиночного экспорта |
| `gui` | Только активная подходящая GUI-интеграция, без fallback | Когда GUI-экспорт выбран намеренно |

`batch_export_and_diff` принимает только `export_mode="headless"`. GUI-результат принимается только после проверки схемы, необходимой для matching.

## Рекомендуемая настройка инспекции адресов

Это необязательный отдельный сервис.

1. Установите upstream IDA MCP integration:

   ```powershell
   uv run ida-pro-mcp --install codex --transport streamable-http --scope global --ida-rpc http://127.0.0.1:8745/mcp
   ```

2. При необходимости активируйте IDA Library для своей установки:

   ```powershell
   uv run "C:\Path\To\IDA\idalib\python\py-activate-idalib.py"
   ```

3. Запустите backend:

   ```powershell
   uv run idalib-mcp --host 127.0.0.1 --port 8745 --max-workers 2
   ```

4. Перезапустите MCP-клиент и проверьте инструменты `idb_list`/`idb_open`.

5. `diaphora-mcp` настраивается отдельно как stdio-сервер.

## GUI-интеграции

### HTTP integration

Если upstream IDA plugin предоставляет Diaphora endpoints, сервер проверяет:

```text
GET  http://127.0.0.1:13337/diaphora/health
POST http://127.0.0.1:13337/diaphora/export
```

Не копируйте и не заменяйте `ida_mcp.py` вручную. Используйте installer upstream-интеграции, затем перезапустите IDA Pro и откройте нужный IDB. Надёжная проверка — health check и успешный export, а не конкретный пункт меню.

### Legacy XML-RPC listener

`diaphora_gui_listener.py` — необязательный fallback этого репозитория. Устанавливайте его только для legacy GUI-сценария. Он слушает `127.0.0.1:28652` и проверяет путь открытого IDB перед экспортом.

Для headless-режима listener не нужен.

## Полный workflow matching

1. Проанализируйте и сохраните оба `.i64`/`.idb`.
2. Вызовите `batch_export_and_diff` с `export_mode="headless"`, `use_decompiler=false`, а для быстрого первого прохода — `summaries_only=true`.
3. Сохраните пути `.diaphora.sqlite` и `.diaphora` из результата.
4. Прочитайте результаты через `get_diff_summary` или `get_diff_results`.
5. Для старого адреса вызовите `find_function_match`.
6. Для `compare_functions`, `get_changed_callgraph` и `compare_call_path` передавайте `match_results_path`, чтобы адреса после rebase были сопоставлены правильно.
7. Для низкоуровневой проверки используйте upstream `ida-pro-mcp`/`idalib-mcp`.

Пример:

```text
batch_export_and_diff(
  idb1_path="C:/analysis/old.i64",
  idb2_path="C:/analysis/new.i64",
  output_dir="C:/diaphora-outputs/old-new",
  export_mode="headless",
  summaries_only=true,
  use_decompiler=false
)
```

## Locks и безопасность процессов

Не запускайте headless IDA на IDB, который уже удерживается другим процессом IDA. Варианты:

- закрыть GUI IDB и использовать `export_mode="headless"`;
- экспортировать копию IDB;
- использовать `export_mode="gui"` для активной сессии, если integration доступна.

Перед экспортом сохраните GUI-анализ и убедитесь, какой файл используется.

## Перезапуск

- изменили Python-код или environment `diaphora-mcp`: перезапустите stdio MCP server/client;
- изменили upstream `ida_mcp.py`: перезапустите IDA Pro и upstream backend;
- изменили `diaphora_gui_listener.py`: перезапустите IDA Pro;
- изменили только анализ IDB: сохраните IDB и повторите export.

В Windows перед остановкой проверьте command line процесса. При restart останавливайте только Diaphora server, не закрывайте чужие IDA и `idalib-mcp` процессы.

## Диагностика

| Симптом | Что проверить |
| --- | --- |
| `idat.exe not found` | `IDAT_PATH` и перезапуск сервера |
| GUI mode недоступен | Открыт ли нужный IDB и отвечает ли правильный bridge |
| Export успешен, diff отклонён | Используйте `headless`; не хватает `program`/call-graph metadata |
| Функция не найдена в новой базе | Передайте `.diaphora` как `match_results_path`, не используйте старый адрес напрямую |
| Export завис | Locks, активность диска, timeout и export log |
| Results tools отклоняют input | Передавайте `.diaphora.sqlite`/`.diaphora`, а не `.i64`/`.idb` |
