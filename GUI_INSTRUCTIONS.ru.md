[Read in English](GUI_INSTRUCTIONS.md)

# Инструкция по GUI-мосту и headless-интеграции Diaphora MCP

GUI-мост позволяет MCP-серверу выполнять экспорт баз данных мгновенно прямо из запущенной и открытой на экране программы IDA Pro, избегая конфликтов блокировки файлов и необходимости закрывать IDA.

---

## Рекомендуемый вариант: headless IDA MCP

Для работы через Codex предпочтителен headless-сервис `idalib-mcp`. Он является backend для upstream-проекта `ida-pro-mcp`; отдельного сервера с названием `idalib-mcp` в Codex добавлять не нужно.

1. Установите upstream-плагин и зарегистрируйте его в Codex:
   ```powershell
   uv run ida-pro-mcp --install codex --transport streamable-http --scope global --ida-rpc http://127.0.0.1:8745/mcp
   ```
2. Активируйте окружение IDA Library (путь поправьте под свою установку):
   ```powershell
   uv run "D:\Programs\IDA Professional 9.3\idalib\python\py-activate-idalib.py"
   ```
3. Запустите backend:
   ```powershell
   uv run idalib-mcp --host 127.0.0.1 --port 8745 --max-workers 2
   ```
4. Полностью перезапустите Codex. Проверьте доступность инструментами `idb_list` и `idb_open`.

`diaphora-mcp` остаётся отдельным stdio-сервером этого репозитория: он экспортирует IDB в SQLite, запускает Diaphora diff и анализирует результаты.

## Вариант GUI-моста (необязательно)

Upstream-установщик сам размещает `ida_mcp.py` в каталоге плагинов пользователя. Вручную копировать файл из этого репозитория не требуется:

```powershell
uv run ida-pro-mcp --install codex --transport streamable-http --scope global --ida-rpc http://127.0.0.1:8745/mcp
```

После установки перезапустите IDA Pro и откройте нужный IDB. Плагин запускается автоматически; наличие пункта меню или горячей клавиши зависит от версии upstream-плагина и не является обязательным признаком работы.

`diaphora_gui_listener.py` — отдельный legacy XML-RPC fallback этого проекта на порту `28652`. Его следует устанавливать только если нужен именно GUI-fallback, а headless backend недоступен.

---

## Шаг 2. Запуск и проверка работы

1. Откройте нужную базу данных (например, `sqlite3_aimp.dll.i64`) в GUI IDA Pro.
2. В журнале IDA или при проверке порта `8745` убедитесь, что backend доступен. Для GUI-fallback проверьте порт `28652`.
3. Для upstream `ida-pro-mcp` проверяйте доступность через MCP-инструменты `idb_list`/`idb_open`, а не по фиксированному пункту меню.
4. Попросите ИИ-агента экспортировать базу данных:
   > *«Экспортируй sqlite3_aimp.dll.i64»*
5. Если IDB уже открыт в GUI, экспорт может быть передан активному GUI-мосту. Иначе сервер использует headless `idat.exe`.

Не запускайте headless-экспорт одновременно с `idb_open` на том же IDB: IDA может удерживать файл блокировки. Закройте сессию или используйте копию базы.

Для legacy GUI-fallback в Output Window могут появиться строки:
   ```
   [MCP] Plugin loaded, server will start automatically
   Config: http://127.0.0.1:13337/config.html
   Diaphora: http://127.0.0.1:13337/diaphora/health
   ```
6. Вы увидите лог прогресса экспорта в консоли клиента в реальном времени:
   ```
   [Diaphora MCP] Export progress: 6% (200/3362 functions)...
   [Diaphora MCP] Export progress: 12% (400/3362 functions)...
   ```

---

## Параллельный headless-экспорт

Если вы запрашиваете экспорт базы данных, которая **не открыта в GUI в данный момент**, сервер запускает автономный процесс `idat.exe` (при корректных `IDAT_PATH`, `DIAPHORA_DIR` и `DIAPHORA_OUTPUT_ROOT`).

При этом ваше активное GUI-окно останется полностью отзывчивым, и вы сможете продолжать работу без каких-либо задержек или зависаний.
