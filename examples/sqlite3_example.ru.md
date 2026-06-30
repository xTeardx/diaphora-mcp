# Пример: Сравнение sqlite3.dll (Python против AIMP)

Этот пример демонстрирует, как использовать MCP-сервер Diaphora для выполнения бинарного сравнения (диффинга) двух небольших реальных библиотек DLL, которые уже установлены в вашей Windows-системе.

Мы будем сравнивать две разные сборки библиотеки `sqlite3.dll`:
1. **Версия из Python 3.12**: `C:\Users\<Имя_Пользователя>\AppData\Local\Programs\Python\Python312\DLLs\sqlite3.dll` (скомпилирована ~октябрь 2023, размер ~1.50 МБ)
2. **Версия из плеера AIMP**: `D:\Programs\AIMP\sqlite3.dll` (скомпилирована ~декабрь 2023, размер ~1.63 МБ)

---

## 1. Подготовка баз данных IDA Pro (.i64)

1. Создайте рабочую папку, например, `E:\Program Files\IdaPro_projects\test\`.
2. Скопируйте туда оба DLL-файла, переименовав их для ясности:
   - Копию из Python назовите `sqlite3_python.dll`
   - Копию из AIMP назовите `sqlite3_aimp.dll`
3. Сгенерируйте файлы баз данных IDA Pro (`.i64`), запустив IDA в пакетном (batch) режиме через командную строку:
   ```cmd
   "C:\Program Files\IDA Pro 9.3\idat.exe" -B "E:\Program Files\IdaPro_projects\test\sqlite3_python.dll"
   "C:\Program Files\IDA Pro 9.3\idat.exe" -B "E:\Program Files\IdaPro_projects\test\sqlite3_aimp.dll"
   ```
   Этот процесс проанализирует обе DLL и сохранит файлы `sqlite3_python.dll.i64` и `sqlite3_aimp.dll.i64`.

---

## 2. Запуск пайплайна сравнения (Diff)

Вызовите инструмент `batch_export_and_diff` через вашего MCP-клиента (например, Claude Desktop, Gemini Antigravity, Cursor):

```json
{
  "idb1_path": "E:\\Program Files\\IdaPro_projects\\test\\sqlite3_python.dll.i64",
  "idb2_path": "E:\\Program Files\\IdaPro_projects\\test\\sqlite3_aimp.dll.i64",
  "use_decompiler": false,
  "summaries_only": false,
  "cleanup": false
}
```

### Ожидаемый результат
Инструмент экспортирует обе базы в формат `.sqlite` и создаст файл результатов `.diaphora`, содержащий найденные совпадения:
```json
{
  "success": true,
  "summary": {
    "best_matches": 41,
    "partial_matches": 850,
    "unreliable_matches": 0,
    "multimatches": 54,
    "unmatched_primary": 3000
  }
}
```

---

## 3. Анализ различий по разным адресам

Поскольку библиотеки компилировались независимо, функции в них сместились (например, `sqlite3_exec` имеет адрес `6442949232` в версии Python и `6443299984` в версии AIMP).

Вы можете сравнивать их, передавая одновременно аргументы `address` (для db1) и `address2` (для db2):

### А. Поблоковое сравнение (`compare_functions`)
```json
{
  "db1_path": "E:\\Program Files\\IdaPro_projects\\test\\sqlite3_python.dll.sqlite",
  "db2_path": "E:\\Program Files\\IdaPro_projects\\test\\sqlite3_aimp.dll.sqlite",
  "address": "6442949232",
  "address2": "6443299984"
}
```
**Результат:**
```json
{
  "function_old": {
    "name": "sqlite3_exec",
    "address": "6442949232",
    "instructions": 398,
    "cyclomatic_complexity": 246
  },
  "function_new": {
    "name": "sqlite3_exec_0",
    "address": "6443299984",
    "instructions": 387,
    "cyclomatic_complexity": 228
  },
  "comparison": {
    "name_changed": true,
    "instructions_added": -11,
    "complexity_change": -18,
    "hash_changed": true
  }
}
```

### Б. Описание изменений логики (`detect_behavior_change`)
```json
{
  "db1_path": "E:\\Program Files\\IdaPro_projects\\test\\sqlite3_python.dll.sqlite",
  "db2_path": "E:\\Program Files\\IdaPro_projects\\test\\sqlite3_aimp.dll.sqlite",
  "address": "6442949232",
  "address2": "6443299984"
}
```
**Результат:**
```json
{
  "function_name_old": "sqlite3_exec",
  "function_name_new": "sqlite3_exec_0",
  "change_type": "modified",
  "changes": [
    "renamed from 'sqlite3_exec' to 'sqlite3_exec_0'",
    "shrunk by 11 instructions (398→387)",
    "complexity decreased by 18 (CC 246→228)",
    "CFG: 118→110 blocks, 362→336 edges",
    "loops: 2→1",
    "no longer calls: sqlite3_malloc64_0, sub_180005930, sub_180005DC0..."
  ]
}
```
