[Read in English](sqlite3_example.md)

# Пример: Сравнение sqlite3.dll (Python против AIMP)

Этот пример демонстрирует, как использовать MCP-сервер Diaphora для выполнения бинарного сравнения (диффинга) двух небольших реальных библиотек DLL, которые уже установлены в вашей Windows-системе.

Мы будем сравнивать две разные сборки библиотеки `sqlite3.dll`:
1. **Версия из Python 3.12**: `C:\Users\<Имя_Пользователя>\AppData\Local\Programs\Python\Python312\DLLs\sqlite3.dll` (скомпилирована ~октябрь 2023, размер ~1.50 МБ)
2. **Версия из плеера AIMP**: `D:\Programs\AIMP\sqlite3.dll` (скомпилирована ~декабрь 2023, размер ~1.63 МБ)

---

## 1. Подготовка файлов

1. Создайте рабочую папку, например, `E:\Program Files\IdaPro_projects\test\`.
2. Скопируйте туда оба DLL-файла, переименовав их для ясности:
   - Копию из Python назовите `sqlite3_python.dll`
   - Копию из AIMP назовите `sqlite3_aimp.dll`

*Примечание: Вам не нужно открывать IDA Pro вручную или предварительно генерировать файлы баз данных `.i64`. MCP-сервер Diaphora поддерживает **полноценный headless-режим**. Если вы передадите пути к исходным `.dll` или `.exe` напрямую, IDA Pro автоматически запустится в фоновом режиме, проведет автоанализ и экспортирует базы данных SQLite за один шаг.*

---

## 2. Запуск пайплайна сравнения (Diff)

Вызовите инструмент `batch_export_and_diff` через вашего MCP-клиента (например, Claude Desktop, Gemini Antigravity, Cursor), передав пути к исходным `.dll` файлам:

```json
{
  "idb1_path": "E:\\Program Files\\IdaPro_projects\\test\\sqlite3_python.dll",
  "idb2_path": "E:\\Program Files\\IdaPro_projects\\test\\sqlite3_aimp.dll",
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

### В. Разница ассемблера (Assembly Diff — строится ИИ)

Так как `compare_functions` возвращает полный сырой ассемблер обеих функций, ваш ИИ-ассистент может автоматически сопоставить их и отобразить наглядную разницу:

```diff
- loc_180079aa6:
-   movzx   eax, byte ptr [rcx+71h]
-   cmp     al, 76h ; 'v'
-   jz      short loc_180079B10
+ loc_1800cf4cc:
+   mov     eax, [rcx+5Ch]
+   cmp     eax, 0A029A697h
+   jz      short loc_1800CF544
```
```
