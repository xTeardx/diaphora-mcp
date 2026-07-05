[English version](sqlite3_example.md)

# Diaphora MCP — Пример бинарного диффинга SQLite3 DLL

В этом примере сравниваются две Windows DLL на основе SQLite3 с помощью **Diaphora MCP** (интеграция IDA Pro + Diaphora через протокол MCP).

## 📂 Исходные файлы

| Файл | Размер | Версия SQLite | Хэш |
|---|---|---|---|
| `sqlite3_aimp.dll` | 1.6 MB | **2015** (2015-10-16) | `767c1727fec4ce11b83f25b3f1bfcfe68a2c8b02` |
| `sqlite3_python.dll` | 1.5 MB | **2023** (2023-05-16) | `831d0fb2836b71c9bc51067c49fee4b8f18047814f2ff22d817d25195cf350b0` |

Обе DLL экспортируют SQLite3 API, но:

- **aimp** — старая сборка (2015) с кастомными именованиями (суффикс `_0`, много `sub_*`)
- **python** — новая сборка (2023) с каноническими именами функций

Исходные IDB/i64: `sqlite3_aimp.dll.i64` (62 MB), `sqlite3_python.dll.i64` (77 MB).

---

## 🛠️ Использованные MCP-инструменты

### 1. Полный пайплайн (batch_export_and_diff)

```json
{
  "idb1_path": "sqlite3_aimp.dll.i64",
  "idb2_path": "sqlite3_python.dll.i64",
  "use_decompiler": false
}
```

Выполняет:
- Экспорт обеих .i64 в Diaphora SQLite
- Запуск алгоритма диффинга
- Возврат структурированных результатов

### 2. Сводка (get_diff_summary)

Общая статистика совпадений, топ best/partial matches.

### 3. Ранжирование изменений (rank_changes)

Сортировка функций по важности с security-классификацией.

### 4. Сравнение функций (compare_functions)

Side-by-side ассемблер и псевдокод для пар matched-функций.

### 5. Детектирование изменений поведения (detect_behavior_change)

Анализ: добавились/удалились вызовы, константы, изменился CFG.

### 6. Граф вызовов (get_changed_callgraph)

Кто вызывал и кого вызывала функция — до и после.

### 7. Псевдокод через IDA MCP (decompile)

Настоящий C-подобный псевдокод Hex-Rays для выбранных функций.

### 8. Анализ безопасности (detect_security_patches)

Поиск патчей безопасности: bounds checks, null checks, validation и т.д.

### 9. Анализ компонента (analyze_component)

Групповой анализ связанных функций.

---

## 📊 Формат вывода

Diaphora MCP возвращает **структурированный JSON**, который включает:

### Сводка диффа

```json
{
  "best_matches": 60,
  "partial_matches": 993,
  "unreliable_matches": 0,
  "multimatches": 52,
  "unmatched_primary": 2647,
  "total_matches": 1105
}
```

### Каждая matched-пара

```json
{
  "type": "partial",
  "address": "1800beb20",
  "name": "sub_1800BEB20",
  "address2": "180081df0",
  "name2": "vdbe_exec",
  "ratio": "0.4897823",
  "nodes1": 18,
  "nodes2": 40,
  "description": "assembly changed"
}
```

### Ранжированные изменения

```json
{
  "score": 100,
  "type": "partial",
  "ratio": "0.4805652",
  "name_old": "sqlite3MallocSize",
  "name_new": "sqlite3MallocSize",
  "security_relevant": true,
  "security_categories": ["memory"],
  "complexity_change": 0,
  "ida_pro_mcp": {
    "db1": "aimp.diaphora.sqlite",
    "db2": "python.diaphora.sqlite",
    "addr1": "18002b2a0",
    "addr2": "180005dc0"
  }
}
```

---

## 🔬 Ключевые результаты

### Общая статистика

| Тип совпадения | Количество | Среднее сходство |
|---|---|---|
| ✅ Best (100% идентичны) | 60 | 1.000 |
| 🔶 Partial (частично изменены) | 993 | 0.591 |
| 🔷 Multimatch (1→N) | 52 | 0.761 |
| ❌ Unmatched (только в aimp) | 1,282 | — |
| ❌ Unmatched (только в python) | 1,365 | — |
| **Всего** | **1,105** | — |

### Security-relevant изменения (23 найдено)

| Функция (было → стало) | Категория | Сходство | Что изменилось |
|---|---|---|---|
| `sub_18002B070` → `sqlite3_realloc64` | memory | 0.50 | Новый аллокатор с проверками |
| `sub_1800BEB20` → `vdbe_exec` | process | 0.49 | +50 инструкций, ретрай-цикл |
| `sub_18002B2A0` → `sqlite3MallocSize` | memory | 0.48 | Многоуровневые freelist-бакеты |
| `sub_18002AB40` → `sqlite3_malloc64` | memory | 0.45 | Новая реализация malloc |
| `sub_1800CED80` → `vdbe_prep_check` | validation | 0.43 | Усиленная валидация |

---

## 🧬 Пример: сравнение `vdbe_exec`

### AIMP (старый, 2015) — 94 инструкции, 18 блоков

```c
__int64 __fastcall sub_1800BEB20(a1, a2, a3, a4, a5, a6, a7) {
    *a6 = 0;
    if (!a1) { sqlite3_log(…); return 21; }
    // Проверка по DWORD-магическим числам
    v13 = *(DWORD *)(a1 + 92);
    if (v13 != 0xA029A697) { /* unopened/invalid */ }
    // mutex_enter
    sub_180032720(a1);           // prepare
    v15 = sub_1800BE120(a1, …);  // exec (один проход)
    if (v15 == 17) {             // SQLITE_OK?
        sqlite3_finalize(*a6);
        v15 = sub_1800BE120(a1, …); // повтор
    }
    sub_18000A790(a1);           // cleanup
    return v15;
}
```

### Python (новый, 2023) — 144 инструкции, 40 блоков

```c
__int64 __fastcall vdbe_exec(a1, a2, a3, a4, a5, a6, a7) {
    v7 = 0;  // retry counter
    *a6 = 0;
    if (!a1) { sqlite3_log(…); goto misuse; }
    v14 = *(BYTE *)(a1 + 113);   // enum-based check
    if (v14 != 118) { /* unopened/invalid */ }
    // mutex_enter
    if (!*(BYTE *)(a1 + 111))
        sub_18001E740(a1);       // check cancel
    while (1) {
        v17 = sub_180081850(a1, …); // execute step
        if (!v17) break;
        if (*(a1 + 103)) break;  // cancel requested
        if (v17 == 513) {        // SQLITE_SCHEMA
            if (v7++ >= 25) break;  // max 25 retries
        } else if (v17 == 17) {
            // iterate statements → cancel VDBE on schema change
            for (v23=0; v23 < *(a1+40); v23++) {
                v25 = stmt[v23];
                if (v25->flags & 8) sub_180067CB0(v25);
            }
            if (v7++) break;
        }
    }
    // sqlite3ApiExit, cleanup
    return v27;
}
```

### Ключевые отличия

| Изменение | Старое | Новое |
|---|---|---|
| **Ретрай-цикл** | Нет | До 25 попыток при блокировках |
| **SQLITE_SCHEMA** | Игнорировался | Автоматический перезапуск |
| **Cancel** | Нет | Проверка флага отмены |
| **Проверка соединения** | DWORD magic (0xA029A697) | Enum byte (118) |
| **Обработка ошибок** | Прямой return | Через sqlite3ApiExit |

---

## 🧬 Пример: `sqlite3MallocSize`

### AIMP (старый) — один freelist bucket

```c
if (!a1) goto alloc;
if (*(a1+81)) return 0;          // OOM guard
if (!*(a1+338)) goto alloc;      // freelist disabled
if (size > *(a1+336)) {          // too big
    (*(a1+352))++; goto alloc;   // miss counter
}
result = *(a1+360);              // one freelist
if (result) { *(a1+360) = *result; }
else { (*(a1+356))++; }
```

### Python (новый) — 4 freelist bucket (по размеру)

```c
if (size > *(a1+420)) {
    if (*(a1+416)) { if (*(a1+103)) return 0; }
    else { (*(a1+436))++; goto sub_180005D80; }
}
// <= 128 bytes → bucket @ offset 472
// > 128 ≤ max  → bucket @ offset 464
//                 bucket @ offset 456
//                 bucket @ offset 448
// pop from linked list, hit counter, return
```

---

## ⚠️ Нюансы использования Diaphora MCP

### 1. Направление сравнения влияет на результат

```
aimp → python:  60 best + 993 partial = 1105 matches
python → aimp:  42 best + 847 partial =  943 matches
```

Diaphora **несимметричен** — когда primary БД менее полная (aimp с `sub_*`), алгоритм находит больше совпадений.

### 2. Декомпилятор замедляет экспорт в 10-30×
- `use_decompiler: false` — быстрый первый проход (без псевдокода в SQLite)
- `use_decompiler: true` — включает C-псевдокод, но экспорт в 10-30× дольше

### 3. Размер .i64 имеет значение
- Файлы >100 MB: рекомендуется `summaries_only: auto`
- Для больших бинарников: ограничивайте `limit` и `unmatched_limit`

### 4. IDA MCP дополняет Diaphora
- Diaphora даёт **диффинг** (кто изменился, насколько)
- IDA MCP даёт **глубокий анализ** (псевдокод, граф вызовов, xrefs)
- Комбинация двух MCP даёт наиболее полную картину

---

## 📋 Полный список использованных вызовов MCP

### Diaphora MCP
| Инструмент | Назначение |
|---|---|
| `batch_export_and_diff` | Полный пайплайн экспорт + дифф |
| `get_diff_summary` | Сводная статистика |
| `rank_changes` | Ранжирование с security-анализом |
| `compare_functions` | Side-by-side ассемблер |
| `detect_behavior_change` | Естественно-языковое описание изменений |
| `get_changed_callgraph` | Граф вызовов до/после |
| `detect_security_patches` | Поиск security-патчей |
| `explain_similarity` | Разбор, почему функции совпали на X% |
| `find_function_match` | Поиск соответствия по адресу/имени |

### IDA MCP
| Инструмент | Назначение |
|---|---|
| `idb_open` | Открыть .i64 (.idb) |
| `decompile` | Получить C-псевдокод Hex-Rays |
| `analyze_component` | Анализ группы связанных функций |
| `survey_binary` | Быстрый обзор бинарника |
| `func_profile` | Профилирование функций |

---

## 🏁 Выводы

1. **Diaphora MCP успешно сравнивает два бинарника** и даёт структурированный JSON с matched-парами, процентами сходства и типами совпадений.

2. **Комбинация с IDA MCP** позволяет получить C-псевдокод и детальный анализ для выбранных функций, компенсируя отсутствие декомпилятора в Diaphora SQLite.

3. **SQLite3 2015 → 2023**: изменения затронули все ключевые подсистемы — VDBE (ретраи, отмена), менеджер памяти (4-уровневые бакеты), обработку ошибок (sqlite3ApiExit).

4. **Security-relevant изменения** (23 функции) — в основном memory management и process execution, но Diaphora не пометил их как явные security-патчи.

5. **Формат JSON** с `ida_pro_mcp` ссылками позволяет легко перейти от сводки к глубокому анализу конкретной функции.

---

*Сгенерировано с помощью Claude Code + Diaphora MCP + IDA MCP*
