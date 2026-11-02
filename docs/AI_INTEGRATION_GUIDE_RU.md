# 🧭 Полное руководство: 3-слойная система качества ИИ (`GEMINI.md` + `Lgraph` + `Independent Auditor`)

Это руководство описывает модульную систему управления качеством ИИ-агентов для **Google Antigravity**, **Cursor** и **Claude Code**.

---

## 1. Архитектура 3 слоёв (экономия контекста в ~25 раз)

Вместо одной громоздкой простыни текстовых правил в памяти модели работают **3 непересекающихся слоя** (*Progressive Disclosure* — раскрытие деталей только по мере надобности):

1. **Слой 1 — Компактные Глобальные Правила (`~/.gemini/GEMINI.md`, `~850` токенов):**
   - Задают планку **Principal Systems Engineer**, лимит размера файла `<= 350` строк, безопасность входных данных/SQL/секретов и сверку реальных версий пакетов перед поиском в сети.
   - Управляют **Коробкой из 3 передач сложности**:
     - *1-я передача (мелкая правка 1 безопасного файла):* точечное чтение -> правка -> проверка `verify_architecture_rules` (без бумажной бюрократии);
     - *2-я передача (фича / `>= 2` связанных модулей):* разведка `Lgraph` -> `Implementation Plan` -> реализация + автотесты + `verify_architecture_rules`;
     - *3-я передача (зона `CRITICAL`, сквозные контракты `UI <-> IPC <-> API`, миграции БД, конкурентность `asyncio`/потоков, автономный режим `/goal`):* плюс обязательная проверка **Независимым Red-Team Аудитором** с чистым контекстом до `0 P0, 0 P1`.

2. **Слой 2 — Два автономных глобальных плагина (`~/.gemini/config/plugins/`):**
   - **`lgraph-intelligence`** — поднимает локальный MCP-сервер **`lgraph`** (`run_mcp_server.py`, работает без `cwd` и без необходимости держать окно `Lgraph` открытым — сверяет изменившиеся файлы на диске за `~2–4 мс`), хранит базовое правило `rules/AGENTS.md` и навык `system-intelligence`.
   - **`independent-auditor`** — отдельный глобальный плагин **Независимого Red-Team Аудитора** с чистым контекстом (`Cold Plan Audit` и `Cold Code Audit` + профильные чек-листы `stack_checklists.md`). Включает жёсткий стоп-кран против бесконечных ревизий после достижения `0 P0, 0 P1`.

3. **Слой 3 — Локальный контур проекта (`lgraph.yaml` + `.agent/MEMORY.md <= 150` строк):**
   - Машинные инварианты (размеры файлов, запрет циклов, шлюзы, запрещённые конструкции) проверяются кодом `GuardrailEngine` с расходом **`0` токенов** и точностью **100%**.
   - В `.agent/MEMORY.md` хранятся только паспорт проекта и короткие доменные предохранители, а разборы инцидентов уходят в `.agent/MEMORY_ARCHIVE.md`.

---

## 2. Быстрая установка плагинов в Antigravity

Запустите установщик из корня клонированного репозитория `Lgraph`:

```powershell
python scripts/install_antigravity_plugin.py
```

Скрипт скопирует оба плагина в `%USERPROFILE%\.gemini\config\plugins\` и сам подставит ваш локальный путь к виртуальному окружению Python и `run_mcp_server.py`.

---

## 3. Шпаргалка по 6 инструментам MCP-сервера `lgraph`

| Инструмент | Когда вызывает агент | Что возвращает и чем защищает |
| :--- | :--- | :--- |
| `get_context_pack` | **В начале задачи** (до чтения сырых файлов) | Сжатую капсулу (`token_budget=2500`): активные правила, заметки `C3`/`C4`, межъязыковые мосты и ключевые символы по `PageRank` |
| `inspect_node_or_search` | Для точечного осмотра **1 файла/функции** или поиска | Полный техпаспорт узла с соседями и мостами либо мгновенный поиск `SQLite FTS5` |
| `simulate_change_impact` | **Перед правкой** API, IPC, схем БД, сигнатур или файлов `CRITICAL` | Двусторонний радиус зацепления (`Frontend <-> Backend`), `signature_changes` vs `body_only_changes` и флаг `red_zone_touched` |
| `verify_architecture_rules` | **Обязательно после написания кода** (и внутри Аудитора) | Вердикт `✅ ALL GUARDRAILS PASSED` или объяснимый список нарушений + защиту от опечаток в путях (`NO FILES MATCHED FILTER`) |
| `save_architectural_note` | После создания **нового модуля** или критического шлюза | Сохраняет русскоязычный паспорт и уровень риска в вечную таблицу `architectural_notes` |
| `open_or_index_project` | При первом открытии проекта или запросе полной сводки | Полную статистику узлов, связей и межъязыковых мостов |

---

## 4. Подключение к Cursor / Claude Code / Windsurf

Для IDE, использующих стандартный `mcp_config.json` (замените `<PATH_TO_LGRAPH>` на фактический путь к папке `Lgraph`):

```json
{
  "mcpServers": {
    "lgraph": {
      "command": "<PATH_TO_LGRAPH>\\backend\\venv\\Scripts\\python.exe",
      "args": [
        "<PATH_TO_LGRAPH>\\run_mcp_server.py"
      ],
      "env": {
        "PYTHONUTF8": "1",
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

---

## 5. Стартовый шаблон `lgraph.yaml` для новых проектов

Подробный справочник всех 5 предикатов находится в [`.agent/skills/system-intelligence/references/lgraph_yaml_cookbook.md`](../.agent/skills/system-intelligence/references/lgraph_yaml_cookbook.md):

```yaml
bridge_adapters:
  http_wrappers:
    - caller_name: "apiFetch"
      prepend_prefix: "/api"

guardrails:
  - rule_id: "GR-MAX-SIZE"
    title: "Лимит анти-монолита размера файла (<= 350 строк)"
    severity: "blocker"
    scope: "*.py,backend/**,frontend/src/**,electron/**"
    exclude_scope: "**/tests/**,**/migrations/**"
    predicate_type: "max_file_lines"
    predicate_params:
      max_lines: 350
    rationale_ru: "Крупные файлы перегружают контекст ИИ и повышают риск скрытых поломок при правках."
    remediation_ru: "Разделите модуль на небольшие файлы с одной чёткой ответственностью."

  - rule_id: "GR-NO-CYCLES"
    title: "Запрет циклических импортов между модулями"
    severity: "blocker"
    scope: "backend/**,frontend/src/**"
    predicate_type: "no_cycles"
    predicate_params: {}
    rationale_ru: "Циклические импорты приводят к сбоям запуска и непредсказуемому порядку инициализации."
    remediation_ru: "Вынесите общие схемы и интерфейсы в отдельный базовый модуль."
```
