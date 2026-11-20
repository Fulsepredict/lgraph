# 🧭 Полное руководство: 3-слойная система качества ИИ (`GEMINI.md` + `Lgraph v2.4.2` + `Independent Auditor`)

Это руководство описывает модульную систему управления качеством ИИ-агентов для **Google Antigravity 2.0**, **Cursor** и **Claude Code**.

---

## 1. Архитектура 3 слоёв (экономия контекста в ~25 раз)

Вместо одной громоздкой простыни текстовых правил в памяти модели работают **3 непересекающихся слоя** (*Progressive Disclosure* — раскрытие деталей только по мере надобности):

1. **Слой 1 — Компактные Глобальные Правила (`~/.gemini/GEMINI.md`, `~850` токенов):**
   - Задают планку **Principal Systems Engineer**, лимит размера файла `<= 350` строк, безопасность входных данных/SQL/секретов и сверку реальных версий пакетов перед поиском в сети.
   - Управляют **Коробкой из 3 передач сложности**:
     - *1-я передача (мелкая правка 1 безопасного файла):* точечное чтение -> правка -> проверка `verify_architecture_rules` (без бумажной бюрократии);
     - *2-я передача (фича / `>= 2` связанных модулей):* разведка `Lgraph` -> `Implementation Plan` -> реализация + автотесты + `verify_architecture_rules` + `CONTRACT PREFLIGHT`;
     - *3-я передача (зона `CRITICAL`, сквозные контракты `UI <-> IPC <-> API`, миграции БД, конкурентность `asyncio`/потоков, автономный режим `/goal`):* плюс обязательная проверка **Независимым Red-Team Аудитором** с чистым контекстом до `0 P0, 0 P1`.

2. **Слой 2 — Два автономных глобальных плагина (`<USER_PLUGINS_DIR>/`):**
   - **`lgraph-intelligence` (`v2.4.2`)** — поднимает локальный MCP-сервер **`lgraph`** (`run_mcp_server.py`, работает без `cwd` и при закрытом окне `Lgraph` — сверяет исходники, `lgraph.yaml` и `tsconfig*.json` / `jsconfig.json` на диске за `~2–4 мс`), хранит компактное правило `rules/AGENTS.md`, навык `system-intelligence` и опциональный хук телеметрии `hooks.json` (`"enabled": false` по умолчанию).
   - **`independent-auditor`** — отдельный глобальный плагин **Независимого Red-Team Аудитора** с чистым контекстом (`Cold Plan Audit` и `Cold Code Audit` + профильные чек-листы `stack_checklists.md`). В `v2.4.2` дополнительно проверяет `preflight.passed`, `unupdated_contract_partners`, `broken_bridges_vs_head`, `bridge_coverage` и `[STALE]`-заметки. Включает жёсткий стоп-кран против бесконечных ревизий после достижения `0 P0, 0 P1`.

3. **Слой 3 — Локальный контур проекта (`lgraph.yaml` + `.agent/MEMORY.md <= 150` строк):**
   - Машинные инварианты (размеры файлов, запрет циклов, шлюзы, запрещённые конструкции) проверяются кодом `GuardrailEngine` с расходом **`0` токенов** и точностью **100%**.
   - В `.agent/MEMORY.md` хранятся только паспорт проекта и короткие доменные предохранители, а разборы инцидентов уходят в `.agent/MEMORY_ARCHIVE.md`.

---

## 2. Быстрая установка и живая перезагрузка в Antigravity 2.0

Запустите установщик из корня клонированного репозитория `Lgraph`:

```powershell
python scripts/install_antigravity_plugin.py
```

Скрипт скопирует оба плагина в `%USERPROFILE%\.gemini\config\plugins\` (POSIX: `~/.gemini/config/plugins/`) и автоматически подставит локальный путь к Python, `run_mcp_server.py` в `mcp_config.json`, `scripts/lgraph_telemetry_hook.py` в `hooks.json` (сохраняя `"enabled": false`) и путь к `stack_checklists.md` в `independent-auditor`.

### Живая перезагрузка без рестарта приложения (Antigravity 2.0)
1. Откройте панель **Skills & Customizations**.
2. Найдите `lgraph-intelligence` (`customization://lgraph-intelligence`).
3. Переключите тумблер **Выкл -> Вкл** (*Off -> On*) — Antigravity 2.0 сразу применит обновлённые правила, навык, `hooks.json` и перезапустит MCP-сервер `lgraph`.

### Опциональная телеметрия капсулы (`hooks.json`) и периметр (`LGRAPH_ALLOWED_ROOTS`)
- **Телеметрия промахов капсулы (`I8`):** внутрипроцессный сбор `packed_uris / read_uris / edited_uris` в MCP работает всегда за `< 0.5 мс` без блокировки `lgraph.sqlite3` (запись идёт в отдельный файл `*_telemetry.sqlite3`). Чтобы также учитывать прямые вызовы `read_file` и `edit_file` агента, откройте установленный `<USER_PLUGINS_DIR>/lgraph-intelligence/hooks.json`, замените `"enabled": false` на `"enabled": true` и переключите `customization://lgraph-intelligence` **Выкл -> Вкл**.
- **Белый список рабочих папок (`LGRAPH_ALLOWED_ROOTS`):** при необходимости ограничьте индексацию и чтение (включая обращения по `proj_<id>`) конкретными корнями, добавив переменную `LGRAPH_ALLOWED_ROOTS` в блок `env` файла `mcp_config.json` (разделитель `;` в Windows, `:` в POSIX). Системные/секретные директории и симлинки/NTFS Junctions заблокированы по умолчанию, при этом папки **OneDrive** поддерживаются корректно.

---

## 3. Шпаргалка по 6 инструментам MCP-сервера `lgraph` (`v2.4.2`, Вариант А)

Набор и сигнатуры всех **6 публичных MCP-инструментов** сохранены на 100% без ломки совместимости, при этом в них встроены `CONTRACT PREFLIGHT`, `OMITTED SUMMARY`, `bridge_coverage` и контроль устаревания заметок:

| Инструмент | Когда вызывает агент | Что возвращает и чем защищает (`v2.4.2`) |
| :--- | :--- | :--- |
| `get_context_pack` | **В начале задачи** (до чтения сырых файлов) | Сжатую капсулу строго в калиброванном `token_budget`: активные правила, заметки `C3`/`C4` с приоритетом `CRITICAL` и метками `[STALE: ...]`, мосты, символы по направленному `PageRank` (`impact:` / `understand:`, seeds из `git diff` / `traceback`) и подвал **`OMITTED SUMMARY`** |
| `inspect_node_or_search` | Для точечного осмотра **1 файла/функции** или поиска | Полный техпаспорт узла с соседями и мостами (с авто-канонизацией `c3://domain/...`) либо мгновенный поиск `SQLite FTS5` + неблокирующая телеметрия чтения |
| `simulate_change_impact` | **Перед правкой** и при изменении контрактов **после правки** | Двусторонний радиус зацепления (`Frontend <-> Backend`, без эвристического шума), `signature_changes` (включая поля `BaseModel` / `SQLModel` / `TypedDict` / `@dataclass`), метрика **`bridge_coverage`**, объект **`preflight`** (`passed`, `unupdated_contract_partners`, `broken_bridges_vs_head`, `broken_callers_vs_head`) и `red_zone_touched` |
| `verify_architecture_rules` | **Обязательно после написания кода** (и внутри Аудитора) | Вердикт `✅ ALL GUARDRAILS PASSED` или `❌ GUARDRAIL VIOLATIONS FOUND (N)` + отдельный блок **`📋 CONTRACT PREFLIGHT`** в конце отчёта (без искажения счётчика правил `lgraph.yaml`) и защиту `NO FILES MATCHED FILTER` |
| `save_architectural_note` | После создания **нового модуля** (`c3://domain/<контейнер>/<папка>`) или критического шлюза | Сохраняет русскоязычный паспорт в `architectural_notes` со штампом `target_signature_hash`, `provenance="agent"` и `ttl_days=90` для автоматической подсветки `[STALE]` при изменении кода |
| `open_or_index_project` | При первом открытии проекта или запросе полной сводки | Полную статистику узлов, связей, межъязыковых мостов и **`bridge_coverage`** |

---

## 4. Подключение к Cursor / Claude Code / Windsurf

Для IDE, использующих стандартный `mcp_config.json` (замените `<PATH_TO_LGRAPH>` и `<PATH_TO_WORKSPACES>` на фактические пути):

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
        "PYTHONIOENCODING": "utf-8",
        "LGRAPH_ALLOWED_ROOTS": "<PATH_TO_WORKSPACES>"
      }
    }
  }
}
```
*(Поле `LGRAPH_ALLOWED_ROOTS` опционально — удалите его, если хотите разрешить индексацию любых пользовательских проектов вне системных каталогов.)*

---

## 5. Стартовый шаблон `lgraph.yaml` для новых проектов

Подробный справочник всех 5 предикатов, `bridge_adapters`, `@dataclass` и `LGRAPH_ALLOWED_ROOTS` находится в [`antigravity-plugin/lgraph-intelligence/skills/system-intelligence/references/lgraph_yaml_cookbook.md`](../antigravity-plugin/lgraph-intelligence/skills/system-intelligence/references/lgraph_yaml_cookbook.md):

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
