# Lgraph Intelligence (`v2.4.2`)

Готовый пакет интеграции **Lgraph** для среды разработки **Google Antigravity**. Объединяет в один переключаемый модуль:
1. **MCP-сервер `lgraph`** (`mcp_config.json`) — 6 локальных инструментов с авто-проверкой диска (`~2–4 мс`, включая `lgraph.yaml` и `tsconfig*.json` / `jsconfig.json`), проверкой `CONTRACT PREFLIGHT`, метрикой `bridge_coverage` и подвалом `OMITTED SUMMARY` в капсуле. Работает полностью автономно через `run_mcp_server.py` даже при закрытом окне `Lgraph`.
2. **Всегда активное правило контура качества** (`rules/AGENTS.md`) — компактный протокол: разведка с проверкой `OMITTED SUMMARY` -> проверка радиуса взрыва -> машинная приёмка + `CONTRACT PREFLIGHT`, каноническая схема заметок `c3://domain/<контейнер>/<папка>` и верификация `[STALE]`-заметок.
3. **Подробный навык `system-intelligence`** (`skills/system-intelligence/SKILL.md` + справочник `references/lgraph_yaml_cookbook.md`) — загружается по принципу Progressive Disclosure только тогда, когда агенту нужны детали протокола, префиксы фокуса или предикаты `lgraph.yaml`.
4. **Опциональный хук телеметрии капсулы** (`hooks.json`, по умолчанию `"enabled": false`) — при ручном включении перехватывает `PostToolUse` (`read_file`, `view_file`, `edit_file`, `write_file`, `replace_file_content`, `multi_replace_file_content`) и записывает прочитанные и отредактированные файлы строго в отдельную БД `*_telemetry.sqlite3` (не блокируя основную `lgraph.sqlite3`) для оценки `edit_recall`.

## Автоматическая установка (рекомендуется)
Запустите из корня репозитория `Lgraph`:
```powershell
python scripts/install_antigravity_plugin.py
```
Скрипт скопирует плагин в `%USERPROFILE%\.gemini\config\plugins\lgraph-intelligence` (POSIX: `~/.gemini/config/plugins/lgraph-intelligence`) и автоматически подставит ваш локальный путь к `python.exe`, `run_mcp_server.py` в `mcp_config.json` и `scripts/lgraph_telemetry_hook.py` в `hooks.json` (сохраняя безопасный opt-in статус `"enabled": false`).

## Живая перезагрузка в Antigravity 2.0
После установки или обновления плагина перезапускать приложение не требуется:
1. Откройте панель **Skills & Customizations** в **Antigravity 2.0**.
2. Найдите плагин `lgraph-intelligence` (`customization://lgraph-intelligence`).
3. Переключите его **Выкл -> Вкл** (*Off -> On*) — Antigravity 2.0 мгновенно перечитает `rules/AGENTS.md`, навык `system-intelligence`, `hooks.json` и переподключит MCP-сервер `lgraph`.

## Опциональная телеметрия (`hooks.json`)
Внутрипроцессная телеметрия вызовов MCP (`get_context_pack`, `inspect_node_or_search`, `verify_architecture_rules`) работает всегда и не создаёт блокировок (`< 0.5 мс`). Чтобы дополнительно учитывать прямые вызовы `read_file` и `edit_file` агента:
1. Откройте установленный `<USER_PLUGINS_DIR>/lgraph-intelligence/hooks.json`.
2. Измените `"enabled": false` на `"enabled": true` внутри `lgraph-capsule-telemetry`.
3. Переключите `customization://lgraph-intelligence` **Выкл -> Вкл** в **Skills & Customizations**.
