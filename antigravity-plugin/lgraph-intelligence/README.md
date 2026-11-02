# Lgraph Intelligence (`v2.4.0`)

Готовый пакет интеграции **Lgraph** для среды разработки **Google Antigravity**. Объединяет в один переключаемый модуль:
1. **MCP-сервер `lgraph`** (`mcp_config.json`) — 6 локальных инструментов с авто-проверкой диска (`~2–4 мс`), работает полностью автономно через `run_mcp_server.py` даже при закрытом окне `Lgraph`.
2. **Всегда активное правило контура качества** (`rules/AGENTS.md`) — компактный протокол: разведка до чтения файлов -> проверка радиуса взрыва до правки контрактов -> машинная приёмка после правок.
3. **Подробный навык `system-intelligence`** (`skills/system-intelligence/SKILL.md` + справочник `references/lgraph_yaml_cookbook.md`) — загружается по принципу Progressive Disclosure только тогда, когда агенту нужны детали предикатов `lgraph.yaml`.

## Автоматическая установка (рекомендуется)
Запустите из корня репозитория `Lgraph`:
```powershell
python scripts/install_antigravity_plugin.py
```
Скрипт скопирует плагин в `%USERPROFILE%\.gemini\config\plugins\lgraph-intelligence` и автоматически пропишет реальный локальный путь к `python.exe` и `run_mcp_server.py` в `mcp_config.json`. После установки перезапустите окно **Antigravity**.
