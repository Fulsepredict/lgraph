# 📂 Правила структуры проекта Lgraph

> Обязательный регламент размещения файлов в репозитории `Lgraph`.
> **Железный лимит анти-монолита (`G-03`):** ни один продуктовый файл `.py`, `.ts`, `.tsx`, `.cjs` не должен превышать **350 строк**.

## Дерево директорий проекта

```text
Lgraph/
├── .agent/                      # Система памяти проекта, правила и навыки ИИ
│   ├── MEMORY.md                # Компактный реестр паспорта и активных Guardrails (<= 150 строк)
│   ├── MEMORY_ARCHIVE.md        # Холодный архив разборов инцидентов (5 Почему)
│   ├── rules/                   # Правила структуры и архитектуры Lgraph
│   └── skills/                  # Переносимые навыки (включая system-intelligence)
├── antigravity-plugin/          # Готовые глобальные плагины (lgraph-intelligence, independent-auditor)
├── scripts/                     # Установщик плагинов и генератор нативных ярлыков Windows (.ico / .lnk / CLI)
├── docs/                        # Руководства по интеграции ИИ и архитектурная спецификация
├── backend/                     # Ядро платформы (Python 3.11+ + FastAPI + SQLite WAL + MCP)
│   ├── core/                    # Управление проектами, канонические URI, хэши, конфигурация демона
│   ├── storage/                 # Схема SQLite (WAL + FTS5), покрывающие индексы, репозитории графа
│   ├── analyzers/               # Независимые аналитические модули:
│   │   ├── code_graph/          # Tree-sitter парсеры Python / JS / TS и резолвер импортов
│   │   ├── bridge_linker/       # Сшиватель мостов (HTTP API, Electron IPC, контракты данных)
│   │   ├── guardrail_engine/    # Машинно-проверяемые правила (5 предикатов + объяснение нарушений)
│   │   └── impact_engine/       # Двусторонний анализ влияния (signature vs body, Git Diff)
│   ├── context_pack/            # Ранжирование PageRank и сборка сжатых капсул в лимит токенов
│   ├── api/                     # Локальные REST-роутеры FastAPI и защита периметра X-Lgraph-Token
│   ├── mcp_server/              # Автономный MCP-сервер (6 инструментов с ToolAnnotations)
│   └── tests/                   # Автотесты, E2E-проверка Electron и замеры целевых метрик (SLO)
├── fixtures/                    # Эталонные синтетические микро-проекты (Golden Test Corpus)
└── frontend/                    # Десктопный интерфейс в монохромной графитовой эстетике
    ├── electron/                # Оболочка окна (main.cjs, preload.cjs, ipcGateway.cjs)
    ├── public/                  # Фирменный рубиновый логотип (logo.png, logo.ico, logo.svg)
    └── src/                     # Компоненты карты (@xyflow/react + ELK.js), Zustand-стор и API-клиент
```

## Правила размещения новых файлов
1. **Продакшен-код анализаторов:** строго в `backend/analyzers/<module>/` (не смешивать парсинг AST с HTTP-роутерами или SQL-запросами).
2. **Эталонные тестовые полигоны (`Golden Fixtures`):** строго в `fixtures/<fixture_name>/` вместе с `ground_truth.json`.
3. **Автотесты и бенчмарки:** строго в `backend/tests/` (все тесты создают БД исключительно в `tempfile.TemporaryDirectory()`).
4. **UI-компоненты:** строго в профильные подпапки `frontend/src/components/<Category>/`.
5. **Документация и руководства:** строго в `docs/`.
