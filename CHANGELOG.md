# История изменений Lgraph (Changelog)

## v2.4.2 (2026-11-19)

Фокус релиза — повышение качества итогового `diff` при работе ИИ-агентов (ловля рассинхрона контрактов и оборванных мостов), прозрачность сжатия контекста, защита периметра путей и ускорение на крупных репозиториях. Все 6 публичных MCP-инструментов и их сигнатуры сохранены без ломающих изменений.

### 1. Контрактный префлайт и покрытие мостов (`I1`, `I5`)
- **Детектор забытых партнёров и обрыва контрактов (`CONTRACT PREFLIGHT`):** в JSON-ответ `simulate_change_impact` (`preflight`, `bridge_coverage`) и в финальный отчёт `verify_architecture_rules` (`📋 CONTRACT PREFLIGHT`) добавлены проверки:
  - `unupdated_contract_partners` — изменение сигнатуры FastAPI-хэндлера, полей `Pydantic` / `SQLModel` / `TypedDict` или `@dataclass`, когда парный TypeScript-клиент не задет в правках (включая транзитивную цепочку `DataContract <-[CALLS:type_annotation]- route <-[BRIDGES_TO]- TS`);
  - `broken_bridges_vs_head` — маршруты и IPC-каналы, сшивавшиеся против `HEAD`, но исчезнувшие после переименования URL или смены HTTP-метода (устранён ложно-пустой `impact`);
  - `broken_callers_vs_head` — живые файлы на диске, продолжающие импортировать удалённый/переименованный модуль или вызывать удалённый символ.
- **Метрика `bridge_coverage`:** учёт точных, шаблонных, динамических (`unresolved_dynamic`) и несовпавших статических (`unmatched_static`) клиентских вызовов HTTP/IPC с корректным исключением функций-обёрток (`wrapper_passthrough`).
- **Усиление AST и графа вызовов:** распознавание `@dataclass` как `DataContract`, учёт полей схем в `signature_hash`, внутриязыковые рёбра по аннотациям типов (`CALLS`, `tier=VERIFIED`) с сериализацией в `file_cache` (`PARSER_SCHEMA_VERSION = "2.4.2"`), строгая изоляция `CALLS` внутри языка (без ложных склеек одноимённых методов `TS -> Python`), гейтинг по `confidence_tier` и отслеживание `tsconfig*.json` / `jsconfig.json` во всех контейнерных папках.

### 2. Прозрачная капсула контекста, умные `seeds` и масштаб 50k узлов (`I2`, `I6`, `I7`)
- **Явная омиссия и калиброванный токенизатор:** 3-корзинная оценка токенов (`ASCII` буквы / пунктуация и цифры / кириллица + `10%` страховой запас), долевые квоты секций шапки, добор компактных символов (`continue` вместо жёсткого `break`), поля `packed_uris` / `omitted_counts` / `omitted_symbols` и компактная секция `## OMITTED SUMMARY`.
- **Ранжирование без засилья хабов:** автоматическое извлечение `seeds` из `git diff` (hunks) и стеков ошибок Python/TS, сегментно-безопасный поиск путей вместо сырой подстроки, демпфирование утилитарных хабов по степени узла и режимы направления `impact:` / `understand:`.
- **Кэш ревизии и ускорение PPR:** кэширование компактного снимка ревизии графа с отпечатком заметок (`notes_stamp`) и LRU-кэш результатов PPR по `(db_path, project_id, index_revision, mode, seeds_hash)`, плюс лёгкое чтение метаданных `file_cache` без загрузки AST JSON при проверке диска. На полигоне 50k узлов (`150k` рёбер) `get_context_pack` ускорился с `4.75 с` до `~409 мс` (новые `seeds`) и `~12 мс` (LRU-кэш). Разделены тайминг и `tracemalloc` в `backend/tests/benchmark_slo.py`.

### 3. Память заметок, доверие путей и телеметрия (`I3`, `I4`, `I8`)
- **Заметки со штампами и защитой от устаревания:** идемпотентная миграция `architectural_notes` (`target_signature_hash`, `target_body_hash`, `saved_revision`, `provenance` `human`/`agent`, `ttl_days`); устаревшие и осиротевшие заметки помечаются `[STALE: ...]` без затирания свежего докстринга функции; автомиграция и канонизация `domain://...` → `c3://domain/...`; приоритет `CRITICAL`-заметок при сортировке и санитизация переводов строк/тегов.
- **Двухуровневая модель доверия путей:** раздельные списки `DENIED_EXACT_ROOTS` и `DENIED_SUBTREE_ROOTS` (с разрешением дочерних папок `Temp`), опциональный `LGRAPH_ALLOWED_ROOTS` (включая проверку `proj_<id>`), точная фильтрация `st_reparse_tag` (`NameSurrogate` `0x20000000` + `AppExecLink` `0x8000001B` — снимает ложную блокировку папок OneDrive при сохранении защиты от NTFS Junctions) и поддержка локальных путей `\\?\Drive:\...`.
- **Неблокирующая телеметрия капсулы (`packed_uris / read_uris / edited_uris`):** буферизация в памяти (`< 0.05 мс`, `0` write-lock на `lgraph.sqlite3`), сохранение в изолированную БД `*_telemetry.sqlite3` и опциональный `PostToolUse` хук `hooks.json` (`enabled: false` по умолчанию).

### 4. Плагины Antigravity и тесты
- Обновлены `antigravity-plugin/lgraph-intelligence` (`v2.4.2`), `antigravity-plugin/independent-auditor`, `.agent/skills/system-intelligence/SKILL.md`, `scripts/install_antigravity_plugin.py` и `docs/AI_INTEGRATION_GUIDE_RU.md`.
- Добавлен регрессионный модуль `backend/tests/test_phase2_quality_and_scale.py` (`32/32` активных тестов пройдено, `0` нарушений Guardrails, `0` циклов, все продуктовые файлы `<= 350` строк).

---

## v2.4.1 (2026-11-11)
- Усиление периметра локального ASGI-демона (HTTP + WebSocket `1008`, `X-Lgraph-Token`, отключение `testserver` по умолчанию), маскировка секретов в AST-кэше и заметках, `BEGIN IMMEDIATE` для межпроцессного SQLite WAL, `Fail-Closed` валидация `lgraph.yaml`, чистые 7-bit ASCII/CRLF `.bat`-лаунчеры, in-place обновление плагинов под `WinError 32` и E2E-тесты.
