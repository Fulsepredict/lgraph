# 📘 Справочник конфигурации `lgraph.yaml` и `.lgraphignore` (Lgraph v2.4)

Файл `lgraph.yaml` в корне любого проекта позволяет задать:
1. **Сетевые и IPC-обёртки (`bridge_adapters`)** — чтобы `BridgeLinker` с точностью 100% сшивал ваши кастомные клиентские функции с маршрутами `FastAPI` и каналами `Electron IPC`.
2. **Машинно-проверяемые правила (`guardrails`)** — чтобы `GuardrailEngine` и инструмент `verify_architecture_rules` математически проверяли код и объясняли каждое нарушение простым русским языком.

> Если файла `lgraph.yaml` в проекте пока нет, `Lgraph` автоматически включает два базовых предохранителя: лимит размера файла `<= 350` строк (`GR-CORE-SIZE`) и запрет циклических импортов (`GR-CORE-CYCLES`).

---

## 1. Сшивка кастомных HTTP и IPC обёрток (`bridge_adapters`)

```yaml
bridge_adapters:
  http_wrappers:
    - caller_name: "appFetch"             # Имя функции-обёртки во Frontend (TS/JS)
      prepend_prefix: "/api"              # Автоматически добавляемый префикс URL на сервере
```

Что `BridgeLinker` распознаёт автоматически (даже без `lgraph.yaml`):
- `fetch(...)`, `axios.get/post/put/delete/patch(...)`, методы внутри API-объектов (`export const api = { async save() { ... } }`);
- шаблонные строки с базовым хостом: `` `${API_BASE_URL}/api/orders/${id}` `` и конкатенацию `API_BASE_URL + '/api/orders/' + id`;
- префиксы роутеров `APIRouter(prefix="/api/orders")` и `app.include_router(router, prefix="/api")`;
- двусторонний `Electron IPC`: `ipcRenderer.invoke/send <-> ipcMain.handle/on` и серверные пуши `webContents.send <-> ipcRenderer.on`;
- общие контракты данных: `Pydantic BaseModel` / `SQLModel` / `TypedDict` / `dataclass` <-> `TypeScript interface` / `type`.

---

## 2. Все 5 типов машинных правил (`guardrails`)

Каждое правило имеет общие поля:
- `rule_id`: уникальный код правила (например, `"GR-ARCH-01"`).
- `title`: понятное название правила.
- `severity`: `"blocker"` (критично — ИИ не имеет права сдавать задачу) или `"warning"` (предупреждение).
- `scope`: одна или несколько `glob`-масок через запятую (`"backend/**,frontend/src/**"`).
- `exclude_scope` *(необязательно)*: маски исключений (`"**/tests/**,**/migrations/**"`).
- `predicate_type`: один из 5 детерминированных предикатов ниже.
- `predicate_params`: параметры предиката.
- `rationale_ru`: **почему** это правило важно для проекта.
- `remediation_ru`: **как именно** исправить нарушение.

### 2.1. `max_file_lines` — Защита от файлов-монолитов
Проверяет количество строк в каждом исходном файле внутри `scope`.
```yaml
  - rule_id: "GR-MAX-LINES"
    title: "Лимит анти-монолита (не более 350 строк)"
    severity: "blocker"
    scope: "*.py,backend/**,frontend/src/**,frontend/electron/**"
    exclude_scope: "**/tests/**"
    predicate_type: "max_file_lines"
    predicate_params:
      max_lines: 350
    rationale_ru: "Крупные файлы раздувают контекст ИИ и повышают риск поломки соседней логики."
    remediation_ru: "Вынесите независимую подзадачу или дочерний UI-компонент в отдельный модуль."
```

### 2.2. `forbidden_dependency` — Запрет прямых связей между слоями
Запрещает любые `IMPORTS`, `CALLS` и `BRIDGES_TO` из файлов `scope` в файлы `target_scope`.
```yaml
  - rule_id: "GR-NO-UI-TO-DB"
    title: "UI-компоненты не должны напрямую импортировать слой БД"
    severity: "blocker"
    scope: "frontend/src/components/**"
    predicate_type: "forbidden_dependency"
    predicate_params:
      target_scope: "backend/storage/**"
    rationale_ru: "Прямое обращение к хранилищу ломает разделение ответственности и валидацию."
    remediation_ru: "Обращайтесь к данным только через клиентский сервис API и серверный роутер."
```

### 2.3. `must_route_via` — Обязательное прохождение через единый шлюз
Требует, чтобы любые обращения из `scope` к `target_scope` шли исключительно через шлюз `via_scope`.
```yaml
  - rule_id: "GR-API-GATEWAY-ONLY"
    title: "UI общается с API только через единый клиент services/api.ts"
    severity: "blocker"
    scope: "frontend/src/**"
    predicate_type: "must_route_via"
    predicate_params:
      target_scope: "backend/api/**"
      via_scope: "frontend/src/services/**"
    rationale_ru: "Прямые вызовы fetch из компонентов обходят токен авторизации и обработку ошибок."
    remediation_ru: "Перенесите сетевой запрос в модуль `frontend/src/services/api.ts`."
```

### 2.4. `no_cycles` — Запрет циклических импортов (`A -> B -> A`)
Ищет замкнутые кольца импортов между файлами внутри `scope`.
```yaml
  - rule_id: "GR-NO-CYCLES"
    title: "Запрет циклических импортов в ядре"
    severity: "blocker"
    scope: "backend/**,frontend/src/**"
    predicate_type: "no_cycles"
    predicate_params: {}
    rationale_ru: "Циклические зависимости приводят к ошибкам инициализации (`ImportError`) и хрупкому коду."
    remediation_ru: "Вынесите общие типы данных или базовые утилиты в отдельный модуль нижнего уровня."
```

### 2.5. `ast_forbidden_regex` — Запрет опасных конструкций в коде
Ищет запрещённое регулярное выражение в строках кода (однострочные и блочные комментарии автоматически пропускаются, чтобы документация не вызывала ложных тревог).
```yaml
  - rule_id: "GR-NO-RAW-SQL-EXEC"
    title: "Запрет конкатенации сырого SQL и опасного eval"
    severity: "blocker"
    scope: "backend/**"
    exclude_scope: "backend/tests/**"
    predicate_type: "ast_forbidden_regex"
    predicate_params:
      pattern: "\\beval\\s*\\(|execute\\s*\\(\\s*f[\"']"
    rationale_ru: "Динамическое выполнение строк открывает уязвимость для инъекций кода и SQL-инъекций."
    remediation_ru: "Используйте параметризованные запросы ORM/SQLite (`?`) и явные словари диспетчеризации."
```

---

## 3. Исключение папок и файлов (`.lgraphignore`)

Служебные папки (`node_modules`, `venv`, `.git`, `dist`, `build`, `*_release`, `.agent`, `.lgraph_runtime`) пропускаются автоматически. Для дополнительных исключений создайте в корне проекта файл `.lgraphignore` (синтаксис `glob` построчно):

```gitignore
# Пропускаем сгенерированные снапшоты и архивы старых миграций
legacy_archive/**
frontend/src/generated/**
*.min.js
```
