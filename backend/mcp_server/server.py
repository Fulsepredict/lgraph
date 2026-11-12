"""
MCP-сервер Lgraph v2.4.1 (на базе официального SDK `mcp` v2.x).

Почему здесь 6 сфокусированных макро-инструментов с авто-проверкой диска (`is_project_disk_dirty`):
1. ИИ-агент работает с проектом даже тогда, когда визуальное окно Lgraph закрыто (и фоновый Watchdog
   не запущен). Перед каждым ответом сервер за ~2–4 мс сверяет метки времени файлов и `lgraph.yaml`
   на диске, автоматически обновляя изменившиеся файлы без ручных напоминаний.
2. Ожидаемые ошибки валидации путей и конфигурации перехватываются в `ToolError`, чтобы SDK `mcp` v2
   передавал агенту понятный русский текст ошибки вместо обезличенного `UnexpectedToolError`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import ToolAnnotations

from backend.analyzers.code_graph.disk_state import is_project_disk_dirty
from backend.analyzers.code_graph.scanner import index_project_directory
from backend.analyzers.impact_engine.analyzer import analyze_change_impact
from backend.context_pack.builder import build_context_pack_markdown
from backend.core.config import (
    DEFAULT_TOKEN_BUDGET,
    LGRAPH_VERSION,
    get_default_runtime_dir,
    validate_safe_project_root,
)
from backend.mcp_server.tool_helpers import (
    execute_inspect_or_search,
    execute_verify_guardrails_report,
)
from backend.storage.queries import GraphQueryService
from backend.storage.repository import GraphRepository, compute_project_id

_READONLY_ANNOTATIONS = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)
_METADATA_WRITE_ANNOTATIONS = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)


def create_lgraph_mcp_server(runtime_dir: Path | None = None) -> MCPServer:
    """Создаёт экземпляр MCP-сервера с привязкой к указанной директории БД."""
    actual_runtime = runtime_dir or get_default_runtime_dir()
    db_path = actual_runtime / "lgraph.sqlite3"
    repo = GraphRepository(db_path)
    queries = GraphQueryService(db_path)

    mcp = MCPServer(
        "lgraph",
        title="Lgraph Architecture, Contract & Context Intelligence",
        version=LGRAPH_VERSION,
        instructions=(
            "Протокол качества Lgraph: "
            "1) ДО чтения сырых файлов незнакомого контура вызовите `get_context_pack` (или `inspect_node_or_search`). "
            "2) ПЕРЕД изменением API, IPC, схем данных или файлов красного контура вызовите `simulate_change_impact`. "
            "3) ПОСЛЕ правок обязательно вызовите `verify_architecture_rules` для изменённых файлов и `save_architectural_note` для новых модулей."
        ),
    )

    def _resolve_or_auto_index(project_root_or_id: str) -> tuple[str, Path, bool]:
        try:
            cleaned = project_root_or_id.strip()
            if cleaned.startswith("proj_"):
                proj = repo.get_project(cleaned)
                if not proj:
                    raise ValueError(f"Проект с ID `{cleaned}` ещё не зарегистрирован в Lgraph.")
                root = validate_safe_project_root(proj["root_path"])
                pid = cleaned
            else:
                root = validate_safe_project_root(cleaned)
                pid = compute_project_id(root)

            if is_project_disk_dirty(root, repo, pid):
                index_project_directory(root, repo)
                return pid, root, True
            return pid, root, False
        except ToolError:
            raise
        except (ValueError, FileNotFoundError) as exc:
            raise ToolError(str(exc)) from exc

    @mcp.tool(
        title="Открыть или переиндексировать проект",
        description="Принудительно открывает или обновляет индекс проекта в Lgraph (с кэшем mtime/SHA-256) и возвращает сводку узлов и мостов.",
        annotations=_METADATA_WRITE_ANNOTATIONS,
    )
    def open_or_index_project(project_root: str) -> str:
        try:
            safe_root = validate_safe_project_root(project_root)
            report = index_project_directory(safe_root, repo)
            return json.dumps(report, ensure_ascii=False, indent=2)
        except ToolError:
            raise
        except (ValueError, FileNotFoundError) as exc:
            raise ToolError(str(exc)) from exc

    @mcp.tool(
        title="Получить сжатую архитектурную капсулу (Context Pack)",
        description=(
            "Возвращает сжатую капсулу архитектуры проекта (Personalized PageRank) строго в рамках token_budget: "
            "активные правила Guardrails, сохранённые заметки C3/C4, межъязыковые мосты (TS/JS <-> IPC <-> Python) и ключевые сигнатуры."
        ),
        annotations=_READONLY_ANNOTATIONS,
    )
    def get_context_pack(
        project_root_or_id: str,
        focus_queries: list[str] | None = None,
        token_budget: int = DEFAULT_TOKEN_BUDGET,
    ) -> str:
        try:
            pid, root, _ = _resolve_or_auto_index(project_root_or_id)
            pack = build_context_pack_markdown(
                project_id=pid,
                query_service=queries,
                focus_query_or_paths=focus_queries or [],
                token_budget=token_budget,
                project_root=root,
            )
            return str(pack.get("context_markdown") or json.dumps(pack, ensure_ascii=False))
        except ToolError:
            raise
        except (ValueError, FileNotFoundError) as exc:
            raise ToolError(str(exc)) from exc

    @mcp.tool(
        title="Точечный паспорт узла или поиск в коде (FTS5)",
        description=(
            "Если передан URI узла или путь к файлу (`path` или `path#symbol`) — возвращает точный техпаспорт файла/функции, "
            "список символов внутри файла, межъязыковые мосты, входящих и исходящих соседей. Иначе выполняет быстрый поиск FTS5."
        ),
        annotations=_READONLY_ANNOTATIONS,
    )
    def inspect_node_or_search(
        project_root_or_id: str,
        query_or_uri: str,
        max_depth: int = 2,
    ) -> str:
        try:
            pid, root, _ = _resolve_or_auto_index(project_root_or_id)
            return execute_inspect_or_search(pid, root, queries, query_or_uri, max_depth=max_depth)
        except ToolError:
            raise
        except (ValueError, FileNotFoundError) as exc:
            raise ToolError(str(exc)) from exc

    @mcp.tool(
        title="Симуляция радиуса влияния правок (Impact Analysis)",
        description=(
            "Рассчитывает радиус влияния правок: прямые и косвенные зависимые файлы, двусторонние межъязыковые контракты "
            "Frontend<->Backend, изменение сигнатур (`signature_changes` vs `body_only_changes`), красный контур и правила Guardrails."
        ),
        annotations=_READONLY_ANNOTATIONS,
    )
    def simulate_change_impact(
        project_root_or_id: str,
        target_uris_or_paths: list[str] | None = None,
        git_diff_text: str = "",
    ) -> str:
        try:
            pid, root, auto_reindexed = _resolve_or_auto_index(project_root_or_id)
            report = analyze_change_impact(
                project_id=pid,
                project_root=root,
                query_service=queries,
                target_uris_or_paths=target_uris_or_paths or [],
                git_diff_text=git_diff_text,
            )
            report["auto_reindexed_from_disk"] = auto_reindexed
            return json.dumps(report, ensure_ascii=False, indent=2)
        except ToolError:
            raise
        except (ValueError, FileNotFoundError) as exc:
            raise ToolError(str(exc)) from exc

    @mcp.tool(
        title="Проверка архитектурных правил (Guardrail Engine)",
        description=(
            "Проверяет машинно-исполняемые архитектурные правила проекта (с автоматическим обновлением изменённых на диске файлов) "
            "и выдаёт объяснимый отчёт по каждому нарушению. Принимает как относительные, так и абсолютные пути в `only_paths`."
        ),
        annotations=_READONLY_ANNOTATIONS,
    )
    def verify_architecture_rules(
        project_root_or_id: str,
        only_paths: list[str] | None = None,
    ) -> str:
        try:
            pid, root, auto_reindexed = _resolve_or_auto_index(project_root_or_id)
            return execute_verify_guardrails_report(pid, root, queries, only_paths, auto_reindexed)
        except ToolError:
            raise
        except (ValueError, FileNotFoundError) as exc:
            raise ToolError(str(exc)) from exc

    @mcp.tool(
        title="Сохранить паспорт модуля в долговременную память",
        description=(
            "Сохраняет русскоязычный паспорт модуля/файла/функции и уровень риска (low | medium | critical) в долговременную "
            "память Lgraph (таблица architectural_notes переживает любые переиндексации и передаётся в Context Pack)."
        ),
        annotations=_METADATA_WRITE_ANNOTATIONS,
    )
    def save_architectural_note(
        project_root_or_id: str,
        target_uri: str,
        summary_ru: str,
        risk_level: str = "",
    ) -> str:
        try:
            if risk_level and risk_level not in ("low", "medium", "critical"):
                raise ValueError("Параметр risk_level должен быть одним из: '', 'low', 'medium', 'critical'.")
            pid, _, _ = _resolve_or_auto_index(project_root_or_id)
            queries.save_architectural_note(
                project_id=pid,
                target_uri=target_uri.strip(),
                summary_ru=summary_ru,
                risk_level=risk_level,
            )
            return f"Заметка успешно сохранена для `{target_uri.strip()}` и синхронизирована с поиском FTS5."
        except ToolError:
            raise
        except (ValueError, FileNotFoundError) as exc:
            raise ToolError(str(exc)) from exc

    return mcp


_DEFAULT_MCP_APP: MCPServer | None = None


def __getattr__(name: str) -> Any:
    global _DEFAULT_MCP_APP
    if name == "mcp_app":
        if _DEFAULT_MCP_APP is None:
            _DEFAULT_MCP_APP = create_lgraph_mcp_server()
        return _DEFAULT_MCP_APP
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


if __name__ == "__main__":
    create_lgraph_mcp_server().run(transport="stdio")
