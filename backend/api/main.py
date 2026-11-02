"""
Главное FastAPI-приложение локального демона Lgraph (`127.0.0.1:8765`).

Почему создано через фабрику `create_lgraph_app(runtime_dir)`:
Фабрика позволяет в продакшене работать с рабочей папкой `.lgraph_runtime`, а в автотестах
передавать чистую временную папку `tempfile.TemporaryDirectory()`, никогда не смешивая
боевые проекты пользователя с тестовыми полигонами.
"""

from __future__ import annotations

import dataclasses
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.analyzers.code_graph.disk_state import is_project_disk_dirty
from backend.analyzers.code_graph.scanner import index_project_directory
from backend.analyzers.guardrail_engine.evaluator import evaluate_project_guardrails
from backend.analyzers.impact_engine.analyzer import analyze_change_impact
from backend.api.security import LocalPerimeterMiddleware
from backend.api.watcher import ProjectWatcherManager
from backend.context_pack.builder import build_context_pack_markdown
from backend.core.config import (
    DEFAULT_DAEMON_HOST,
    DEFAULT_DAEMON_PORT,
    DEFAULT_MAX_FILE_LINES,
    DEFAULT_TOKEN_BUDGET,
    LGRAPH_VERSION,
    ensure_local_daemon_token,
    get_default_runtime_dir,
    validate_safe_project_root,
)
from backend.storage.queries import GraphQueryService
from backend.storage.repository import GraphRepository


class OpenProjectRequest(BaseModel):
    root_path: str = Field(..., min_length=1, max_length=1024)
    enable_watcher: bool = Field(default=True)


class SaveNoteRequest(BaseModel):
    target_uri: str = Field(..., min_length=3, max_length=512)
    summary_ru: str = Field(default="", max_length=2000)
    risk_level: str = Field(default="", pattern=r"^(|low|medium|critical)$")


class ImpactRequest(BaseModel):
    target_uris_or_paths: list[str] = Field(default_factory=list)
    git_diff_text: str = Field(default="", max_length=500_000)


class ContextPackRequest(BaseModel):
    focus_queries: list[str] = Field(default_factory=list)
    token_budget: int = Field(default=DEFAULT_TOKEN_BUDGET, ge=400, le=12000)


def create_lgraph_app(runtime_dir: Path | None = None, enable_watchers_default: bool = True) -> FastAPI:
    """Создаёт и настраивает экземпляр локального сервера Lgraph."""
    actual_runtime = runtime_dir or get_default_runtime_dir()
    db_path = actual_runtime / "lgraph.sqlite3"
    token = ensure_local_daemon_token(actual_runtime)

    repo = GraphRepository(db_path)
    queries = GraphQueryService(db_path)
    watcher_mgr = ProjectWatcherManager(repo)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):  # type: ignore[no-untyped-def]
        yield
        watcher_mgr.stop_all()

    app = FastAPI(
        title="Lgraph Daemon API",
        version=LGRAPH_VERSION,
        lifespan=lifespan,
    )

    app.add_middleware(LocalPerimeterMiddleware, expected_token=token)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:5179", "http://localhost:5179"],
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    def _require_project(project_id: str) -> dict[str, Any]:
        proj = repo.get_project(project_id)
        if not proj:
            raise HTTPException(status_code=404, detail=f"Проект `{project_id}` не найден.")
        return proj

    def _ensure_project_fresh(project_id: str) -> tuple[dict[str, Any], Path]:
        proj = _require_project(project_id)
        try:
            root = validate_safe_project_root(proj["root_path"])
        except (ValueError, FileNotFoundError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if enable_watchers_default:
            watcher_mgr.ensure_watching(project_id, root)
        if is_project_disk_dirty(root, repo, project_id):
            index_project_directory(root, repo)
        return proj, root

    @app.get("/api/health")
    def health_check() -> dict[str, str]:
        return {"status": "ok", "service": "lgraph", "version": LGRAPH_VERSION}

    @app.get("/api/projects")
    def list_opened_projects() -> dict[str, Any]:
        active = [p for p in repo.list_projects() if Path(str(p.get("root_path", ""))).is_dir()]
        return {"projects": active}

    @app.post("/api/projects/open")
    def open_and_index_project(payload: OpenProjectRequest) -> dict[str, Any]:
        try:
            safe_root = validate_safe_project_root(payload.root_path)
        except (ValueError, FileNotFoundError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        index_report = index_project_directory(safe_root, repo)
        project_id = str(index_report["project_id"])
        if enable_watchers_default and payload.enable_watcher:
            watcher_mgr.ensure_watching(project_id, safe_root)

        return {
            "index_report": index_report,
            "stats": queries.get_project_stats(project_id),
        }

    @app.post("/api/projects/{project_id}/reindex")
    def reindex_existing_project(project_id: str) -> dict[str, Any]:
        proj = _require_project(project_id)
        try:
            root = validate_safe_project_root(proj["root_path"])
        except (ValueError, FileNotFoundError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        index_report = index_project_directory(root, repo)
        if enable_watchers_default:
            watcher_mgr.ensure_watching(project_id, root)
        return {
            "index_report": index_report,
            "stats": queries.get_project_stats(project_id),
        }

    @app.get("/api/projects/{project_id}/stats")
    def get_stats(project_id: str) -> dict[str, Any]:
        _require_project(project_id)
        return queries.get_project_stats(project_id)

    @app.get("/api/projects/{project_id}/map")
    def get_architecture_map(
        project_id: str,
        max_c4_level: int = Query(default=3, ge=1, le=4),
    ) -> dict[str, Any]:
        _require_project(project_id)
        c4_data = queries.get_c4_map(project_id, max_c4_level=max_c4_level)
        all_nodes, _ = queries.get_all_graph_raw(project_id)

        # Вычисляем метрики «Радара здоровья архитектуры» для подсветки раздутых модулей
        oversized_by_domain: dict[str, list[dict[str, Any]]] = {}
        file_counts_by_domain: dict[str, int] = {}
        for nd in all_nodes:
            if nd.get("node_type") == "File":
                dom_uri = str(nd.get("parent_uri") or "")
                file_counts_by_domain[dom_uri] = file_counts_by_domain.get(dom_uri, 0) + 1
                lines = int((nd.get("meta") or {}).get("line_count") or nd.get("end_line") or 0)
                if lines > DEFAULT_MAX_FILE_LINES:
                    oversized_by_domain.setdefault(dom_uri, []).append(
                        {"rel_path": nd.get("rel_path"), "lines": lines}
                    )

        for mapped_node in c4_data["nodes"]:
            u = str(mapped_node["uri"])
            mapped_node["file_count"] = file_counts_by_domain.get(u, 0)
            mapped_node["oversized_files"] = oversized_by_domain.get(u, [])

        return c4_data

    @app.get("/api/projects/{project_id}/node")
    def get_node_passport(project_id: str, uri: str = Query(..., min_length=3)) -> dict[str, Any]:
        _require_project(project_id)
        node = queries.get_node_by_uri(project_id, uri)
        if not node:
            raise HTTPException(status_code=404, detail=f"Узел `{uri}` не найден.")
        rules = queries.get_guardrail_rules(project_id)
        return {
            "node": node,
            "guardrails_count": len(rules),
        }

    @app.get("/api/projects/{project_id}/search")
    def search_project_nodes(
        project_id: str,
        q: str = Query(default="", max_length=200),
        limit: int = Query(default=25, ge=1, le=100),
    ) -> dict[str, Any]:
        _require_project(project_id)
        return {"results": queries.search_nodes(project_id, q, limit=limit)}

    @app.post("/api/projects/{project_id}/notes")
    def save_node_note(project_id: str, payload: SaveNoteRequest) -> dict[str, Any]:
        _require_project(project_id)
        queries.save_architectural_note(
            project_id=project_id,
            target_uri=payload.target_uri,
            summary_ru=payload.summary_ru,
            risk_level=payload.risk_level,
        )
        return {"ok": True, "node": queries.get_node_by_uri(project_id, payload.target_uri)}

    @app.post("/api/projects/{project_id}/impact")
    def calculate_impact(project_id: str, payload: ImpactRequest) -> dict[str, Any]:
        _, root = _ensure_project_fresh(project_id)
        return analyze_change_impact(
            project_id=project_id,
            project_root=root,
            query_service=queries,
            target_uris_or_paths=payload.target_uris_or_paths,
            git_diff_text=payload.git_diff_text,
        )

    @app.get("/api/projects/{project_id}/guardrails")
    def verify_guardrails(project_id: str) -> dict[str, Any]:
        _, root = _ensure_project_fresh(project_id)
        nodes, edges = queries.get_all_graph_raw(project_id)
        rules = queries.get_guardrail_rules(project_id)
        violations = evaluate_project_guardrails(
            project_root=root,
            nodes=nodes,
            edges=edges,
            configured_rules=rules,
        )
        return {
            "rules": [dataclasses.asdict(r) for r in rules],
            "violations": [dataclasses.asdict(v) for v in violations],
            "passed": len(violations) == 0,
        }

    @app.post("/api/projects/{project_id}/context-pack")
    def generate_context_pack(project_id: str, payload: ContextPackRequest) -> dict[str, Any]:
        _, root = _ensure_project_fresh(project_id)
        return build_context_pack_markdown(
            project_id=project_id,
            query_service=queries,
            focus_query_or_paths=payload.focus_queries,
            token_budget=payload.token_budget,
            project_root=root,
        )

    return app


_DEFAULT_FASTAPI_APP: FastAPI | None = None


def __getattr__(name: str) -> Any:
    """Ленивое создание боевого экземпляра FastAPI только для Uvicorn, чтобы импорт в тестах не трогал рабочую БД."""
    global _DEFAULT_FASTAPI_APP
    if name == "app":
        if _DEFAULT_FASTAPI_APP is None:
            _DEFAULT_FASTAPI_APP = create_lgraph_app()
        return _DEFAULT_FASTAPI_APP
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

if __name__ == "__main__":
    uvicorn.run(
        "backend.api.main:app",
        host=DEFAULT_DAEMON_HOST,
        port=DEFAULT_DAEMON_PORT,
        reload=False,
        log_level="info",
    )
