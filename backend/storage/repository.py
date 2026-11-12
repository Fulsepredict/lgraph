"""
Репозиторий чтения и записи графа Lgraph в SQLite.

Почему обход графа реализован через SQL `WITH RECURSIVE` с `visited_path`:
В реальных проектах встречаются циклические импорты (A -> B -> A). Без проверки
посещённых узлов рекурсивный запрос уйдёт в бесконечный цикл, а проверка
`INSTR(visited_path, '|' || next_uri || '|') = 0` гарантирует остановку за миллисекунды.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.core.models import (
    ConfidenceTier,
    EdgeType,
    GraphEdgeRecord,
    GraphNodeRecord,
    GuardrailRuleSpec,
    NodeType,
    RiskLevel,
    redact_inline_secrets,
)
from backend.storage.schema import initialize_database, open_sqlite_connection

SQLITE_WRITE_BUSY_TIMEOUT_MS: int = 15000


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def begin_immediate_transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """
    Явно открывает транзакцию записи `BEGIN IMMEDIATE` до первого `SELECT`.
    Почему это критично в SQLite WAL: отложенный `with conn:` захватывает write-lock только на первом
    `INSERT/DELETE`, из-за чего предварительный `SELECT` при параллельной записи из другого процесса
    не ждёт `busy_timeout`, а сразу падает с `SQLITE_BUSY` (`database is locked`).
    """
    conn.execute(f"PRAGMA busy_timeout={SQLITE_WRITE_BUSY_TIMEOUT_MS};")
    if conn.in_transaction:
        conn.commit()
    prev_isolation = conn.isolation_level
    conn.isolation_level = None
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.execute("COMMIT")
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.isolation_level = prev_isolation


def compute_project_id(root_path: Path) -> str:
    """Генерирует стабильный короткий ID проекта из канонического пути на диске."""
    norm = str(root_path.resolve()).lower().replace("\\", "/")
    digest = hashlib.sha256(norm.encode("utf-8")).hexdigest()[:12]
    return f"proj_{digest}"


class GraphRepository:
    """Единая точка безопасной работы с SQLite-хранилищем графа."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        initialize_database(self.db_path)

    def register_project(self, root_path: Path, name: str | None = None) -> dict[str, Any]:
        resolved = root_path.resolve()
        project_id = compute_project_id(resolved)
        proj_name = name or resolved.name
        with closing(open_sqlite_connection(self.db_path)) as conn:
            with begin_immediate_transaction(conn):
                conn.execute(
                    """
                    INSERT INTO projects (project_id, name, root_path)
                    VALUES (?, ?, ?)
                    ON CONFLICT(project_id) DO UPDATE SET
                        name = excluded.name,
                        root_path = excluded.root_path
                    """,
                    (project_id, proj_name, str(resolved)),
                )
            row = conn.execute(
                "SELECT * FROM projects WHERE project_id = ?", (project_id,)
            ).fetchone()
        return dict(row) if row else {}

    def list_projects(self) -> list[dict[str, Any]]:
        with closing(open_sqlite_connection(self.db_path)) as conn:
            rows = conn.execute(
                "SELECT * FROM projects ORDER BY indexed_at_iso DESC, name ASC"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_project(self, project_id: str) -> dict[str, Any] | None:
        with closing(open_sqlite_connection(self.db_path)) as conn:
            row = conn.execute(
                "SELECT * FROM projects WHERE project_id = ?", (project_id,)
            ).fetchone()
        return dict(row) if row else None

    def get_file_cache_map(self, project_id: str) -> dict[str, dict[str, Any]]:
        """Загружает карту закэшированных SHA-256 файлов проекта за один запрос."""
        with closing(open_sqlite_connection(self.db_path)) as conn:
            rows = conn.execute(
                "SELECT * FROM file_cache WHERE project_id = ?", (project_id,)
            ).fetchall()
        return {str(r["rel_path"]): dict(r) for r in rows}

    def save_full_index_atomic(
        self,
        project_id: str,
        nodes: list[GraphNodeRecord],
        edges: list[GraphEdgeRecord],
        file_cache_entries: list[dict[str, Any]],
        guardrail_rules: list[GuardrailRuleSpec] | None = None,
        config_mtime_ns: int = 0,
    ) -> int:
        """
        Атомарно сохраняет новую ревизию графа, накладывая поверх сохранённые
        пользовательские/агентские заметки из `architectural_notes`.
        """
        now_iso = utc_now_iso()
        with closing(open_sqlite_connection(self.db_path)) as conn:
            with begin_immediate_transaction(conn):
                rev_row = conn.execute(
                    "SELECT index_revision FROM projects WHERE project_id = ?",
                    (project_id,),
                ).fetchone()
                next_rev = (int(rev_row["index_revision"]) if rev_row else 0) + 1

                notes_rows = conn.execute(
                    "SELECT target_uri, summary_ru, risk_level FROM architectural_notes WHERE project_id = ?",
                    (project_id,),
                ).fetchall()
                notes_by_uri = {str(r["target_uri"]): dict(r) for r in notes_rows}

                conn.execute("DELETE FROM nodes WHERE project_id = ?", (project_id,))
                conn.execute("DELETE FROM edges WHERE project_id = ?", (project_id,))
                conn.execute("DELETE FROM nodes_fts WHERE project_id = ?", (project_id,))
                conn.execute("DELETE FROM file_cache WHERE project_id = ?", (project_id,))

                node_tuples: list[tuple[Any, ...]] = []
                fts_tuples: list[tuple[Any, ...]] = []
                for n in nodes:
                    saved_note = notes_by_uri.get(n.uri)
                    raw_summary = saved_note["summary_ru"] if saved_note is not None else n.summary_ru
                    summary_ru, _ = redact_inline_secrets(raw_summary)
                    safe_sig, _ = redact_inline_secrets(n.signature)
                    risk_val = (
                        saved_note["risk_level"]
                        if saved_note and saved_note["risk_level"]
                        else str(n.risk_level.value if isinstance(n.risk_level, RiskLevel) else n.risk_level)
                    )
                    node_tuples.append(
                        (
                            project_id,
                            n.uri,
                            str(n.node_type.value if isinstance(n.node_type, NodeType) else n.node_type),
                            n.name,
                            n.rel_path,
                            n.start_line,
                            n.end_line,
                            n.c4_level,
                            risk_val,
                            safe_sig,
                            n.signature_hash,
                            n.body_hash,
                            summary_ru,
                            n.pattern_tag,
                            n.parent_uri,
                            float(n.confidence),
                            n.source_module,
                            json.dumps(n.meta, ensure_ascii=False),
                            next_rev,
                        )
                    )
                    fts_tuples.append((project_id, n.uri, n.name, n.rel_path, summary_ru, safe_sig))

                conn.executemany(
                    """
                    INSERT OR REPLACE INTO nodes (
                        project_id, uri, node_type, name, rel_path, start_line, end_line,
                        c4_level, risk_level, signature, signature_hash, body_hash,
                        summary_ru, pattern_tag, parent_uri, confidence, source_module,
                        meta_json, index_revision
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    node_tuples,
                )
                conn.executemany(
                    "INSERT INTO nodes_fts (project_id, uri, name, rel_path, summary_ru, signature) VALUES (?, ?, ?, ?, ?, ?)",
                    fts_tuples,
                )

                edge_tuples = [
                    (
                        project_id,
                        e.src_uri,
                        e.dst_uri,
                        str(e.edge_type.value if isinstance(e.edge_type, EdgeType) else e.edge_type),
                        float(e.confidence),
                        str(e.confidence_tier.value if isinstance(e.confidence_tier, ConfidenceTier) else e.confidence_tier),
                        e.source_module,
                        redact_inline_secrets(e.evidence)[0],
                        json.dumps(e.meta, ensure_ascii=False),
                        next_rev,
                    )
                    for e in edges
                ]
                conn.executemany(
                    """
                    INSERT OR REPLACE INTO edges (
                        project_id, src_uri, dst_uri, edge_type, confidence,
                        confidence_tier, source_module, evidence, meta_json, index_revision
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    edge_tuples,
                )

                cache_tuples = [
                    (
                        project_id,
                        c["rel_path"],
                        c["file_sha256"],
                        c["parser_version"],
                        int(c.get("mtime_ns", 0)),
                        int(c.get("size_bytes", 0)),
                        int(c.get("line_count", 0)),
                        c.get("language", ""),
                        1 if c.get("has_redacted_secret") else 0,
                        c.get("cached_payload_json", "{}"),
                        now_iso,
                    )
                    for c in file_cache_entries
                ]
                conn.executemany(
                    """
                    INSERT OR REPLACE INTO file_cache (
                        project_id, rel_path, file_sha256, parser_version,
                        mtime_ns, size_bytes, line_count, language,
                        has_redacted_secret, cached_payload_json, updated_at_iso
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    cache_tuples,
                )

                # Всегда синхронизируем правила из lgraph.yaml (включая случай удаления всех правил -> пустой список)
                if guardrail_rules is not None:
                    conn.execute("DELETE FROM guardrail_rules WHERE project_id = ?", (project_id,))
                    if guardrail_rules:
                        conn.executemany(
                            """
                            INSERT OR REPLACE INTO guardrail_rules (
                                project_id, rule_id, title, severity, scope, exclude_scope,
                                predicate_type, predicate_params_json, rationale_ru, remediation_ru
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            [
                                (
                                    project_id,
                                    r.rule_id,
                                    r.title,
                                    r.severity,
                                    r.scope,
                                    r.exclude_scope,
                                    r.predicate_type,
                                    json.dumps(r.predicate_params, ensure_ascii=False),
                                    r.rationale_ru,
                                    r.remediation_ru,
                                )
                                for r in guardrail_rules
                            ],
                        )

                conn.execute(
                    """
                    UPDATE projects
                    SET index_revision = ?, indexed_at_iso = ?, is_stale = 0, config_mtime_ns = ?
                    WHERE project_id = ?
                    """,
                    (next_rev, now_iso, int(config_mtime_ns), project_id),
                )
        return next_rev
