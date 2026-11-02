"""
Запросы чтения, полнотекстового поиска FTS5 и безопасного рекурсивного обхода графа.

Почему рекурсивный обход вынесен отдельно от записи:
Разделение чтения (CQRS-подход) позволяет держать каждый файл компактным (< 250 строк)
и оптимизировать запросы для UI и MCP независимо от транзакций индексатора.
"""

from __future__ import annotations

import json
import re
from contextlib import closing
from pathlib import Path
from typing import Any

from backend.core.models import GuardrailRuleSpec
from backend.storage.repository import utc_now_iso
from backend.storage.schema import open_sqlite_connection


def _sanitize_fts_query(raw_query: str) -> str:
    """Очищает поисковый запрос от спецсимволов синтаксиса SQLite FTS5, чтобы избежать SQL-ошибок."""
    tokens = re.findall(r"[A-Za-zА-Яа-яЁё0-9_./#-]+", raw_query)
    if not tokens:
        return ""
    return " OR ".join(f'"{t}"*' for t in tokens[:8])


class GraphQueryService:
    """Быстрые операции чтения из SQLite для REST API, UI и MCP-инструментов."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    def get_project_stats(self, project_id: str) -> dict[str, Any]:
        with closing(open_sqlite_connection(self.db_path)) as conn:
            proj = conn.execute("SELECT * FROM projects WHERE project_id = ?", (project_id,)).fetchone()
            if not proj:
                return {}
            node_counts = conn.execute(
                "SELECT node_type, COUNT(*) AS cnt FROM nodes WHERE project_id = ? GROUP BY node_type",
                (project_id,),
            ).fetchall()
            edge_counts = conn.execute(
                "SELECT edge_type, COUNT(*) AS cnt FROM edges WHERE project_id = ? GROUP BY edge_type",
                (project_id,),
            ).fetchall()
            secret_files = conn.execute(
                "SELECT COUNT(*) AS cnt FROM file_cache WHERE project_id = ? AND has_redacted_secret = 1",
                (project_id,),
            ).fetchone()
            critical_nodes = conn.execute(
                "SELECT COUNT(*) AS cnt FROM nodes WHERE project_id = ? AND risk_level = 'critical'",
                (project_id,),
            ).fetchone()
        return {
            "project": dict(proj),
            "nodes_by_type": {str(r["node_type"]): int(r["cnt"]) for r in node_counts},
            "edges_by_type": {str(r["edge_type"]): int(r["cnt"]) for r in edge_counts},
            "total_nodes": sum(int(r["cnt"]) for r in node_counts),
            "total_edges": sum(int(r["cnt"]) for r in edge_counts),
            "files_with_redacted_secrets": int(secret_files["cnt"]) if secret_files else 0,
            "critical_risk_nodes": int(critical_nodes["cnt"]) if critical_nodes else 0,
        }

    def get_c4_map(self, project_id: str, max_c4_level: int = 3) -> dict[str, Any]:
        """Возвращает узлы и связи для выбранного уровня масштаба C1..C4."""
        with closing(open_sqlite_connection(self.db_path)) as conn:
            nodes = conn.execute(
                """
                SELECT * FROM nodes
                WHERE project_id = ? AND c4_level <= ?
                ORDER BY c4_level ASC, name ASC
                """,
                (project_id, max_c4_level),
            ).fetchall()
            node_uris = {str(n["uri"]) for n in nodes}
            edges = conn.execute(
                "SELECT * FROM edges WHERE project_id = ?",
                (project_id,),
            ).fetchall()

        parsed_nodes = [self._parse_node_row(r) for r in nodes]
        visible_edges = [
            self._parse_edge_row(e)
            for e in edges
            if str(e["src_uri"]) in node_uris and str(e["dst_uri"]) in node_uris
        ]
        return {"nodes": parsed_nodes, "edges": visible_edges}

    def get_all_graph_raw(self, project_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Возвращает все узлы и рёбра проекта для аналитики PageRank и GuardrailEngine."""
        with closing(open_sqlite_connection(self.db_path)) as conn:
            nodes = conn.execute("SELECT * FROM nodes WHERE project_id = ?", (project_id,)).fetchall()
            edges = conn.execute("SELECT * FROM edges WHERE project_id = ?", (project_id,)).fetchall()
        return [self._parse_node_row(n) for n in nodes], [self._parse_edge_row(e) for e in edges]

    def get_node_by_uri(self, project_id: str, uri: str) -> dict[str, Any] | None:
        with closing(open_sqlite_connection(self.db_path)) as conn:
            row = conn.execute(
                "SELECT * FROM nodes WHERE project_id = ? AND uri = ?",
                (project_id, uri),
            ).fetchone()
            if not row:
                return None
            inbound = conn.execute(
                "SELECT * FROM edges WHERE project_id = ? AND dst_uri = ? ORDER BY confidence DESC",
                (project_id, uri),
            ).fetchall()
            outbound = conn.execute(
                "SELECT * FROM edges WHERE project_id = ? AND src_uri = ? ORDER BY confidence DESC",
                (project_id, uri),
            ).fetchall()
        result = self._parse_node_row(row)
        result["inbound_edges"] = [self._parse_edge_row(e) for e in inbound]
        result["outbound_edges"] = [self._parse_edge_row(e) for e in outbound]
        return result

    def search_nodes(self, project_id: str, query: str, limit: int = 25) -> list[dict[str, Any]]:
        fts_expr = _sanitize_fts_query(query)
        with closing(open_sqlite_connection(self.db_path)) as conn:
            if not fts_expr:
                rows = conn.execute(
                    "SELECT * FROM nodes WHERE project_id = ? AND c4_level <= 3 ORDER BY c4_level ASC, name ASC LIMIT ?",
                    (project_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT n.*
                    FROM nodes_fts f
                    JOIN nodes n ON n.project_id = f.project_id AND n.uri = f.uri
                    WHERE f.project_id = ? AND nodes_fts MATCH ?
                    ORDER BY bm25(nodes_fts), n.c4_level ASC
                    LIMIT ?
                    """,
                    (project_id, fts_expr, limit),
                ).fetchall()
        return [self._parse_node_row(r) for r in rows]

    def traverse_neighbors_safe(
        self,
        project_id: str,
        start_uri: str,
        direction: str = "inbound",
        max_depth: int = 3,
        include_hierarchy: bool = False,
    ) -> list[dict[str, Any]]:
        """
        Рекурсивно находит связанные узлы с гарантированной защитой от циклов (`visited_path`).
        Почему по умолчанию `include_hierarchy=False`: иерархические рёбра `CONTAINS` и визуальные
        стрелки `c4_rollup` связывают папку со всеми её файлами. Их пропуск оставляет в обходе
        только настоящие кодовые зависимости (`IMPORTS`, `CALLS`, `BRIDGES_TO`, `USES_CONTRACT`).
        """
        clamped_depth = max(1, min(max_depth, 8))
        if direction == "inbound":
            join_clause = "e.dst_uri = t.current_uri"
            next_col = "e.src_uri"
        else:
            join_clause = "e.src_uri = t.current_uri"
            next_col = "e.dst_uri"

        edge_filter = "" if include_hierarchy else "AND e.edge_type != 'CONTAINS' AND e.source_module != 'c4_rollup'"

        sql = f"""
        WITH RECURSIVE walk(current_uri, depth, edge_type, confidence, visited_path) AS (
            SELECT
                {next_col},
                1,
                e.edge_type,
                e.confidence,
                '|' || ? || '|' || {next_col} || '|'
            FROM edges e
            WHERE e.project_id = ?
              AND {'e.dst_uri = ?' if direction == 'inbound' else 'e.src_uri = ?'}
              {edge_filter}
            UNION ALL
            SELECT
                {next_col},
                t.depth + 1,
                e.edge_type,
                MIN(t.confidence, e.confidence),
                t.visited_path || {next_col} || '|'
            FROM edges e
            JOIN walk t ON e.project_id = ? AND {join_clause}
            WHERE t.depth < ?
              {edge_filter}
              AND INSTR(t.visited_path, '|' || {next_col} || '|') = 0
        )
        SELECT
            w.current_uri AS uri,
            MIN(w.depth) AS min_depth,
            MAX(w.confidence) AS max_confidence,
            GROUP_CONCAT(DISTINCT w.edge_type) AS edge_types,
            n.name,
            n.node_type,
            n.rel_path,
            n.c4_level,
            n.risk_level
        FROM walk w
        LEFT JOIN nodes n ON n.project_id = ? AND n.uri = w.current_uri
        GROUP BY w.current_uri
        ORDER BY min_depth ASC, max_confidence DESC
        """
        with closing(open_sqlite_connection(self.db_path)) as conn:
            rows = conn.execute(
                sql,
                (start_uri, project_id, start_uri, project_id, clamped_depth, project_id),
            ).fetchall()
        return [dict(r) for r in rows]

    def save_architectural_note(
        self,
        project_id: str,
        target_uri: str,
        summary_ru: str,
        risk_level: str = "",
    ) -> None:
        now_iso = utc_now_iso()
        with closing(open_sqlite_connection(self.db_path)) as conn:
            with conn:
                conn.execute(
                    """
                    INSERT INTO architectural_notes (project_id, target_uri, summary_ru, risk_level, updated_at_iso)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(project_id, target_uri) DO UPDATE SET
                        summary_ru = excluded.summary_ru,
                        risk_level = CASE WHEN excluded.risk_level != '' THEN excluded.risk_level ELSE architectural_notes.risk_level END,
                        updated_at_iso = excluded.updated_at_iso
                    """,
                    (project_id, target_uri, summary_ru.strip(), risk_level.strip(), now_iso),
                )
                if summary_ru.strip():
                    conn.execute(
                        "UPDATE nodes SET summary_ru = ? WHERE project_id = ? AND uri = ?",
                        (summary_ru.strip(), project_id, target_uri),
                    )
                    # Мгновенно синхронизируем полнотекстовый индекс FTS5 без ожидания полной переиндексации
                    conn.execute(
                        "UPDATE nodes_fts SET summary_ru = ? WHERE project_id = ? AND uri = ?",
                        (summary_ru.strip(), project_id, target_uri),
                    )
                if risk_level.strip():
                    conn.execute(
                        "UPDATE nodes SET risk_level = ? WHERE project_id = ? AND uri = ?",
                        (risk_level.strip(), project_id, target_uri),
                    )

    def get_architectural_notes(self, project_id: str) -> list[dict[str, Any]]:
        """Возвращает сохранённые человеком и ИИ паспорта модулей (включая карточки C3 и файлы C4)."""
        with closing(open_sqlite_connection(self.db_path)) as conn:
            rows = conn.execute(
                """
                SELECT
                    a.target_uri,
                    a.summary_ru,
                    a.risk_level AS note_risk_level,
                    a.updated_at_iso,
                    COALESCE(n.name, a.target_uri) AS name,
                    COALESCE(n.rel_path, '') AS rel_path,
                    COALESCE(n.node_type, 'Note') AS node_type,
                    COALESCE(n.c4_level, 4) AS c4_level
                FROM architectural_notes a
                LEFT JOIN nodes n ON n.project_id = a.project_id AND n.uri = a.target_uri
                WHERE a.project_id = ?
                ORDER BY c4_level ASC, a.updated_at_iso DESC
                """,
                (project_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_guardrail_rules(self, project_id: str) -> list[GuardrailRuleSpec]:
        with closing(open_sqlite_connection(self.db_path)) as conn:
            rows = conn.execute(
                "SELECT * FROM guardrail_rules WHERE project_id = ? ORDER BY rule_id ASC",
                (project_id,),
            ).fetchall()
        return [
            GuardrailRuleSpec(
                rule_id=str(r["rule_id"]),
                title=str(r["title"]),
                severity=str(r["severity"]),
                scope=str(r["scope"]),
                exclude_scope=str(r["exclude_scope"]),
                predicate_type=str(r["predicate_type"]),
                predicate_params=json.loads(r["predicate_params_json"] or "{}"),
                rationale_ru=str(r["rationale_ru"]),
                remediation_ru=str(r["remediation_ru"]),
            )
            for r in rows
        ]

    @staticmethod
    def _parse_node_row(row: Any) -> dict[str, Any]:
        d = dict(row)
        d["meta"] = json.loads(d.pop("meta_json", "{}") or "{}")
        return d

    @staticmethod
    def _parse_edge_row(row: Any) -> dict[str, Any]:
        d = dict(row)
        d["meta"] = json.loads(d.pop("meta_json", "{}") or "{}")
        return d
