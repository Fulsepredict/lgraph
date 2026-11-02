"""
Вспомогательные функции форматирования и разрешения запросов для MCP-инструментов Lgraph.

Почему вынесено в `tool_helpers.py`:
Отделение чистой логики поиска паспорта узла и фильтрации путей от деклараций `@mcp.tool`
делает `server.py` компактным (~200 строк) и позволяет тестировать обработчики изолированно.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from backend.analyzers.guardrail_engine.evaluator import (
    evaluate_project_guardrails,
    matches_focus_paths,
)
from backend.core.models import to_project_rel_path
from backend.storage.queries import GraphQueryService

_LINE_ANCHOR_RE = re.compile(r"^L\d+(?:-L?\d+)?$", re.IGNORECASE)


def execute_inspect_or_search(
    project_id: str,
    project_root: Path,
    queries: GraphQueryService,
    query_or_uri: str,
    max_depth: int = 2,
) -> str:
    """
    Разрешает URI, относительный/абсолютный путь файла (с опциональным `#символ`) в техпаспорт узла,
    либо выполняет полнотекстовый поиск `SQLite FTS5` по ключевым словам.
    """
    q = query_or_uri.strip()
    if not q:
        raise ValueError("Параметр `query_or_uri` не может быть пустым.")

    node = queries.get_node_by_uri(project_id, q) if "://" in q and not q.lower().startswith("file://") else None

    if node is None:
        anchor = ""
        if "#" in q:
            raw_anchor = q.rsplit("#", 1)[1].strip()
            if raw_anchor and not _LINE_ANCHOR_RE.match(raw_anchor):
                anchor = raw_anchor

        rel_candidate = to_project_rel_path(q, project_root)
        if rel_candidate:
            candidates = (
                [f"{sc}://{rel_candidate}#{anchor}" for sc in ("py", "ts", "js")]
                + [f"{sc}://{rel_candidate}" for sc in ("py", "ts", "js")]
                if anchor
                else [f"{sc}://{rel_candidate}" for sc in ("py", "ts", "js")]
            )
            for cand_u in candidates:
                node = queries.get_node_by_uri(project_id, cand_u)
                if node is not None:
                    break

    if node is not None:
        target_uri = str(node["uri"])
        all_nodes, all_edges = queries.get_all_graph_raw(project_id)
        children = [
            {
                "uri": n["uri"],
                "node_type": n["node_type"],
                "lines": f"{n['start_line']}-{n['end_line']}",
                "signature": n["signature"],
            }
            for n in all_nodes
            if n.get("parent_uri") == target_uri
        ]
        family_uris = {target_uri} | {str(c["uri"]) for c in children}
        bridges = [
            {
                "src_uri": e["src_uri"],
                "dst_uri": e["dst_uri"],
                "edge_type": e["edge_type"],
                "evidence": e.get("evidence", ""),
            }
            for e in all_edges
            if e.get("source_module") != "c4_rollup"
            and e.get("edge_type") in ("BRIDGES_TO", "USES_CONTRACT")
            and (str(e["src_uri"]) in family_uris or str(e["dst_uri"]) in family_uris)
        ]
        payload = {
            "mode": "exact_node_passport",
            "uri": target_uri,
            "node_type": node["node_type"],
            "name": node["name"],
            "rel_path": node["rel_path"],
            "lines": f"{node['start_line']}-{node['end_line']}",
            "risk_level": node["risk_level"],
            "pattern_tag": node["pattern_tag"],
            "signature": node["signature"],
            "summary_ru": node["summary_ru"],
            "children_symbols": children[:40],
            "cross_language_bridges": bridges[:25],
            "inbound_dependents": queries.traverse_neighbors_safe(project_id, target_uri, "inbound", max_depth=max_depth)[:25],
            "outbound_dependencies": queries.traverse_neighbors_safe(project_id, target_uri, "outbound", max_depth=max_depth)[:25],
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)

    hits = queries.search_nodes(project_id, q, limit=15)
    compact_hits = [
        {
            "uri": h["uri"],
            "node_type": h["node_type"],
            "location": f"{h['rel_path']}:{h['start_line']}-{h['end_line']}" if h.get("rel_path") else h["uri"],
            "risk_level": h["risk_level"],
            "signature": h["signature"],
            "summary_ru": h["summary_ru"],
        }
        for h in hits
    ]
    return json.dumps(
        {"mode": "fts5_search", "query": q, "count": len(compact_hits), "results": compact_hits},
        ensure_ascii=False,
        indent=2,
    )


def execute_verify_guardrails_report(
    project_id: str,
    project_root: Path,
    queries: GraphQueryService,
    only_paths: list[str] | None,
    auto_reindexed: bool,
) -> str:
    """Формирует объяснимый отчёт о проверке правил с защитой от ложно-зелёного фильтра `only_paths`."""
    nodes, edges = queries.get_all_graph_raw(project_id)
    rules = queries.get_guardrail_rules(project_id)
    all_file_rels = [str(n["rel_path"]) for n in nodes if n.get("node_type") == "File" and n.get("rel_path")]

    scoped_set: set[str] | None = None
    unmatched_raw: list[str] = []
    matched_count = len(all_file_rels)

    if only_paths:
        cleaned_inputs = [p.strip() for p in only_paths if p and p.strip()]
        if cleaned_inputs:
            scoped_set = set()
            for raw_p in cleaned_inputs:
                rel_p = to_project_rel_path(raw_p, project_root)
                if rel_p and any(matches_focus_paths(fp, {rel_p}) for fp in all_file_rels):
                    scoped_set.add(rel_p)
                else:
                    unmatched_raw.append(raw_p)
            matched_count = sum(1 for fp in all_file_rels if matches_focus_paths(fp, scoped_set))
            if matched_count == 0:
                return (
                    f"⚠️ WARNING: NO FILES MATCHED FILTER `only_paths={cleaned_inputs}`.\n"
                    "Ни один проиндексированный исходный файл проекта не совпал с переданными путями. "
                    "Убедитесь, что путь принадлежит корню проекта и имеет поддерживаемое кодовое расширение (.py, .ts, .tsx, .js)."
                )

    violations = evaluate_project_guardrails(
        project_root=project_root,
        nodes=nodes,
        edges=edges,
        configured_rules=rules,
        only_rel_paths=scoped_set,
    )
    sync_note = " (индекс автоматически синхронизирован с диском)" if auto_reindexed else ""
    unmatched_note = f"\n⚠️ Примечание: не найдены в индексе пути: {unmatched_raw}" if unmatched_raw else ""

    if not violations:
        return (
            f"✅ ALL GUARDRAILS PASSED{sync_note}: Проверено файлов в фокусе: {matched_count}/{len(all_file_rels)}. "
            f"Нарушений архитектурных правил не обнаружено.{unmatched_note}"
        )

    lines = [
        f"❌ GUARDRAIL VIOLATIONS FOUND ({len(violations)}) | Проверено файлов: {matched_count}/{len(all_file_rels)}{sync_note}:"
    ]
    if unmatched_note:
        lines.append(unmatched_note.strip())
    for v in violations:
        lines.append(
            f"\n- [{v.rule_id} | {v.severity.upper()}] {v.title}"
            f"\n  Файл/Узел: `{v.target_uri_or_path}` (строка {v.line_number}, область `{v.matched_scope}`)"
            f"\n  Факт: {v.evidence}"
            f"\n  Почему нарушено: {v.why_violated_ru}"
            f"\n  Как исправить: {v.how_to_fix_ru}"
        )
    return "\n".join(lines)
