"""
Сборщик контекстной капсулы `get_context_pack` с алгоритмом Personalized PageRank.

Почему капсула v2.4 исключает `c4_rollup` из PageRank и включает заметки `C3`:
1. Синтетические визуальные рёбра `c4_rollup` соединяют папки целиком и размывали бы веса
   реальных AST-вызовов. Очистка графа делает ранжирование символов хирургически точным.
2. Заметки, которые человек оставил на карточках `C3 Бизнес-модули` в UI, автоматически
   доставляются нейросети в секции `SAVED ARCHITECTURAL NOTES`, связывая человека и ИИ.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from backend.analyzers.guardrail_engine.evaluator import filter_rules_for_paths
from backend.core.config import DEFAULT_TOKEN_BUDGET, MAX_TOKEN_BUDGET
from backend.core.models import normalize_rel_path, to_project_rel_path
from backend.storage.queries import GraphQueryService


def _estimate_tokens(text: str) -> int:
    """Консервативная оценка числа токенов (1 токен ~ 3.4 символа для смеси кода и кириллицы)."""
    return max(1, int(len(text) / 3.4))


def _personalized_pagerank(
    node_uris: list[str],
    edges: list[dict[str, Any]],
    seed_uris: set[str],
    damping: float = 0.82,
    iterations: int = 16,
) -> dict[str, float]:
    """
    Вычисляет важность узлов кода относительно стартовых точек интереса AI-агента (`seed_uris`).
    Межъязыковые мосты (`BRIDGES_TO`, `USES_CONTRACT`) получают повышенный вес `2.8`.
    """
    if not node_uris:
        return {}
    n_count = len(node_uris)
    uri_set = set(node_uris)
    adj: dict[str, list[tuple[str, float]]] = {u: [] for u in node_uris}

    for e in edges:
        etype = str(e.get("edge_type", ""))
        if etype == "CONTAINS" or e.get("source_module") == "c4_rollup":
            continue
        s, d = str(e["src_uri"]), str(e["dst_uri"])
        if s in uri_set and d in uri_set and s != d:
            weight = 2.8 if etype in ("BRIDGES_TO", "USES_CONTRACT") else 1.0
            adj[s].append((d, weight))
            adj[d].append((s, weight))

    valid_seeds = seed_uris.intersection(uri_set)
    if valid_seeds:
        teleport = {u: (1.0 / len(valid_seeds) if u in valid_seeds else 0.0) for u in node_uris}
    else:
        teleport = {u: 1.0 / n_count for u in node_uris}

    scores = dict(teleport)
    for _ in range(iterations):
        next_scores = {u: (1.0 - damping) * teleport[u] for u in node_uris}
        for u, neighbors in adj.items():
            if not neighbors:
                continue
            total_w = sum(w for _, w in neighbors)
            share = damping * scores[u] / total_w
            for nb, w in neighbors:
                next_scores[nb] += share * w
        scores = next_scores
    return scores


def build_context_pack_markdown(
    project_id: str,
    query_service: GraphQueryService,
    focus_query_or_paths: list[str] | str = "",
    token_budget: int = DEFAULT_TOKEN_BUDGET,
    project_root: Path | None = None,
) -> dict[str, Any]:
    """
    Собирает единую сжатую капсулу знаний проекта для нейросети за один вызов строго в пределах `token_budget`.
    """
    clamped_budget = max(400, min(int(token_budget), MAX_TOKEN_BUDGET))
    stats = query_service.get_project_stats(project_id)
    if not stats:
        return {"error": f"Проект `{project_id}` не найден в индексе Lgraph."}

    proj = stats["project"]
    effective_root = project_root or Path(str(proj.get("root_path") or "."))
    nodes, edges = query_service.get_all_graph_raw(project_id)
    c4_nodes = [n for n in nodes if int(n.get("c4_level", 4)) == 4 and n.get("node_type") != "DomainModule"]
    node_by_uri = {str(n["uri"]): n for n in nodes}

    raw_inputs = (
        [focus_query_or_paths]
        if isinstance(focus_query_or_paths, str)
        else list(focus_query_or_paths or [])
    )
    queries = [q.strip() for q in raw_inputs if q and q.strip()]

    seed_uris: set[str] = set()
    seed_paths: set[str] = set()
    focused_c3_uris: set[str] = set()

    for q in queries:
        norm_q = to_project_rel_path(q, effective_root) or normalize_rel_path(q)
        for n in nodes:
            if int(n.get("c4_level", 4)) < 3:
                continue
            rp = str(n.get("rel_path") or "")
            n_uri = str(n["uri"])
            if q == n_uri or (norm_q and rp and (rp == norm_q or rp.endswith("/" + norm_q) or norm_q in rp)):
                if n.get("node_type") == "DomainModule":
                    focused_c3_uris.add(n_uri)
                else:
                    seed_uris.add(n_uri)
                    if rp:
                        seed_paths.add(rp)
                    if n.get("parent_uri", "").startswith("c3://"):
                        focused_c3_uris.add(str(n["parent_uri"]))

        for hit in query_service.search_nodes(project_id, q, limit=12):
            h_uri = str(hit["uri"])
            if hit.get("node_type") == "DomainModule":
                focused_c3_uris.add(h_uri)
            else:
                seed_uris.add(h_uri)
                if hit.get("rel_path"):
                    seed_paths.add(str(hit["rel_path"]))

    # Подтягиваем родительские C3-домены для всех найденных файлов фокуса
    for nd in c4_nodes:
        if nd.get("rel_path") in seed_paths and str(nd.get("parent_uri") or "").startswith("c3://"):
            focused_c3_uris.add(str(nd["parent_uri"]))

    # Находим релевантные межъязыковые мосты (без примеси `c4_rollup` и без чужих маршрутов при узком фокусе)
    real_bridge_edges = [
        e
        for e in edges
        if e.get("source_module") != "c4_rollup" and e.get("edge_type") in ("BRIDGES_TO", "USES_CONTRACT")
    ]
    if seed_uris:
        one_hop_uris = set(seed_uris)
        for e in edges:
            if e.get("edge_type") == "CONTAINS" or e.get("source_module") == "c4_rollup":
                continue
            s, d = str(e["src_uri"]), str(e["dst_uri"])
            if s in seed_uris:
                one_hop_uris.add(d)
            elif d in seed_uris:
                one_hop_uris.add(s)
        relevant_bridges = [
            e for e in real_bridge_edges if str(e["src_uri"]) in one_hop_uris or str(e["dst_uri"]) in one_hop_uris
        ]
    else:
        relevant_bridges = real_bridge_edges[:12]

    bridge_partner_uris: set[str] = set()
    for b in relevant_bridges[:12]:
        bridge_partner_uris.add(str(b["src_uri"]))
        bridge_partner_uris.add(str(b["dst_uri"]))

    ppr_scores = _personalized_pagerank(
        node_uris=[str(n["uri"]) for n in c4_nodes],
        edges=edges,
        seed_uris=seed_uris,
    )
    ranked_nodes = sorted(
        c4_nodes,
        key=lambda n: (
            2 if str(n["uri"]) in seed_uris else (1 if str(n["uri"]) in bridge_partner_uris else 0),
            ppr_scores.get(str(n["uri"]), 0.0),
        ),
        reverse=True,
    )

    lines: list[str] = [
        f"# LGRAPH CONTEXT PACK | project={proj['name']} | rev={proj['index_revision']} | stale={bool(proj['is_stale'])}",
        f"Nodes={stats['total_nodes']} Edges={stats['total_edges']} CriticalNodes={stats['critical_risk_nodes']}",
    ]

    # 1. Релевантные правила-предохранители по области действия (`scope`)
    all_rules = query_service.get_guardrail_rules(project_id)
    scoped_rules = filter_rules_for_paths(all_rules, sorted(seed_paths))
    if scoped_rules:
        lines.append("\n## ACTIVE GUARDRAILS (MUST OBEY IN THIS SCOPE)")
        for r in scoped_rules[:8]:
            lines.append(
                f"- [{r.rule_id} | {r.severity.upper()} | scope:{r.scope}] {r.title} -> {r.remediation_ru}"
            )

    # 2. Долговременные заметки человека и ИИ (включая заметки уровня Бизнес-модулей C3!)
    saved_notes = query_service.get_architectural_notes(project_id)
    if saved_notes:
        matched_notes = [
            nt
            for nt in saved_notes
            if not queries
            or nt["target_uri"] in seed_uris
            or nt["target_uri"] in focused_c3_uris
            or (nt.get("rel_path") and nt["rel_path"] in seed_paths)
        ]
        if matched_notes:
            lines.append("\n## SAVED ARCHITECTURAL NOTES (HUMAN & AI MEMORY)")
            for nt in matched_notes[:8]:
                rk = f" [{str(nt['note_risk_level']).upper()}]" if nt.get("note_risk_level") else ""
                lines.append(f"- `{nt['target_uri']}` ({nt['name']}){rk}: {nt['summary_ru']}")

    # 3. Межъязыковые мосты (`Frontend <-> IPC <-> Backend`)
    if relevant_bridges:
        lines.append("\n## CROSS-BOUNDARY BRIDGES (TS/JS <-> IPC <-> Python)")
        for b in relevant_bridges[:12]:
            lines.append(
                f"- {b['src_uri']} ==[{b['edge_type']}:{b.get('evidence', '')} ({b.get('confidence_tier')})]==> {b['dst_uri']}"
            )
    elif seed_uris:
        lines.append("\n## CROSS-BOUNDARY BRIDGES\n- (no cross-language bridges in focused scope)")

    # 4. Ранжированные узлы и сигнатуры строго до исчерпания `token_budget`
    lines.append("\n## RANKED SYMBOLS & DEPENDENCIES")
    outbound_by_src: dict[str, list[dict[str, Any]]] = {}
    inbound_by_dst: dict[str, list[dict[str, Any]]] = {}
    for e in edges:
        if e.get("edge_type") == "CONTAINS" or e.get("source_module") == "c4_rollup":
            continue
        outbound_by_src.setdefault(str(e["src_uri"]), []).append(e)
        inbound_by_dst.setdefault(str(e["dst_uri"]), []).append(e)

    included_count = 0
    current_text = "\n".join(lines)
    for nd in ranked_nodes:
        uri = str(nd["uri"])
        loc = f"{nd['rel_path']}:{nd['start_line']}-{nd['end_line']}" if nd.get("rel_path") else uri
        risk_badge = " [CRITICAL!]" if nd.get("risk_level") == "critical" else ""
        sig = nd.get("signature") or f"{nd['node_type']} {nd['name']}"
        doc_part = f" | {nd['summary_ru']}" if nd.get("summary_ru") else ""

        callers = [e["src_uri"].split("://", 1)[-1] for e in inbound_by_dst.get(uri, [])[:4]]
        callees = [e["dst_uri"].split("://", 1)[-1] for e in outbound_by_src.get(uri, [])[:4]]

        entry_lines = [f"* `{loc}`{risk_badge} :: `{sig}`{doc_part}"]
        if callers:
            entry_lines.append(f"  <- used_by: {', '.join(callers)}")
        if callees:
            entry_lines.append(f"  -> uses: {', '.join(callees)}")
        block = "\n".join(entry_lines)

        candidate_text = current_text + "\n" + block
        if _estimate_tokens(candidate_text) > clamped_budget:
            break
        lines.append(block)
        current_text = candidate_text
        included_count += 1

    final_markdown = "\n".join(lines)
    _ = node_by_uri
    return {
        "project_id": project_id,
        "index_revision": int(proj["index_revision"]),
        "is_stale": bool(proj["is_stale"]),
        "estimated_tokens": _estimate_tokens(final_markdown),
        "token_budget": clamped_budget,
        "included_symbols": included_count,
        "context_markdown": final_markdown,
    }
