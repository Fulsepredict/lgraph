"""
Сборщик контекстной капсулы `get_context_pack` с кэшированным направленным Personalized PageRank.

Почему капсула v2.4.2 использует долевые квоты, снимок ревизии и отчёт об омиссии:
1. Кэшированный снимок ревизии (`ppr_cache.py`) исключает `get_all_graph_raw` и `json.loads`
   на каждом вызове, сохраняя высокую скорость на графах десятков тысяч узлов.
2. Долевые квоты шапки (`GUARDRAILS <= 25%`, `NOTES <= 20%`, `BRIDGES <= 30%` с гарантией 2 мостов),
   резерв под `## OMITTED SUMMARY` и добор символов через `continue` гарантируют строгий потолок
   `estimated_tokens <= clamped_budget` и прозрачность опущенных сущностей.
3. Устаревшие заметки помечаются `[STALE: reason | provenance=...]`, а свежие не дублируются ниже.
"""

from __future__ import annotations

import heapq
from operator import itemgetter
from pathlib import Path
from typing import Any

from backend.analyzers.guardrail_engine.evaluator import filter_rules_for_paths
from backend.context_pack import ppr_cache, token_and_seed_parser as tsp
from backend.core.config import DEFAULT_TOKEN_BUDGET, MAX_TOKEN_BUDGET
from backend.core.models import redact_inline_secrets
from backend.storage.queries import GraphQueryService

MIN_TOKEN_BUDGET: int = 400
GUARDRAILS_BUDGET_SHARE: float = 0.25
NOTES_BUDGET_SHARE: float = 0.20
BRIDGES_BUDGET_SHARE: float = 0.30
OMITTED_FOOTER_SHARE: float = 0.12
OMITTED_FOOTER_COMPACT_SHARE: float = 0.085
OMITTED_FOOTER_COMPACT_THRESHOLD: int = 700
OMITTED_FOOTER_MAX_TOKENS: int = 95
OMITTED_FOOTER_COMPACT_MAX_TOKENS: int = 42

MIN_GUARANTEED_BRIDGES: int = 2
MAX_DISPLAY_GUARDRAILS: int = 16
MAX_DISPLAY_NOTES: int = 16
MAX_DISPLAY_BRIDGES: int = 12
MIN_REMAINING_TOKENS_FOR_SYMBOL: int = 20
MAX_CONSECUTIVE_SYMBOL_SKIPS: int = 12
TOP_OMITTED_SYMBOLS_LIMIT: int = 10
MAX_TOP_OMITTED_URIS_IN_FOOTER: int = 5
MAX_NEIGHBOR_REFS_PER_SYMBOL: int = 4
LARGE_GRAPH_SORT_THRESHOLD: int = 1000

_NL_RAW: float = tsp.estimate_tokens_raw("\n")
_estimate_tokens = tsp.estimate_tokens


def _personalized_pagerank(
    node_uris: list[str], edges: list[dict[str, Any]], seed_uris: set[str],
    damping: float = ppr_cache.DEFAULT_PPR_DAMPING,
    iterations: int = ppr_cache.DEFAULT_PPR_ITERATIONS,
    direction_mode: str = "balanced",
) -> dict[str, float]:
    """Направленный hub-damped Personalized PageRank со стохастической массой `sum == 1.0`."""
    return ppr_cache.run_ppr_from_raw_edges(node_uris, edges, seed_uris, direction_mode, damping, iterations)


def _append_quota_section(
    lines: list[str], current_raw: float, heading: str, candidate_lines: list[str],
    section_quota: int, hard_ceiling: int, min_guaranteed: int = 0,
) -> tuple[float, list[int]]:
    if not candidate_lines:
        return current_raw, []
    section_raw = tsp.estimate_tokens_raw(heading)
    chosen_lines: list[str] = []
    chosen_indices: list[int] = []
    for idx, item in enumerate(candidate_lines):
        next_sec = section_raw + _NL_RAW + tsp.estimate_tokens_raw(item)
        next_tot = current_raw + _NL_RAW + next_sec
        if tsp.estimate_tokens_from_raw(next_tot) > hard_ceiling:
            continue
        if len(chosen_lines) >= min_guaranteed and tsp.estimate_tokens_from_raw(next_sec) > section_quota:
            continue
        chosen_lines.append(item)
        chosen_indices.append(idx)
        section_raw = next_sec
    if not chosen_lines:
        return current_raw, []
    lines.append(heading)
    lines.extend(chosen_lines)
    return current_raw + _NL_RAW + section_raw, chosen_indices


def _match_notes_for_scope(
    saved_notes: list[dict[str, Any]], cleaned_queries: list[str],
    seed_uris: set[str], focused_c3_uris: set[str], seed_paths: set[str],
) -> list[dict[str, Any]]:
    matched: list[dict[str, Any]] = []
    for nt in saved_notes:
        if not str(nt.get("summary_ru") or "").strip():
            continue
        if not cleaned_queries:
            matched.append(nt)
            continue
        uri = str(nt["target_uri"])
        rp = str(nt.get("rel_path") or "") or (uri.split("://", 1)[1].split("#", 1)[0] if "://" in uri else "")
        if uri in seed_uris or uri in focused_c3_uris or (rp and rp in seed_paths):
            matched.append(nt)
    return matched


def _format_note_line(nt: dict[str, Any]) -> str:
    rk = f" [{str(nt['note_risk_level']).upper()}]" if nt.get("note_risk_level") else ""
    stale = (
        f"[STALE: {nt.get('stale_reason') or 'outdated'} | provenance={nt.get('provenance') or 'human'}] "
        if nt.get("is_stale") else ""
    )
    safe_note = redact_inline_secrets(str(nt.get("summary_ru") or "").strip())[0]
    return f"- {stale}`{nt['target_uri']}` ({nt['name']}){rk}: {safe_note}"


def _format_symbol_block(
    nd: dict[str, Any], snapshot: ppr_cache.RevisionGraphSnapshot,
    notes_by_uri: dict[str, dict[str, Any]], shown_note_uris: set[str], shown_fresh_note_uris: set[str],
) -> tuple[str, str]:
    uri, nt = str(nd["uri"]), notes_by_uri.get(str(nd["uri"]))
    eff_risk = str(nt["note_risk_level"]) if (nt and nt.get("note_risk_level")) else str(nd.get("risk_level") or "low")
    loc = f"{nd['rel_path']}:{nd['start_line']}-{nd['end_line']}" if nd.get("rel_path") else uri
    sig = nd.get("signature") or f"{nd['node_type']} {nd['name']}"
    if nt is not None and not nt.get("is_stale"):
        doc_text = "" if uri in shown_fresh_note_uris else redact_inline_secrets(str(nt.get("summary_ru") or "").strip())[0]
    else:
        doc_text = str(nd.get("summary_ru") or "")
        if nt is not None and uri in shown_note_uris and doc_text.strip() == str(nt.get("summary_ru") or "").strip():
            doc_text = ""
    callers = [u.split("://", 1)[-1] for u in snapshot.inbound_by_dst.get(uri, ())[:MAX_NEIGHBOR_REFS_PER_SYMBOL]]
    callees = [u.split("://", 1)[-1] for u in snapshot.outbound_by_src.get(uri, ())[:MAX_NEIGHBOR_REFS_PER_SYMBOL]]
    entry = [f"* `{loc}`{' [CRITICAL!]' if eff_risk == 'critical' else ''} :: `{sig}`{f' | {doc_text}' if doc_text else ''}"]
    if callers:
        entry.append(f"  <- used_by: {', '.join(callers)}")
    if callees:
        entry.append(f"  -> uses: {', '.join(callees)}")
    return "\n".join(entry), eff_risk


def _append_omitted_summary(
    lines: list[str], current_raw: float, clamped_budget: int,
    omitted_counts: dict[str, int], omitted_symbols: list[dict[str, Any]],
) -> None:
    if not any(omitted_counts.values()):
        return
    heading = "\n## OMITTED SUMMARY"
    c = omitted_counts
    full_counts = (
        f"- Omitted: symbols={c['symbols_total']} (critical={c['critical_symbols']}), "
        f"bridges={c['bridges']}, notes={c['notes']}, guardrails={c['guardrails']}. "
        f"Expand via inspect_node_or_search or higher token_budget."
    )
    compact_counts = (
        f"- Omitted: sym={c['symbols_total']}(crit={c['critical_symbols']}) "
        f"br={c['bridges']} nt={c['notes']} gr={c['guardrails']}; use inspect_node_or_search"
    )
    added = False
    for body_cand in (full_counts, compact_counts):
        cand_raw = current_raw + _NL_RAW + tsp.estimate_tokens_raw(f"{heading}\n{body_cand}")
        if tsp.estimate_tokens_from_raw(cand_raw) <= clamped_budget:
            lines.extend((heading, body_cand))
            current_raw, added = cand_raw, True
            break
    if not added or not omitted_symbols:
        return
    uri_parts: list[str] = []
    for item in omitted_symbols[:MAX_TOP_OMITTED_URIS_IN_FOOTER]:
        part = f"`{item['uri']}`" + (" [CRITICAL]" if item["risk_level"] == "critical" else "")
        cand_line = "- Top omitted: " + ", ".join([*uri_parts, part])
        if tsp.estimate_tokens_from_raw(current_raw + _NL_RAW + tsp.estimate_tokens_raw(cand_line)) > clamped_budget:
            break
        uri_parts.append(part)
    if uri_parts:
        lines.append("- Top omitted: " + ", ".join(uri_parts))


def build_context_pack_markdown(
    project_id: str,
    query_service: GraphQueryService,
    focus_query_or_paths: list[str] | str = "",
    token_budget: int = DEFAULT_TOKEN_BUDGET,
    project_root: Path | None = None,
) -> dict[str, Any]:
    """Собирает сжатую капсулу архитектуры строго в рамках `token_budget` с отчётом об омиссиях."""
    clamped_budget = max(MIN_TOKEN_BUDGET, min(int(token_budget), MAX_TOKEN_BUDGET))
    proj = ppr_cache.fetch_project_header(query_service.db_path, project_id)
    if not proj:
        return {"error": f"Проект `{project_id}` не найден в индексе Lgraph."}

    index_revision = int(proj["index_revision"])
    effective_root = project_root or Path(str(proj.get("root_path") or "."))
    snapshot = ppr_cache.get_or_load_revision_snapshot(query_service.db_path, project_id, index_revision)
    saved_notes = query_service.get_architectural_notes(project_id)
    notes_by_uri = {str(nt["target_uri"]): nt for nt in saved_notes}
    total_nodes, total_edges, total_critical = snapshot.graph_totals
    for n_uri, nt in notes_by_uri.items():
        nd_ref = snapshot.node_by_uri.get(n_uri)
        if nd_ref and nt.get("note_risk_level"):
            total_critical += int(nt["note_risk_level"] == "critical") - int(nd_ref.get("risk_level") == "critical")

    raw_inputs = [focus_query_or_paths] if isinstance(focus_query_or_paths, str) else list(focus_query_or_paths or [])
    direction_mode, cleaned_queries = tsp.detect_query_direction(raw_inputs)
    seed_uris, seed_paths, focused_c3_uris = tsp.collect_seed_uris(
        project_id, cleaned_queries, snapshot, query_service, effective_root
    )

    relevant_bridges = ppr_cache.select_relevant_bridges(snapshot, seed_uris)
    bridge_partner_uris = {u for b in relevant_bridges[:MAX_DISPLAY_BRIDGES] for u in (str(b["src_uri"]), str(b["dst_uri"]))}
    ppr_scores = ppr_cache.compute_cached_ppr(snapshot, seed_uris, direction_mode=direction_mode)

    footer_reserve = (
        min(OMITTED_FOOTER_MAX_TOKENS, int(clamped_budget * OMITTED_FOOTER_SHARE))
        if clamped_budget >= OMITTED_FOOTER_COMPACT_THRESHOLD
        else min(OMITTED_FOOTER_COMPACT_MAX_TOKENS, int(clamped_budget * OMITTED_FOOTER_COMPACT_SHARE))
    )
    content_ceiling = max(1, clamped_budget - footer_reserve)
    lines = [
        f"# LGRAPH CONTEXT PACK | project={proj['name']} | rev={index_revision} | stale={bool(proj['is_stale'])} | mode={direction_mode}",
        f"Nodes={total_nodes} Edges={total_edges} CriticalNodes={max(0, total_critical)}",
    ]
    current_raw = tsp.estimate_tokens_raw("\n".join(lines))

    # 1. Активные правила Guardrails (<= 25%)
    scoped_rules = filter_rules_for_paths(query_service.get_guardrail_rules(project_id), sorted(seed_paths))
    rule_lines = [f"- [{r.rule_id} | {r.severity.upper()} | scope:{r.scope}] {r.title} -> {r.remediation_ru}" for r in scoped_rules[:MAX_DISPLAY_GUARDRAILS]]
    current_raw, shown_rule_idx = _append_quota_section(
        lines, current_raw, "\n## ACTIVE GUARDRAILS (MUST OBEY IN THIS SCOPE)", rule_lines,
        int(clamped_budget * GUARDRAILS_BUDGET_SHARE), content_ceiling,
    )
    omitted_guardrails = max(0, len(scoped_rules) - len(shown_rule_idx))

    # 2. Сохранённые заметки C3/C4 (<= 20%, CRITICAL-first + [STALE])
    matched_notes = _match_notes_for_scope(saved_notes, cleaned_queries, seed_uris, focused_c3_uris, seed_paths)
    current_raw, shown_note_idx = _append_quota_section(
        lines, current_raw, "\n## SAVED ARCHITECTURAL NOTES (HUMAN & AI MEMORY)",
        [_format_note_line(nt) for nt in matched_notes[:MAX_DISPLAY_NOTES]],
        int(clamped_budget * NOTES_BUDGET_SHARE), content_ceiling,
    )
    shown_note_uris = {str(matched_notes[i]["target_uri"]) for i in shown_note_idx}
    shown_fresh_note_uris = {str(matched_notes[i]["target_uri"]) for i in shown_note_idx if not matched_notes[i].get("is_stale")}
    omitted_notes = max(0, len(matched_notes) - len(shown_note_idx))

    # 3. Межъязыковые мосты (<= 30%, минимум 2 моста при наличии)
    bridge_lines = [
        f"- {b['src_uri']} ==[{b['edge_type']}:{b.get('evidence', '')} ({b.get('confidence_tier')})]==> {b['dst_uri']}"
        for b in relevant_bridges[:MAX_DISPLAY_BRIDGES]
    ]
    omitted_bridges = 0
    if bridge_lines:
        current_raw, shown_br_idx = _append_quota_section(
            lines, current_raw, "\n## CROSS-BOUNDARY BRIDGES (TS/JS <-> IPC <-> Python)", bridge_lines,
            int(clamped_budget * BRIDGES_BUDGET_SHARE), content_ceiling, min_guaranteed=MIN_GUARANTEED_BRIDGES,
        )
        omitted_bridges = max(0, len(relevant_bridges) - len(shown_br_idx))
    elif seed_uris:
        no_br = "\n## CROSS-BOUNDARY BRIDGES\n- (no cross-language bridges in focused scope)"
        if tsp.estimate_tokens_from_raw(current_raw + _NL_RAW + tsp.estimate_tokens_raw(no_br)) <= content_ceiling:
            lines.append(no_br)
            current_raw += _NL_RAW + tsp.estimate_tokens_raw(no_br)

    # 4. Ранжированные символы с пропуском тяжёлых блоков (`continue`) и точными омиссиями
    critical_set = {snapshot.idx_to_uri[i] for i in snapshot.critical_c4_indices}
    for n_uri, nt in notes_by_uri.items():
        if n_uri in snapshot.uri_to_idx and nt.get("note_risk_level"):
            critical_set.add(n_uri) if nt["note_risk_level"] == "critical" else critical_set.discard(n_uri)

    n_c4, idx_to_uri, uri_to_idx = len(snapshot.c4_nodes), snapshot.idx_to_uri, snapshot.uri_to_idx

    def _rank_key(idx: int) -> tuple[int, float, str]:
        u = idx_to_uri[idx]
        return (2 if u in seed_uris else (1 if u in bridge_partner_uris else 0), ppr_scores.get(u, 0.0), u)

    if n_c4 <= LARGE_GRAPH_SORT_THRESHOLD:
        ranked_indices = sorted(range(n_c4), key=_rank_key, reverse=True)
    else:
        # C-ускоренный отбор top-K по PPR + обязательные `seed_uris` и партнёры мостов
        top_k = min(n_c4, max(350, clamped_budget // 6))
        cand_idx = {uri_to_idx[u] for u in (seed_uris | bridge_partner_uris) if u in uri_to_idx}
        cand_idx.update(uri_to_idx[u] for u, _ in heapq.nlargest(top_k, ppr_scores.items(), key=itemgetter(1)))
        ranked_indices = sorted(cand_idx, key=_rank_key, reverse=True)
    sym_heading = "\n## RANKED SYMBOLS & DEPENDENCIES"
    if tsp.estimate_tokens_from_raw(current_raw + _NL_RAW + tsp.estimate_tokens_raw(sym_heading)) <= content_ceiling:
        lines.append(sym_heading)
        current_raw += _NL_RAW + tsp.estimate_tokens_raw(sym_heading)

    header_omitted = omitted_guardrails + omitted_notes + omitted_bridges
    packed_uris, packed_set, skipped_indices = [], set(), []
    included_critical, consecutive_skips, stop_pos = 0, 0, len(ranked_indices)

    for pos, idx in enumerate(ranked_indices):
        last_clean = header_omitted == 0 and not skipped_indices and len(packed_uris) + 1 == n_c4 and pos + 1 == len(ranked_indices)
        eff_ceiling = clamped_budget if last_clean else content_ceiling
        if eff_ceiling - tsp.estimate_tokens_from_raw(current_raw) < MIN_REMAINING_TOKENS_FOR_SYMBOL or consecutive_skips >= MAX_CONSECUTIVE_SYMBOL_SKIPS:
            stop_pos = pos
            break
        nd = snapshot.c4_nodes[idx]
        block, eff_risk = _format_symbol_block(nd, snapshot, notes_by_uri, shown_note_uris, shown_fresh_note_uris)
        cand_raw = current_raw + _NL_RAW + tsp.estimate_tokens_raw(block)
        if tsp.estimate_tokens_from_raw(cand_raw) > eff_ceiling:
            consecutive_skips += 1
            skipped_indices.append(idx)
            continue
        lines.append(block)
        current_raw, consecutive_skips = cand_raw, 0
        u = str(nd["uri"])
        packed_uris.append(u)
        packed_set.add(u)
        if eff_risk == "critical":
            included_critical += 1

    omitted_counts = {
        "symbols_total": max(0, n_c4 - len(packed_uris)),
        "critical_symbols": max(0, len(critical_set) - included_critical),
        "bridges": omitted_bridges, "notes": omitted_notes, "guardrails": omitted_guardrails,
    }
    omitted_cand_uris = {idx_to_uri[i] for i in skipped_indices} | {idx_to_uri[i] for i in ranked_indices[stop_pos:]}
    if omitted_counts["critical_symbols"] > 0:
        omitted_cand_uris.update(u for u in critical_set if u not in packed_set)
    omitted_cand_uris.difference_update(packed_set)

    top_omitted = sorted(
        omitted_cand_uris,
        key=lambda u: (1 if u in seed_uris else 0, 1 if u in critical_set else 0, ppr_scores.get(u, 0.0), u),
        reverse=True,
    )[:TOP_OMITTED_SYMBOLS_LIMIT]
    omitted_symbols = [
        {"uri": u, "risk_level": "critical" if u in critical_set else str(snapshot.node_by_uri[u].get("risk_level") or "low"), "ppr_score": round(float(ppr_scores.get(u, 0.0)), 6)}
        for u in top_omitted
    ]

    _append_omitted_summary(lines, current_raw, clamped_budget, omitted_counts, omitted_symbols)
    final_markdown = "\n".join(lines)
    final_tokens = tsp.estimate_tokens(final_markdown)
    while final_tokens > clamped_budget and len(lines) > 2:
        lines.pop()
        final_markdown = "\n".join(lines)
        final_tokens = tsp.estimate_tokens(final_markdown)

    return {
        "project_id": project_id, "index_revision": index_revision, "is_stale": bool(proj["is_stale"]),
        "estimated_tokens": final_tokens, "token_budget": clamped_budget, "included_symbols": len(packed_uris),
        "packed_uris": packed_uris, "omitted_counts": omitted_counts, "omitted_symbols": omitted_symbols,
        "direction_mode": direction_mode, "context_markdown": final_markdown,
    }
