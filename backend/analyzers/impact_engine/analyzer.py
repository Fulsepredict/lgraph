"""
Анализатор влияния изменений (Impact Engine) и радар «Визуального рентгена правок ИИ».

Почему этот модуль проверяет межъязыковые мосты в обе стороны, учитывает `confidence_tier` и `HEAD`:
1. Если агент правит серверный роут или схему Python — находятся клиентские вызовы в TypeScript (`inbound`).
   Если правит клиентский `api.ts` или `interface` — находятся парные роуты и схемы Python (`outbound_contract_partner`).
2. Гейтинг по `confidence_tier` отсекает межъязыковой эвристический шум (`CALLS`), оставляя только
   достоверные контракты (`verified` / `exact` / `pattern_matched`).
3. Сравнение с `HEAD` через `preflight.py` ловит оборванные маршруты и удалённые модули/символы.
"""

from __future__ import annotations

import dataclasses
import subprocess
from collections import deque
from pathlib import Path
from typing import Any

from backend.analyzers.code_graph.disk_state import JS_TS_EXTENSIONS, PY_EXTENSIONS
from backend.analyzers.guardrail_engine.evaluator import evaluate_project_guardrails, matches_focus_paths
from backend.analyzers.impact_engine.diff_classifier import analyze_head_snapshot_and_diff, inspect_git_working_tree
from backend.analyzers.impact_engine.preflight import HIGH_CONFIDENCE_TIERS, run_contract_preflight
from backend.core.models import normalize_rel_path, to_project_rel_path
from backend.storage.queries import GraphQueryService

_TIER_RANK: dict[str, int] = {"exact": 4, "verified": 3, "pattern_matched": 2, "heuristic": 1, "unresolved_dynamic": 0}
_CROSS_LANG_SCHEMES: frozenset[str] = frozenset({"py", "ts", "js"})
_SKIP_DEP_PREFIXES: tuple[str, ...] = ("c1://", "c2://", "c3://", "dynamic://")


def get_git_changed_files(project_root: Path) -> list[str]:
    """Возвращает изменённые/переименованные (оба пути)/удалённые файлы из `git status` или последнего коммита."""
    status = inspect_git_working_tree(project_root)
    if status.has_uncommitted_changes:
        return status.changed_paths
    try:
        proc = subprocess.run(
            ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD"],
            cwd=str(project_root), capture_output=True, text=True, timeout=5.0, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return sorted({normalize_rel_path(ln.strip()) for ln in proc.stdout.splitlines() if ln.strip()})
    except Exception:
        pass
    return []


def parse_changed_files_from_unified_diff(diff_text: str) -> list[str]:
    """Извлекает относительные пути изменённых, удалённых и переименованных файлов из `git diff`."""
    paths: set[str] = set()
    for line in diff_text.splitlines():
        if line.startswith(("+++ b/", "--- a/")):
            if p := normalize_rel_path(line[6:].strip()):
                paths.add(p)
    return sorted(paths)


def _make_dep_entry(
    uri: str, nd: dict[str, Any], edge_types: str, tier: str, conf: float, depth: int = 1
) -> dict[str, Any]:
    return {
        "uri": uri, "min_depth": depth, "max_confidence": round(conf, 4),
        "confidence_tier": tier,
        "confidence_bucket": "high_confidence" if tier in HIGH_CONFIDENCE_TIERS else "low_confidence_heuristic",
        "edge_types": edge_types, "name": nd.get("name"), "node_type": nd.get("node_type"),
        "rel_path": nd.get("rel_path"), "c4_level": nd.get("c4_level"), "risk_level": nd.get("risk_level"),
    }


def _traverse_inbound_with_tiers(
    start_uri: str,
    inbound_by_dst: dict[str, list[dict[str, Any]]],
    node_by_uri: dict[str, dict[str, Any]],
    max_depth: int = 3,
) -> list[tuple[dict[str, Any], set[str]]]:
    """Обходит входящие зависимости до `max_depth`, отслеживая минимальный `confidence_tier` вдоль пути."""
    best: dict[str, tuple[int, int, float, str, set[str], set[str]]] = {}
    queue: deque[tuple[str, int, int, float, str, frozenset[str]]] = deque(
        [(start_uri, 0, 4, 1.0, "exact", frozenset())]
    )
    while queue:
        cur_u, depth, path_rank, path_conf, path_tier, path_etypes = queue.popleft()
        if depth >= max_depth:
            continue
        for edge in inbound_by_dst.get(cur_u, []):
            nxt_u = str(edge["src_uri"])
            if nxt_u == start_uri:
                continue
            e_tier = str(edge.get("confidence_tier") or "verified")
            e_rank, e_conf = _TIER_RANK.get(e_tier, 1), float(edge.get("confidence") or 1.0)
            e_type = str(edge.get("edge_type") or "")
            nxt_d, nxt_rk = depth + 1, min(path_rank, e_rank)
            nxt_tier = e_tier if e_rank <= path_rank else path_tier
            nxt_conf = min(path_conf, e_conf)
            nxt_et = path_etypes | ({e_type} if e_type else frozenset())

            prev = best.get(nxt_u)
            if prev is None:
                best[nxt_u] = (nxt_rk, -nxt_d, nxt_conf, nxt_tier, set(nxt_et), set(nxt_et))
                queue.append((nxt_u, nxt_d, nxt_rk, nxt_conf, nxt_tier, nxt_et))
            else:
                prev[4].update(nxt_et)
                if (nxt_rk, -nxt_d, nxt_conf) > (prev[0], prev[1], prev[2]):
                    best[nxt_u] = (nxt_rk, -nxt_d, nxt_conf, nxt_tier, prev[4], set(nxt_et))
                    queue.append((nxt_u, nxt_d, nxt_rk, nxt_conf, nxt_tier, nxt_et))

    results: list[tuple[dict[str, Any], set[str]]] = []
    for u, (_rk, neg_d, conf, tier_str, all_et, best_et) in best.items():
        results.append((_make_dep_entry(u, node_by_uri.get(u) or {}, ",".join(sorted(all_et)), tier_str, conf, -neg_d), best_et))
    results.sort(key=lambda item: (item[0]["min_depth"], -_TIER_RANK.get(item[0]["confidence_tier"], 0), -item[0]["max_confidence"], item[0]["uri"]))
    return results


def analyze_change_impact(
    project_id: str,
    project_root: Path,
    query_service: GraphQueryService,
    target_uris_or_paths: list[str] | None = None,
    git_diff_text: str = "",
) -> dict[str, Any]:
    """
    Рассчитывает полный отчёт о влиянии изменений: зависимые узлы с гейтингом `confidence_tier`,
    двусторонние межъязыковые контракты, `signature_changes`/`body_only_changes`, `bridge_coverage`,
    `preflight` (включая `capsule_recall`), красный контур и нарушения `GuardrailEngine`.
    """
    nodes, edges = query_service.get_all_graph_raw(project_id)
    node_by_uri = {str(n["uri"]): n for n in nodes}
    all_file_rels = {str(n["rel_path"]) for n in nodes if n.get("node_type") == "File" and n.get("rel_path")}
    supported_exts = PY_EXTENSIONS | JS_TS_EXTENSIONS

    explicit_targets = [t.strip() for t in (target_uris_or_paths or []) if t and t.strip()]
    diff_paths = parse_changed_files_from_unified_diff(git_diff_text) if git_diff_text.strip() else []
    if not explicit_targets and not diff_paths:
        diff_paths = get_git_changed_files(project_root)

    touched_uris: set[str] = set()
    touched_rel_paths: set[str] = {p for p in diff_paths if p in all_file_rels}
    probe_missing_diff = {p for p in diff_paths if p not in all_file_rels and Path(p).suffix.lower() in supported_exts}
    probe_missing_explicit: list[tuple[str, str]] = []
    unmatched_targets: list[str] = []

    for item in explicit_targets:
        if "://" in item and item in node_by_uri:
            touched_uris.add(item)
            if rp := str(node_by_uri[item].get("rel_path") or ""):
                touched_rel_paths.add(rp)
            continue
        norm_p = to_project_rel_path(item, project_root)
        if not norm_p:
            unmatched_targets.append(item)
            continue
        matched_files = {fp for fp in all_file_rels if matches_focus_paths(fp, {norm_p})}
        if matched_files:
            touched_rel_paths.update(matched_files)
        elif Path(norm_p).suffix.lower() in supported_exts:
            probe_missing_explicit.append((item, norm_p))
        else:
            unmatched_targets.append(item)

    probe_all = touched_rel_paths | probe_missing_diff | {np for _, np in probe_missing_explicit}
    head_snap = analyze_head_snapshot_and_diff(project_root, probe_all, nodes)
    for p in probe_missing_diff:
        if head_snap.head_blobs.get(p) is not None:
            touched_rel_paths.add(p)
    for orig_item, np in probe_missing_explicit:
        if head_snap.head_blobs.get(np) is not None:
            touched_rel_paths.add(np)
        else:
            unmatched_targets.append(orig_item)

    for n in nodes:
        if str(n.get("rel_path") or "") in touched_rel_paths and n.get("node_type") in ("File", "Function", "Class", "DataContract", "Test"):
            touched_uris.add(str(n["uri"]))

    inbound_by_dst: dict[str, list[dict[str, Any]]] = {}
    for e in edges:
        if e.get("edge_type") != "CONTAINS" and e.get("source_module") != "c4_rollup":
            inbound_by_dst.setdefault(str(e["dst_uri"]), []).append(e)

    direct_dependents: dict[str, dict[str, Any]] = {}
    indirect_dependents: dict[str, dict[str, Any]] = {}
    cross_language_impacts: list[dict[str, Any]] = []
    seen_cross_pairs: set[tuple[str, str]] = set()
    related_tests: dict[str, dict[str, Any]] = {}

    # 1. Входящие зависимости с гейтингом `confidence_tier` (без межъязыкового эвристического `CALLS`)
    for t_uri in sorted(touched_uris):
        t_scheme = t_uri.split("://", 1)[0]
        for dep, best_etypes in _traverse_inbound_with_tiers(t_uri, inbound_by_dst, node_by_uri, max_depth=3):
            d_uri = str(dep["uri"])
            if d_uri in touched_uris or d_uri.startswith(_SKIP_DEP_PREFIXES):
                continue
            d_tier = str(dep["confidence_tier"])
            if dep.get("node_type") == "Test" or "/tests/" in f"/{dep.get('rel_path', '')}/":
                related_tests[d_uri] = dep
            depth = int(dep["min_depth"])
            if depth == 1:
                prev = direct_dependents.get(d_uri)
                if prev is None or _TIER_RANK.get(d_tier, 0) > _TIER_RANK.get(str(prev.get("confidence_tier", "")), 0):
                    direct_dependents[d_uri] = dep
            else:
                indirect_dependents.setdefault(d_uri, dep)

            d_scheme = d_uri.split("://", 1)[0]
            if (
                d_scheme in _CROSS_LANG_SCHEMES and t_scheme in _CROSS_LANG_SCHEMES and d_scheme != t_scheme
                and d_tier in HIGH_CONFIDENCE_TIERS and bool(best_etypes & {"BRIDGES_TO", "USES_CONTRACT"})
                and (t_uri, d_uri) not in seen_cross_pairs
            ):
                seen_cross_pairs.add((t_uri, d_uri))
                cross_language_impacts.append({
                    "changed_uri": t_uri, "impacted_uri": d_uri,
                    "direction": "inbound_caller" if depth == 1 else f"transitive_depth_{depth}",
                    "via": dep.get("edge_types"), "confidence_tier": d_tier,
                })

    # 2. Исходящие мосты и двусторонние контракты (только high-confidence, без `unresolved_dynamic`)
    for e in edges:
        e_tier = str(e.get("confidence_tier") or "verified")
        if e.get("source_module") == "c4_rollup" or e.get("edge_type") not in ("BRIDGES_TO", "USES_CONTRACT") or e_tier not in HIGH_CONFIDENCE_TIERS:
            continue
        s_uri, d_uri = str(e["src_uri"]), str(e["dst_uri"])
        if s_uri in touched_uris and d_uri not in touched_uris and not d_uri.startswith(_SKIP_DEP_PREFIXES):
            if (s_uri, d_uri) not in seen_cross_pairs:
                seen_cross_pairs.add((s_uri, d_uri))
                cross_language_impacts.append({
                    "changed_uri": s_uri, "impacted_uri": d_uri, "direction": "outbound_contract_partner",
                    "via": f"{e['edge_type']}:{e.get('evidence', '')}", "confidence_tier": e_tier,
                })
                if p_nd := node_by_uri.get(d_uri):
                    direct_dependents.setdefault(d_uri, _make_dep_entry(d_uri, p_nd, str(e["edge_type"]), e_tier, float(e.get("confidence", 1.0))))

    # 3. Предполётная сверка контрактов, оборванных мостов и оборванных вызывающих против Git HEAD
    preflight = run_contract_preflight(
        project_id=project_id, project_root=project_root, query_service=query_service,
        nodes=nodes, edges=edges, head_snapshot=head_snap, touched_rel_paths=touched_rel_paths,
    )
    preflight["capsule_recall"] = query_service.record_capsule_edits_and_score(project_id, sorted(touched_rel_paths))

    for br in preflight["broken_bridges_vs_head"]:
        src_u, dst_u = str(br["src_uri"]), str(br["dst_uri"])
        ch_u, imp_u = (dst_u, src_u) if br.get("dst_rel_path") in touched_rel_paths else (src_u, dst_u)
        if (ch_u, imp_u) not in seen_cross_pairs:
            seen_cross_pairs.add((ch_u, imp_u))
            cross_language_impacts.append({
                "changed_uri": ch_u, "impacted_uri": imp_u, "direction": "broken_bridge_vs_head",
                "via": f"BROKEN_{br['protocol']}:{br['endpoint']}", "confidence_tier": "exact",
            })
        if (p_nd := node_by_uri.get(imp_u)) and imp_u not in touched_uris:
            direct_dependents.setdefault(imp_u, _make_dep_entry(imp_u, p_nd, "BROKEN_BRIDGE_VS_HEAD", "exact", 1.0))

    for bc in preflight["broken_callers_vs_head"]:
        c_u = str(bc["caller_uri"])
        if (c_nd := node_by_uri.get(c_u)) and c_u not in touched_uris:
            direct_dependents.setdefault(c_u, _make_dep_entry(c_u, c_nd, str(bc["kind"]).upper(), "verified", 0.95))

    # 4. Проекция на уровень C3 (Бизнес-модули) и проверка красного контура безопасности
    file_to_c3 = {
        str(e["dst_uri"]): str(e["src_uri"])
        for e in edges if e.get("edge_type") == "CONTAINS" and str(e["src_uri"]).startswith("c3://")
    }
    modified_c3_uris, impacted_c3_uris, red_zone_nodes = set(), set(), []
    for u in touched_uris:
        if (c3 := file_to_c3.get(u.split("#", 1)[0])):
            modified_c3_uris.add(c3)
        if (nd := node_by_uri.get(u)) and nd.get("risk_level") == "critical":
            red_zone_nodes.append(nd.get("rel_path") or u)
    for dep_uri in set(direct_dependents).union(indirect_dependents):
        if (c3 := file_to_c3.get(dep_uri.split("#", 1)[0])) and c3 not in modified_c3_uris:
            impacted_c3_uris.add(c3)
        if (nd := node_by_uri.get(dep_uri)) and nd.get("risk_level") == "critical":
            red_zone_nodes.append(nd.get("rel_path") or dep_uri)

    signature_changes, body_only_changes = head_snap.signature_changes, head_snap.body_only_changes
    rules = query_service.get_guardrail_rules(project_id)
    violations = evaluate_project_guardrails(
        project_root=project_root, nodes=nodes, edges=edges, configured_rules=rules,
        only_rel_paths=touched_rel_paths if touched_rel_paths else (set() if explicit_targets else None),
    )

    sorted_direct = sorted(
        direct_dependents.values(),
        key=lambda d: (-_TIER_RANK.get(str(d.get("confidence_tier", "")), 0), int(d.get("min_depth", 1)), str(d.get("uri", ""))),
    )
    red_zone_unique = sorted(set(red_zone_nodes))
    preflight_note = "" if preflight["passed"] else " Preflight контрактов: ⚠️ WARNING."
    summary_human_ru = (
        f"Изменено файлов: {len(touched_rel_paths)} (бизнес-модулей: {len(modified_c3_uris)}, "
        f"в радиусе зацепления: {len(impacted_c3_uris)}). "
        f"Контрактных правок сигнатур: {len(signature_changes)}, внутренних правок тел: {len(body_only_changes)}. "
        f"Межъязыковых связей Frontend↔Backend: {len(cross_language_impacts)}. "
        f"Контур критического риска (🔴): {'ЗАТРОНУТ (' + ', '.join(red_zone_unique[:3]) + ')' if red_zone_unique else 'НЕ ЗАТРОНУТ (Безопасно)'}. "
        f"Нарушений правил Guardrails: {len(violations)}.{preflight_note}"
    )

    return {
        "touched_files": sorted(touched_rel_paths),
        "unmatched_targets": unmatched_targets,
        "modified_c3_uris": sorted(modified_c3_uris),
        "impacted_c3_uris": sorted(impacted_c3_uris),
        "signature_changes": signature_changes[:40],
        "body_only_changes": body_only_changes[:40],
        "direct_dependents": sorted_direct[:40],
        "indirect_dependents": list(indirect_dependents.values())[:40],
        "cross_language_impacts": cross_language_impacts,
        "related_tests": list(related_tests.values())[:25],
        "red_zone_touched": bool(red_zone_unique),
        "red_zone_items": red_zone_unique,
        "guardrail_violations": [dataclasses.asdict(v) for v in violations],
        "bridge_coverage": preflight["bridge_coverage"],
        "preflight": preflight,
        "summary_human_ru": summary_human_ru,
    }
