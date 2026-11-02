"""
Анализатор влияния изменений (Impact Engine) и радар «Визуального рентгена правок ИИ».

Почему этот модуль проверяет межъязыковые мосты в обе стороны и учитывает `signature_hash`:
1. Если агент правит серверный роут Python — нужно найти клиентские вызовы в TypeScript (`inbound`).
   Но если агент правит клиентский `api.ts` или `interface` — нужно так же показать парный роут
   или схему `Pydantic` на стороне Python (`outbound_contract_partner`).
2. Разделение `signature_changes` и `body_only_changes` сразу показывает, сломан ли внешний контракт.
"""

from __future__ import annotations

import dataclasses
import subprocess
from pathlib import Path
from typing import Any

from backend.analyzers.guardrail_engine.evaluator import (
    evaluate_project_guardrails,
    matches_focus_paths,
)
from backend.analyzers.impact_engine.diff_classifier import classify_symbol_changes_vs_git_head
from backend.core.models import normalize_rel_path, to_project_rel_path
from backend.storage.queries import GraphQueryService


def get_git_changed_files(project_root: Path) -> list[str]:
    """
    Определяет список изменённых файлов в репозитории Git:
    сначала проверяет незакоммиченные правки (`git status --porcelain`),
    а если рабочее дерево чистое — берёт последний коммит (`git diff-tree -r HEAD`).
    """
    try:
        proc = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=str(project_root),
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if proc.returncode == 0 and proc.stdout.strip():
            changed: list[str] = []
            for line in proc.stdout.splitlines():
                if len(line) > 3:
                    raw_p = line[3:].strip().strip('"')
                    if " -> " in raw_p:
                        raw_p = raw_p.split(" -> ", 1)[1].strip()
                    changed.append(normalize_rel_path(raw_p))
            return sorted(set(changed))

        last_commit = subprocess.run(
            ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD"],
            cwd=str(project_root),
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if last_commit.returncode == 0 and last_commit.stdout.strip():
            return sorted({normalize_rel_path(ln.strip()) for ln in last_commit.stdout.splitlines() if ln.strip()})
    except Exception:
        pass
    return []


def parse_changed_files_from_unified_diff(diff_text: str) -> list[str]:
    """Извлекает относительные пути изменённых файлов из текста `git diff`."""
    paths: set[str] = set()
    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            paths.add(normalize_rel_path(line[6:].strip()))
    return sorted(paths)


def analyze_change_impact(
    project_id: str,
    project_root: Path,
    query_service: GraphQueryService,
    target_uris_or_paths: list[str] | None = None,
    git_diff_text: str = "",
) -> dict[str, Any]:
    """
    Рассчитывает полный отчёт о влиянии изменений:
    - прямые и косвенные потребители (включая двусторонние межъязыковые мосты и контракты),
    - разделение контрактных (`signature_changes`) и внутренних (`body_only_changes`) правок,
    - затронутые бизнес-модули C3, красный контур безопасности и нарушения `GuardrailEngine`.
    """
    nodes, edges = query_service.get_all_graph_raw(project_id)
    node_by_uri = {str(n["uri"]): n for n in nodes}
    all_file_rels = {str(n["rel_path"]) for n in nodes if n.get("node_type") == "File" and n.get("rel_path")}

    explicit_targets = [t.strip() for t in (target_uris_or_paths or []) if t and t.strip()]
    diff_paths = parse_changed_files_from_unified_diff(git_diff_text) if git_diff_text.strip() else []
    if not explicit_targets and not diff_paths:
        diff_paths = get_git_changed_files(project_root)

    touched_uris: set[str] = set()
    touched_rel_paths: set[str] = {p for p in diff_paths if p in all_file_rels}
    unmatched_targets: list[str] = []

    for item in explicit_targets:
        if "://" in item and item in node_by_uri:
            touched_uris.add(item)
            rp = str(node_by_uri[item].get("rel_path") or "")
            if rp:
                touched_rel_paths.add(rp)
            continue

        norm_p = to_project_rel_path(item, project_root)
        if not norm_p:
            unmatched_targets.append(item)
            continue

        matched_files = {fp for fp in all_file_rels if matches_focus_paths(fp, {norm_p})}
        if matched_files:
            touched_rel_paths.update(matched_files)
        else:
            unmatched_targets.append(item)

    for n in nodes:
        rp = str(n.get("rel_path") or "")
        if rp in touched_rel_paths and n.get("node_type") in ("File", "Function", "Class", "DataContract", "Test"):
            touched_uris.add(str(n["uri"]))

    direct_dependents: dict[str, dict[str, Any]] = {}
    indirect_dependents: dict[str, dict[str, Any]] = {}
    cross_language_impacts: list[dict[str, Any]] = []
    seen_cross_pairs: set[tuple[str, str]] = set()
    related_tests: dict[str, dict[str, Any]] = {}

    # 1. Обход входящих зависимостей (кто вызывает / импортирует затронутые узлы, глубина до 3)
    for t_uri in sorted(touched_uris):
        inbound = query_service.traverse_neighbors_safe(project_id, t_uri, direction="inbound", max_depth=3)
        t_scheme = t_uri.split("://", 1)[0]
        for dep in inbound:
            d_uri = str(dep["uri"])
            if d_uri in touched_uris or d_uri.startswith(("c1://", "c2://", "c3://")):
                continue
            if dep.get("node_type") == "Test" or "/tests/" in f"/{dep.get('rel_path', '')}/":
                related_tests[d_uri] = dep
            depth = int(dep["min_depth"])
            if depth == 1:
                direct_dependents[d_uri] = dep
            else:
                indirect_dependents.setdefault(d_uri, dep)

            d_scheme = d_uri.split("://", 1)[0]
            if d_scheme in ("py", "ts", "js") and t_scheme in ("py", "ts", "js") and d_scheme != t_scheme:
                pair = (t_uri, d_uri)
                if pair not in seen_cross_pairs:
                    seen_cross_pairs.add(pair)
                    cross_language_impacts.append(
                        {
                            "changed_uri": t_uri,
                            "impacted_uri": d_uri,
                            "direction": "inbound_caller" if depth == 1 else f"transitive_depth_{depth}",
                            "via": dep.get("edge_types"),
                        }
                    )

    # 2. Проверка исходящих мостов и двусторонних контрактов (когда агент правит клиентский TS/JS или интерфейс)
    for e in edges:
        if e.get("source_module") == "c4_rollup" or e.get("edge_type") not in ("BRIDGES_TO", "USES_CONTRACT"):
            continue
        s_uri, d_uri = str(e["src_uri"]), str(e["dst_uri"])
        if s_uri in touched_uris and d_uri not in touched_uris and not d_uri.startswith(("c1://", "c2://", "c3://")):
            pair = (s_uri, d_uri)
            if pair not in seen_cross_pairs:
                seen_cross_pairs.add(pair)
                cross_language_impacts.append(
                    {
                        "changed_uri": s_uri,
                        "impacted_uri": d_uri,
                        "direction": "outbound_contract_partner",
                        "via": f"{e['edge_type']}:{e.get('evidence', '')}",
                    }
                )
                partner_nd = node_by_uri.get(d_uri)
                if partner_nd:
                    direct_dependents.setdefault(
                        d_uri,
                        {
                            "uri": d_uri,
                            "min_depth": 1,
                            "max_confidence": e.get("confidence", 1.0),
                            "edge_types": e["edge_type"],
                            "name": partner_nd.get("name"),
                            "node_type": partner_nd.get("node_type"),
                            "rel_path": partner_nd.get("rel_path"),
                            "c4_level": partner_nd.get("c4_level"),
                            "risk_level": partner_nd.get("risk_level"),
                        },
                    )

    # 3. Проекция на уровень C3 (Бизнес-модули) и проверка красного контура безопасности
    file_to_c3 = {
        str(e["dst_uri"]): str(e["src_uri"])
        for e in edges
        if e.get("edge_type") == "CONTAINS" and str(e["src_uri"]).startswith("c3://")
    }
    modified_c3_uris: set[str] = set()
    impacted_c3_uris: set[str] = set()
    red_zone_nodes: list[str] = []

    for u in touched_uris:
        base_file = u.split("#", 1)[0]
        if base_file in file_to_c3:
            modified_c3_uris.add(file_to_c3[base_file])
        nd = node_by_uri.get(u)
        if nd and nd.get("risk_level") == "critical":
            red_zone_nodes.append(nd.get("rel_path") or u)

    for dep_uri in set(direct_dependents).union(indirect_dependents):
        base_file = dep_uri.split("#", 1)[0]
        c3 = file_to_c3.get(base_file)
        if c3 and c3 not in modified_c3_uris:
            impacted_c3_uris.add(c3)
        nd = node_by_uri.get(dep_uri)
        if nd and nd.get("risk_level") == "critical":
            red_zone_nodes.append(nd.get("rel_path") or dep_uri)

    signature_changes, body_only_changes = classify_symbol_changes_vs_git_head(
        project_root=project_root,
        touched_rel_paths=touched_rel_paths,
        current_nodes=nodes,
    )

    rules = query_service.get_guardrail_rules(project_id)
    violations = evaluate_project_guardrails(
        project_root=project_root,
        nodes=nodes,
        edges=edges,
        configured_rules=rules,
        only_rel_paths=touched_rel_paths if touched_rel_paths else (set() if explicit_targets else None),
    )

    red_zone_unique = sorted(set(red_zone_nodes))
    summary_human_ru = (
        f"Изменено файлов: {len(touched_rel_paths)} (бизнес-модулей: {len(modified_c3_uris)}, "
        f"в радиусе зацепления: {len(impacted_c3_uris)}). "
        f"Контрактных правок сигнатур: {len(signature_changes)}, внутренних правок тел: {len(body_only_changes)}. "
        f"Межъязыковых связей Frontend↔Backend: {len(cross_language_impacts)}. "
        f"Контур критического риска (🔴): {'ЗАТРОНУТ (' + ', '.join(red_zone_unique[:3]) + ')' if red_zone_unique else 'НЕ ЗАТРОНУТ (Безопасно)'}. "
        f"Нарушений правил Guardrails: {len(violations)}."
    )

    return {
        "touched_files": sorted(touched_rel_paths),
        "unmatched_targets": unmatched_targets,
        "modified_c3_uris": sorted(modified_c3_uris),
        "impacted_c3_uris": sorted(impacted_c3_uris),
        "signature_changes": signature_changes[:40],
        "body_only_changes": body_only_changes[:40],
        "direct_dependents": list(direct_dependents.values())[:40],
        "indirect_dependents": list(indirect_dependents.values())[:40],
        "cross_language_impacts": cross_language_impacts,
        "related_tests": list(related_tests.values())[:25],
        "red_zone_touched": bool(red_zone_unique),
        "red_zone_items": red_zone_unique,
        "guardrail_violations": [dataclasses.asdict(v) for v in violations],
        "summary_human_ru": summary_human_ru,
    }
