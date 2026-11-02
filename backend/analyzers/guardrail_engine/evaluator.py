"""
Движок машинно-проверяемых правил архитектуры (GuardrailEngine).

Почему правила реализованы через детерминированные предикаты и `scope`:
Текстовые памятки нейросеть может случайно пропустить при большом контексте.
Машинный предикат (запрет связи слоёв, лимит строк, запрет циклов или запрещённый шаблон)
проверяет граф математически и выдаёт объяснимый вердикт: что, где, почему нарушено и как исправить.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Any

from backend.core.config import DEFAULT_MAX_FILE_LINES, is_reparse_or_symlink
from backend.core.models import (
    GuardrailRuleSpec,
    GuardrailViolation,
    normalize_rel_path,
    redact_inline_secrets,
)


def default_builtin_guardrails() -> list[GuardrailRuleSpec]:
    """Базовые предохранители по умолчанию для проектов, где ещё не создан `lgraph.yaml`."""
    return [
        GuardrailRuleSpec(
            rule_id="GR-CORE-SIZE",
            title="Лимит анти-монолита размера файла (<= 350 строк)",
            severity="warning",
            scope="**",
            exclude_scope="**/tests/**",
            predicate_type="max_file_lines",
            predicate_params={"max_lines": DEFAULT_MAX_FILE_LINES},
            rationale_ru="Файлы свыше 350 строк превращаются в монолит и перегружают контекст нейросети при правках.",
            remediation_ru="Вынесите независимую подзадачу или дочерний UI-блок в отдельный профильный модуль.",
        ),
        GuardrailRuleSpec(
            rule_id="GR-CORE-CYCLES",
            title="Отсутствие циклических импортов между файлами",
            severity="warning",
            scope="**",
            predicate_type="no_cycles",
            predicate_params={},
            rationale_ru="Циклические импорты создают хрупкую сцепку модулей и ошибки инициализации.",
            remediation_ru="Вынесите общие типы или интерфейсы в отдельный базовый модуль.",
        ),
    ]


def path_matches_scope(rel_path: str, scope: str, exclude_scope: str = "") -> bool:
    """Проверяет попадание относительного пути файла в `glob`-область правила с учётом исключений."""
    norm = normalize_rel_path(rel_path)
    if not norm:
        return False

    def _match_one(p: str, pat: str) -> bool:
        clean_pat = pat.strip().replace("\\", "/").strip("/")
        if not clean_pat or clean_pat == "**":
            return True
        if clean_pat.endswith("/**"):
            prefix = clean_pat[:-3]
            if p == prefix or p.startswith(prefix + "/"):
                return True
        return fnmatch.fnmatch(p, clean_pat)

    if exclude_scope:
        for ex in [s.strip() for s in exclude_scope.split(",") if s.strip()]:
            if _match_one(norm, ex):
                return False

    return any(_match_one(norm, sc) for sc in [s.strip() for s in scope.split(",") if s.strip()])


def filter_rules_for_paths(rules: list[GuardrailRuleSpec], rel_paths: list[str]) -> list[GuardrailRuleSpec]:
    """Возвращает только те правила, чья область действия покрывает запрошенные файлы."""
    effective_rules = rules if rules else default_builtin_guardrails()
    if not rel_paths:
        return effective_rules
    matched: list[GuardrailRuleSpec] = []
    for rule in effective_rules:
        if any(path_matches_scope(rp, rule.scope, rule.exclude_scope) for rp in rel_paths):
            matched.append(rule)
    return matched


def matches_focus_paths(rel_path: str, focus_paths: set[str] | None) -> bool:
    """Проверяет попадание файла в целевой фильтр (поддерживает точный путь, папку и glob-маску)."""
    if focus_paths is None:
        return True
    norm = normalize_rel_path(rel_path)
    return any(
        norm == fp or norm.startswith(fp + "/") or path_matches_scope(norm, fp)
        for fp in focus_paths
        if fp
    )


def evaluate_project_guardrails(
    project_root: Path,
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    configured_rules: list[GuardrailRuleSpec],
    only_rel_paths: set[str] | None = None,
) -> list[GuardrailViolation]:
    """
    Проверяет все активные правила на графе и исходных файлах проекта.
    Если передан `only_rel_paths` (например, из `git diff`), фильтрует отчёт по задетым файлам.
    """
    rules = configured_rules if configured_rules else default_builtin_guardrails()
    node_by_uri = {str(n["uri"]): n for n in nodes}
    file_nodes = [n for n in nodes if n.get("node_type") == "File" and n.get("rel_path")]
    violations: list[GuardrailViolation] = []

    for rule in rules:
        ptype = rule.predicate_type

        if ptype == "forbidden_dependency":
            target_scope = str(rule.predicate_params.get("target_scope", ""))
            if not target_scope:
                continue
            seen_pairs: set[tuple[str, str]] = set()
            for edge in edges:
                if edge.get("source_module") == "c4_rollup" or edge.get("edge_type") not in ("IMPORTS", "CALLS", "BRIDGES_TO"):
                    continue
                src_n = node_by_uri.get(str(edge["src_uri"]))
                dst_n = node_by_uri.get(str(edge["dst_uri"]))
                if not src_n or not dst_n:
                    continue
                src_path = str(src_n.get("rel_path", ""))
                dst_path = str(dst_n.get("rel_path", ""))
                if not src_path or not dst_path or (src_path, dst_path) in seen_pairs:
                    continue
                if not (matches_focus_paths(src_path, only_rel_paths) or matches_focus_paths(dst_path, only_rel_paths)):
                    continue
                if path_matches_scope(src_path, rule.scope, rule.exclude_scope) and path_matches_scope(dst_path, target_scope):
                    seen_pairs.add((src_path, dst_path))
                    violations.append(
                        GuardrailViolation(
                            rule_id=rule.rule_id,
                            title=rule.title,
                            severity=rule.severity,
                            matched_scope=rule.scope,
                            target_uri_or_path=src_path,
                            line_number=int(src_n.get("start_line") or 1),
                            evidence=f"{src_path} -> [{edge['edge_type']}] -> {dst_path}",
                            why_violated_ru=(
                                f"Модуль `{src_path}` из области `{rule.scope}` напрямую обращается к `{dst_path}` "
                                f"из закрытой области `{target_scope}`. {rule.rationale_ru}"
                            ),
                            how_to_fix_ru=rule.remediation_ru,
                        )
                    )

        elif ptype == "must_route_via":
            target_scope = str(rule.predicate_params.get("target_scope", ""))
            via_scope = str(rule.predicate_params.get("via_scope", ""))
            if not target_scope or not via_scope:
                continue
            seen_bypass: set[tuple[str, str]] = set()
            for edge in edges:
                if edge.get("source_module") == "c4_rollup" or edge.get("edge_type") not in ("IMPORTS", "CALLS", "BRIDGES_TO"):
                    continue
                src_n = node_by_uri.get(str(edge["src_uri"]))
                dst_n = node_by_uri.get(str(edge["dst_uri"]))
                if not src_n or not dst_n:
                    continue
                src_path = str(src_n.get("rel_path", ""))
                dst_path = str(dst_n.get("rel_path", ""))
                if not src_path or not dst_path or (src_path, dst_path) in seen_bypass:
                    continue
                if not (matches_focus_paths(src_path, only_rel_paths) or matches_focus_paths(dst_path, only_rel_paths)):
                    continue
                if (
                    path_matches_scope(src_path, rule.scope, rule.exclude_scope)
                    and not path_matches_scope(src_path, via_scope)
                    and path_matches_scope(dst_path, target_scope)
                    and not path_matches_scope(dst_path, via_scope)
                ):
                    seen_bypass.add((src_path, dst_path))
                    violations.append(
                        GuardrailViolation(
                            rule_id=rule.rule_id,
                            title=rule.title,
                            severity=rule.severity,
                            matched_scope=rule.scope,
                            target_uri_or_path=src_path,
                            line_number=int(src_n.get("start_line") or 1),
                            evidence=f"Обход шлюза `{via_scope}`: {src_path} -> [{edge['edge_type']}] -> {dst_path}",
                            why_violated_ru=(
                                f"Модуль `{src_path}` обращается напрямую к `{dst_path}` (`{target_scope}`), "
                                f"минуя обязательный шлюз `{via_scope}`. {rule.rationale_ru}"
                            ),
                            how_to_fix_ru=rule.remediation_ru,
                        )
                    )

        elif ptype == "max_file_lines":
            max_lines = int(rule.predicate_params.get("max_lines", DEFAULT_MAX_FILE_LINES))
            for fn in file_nodes:
                rp = str(fn["rel_path"])
                if not matches_focus_paths(rp, only_rel_paths):
                    continue
                if not path_matches_scope(rp, rule.scope, rule.exclude_scope):
                    continue
                line_cnt = int((fn.get("meta") or {}).get("line_count") or fn.get("end_line") or 0)
                if line_cnt > max_lines:
                    violations.append(
                        GuardrailViolation(
                            rule_id=rule.rule_id,
                            title=rule.title,
                            severity=rule.severity,
                            matched_scope=rule.scope,
                            target_uri_or_path=rp,
                            line_number=line_cnt,
                            evidence=f"line_count={line_cnt} > max_lines={max_lines}",
                            why_violated_ru=(
                                f"Файл `{rp}` содержит {line_cnt} строк при максимально допустимом пороге {max_lines} "
                                f"для области `{rule.scope}`. {rule.rationale_ru}"
                            ),
                            how_to_fix_ru=rule.remediation_ru,
                        )
                    )

        elif ptype == "ast_forbidden_regex":
            raw_pat = str(rule.predicate_params.get("pattern", ""))
            if not raw_pat:
                continue
            compiled = re.compile(raw_pat)
            for fn in file_nodes:
                rp = str(fn["rel_path"])
                if not matches_focus_paths(rp, only_rel_paths):
                    continue
                if not path_matches_scope(rp, rule.scope, rule.exclude_scope):
                    continue
                disk_file = project_root / rp
                if not disk_file.is_file() or is_reparse_or_symlink(disk_file):
                    continue
                try:
                    lines = disk_file.read_text(encoding="utf-8", errors="replace").splitlines()
                except OSError:
                    continue
                for idx, line_txt in enumerate(lines, start=1):
                    stripped_ln = line_txt.strip()
                    # Пропускаем однострочные и блочные комментарии, чтобы пояснения в коде не давали ложных тревог
                    if stripped_ln.startswith(("#", "//", "/*", "*", "*/", "<!--")):
                        continue
                    if compiled.search(line_txt):
                        safe_snippet, _ = redact_inline_secrets(line_txt.strip()[:120])
                        violations.append(
                            GuardrailViolation(
                                rule_id=rule.rule_id,
                                title=rule.title,
                                severity=rule.severity,
                                matched_scope=rule.scope,
                                target_uri_or_path=rp,
                                line_number=idx,
                                evidence=f"Строка {idx}: `{safe_snippet}`",
                                why_violated_ru=(
                                    f"В файле `{rp}` на строке {idx} обнаружена запрещённая конструкция по шаблону "
                                    f"`{raw_pat}` в области `{rule.scope}`. {rule.rationale_ru}"
                                ),
                                how_to_fix_ru=rule.remediation_ru,
                            )
                        )
                        break

        elif ptype == "no_cycles":
            cycles = _find_import_cycles_in_scope(file_nodes, edges, rule.scope, rule.exclude_scope)
            for cyc_chain in cycles:
                if only_rel_paths is not None and not any(matches_focus_paths(p, only_rel_paths) for p in cyc_chain):
                    continue
                chain_str = " -> ".join(cyc_chain + [cyc_chain[0]])
                violations.append(
                    GuardrailViolation(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        severity=rule.severity,
                        matched_scope=rule.scope,
                        target_uri_or_path=cyc_chain[0],
                        line_number=1,
                        evidence=f"Цикл импортов: {chain_str}",
                        why_violated_ru=(
                            f"Обнаружена замкнутая петля зависимостей ({chain_str}) в области `{rule.scope}`. "
                            f"{rule.rationale_ru}"
                        ),
                        how_to_fix_ru=rule.remediation_ru,
                    )
                )

    return violations


def _find_import_cycles_in_scope(
    file_nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    scope: str,
    exclude_scope: str,
) -> list[list[str]]:
    """Находит элементарные циклы файловых `IMPORTS` внутри заданной области действия."""
    scoped_uri_to_path = {
        str(fn["uri"]): str(fn["rel_path"])
        for fn in file_nodes
        if path_matches_scope(str(fn["rel_path"]), scope, exclude_scope)
    }
    adj: dict[str, set[str]] = {u: set() for u in scoped_uri_to_path}
    for e in edges:
        if e.get("edge_type") == "IMPORTS":
            s, d = str(e["src_uri"]), str(e["dst_uri"])
            if s in adj and d in adj and s != d:
                adj[s].add(d)

    visited_global: set[str] = set()
    seen_cycle_keys: set[tuple[str, ...]] = set()
    found_cycles: list[list[str]] = []

    for start_u in sorted(adj):
        if start_u in visited_global:
            continue
        stack_path: list[str] = []
        on_stack: set[str] = set()

        def _dfs(u: str) -> None:
            visited_global.add(u)
            stack_path.append(u)
            on_stack.add(u)
            for nxt in sorted(adj.get(u, ())):
                if nxt not in visited_global:
                    _dfs(nxt)
                elif nxt in on_stack:
                    idx = stack_path.index(nxt)
                    raw_uris = stack_path[idx:]
                    rel_chain = [scoped_uri_to_path[x] for x in raw_uris]
                    # Канонизируем ключ цикла, чтобы A->B->A и B->A->B не дублировались
                    min_pos = rel_chain.index(min(rel_chain))
                    canon_key = tuple(rel_chain[min_pos:] + rel_chain[:min_pos])
                    if canon_key not in seen_cycle_keys:
                        seen_cycle_keys.add(canon_key)
                        found_cycles.append(list(canon_key))
            stack_path.pop()
            on_stack.remove(u)

        _dfs(start_u)

    return found_cycles
