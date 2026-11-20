"""
Контур предполётной проверки контрактов (`Contract Preflight`) после правок кода.

Сравнивает текущий индекс и `file_cache` со снимком `HEAD` (за 1 вызов `git cat-file --batch`),
обнаруживая: `unupdated_contract_partners`, `broken_bridges_vs_head` и `broken_callers_vs_head`.
"""

from __future__ import annotations

import json
from contextlib import closing
from pathlib import Path
from typing import Any

from backend.analyzers.bridge_linker.coverage import (
    collect_ipc_targets, diff_broken_bridges_vs_head, empty_bridge_coverage, summarize_bridge_call_sites,
)
from backend.analyzers.bridge_linker.linker import (
    build_server_http_endpoints, extract_http_wrapper_map, load_project_lgraph_config,
)
from backend.analyzers.code_graph.call_and_contract_helpers import uri_lang_family
from backend.analyzers.code_graph.disk_state import JS_TS_EXTENSIONS, PY_EXTENSIONS
from backend.analyzers.code_graph.import_resolver import resolve_js_ts_imports, resolve_python_imports
from backend.analyzers.impact_engine.diff_classifier import (
    GitHeadSnapshot, analyze_head_snapshot_and_diff, inspect_git_working_tree,
)
from backend.core.models import GraphEdgeRecord, build_canonical_uri
from backend.storage.queries import GraphQueryService
from backend.storage.schema import open_sqlite_connection

HIGH_CONFIDENCE_TIERS: frozenset[str] = frozenset({"verified", "exact", "pattern_matched"})
_MAX_PREFLIGHT_ITEMS: int = 40
_SKIP_PARTNER_PREFIXES: tuple[str, ...] = ("c1://", "c2://", "c3://", "dynamic://")


def _load_file_cache_payloads(db_path: Path, project_id: str) -> dict[str, dict[str, Any]]:
    payloads: dict[str, dict[str, Any]] = {}
    with closing(open_sqlite_connection(db_path)) as conn:
        rows = conn.execute(
            "SELECT rel_path, cached_payload_json FROM file_cache WHERE project_id = ?", (project_id,)
        ).fetchall()
    for r in rows:
        try:
            data = json.loads(r["cached_payload_json"] or "{}")
            if isinstance(data, dict):
                payloads[str(r["rel_path"])] = data
        except Exception:
            continue
    return payloads


def _rel_from_uri(uri: str) -> str:
    return uri.split("://", 1)[1].split("#", 1)[0] if "://" in uri and uri.split("://", 1)[0] in ("py", "ts", "js") else ""


def _scheme_for_rel(rel_path: str) -> str:
    low = rel_path.lower()
    return "py" if low.endswith(".py") else ("ts" if low.endswith((".ts", ".tsx")) else "js")


def _extract_bridge_coverage(nodes: list[dict[str, Any]]) -> dict[str, Any]:
    for n in nodes:
        if n.get("uri") == "c1://project/self":
            cov = (n.get("meta") or {}).get("bridge_coverage")
            return dict(cov) if isinstance(cov, dict) else empty_bridge_coverage()
    return empty_bridge_coverage()


def _find_unupdated_contract_partners(
    signature_changes: list[dict[str, Any]],
    touched_files: set[str],
    node_by_uri: dict[str, dict[str, Any]],
    edges: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    bridge_partners: dict[str, list[tuple[str, str, str, str]]] = {}
    type_ann_callers: dict[str, list[str]] = {}
    for e in edges:
        tier = str(e.get("confidence_tier") or "verified")
        if e.get("source_module") == "c4_rollup" or tier not in HIGH_CONFIDENCE_TIERS:
            continue
        etype, src, dst, ev = str(e.get("edge_type") or ""), str(e["src_uri"]), str(e["dst_uri"]), str(e.get("evidence") or "")
        if etype in ("BRIDGES_TO", "USES_CONTRACT"):
            if not (src.startswith(_SKIP_PARTNER_PREFIXES) or dst.startswith(_SKIP_PARTNER_PREFIXES)):
                bridge_partners.setdefault(src, []).append((dst, etype, ev, tier))
                bridge_partners.setdefault(dst, []).append((src, etype, ev, tier))
        elif etype == "CALLS" and ev.startswith("type_annotation "):
            type_ann_callers.setdefault(dst, []).append(src)

    partners: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for sc in signature_changes:
        ch_kind, ch_uri, ch_rel = str(sc.get("change_kind") or ""), str(sc.get("uri") or ""), str(sc.get("rel_path") or "")
        if ch_kind not in ("signature_modified", "removed") or not ch_uri:
            continue

        def _maybe_add(p_uri: str, via_txt: str, tier_val: str) -> None:
            p_rel = str((node_by_uri.get(p_uri) or {}).get("rel_path") or _rel_from_uri(p_uri))
            if not p_rel or p_rel in touched_files or (ch_uri, p_uri) in seen:
                return
            seen.add((ch_uri, p_uri))
            partners.append({
                "changed_uri": ch_uri, "changed_rel_path": ch_rel, "change_kind": ch_kind,
                "partner_uri": p_uri, "partner_rel_path": p_rel, "via": via_txt, "confidence_tier": tier_val,
            })

        for p_uri, etype, ev, tier in bridge_partners.get(ch_uri, []):
            _maybe_add(p_uri, f"{etype}:{ev}" if ev else etype, tier)

        # 2-шаговая цепочка `DataContract <-[CALLS:type_annotation]- route <-[BRIDGES_TO]- TS`
        holders, frontier = set(), {ch_uri}
        for _ in range(2):
            frontier = {c for u in frontier for c in type_ann_callers.get(u, []) if c != ch_uri and c not in holders}
            holders.update(frontier)
            if not frontier:
                break
        for holder_u in sorted(holders):
            for p_uri, etype, ev, tier in bridge_partners.get(holder_u, []):
                if etype == "BRIDGES_TO":
                    _maybe_add(p_uri, f"type_annotation -> {holder_u} -> {etype}:{ev}", tier)
    return partners[:_MAX_PREFLIGHT_ITEMS]


def _append_cached_bridge_data(
    rp: str, cp: dict[str, Any], py_rt: dict[str, list[dict[str, Any]]], py_inc: list[dict[str, str]], js_sites: list[dict[str, Any]]
) -> None:
    if cp.get("fastapi_routes"):
        py_rt[rp] = cp["fastapi_routes"]
    py_inc.extend(cp.get("router_includes", []))
    js_sites.extend(cp.get("js_call_sites", []))


def _detect_broken_bridges_vs_head(
    project_root: Path, head_snapshot: GitHeadSnapshot, cached_payloads: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    if not head_snapshot.has_head or not head_snapshot.head_blobs:
        return []
    try:
        wrapper_map = extract_http_wrapper_map(load_project_lgraph_config(project_root))
    except Exception:
        wrapper_map = {}

    curr_py_rt, curr_py_inc, curr_js = {}, [], []
    head_py_rt, head_py_inc, head_js = {}, [], []
    for rp in sorted(set(cached_payloads) | set(head_snapshot.head_blobs)):
        cp = cached_payloads.get(rp)
        if cp:
            _append_cached_bridge_data(rp, cp, curr_py_rt, curr_py_inc, curr_js)
        if rp in head_snapshot.head_blobs:
            if head_snapshot.head_blobs[rp] is None:
                continue
            if rp in head_snapshot.head_py_results:
                h_py = head_snapshot.head_py_results[rp]
                if h_py.fastapi_routes:
                    head_py_rt[rp] = h_py.fastapi_routes
                head_py_inc.extend(h_py.router_includes)
            elif rp in head_snapshot.head_js_results:
                head_js.extend(head_snapshot.head_js_results[rp].raw_call_sites)
        elif cp:
            _append_cached_bridge_data(rp, cp, head_py_rt, head_py_inc, head_js)

    curr_eps, (curr_ih, curr_il) = build_server_http_endpoints(curr_py_rt, curr_py_inc), collect_ipc_targets(curr_js)
    head_eps, (head_ih, head_il) = build_server_http_endpoints(head_py_rt, head_py_inc), collect_ipc_targets(head_js)
    curr_quads, curr_calls, curr_unmatched, _ = summarize_bridge_call_sites(
        curr_js, curr_eps, curr_ih, curr_il, wrapper_map
    )
    head_quads, _, head_unmatched, _ = summarize_bridge_call_sites(head_js, head_eps, head_ih, head_il, wrapper_map)
    return diff_broken_bridges_vs_head(
        head_quads, head_unmatched, curr_quads, curr_calls, curr_unmatched, _MAX_PREFLIGHT_ITEMS
    )


def _detect_broken_callers_vs_head(
    project_root: Path,
    head_snapshot: GitHeadSnapshot,
    cached_payloads: dict[str, dict[str, Any]],
    current_nodes: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not head_snapshot.has_head or not head_snapshot.head_blobs:
        return []

    curr_file_uri: dict[str, str] = {}
    curr_syms: dict[str, set[str]] = {}
    for nd in current_nodes:
        rp = str(nd.get("rel_path") or "")
        if not rp:
            continue
        if nd.get("node_type") == "File":
            curr_file_uri[rp] = str(nd["uri"])
        elif short := str(nd.get("name") or "").rsplit(".", 1)[-1]:
            curr_syms.setdefault(rp, set()).add(short)

    removed_rels = {rp for rp, b in head_snapshot.head_blobs.items() if b is not None and rp not in curr_file_uri}
    combined_uri = {**curr_file_uri, **{rp: build_canonical_uri(_scheme_for_rel(rp), rp) for rp in removed_rels}}

    pending_py, pending_js = [], []
    for rp, p in cached_payloads.items():
        if fu := curr_file_uri.get(rp):
            pending_py.extend((fu, m, nms) for m, nms in p.get("py_imports", []))
            pending_js.extend((fu, rp, spec) for spec in p.get("js_imports", []))

    probe_edges: list[GraphEdgeRecord] = []
    resolve_python_imports(pending_py, combined_uri, probe_edges)
    resolve_js_ts_imports(pending_js, combined_uri, probe_edges, project_root=project_root)

    broken: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    live_imports: dict[str, set[str]] = {}
    spec_targets: dict[tuple[str, str], set[str]] = {}

    def _add(kind: str, c_u: str, c_rel: str, m_u: str, m_rel: str, ev: str, sym: str = "") -> None:
        if (kind, c_u, m_u) in seen:
            return
        seen.add((kind, c_u, m_u))
        rec: dict[str, Any] = {
            "kind": kind, "caller_uri": c_u, "caller_rel_path": c_rel,
            "missing_target_uri": m_u, "missing_rel_path": m_rel, "evidence": ev,
        }
        if sym:
            rec["symbol_name"] = sym
        broken.append(rec)

    for edge in probe_edges:
        sr, dr = _rel_from_uri(edge.src_uri), _rel_from_uri(edge.dst_uri)
        if not sr or not dr:
            continue
        live_imports.setdefault(sr, set()).add(dr)
        if edge.evidence.startswith("import "):
            if raw_spec := edge.evidence[7:].strip().strip("'\""):
                spec_targets.setdefault((sr, raw_spec), set()).add(dr)
        if dr in removed_rels:
            _add("broken_import", edge.src_uri, sr, edge.dst_uri, dr, edge.evidence)

    rem_by_lang_short: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for sc in head_snapshot.signature_changes:
        if sc.get("change_kind") == "removed" and sc.get("uri"):
            if short := str(sc.get("name") or "").rsplit(".", 1)[-1]:
                rem_by_lang_short.setdefault((uri_lang_family(str(sc["uri"])), short), []).append(sc)
    if not rem_by_lang_short:
        return broken[:_MAX_PREFLIGHT_ITEMS]

    for c_rel, payload in sorted(cached_payloads.items()):
        if not (c_file_u := curr_file_uri.get(c_rel)):
            continue
        lang, imp_rels = uri_lang_family(c_file_u), live_imports.get(c_rel, set())
        scope_rels = {c_rel} | imp_rels
        live_imported = set(curr_syms.get(c_rel, set()))
        for r_imp in imp_rels:
            if r_imp in curr_file_uri:
                live_imported.update(curr_syms.get(r_imp, set()))
                live_imported.update((cached_payloads.get(r_imp) or {}).get("symbol_imports") or {})

        sym_imps = payload.get("symbol_imports") or {}
        for origin in sym_imps.values():
            if ":" not in origin:
                continue
            mod_spec, orig_sym = [x.strip() for x in origin.split(":", 1)]
            if not orig_sym or orig_sym == "default":
                continue
            tgts = spec_targets.get((c_rel, mod_spec), set())
            for rem in rem_by_lang_short.get((lang, orig_sym), []):
                r_rel = str(rem.get("rel_path") or "")
                r_exports = curr_syms.get(r_rel, set()) | set((cached_payloads.get(r_rel) or {}).get("symbol_imports") or {})
                if r_rel in tgts and orig_sym not in r_exports:
                    _add("broken_symbol_import", c_file_u, c_rel, str(rem["uri"]), r_rel, f"imports removed `{orig_sym}` from `{r_rel}`", str(rem["name"]))

        for caller_u, raw_callee in payload.get("calls", []):
            short = raw_callee.rsplit(".", 1)[-1]
            if "." not in raw_callee and ":" in sym_imps.get(raw_callee, ""):
                al = sym_imps[raw_callee].split(":", 1)[1].strip()
                if al and al != "default":
                    short = al
            if short in live_imported:
                continue
            for rem in rem_by_lang_short.get((lang, short), []):
                r_rel = str(rem.get("rel_path") or "")
                if r_rel in scope_rels:
                    _add("broken_call", caller_u, c_rel, str(rem["uri"]), r_rel, f"calls `{raw_callee}` removed from `{r_rel}`", str(rem["name"]))
    return broken[:_MAX_PREFLIGHT_ITEMS]


def run_contract_preflight(
    project_id: str, project_root: Path, query_service: GraphQueryService, target_rel_paths: set[str] | None = None,
    *, nodes: list[dict[str, Any]] | None = None, edges: list[dict[str, Any]] | None = None,
    head_snapshot: GitHeadSnapshot | None = None, touched_rel_paths: set[str] | None = None,
) -> dict[str, Any]:
    """Возвращает `{passed, bridge_coverage, unupdated_contract_partners, broken_bridges_vs_head, broken_callers_vs_head}`."""
    if nodes is None or edges is None:
        nodes, edges = query_service.get_all_graph_raw(project_id)
    node_by_uri, bridge_coverage = {str(n["uri"]): n for n in nodes}, _extract_bridge_coverage(nodes)

    if touched_rel_paths is not None:
        effective_touched = set(touched_rel_paths)
        partner_touched = effective_touched
    else:
        git_status = inspect_git_working_tree(project_root)
        git_changed = set(git_status.changed_paths)
        if target_rel_paths is not None:
            all_known = {str(n["rel_path"]) for n in nodes if n.get("node_type") == "File" and n.get("rel_path")} | git_changed
            prefs = [tp.rstrip("/") for tp in target_rel_paths if tp.rstrip("/")]
            effective_touched = set(target_rel_paths) | {
                fp for fp in all_known if any(fp == pr or fp.startswith(pr + "/") for pr in prefs)
            }
            for old_p, new_p in git_status.renamed_pairs:
                if old_p in effective_touched or new_p in effective_touched:
                    effective_touched.update((old_p, new_p))
            partner_touched = effective_touched | git_changed
        else:
            effective_touched = partner_touched = git_changed

    code_touched = {rp for rp in effective_touched if Path(rp).suffix.lower() in (PY_EXTENSIONS | JS_TS_EXTENSIONS)}
    snap = head_snapshot if head_snapshot is not None else analyze_head_snapshot_and_diff(project_root, code_touched, nodes)
    cached_payloads = _load_file_cache_payloads(query_service.db_path, project_id) if snap.has_head and snap.head_blobs else {}

    unupdated = _find_unupdated_contract_partners(snap.signature_changes, partner_touched, node_by_uri, edges)
    broken_bridges = _detect_broken_bridges_vs_head(project_root, snap, cached_payloads)
    broken_callers = _detect_broken_callers_vs_head(project_root, snap, cached_payloads, nodes)
    return {
        "passed": not (unupdated or broken_bridges or broken_callers), "bridge_coverage": bridge_coverage,
        "unupdated_contract_partners": unupdated, "broken_bridges_vs_head": broken_bridges, "broken_callers_vs_head": broken_callers,
    }


def format_preflight_markdown_block(preflight: dict[str, Any]) -> str:
    """Форматирует компактный блок `📋 CONTRACT PREFLIGHT: ...` (или `''`, если предупреждений нет)."""
    if not isinstance(preflight, dict):
        return ""
    unupdated = list(preflight.get("unupdated_contract_partners") or [])
    broken_bridges = list(preflight.get("broken_bridges_vs_head") or [])
    broken_callers = list(preflight.get("broken_callers_vs_head") or [])
    if bool(preflight.get("passed", True)) and not (unupdated or broken_bridges or broken_callers):
        return ""

    cov = preflight.get("bridge_coverage") or {}
    total_calls = int(cov.get("total_client_calls") or 0)
    cov_part = f" | bridge_coverage={int(round(float(cov.get('coverage_ratio', 1.0)) * 100))}% ({total_calls} calls)" if total_calls else ""
    lines = [
        f"📋 CONTRACT PREFLIGHT: WARNING ({len(unupdated)} unupdated partners, "
        f"{len(broken_bridges)} broken bridges, {len(broken_callers)} broken callers{cov_part})"
    ]
    for it in unupdated[:8]:
        lines.append(f"- [UNUPDATED PARTNER] `{it.get('changed_uri')}` ({it.get('change_kind')}) -> `{it.get('partner_uri')}` (`{it.get('partner_rel_path')}` не тронут; {it.get('via')})")
    for it in broken_bridges[:8]:
        lines.append(f"- [BROKEN BRIDGE vs HEAD] `{it.get('endpoint')}`: `{it.get('src_uri')}` -X-> `{it.get('dst_uri')}` ({it.get('reason')})")
    for it in broken_callers[:8]:
        lines.append(f"- [BROKEN CALLER vs HEAD] `{it.get('caller_uri')}` -> `{it.get('missing_target_uri')}` ({it.get('evidence')})")
    return "\n".join(lines)
