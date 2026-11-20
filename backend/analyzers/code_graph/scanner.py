"""
Главный координатор сканирования проекта (CodeGraph Scanner) с двухуровневым кэшем (`mtime_ns` + `SHA-256`).

Почему используется двухуровневое кэширование:
1. Если `mtime_ns`, `size_bytes` и `PARSER_SCHEMA_VERSION` файла не менялись — готовый AST
   восстанавливается из `file_cache` мгновенно без чтения байтов файла с диска.
2. Если метка времени изменилась (например, после `git checkout`), проверяется `SHA-256`:
   при совпадении содержимого повторный парсинг Tree-sitter также пропускается.
"""

from __future__ import annotations

import dataclasses
import json
import time
from pathlib import Path
from typing import Any

from backend.analyzers.bridge_linker.linker import (
    link_cross_language_bridges_with_coverage,
    load_project_lgraph_config,
)
from backend.analyzers.code_graph.c4_classifier import (
    build_c1_to_c3_hierarchy_and_rollups,
    classify_risk_and_pattern,
    resolve_container_and_domain,
)
from backend.analyzers.code_graph.call_and_contract_helpers import (
    build_imported_files_index,
    resolve_intra_language_calls,
    resolve_type_annotation_edges,
    uri_lang_family,
)
from backend.analyzers.code_graph.disk_state import (
    PY_EXTENSIONS,
    compute_config_fingerprint_ns,
    iter_trackable_source_files,
    load_ignore_globs,
)
from backend.analyzers.code_graph.import_resolver import resolve_js_ts_imports, resolve_python_imports
from backend.analyzers.code_graph.ts_js_parser import JsTsFileParseResult, parse_js_ts_file
from backend.analyzers.code_graph.ts_python_parser import PythonFileParseResult, parse_python_file
from backend.core.config import PARSER_SCHEMA_VERSION, get_project_index_lock, validate_safe_project_root
from backend.core.models import (
    EdgeType, GraphEdgeRecord, GraphNodeRecord, GuardrailRuleSpec,
    NodeType, RiskLevel, compute_sha256_bytes, redact_inline_secrets,
)
from backend.storage.repository import GraphRepository


def _redact_payload_values(obj: Any) -> tuple[Any, bool]:
    """Гарантирует отсутствие сырых секретов в любых строковых полях AST-кэша перед `json.dumps`."""
    if isinstance(obj, str):
        return redact_inline_secrets(obj)
    if isinstance(obj, (list, tuple)):
        pairs = [_redact_payload_values(x) for x in obj]
        return [v for v, _ in pairs], any(f for _, f in pairs)
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        found = False
        for k, val in obj.items():
            v, f = (val, False) if k in ("node_type", "risk_level", "lang") else _redact_payload_values(val)
            out[k], found = v, (found or f)
        return out, found
    return obj, False


def _extract_guardrail_specs_from_yaml(project_root: Path) -> list[GuardrailRuleSpec]:
    cfg = load_project_lgraph_config(project_root)
    raw_rules = cfg.get("guardrails") or []
    specs: list[GuardrailRuleSpec] = []
    for item in raw_rules:
        if not isinstance(item, dict) or not item.get("rule_id"):
            continue
        specs.append(
            GuardrailRuleSpec(
                rule_id=str(item["rule_id"]),
                title=str(item.get("title", item["rule_id"])),
                severity=str(item.get("severity", "warning")),
                scope=str(item.get("scope", "**")),
                exclude_scope=str(item.get("exclude_scope", "")),
                predicate_type=str(item.get("predicate_type", "advisory_only")),
                predicate_params=dict(item.get("predicate_params") or {}),
                rationale_ru=str(item.get("rationale_ru", "")),
                remediation_ru=str(item.get("remediation_ru", "")),
            )
        )
    return specs


def index_project_directory(project_root_raw: str | Path, repo: GraphRepository) -> dict[str, Any]:
    """
    Выполняет полный или кэш-ускоренный цикл индексации проекта:
    Файлы -> Кэш mtime/SHA-256 или Tree-sitter -> Импорты и Вызовы -> BridgeLinker -> C1..C3 -> SQLite.
    """
    t0 = time.perf_counter()
    root = validate_safe_project_root(project_root_raw)
    proj_row = repo.register_project(root)
    project_id = str(proj_row["project_id"])
    with get_project_index_lock(project_id):
        return _index_project_locked(root, proj_row, project_id, repo, t0)


def _index_project_locked(
    root: Path, proj_row: dict[str, Any], project_id: str, repo: GraphRepository, t0: float
) -> dict[str, Any]:
    # Fail-Closed: валидируем lgraph.yaml до сканирования и до любой записи в SQLite
    guardrails = _extract_guardrail_specs_from_yaml(root)
    existing_cache = repo.get_file_cache_map(project_id)
    ignore_globs = load_ignore_globs(root)
    config_fp_ns = compute_config_fingerprint_ns(root)

    all_nodes: list[GraphNodeRecord] = []
    file_nodes: list[GraphNodeRecord] = []
    code_edges: list[GraphEdgeRecord] = []
    new_cache_entries: list[dict[str, Any]] = []

    file_uri_by_rel: dict[str, str] = {}
    symbol_uris_by_lang_name: dict[tuple[str, str], list[str]] = {}
    symbol_uris_by_lang_qualname: dict[tuple[str, str], list[str]] = {}
    type_uris_by_lang_name: dict[tuple[str, str], list[str]] = {}
    pending_py_imports: list[tuple[str, str, list[str]]] = []
    pending_js_imports: list[tuple[str, str, str]] = []
    pending_calls: list[tuple[str, str]] = []
    pending_type_refs: list[tuple[str, str]] = []
    symbol_imports_by_file: dict[str, dict[str, str]] = {}
    py_routes_by_file: dict[str, list[dict[str, Any]]] = {}
    py_router_includes: list[dict[str, str]] = []
    js_call_sites: list[dict[str, Any]] = []

    file_to_domain: dict[str, str] = {}
    domain_to_container: dict[str, str] = {}
    containers_meta: dict[str, str] = {}
    domains_meta: dict[str, tuple[str, str]] = {}

    cache_hits = 0
    parsed_files = 0

    for rel_path, fpath, mtime_ns, size_bytes in iter_trackable_source_files(root, ignore_globs):
        ext = fpath.suffix.lower()
        file_risk, pat_title, pat_desc = classify_risk_and_pattern(rel_path)
        cached_row = existing_cache.get(rel_path)

        payload: dict[str, Any] | None = None
        sha = ""
        had_secret = False

        # Быстрый путь 1: метаданные NTFS (mtime_ns + size_bytes) и версия схемы не изменились
        if (
            cached_row
            and mtime_ns > 0
            and int(cached_row.get("mtime_ns") or -1) == mtime_ns
            and int(cached_row.get("size_bytes") or -1) == size_bytes
            and cached_row.get("parser_version") == PARSER_SCHEMA_VERSION
        ):
            try:
                payload = json.loads(cached_row.get("cached_payload_json") or "{}")
                sha = str(cached_row.get("file_sha256") or "")
                had_secret = bool(cached_row.get("has_redacted_secret"))
                cache_hits += 1
            except Exception:
                payload = None

        raw_bytes: bytes | None = None
        if payload is None:
            try:
                raw_bytes = fpath.read_bytes()
            except OSError:
                continue
            sha = compute_sha256_bytes(raw_bytes)
            _, had_secret = redact_inline_secrets(raw_bytes.decode("utf-8", errors="replace"))

            # Быстрый путь 2: метка времени обновилась, но содержимое SHA-256 идентично
            if (
                cached_row
                and cached_row.get("file_sha256") == sha
                and cached_row.get("parser_version") == PARSER_SCHEMA_VERSION
            ):
                try:
                    payload = json.loads(cached_row.get("cached_payload_json") or "{}")
                    cache_hits += 1
                except Exception:
                    payload = None

        if had_secret:
            file_risk = RiskLevel.CRITICAL

        if payload is None:
            assert raw_bytes is not None
            parsed_files += 1
            if ext in PY_EXTENSIONS:
                py_res: PythonFileParseResult = parse_python_file(rel_path, raw_bytes, file_risk)
                payload = {
                    "lang": "python",
                    "nodes": [dataclasses.asdict(n) for n in py_res.nodes],
                    "py_imports": py_res.imports,
                    "js_imports": [],
                    "calls": py_res.calls,
                    "type_refs": py_res.type_refs,
                    "symbol_imports": py_res.symbol_imports,
                    "fastapi_routes": py_res.fastapi_routes,
                    "router_includes": py_res.router_includes,
                    "js_call_sites": [],
                }
            else:
                js_res: JsTsFileParseResult = parse_js_ts_file(rel_path, raw_bytes, file_risk)
                if js_res.has_redacted_secret:
                    had_secret = True
                payload = {
                    "lang": js_res.scheme,
                    "nodes": [dataclasses.asdict(n) for n in js_res.nodes],
                    "py_imports": [],
                    "js_imports": js_res.imports,
                    "calls": js_res.calls,
                    "type_refs": js_res.type_refs,
                    "symbol_imports": js_res.symbol_imports,
                    "fastapi_routes": [],
                    "router_includes": [],
                    "js_call_sites": js_res.raw_call_sites,
                }
            payload, payload_sec = _redact_payload_values(payload)
            if payload_sec:
                had_secret = True
            if had_secret:
                for nd_dict in payload["nodes"]:
                    nd_dict["risk_level"] = RiskLevel.CRITICAL.value

        restored_nodes = [
            GraphNodeRecord(
                **{
                    **nd,
                    "node_type": NodeType(nd["node_type"]),
                    "risk_level": RiskLevel(nd["risk_level"]),
                }
            )
            for nd in payload["nodes"]
        ]
        if had_secret:
            for rnd in restored_nodes:
                rnd.risk_level = RiskLevel.CRITICAL

        c2_pair, c3_pair = resolve_container_and_domain(rel_path)
        containers_meta[c2_pair[0]] = c2_pair[1]
        domains_meta.setdefault(c3_pair[0], (c3_pair[1], rel_path))
        domain_to_container[c3_pair[0]] = c2_pair[0]

        file_node = restored_nodes[0]
        file_node.parent_uri = c3_pair[0]
        file_node.pattern_tag = pat_title
        if not file_node.summary_ru:
            file_node.summary_ru = pat_desc
        if had_secret:
            file_node.meta["has_redacted_secret"] = True

        file_nodes.append(file_node)
        file_uri_by_rel[rel_path] = file_node.uri
        file_to_domain[file_node.uri] = c3_pair[0]
        code_edges.append(GraphEdgeRecord(src_uri=c3_pair[0], dst_uri=file_node.uri, edge_type=EdgeType.CONTAINS))

        for nd in restored_nodes:
            all_nodes.append(nd)
            if nd.node_type != NodeType.FILE:
                lang_fam = uri_lang_family(nd.uri)
                short_nm = nd.name.rsplit(".", 1)[-1]
                symbol_uris_by_lang_name.setdefault((lang_fam, short_nm), []).append(nd.uri)
                symbol_uris_by_lang_qualname.setdefault((lang_fam, nd.name), []).append(nd.uri)
                if nd.node_type in (NodeType.DATA_CONTRACT, NodeType.CLASS):
                    type_uris_by_lang_name.setdefault((lang_fam, short_nm), []).append(nd.uri)
                if nd.parent_uri:
                    code_edges.append(GraphEdgeRecord(src_uri=nd.parent_uri, dst_uri=nd.uri, edge_type=EdgeType.CONTAINS))

        for mod_name, imp_names in payload.get("py_imports", []):
            pending_py_imports.append((file_node.uri, mod_name, imp_names))
        for js_imp in payload.get("js_imports", []):
            pending_js_imports.append((file_node.uri, rel_path, js_imp))
        for caller_u, callee_nm in payload.get("calls", []):
            pending_calls.append((caller_u, callee_nm))
        for owner_u, ref_nm in payload.get("type_refs", []):
            pending_type_refs.append((owner_u, ref_nm))
        sym_imps = payload.get("symbol_imports") or {}
        if isinstance(sym_imps, dict) and sym_imps:
            symbol_imports_by_file[rel_path] = sym_imps
        if payload.get("fastapi_routes"):
            py_routes_by_file[rel_path] = payload["fastapi_routes"]
        py_router_includes.extend(payload.get("router_includes", []))
        js_call_sites.extend(payload.get("js_call_sites", []))

        new_cache_entries.append(
            {
                "rel_path": rel_path,
                "file_sha256": sha,
                "parser_version": PARSER_SCHEMA_VERSION,
                "mtime_ns": mtime_ns,
                "size_bytes": size_bytes,
                "line_count": int(file_node.meta.get("line_count", 0)),
                "language": payload["lang"],
                "has_redacted_secret": had_secret,
                "cached_payload_json": json.dumps(payload, ensure_ascii=False),
            }
        )

    resolve_python_imports(pending_py_imports, file_uri_by_rel, code_edges)
    resolve_js_ts_imports(pending_js_imports, file_uri_by_rel, code_edges, project_root=root)

    imported_files_by_src = build_imported_files_index(code_edges)
    resolve_intra_language_calls(
        pending_calls, symbol_uris_by_lang_name, symbol_uris_by_lang_qualname,
        imported_files_by_src, symbol_imports_by_file, code_edges,
    )
    resolve_type_annotation_edges(
        pending_type_refs, type_uris_by_lang_name, imported_files_by_src, symbol_imports_by_file, code_edges,
    )

    bridge_nodes, bridge_edges, bridge_coverage = link_cross_language_bridges_with_coverage(
        project_root=root, py_routes_by_file=py_routes_by_file,
        py_router_includes=py_router_includes, js_call_sites=js_call_sites, all_nodes=all_nodes,
    )
    all_nodes.extend(bridge_nodes)
    code_edges.extend(bridge_edges)

    c_nodes, c_edges = build_c1_to_c3_hierarchy_and_rollups(
        project_name=str(proj_row["name"]), file_nodes=file_nodes, code_edges=code_edges,
        file_to_domain=file_to_domain, domain_to_container=domain_to_container,
        containers_meta=containers_meta, domains_meta=domains_meta,
    )
    for cn in c_nodes:
        if cn.uri == "c1://project/self":
            cn.meta["bridge_coverage"] = bridge_coverage
            break
    all_nodes.extend(c_nodes)
    code_edges.extend(c_edges)

    # Передаём список правил явно (включая `[]`), чтобы удаление правил из lgraph.yaml очищало их в БД
    revision = repo.save_full_index_atomic(
        project_id=project_id, nodes=all_nodes, edges=code_edges,
        file_cache_entries=new_cache_entries, guardrail_rules=guardrails, config_mtime_ns=config_fp_ns,
    )

    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    return {
        "project_id": project_id, "project_name": proj_row["name"], "index_revision": revision,
        "elapsed_ms": elapsed_ms, "parsed_files": parsed_files, "cache_hits": cache_hits,
        "total_nodes": len(all_nodes), "total_edges": len(code_edges), "bridge_coverage": bridge_coverage,
    }
