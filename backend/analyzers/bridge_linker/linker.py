"""
Сшиватель межъязыковых мостов (BridgeLinker): TypeScript/JS <-> Electron IPC <-> Python FastAPI.

Почему универсального регулярного выражения недостаточно и нужен канонический шаблон + адаптеры:
1. На клиенте параметры пишутся как `${orderId}`, а в FastAPI — как `{order_id}` или `{id:int}`.
   Приведение обеих сторон к единой маске `/api/orders/{param}/confirm` с учётом HTTP-метода
   исключает ложные склейки `GET` с `DELETE`.
2. Для самописных шлюзов (`apiFetch`, `appFetch`, `lgraphFetch`) декларативная секция
   `bridge_adapters` в `lgraph.yaml` и эвристика `*Fetch` дают высокую точность.
3. Покрытие `bridge_coverage` и классификация отдельных вызовов вынесены в `coverage.py`,
   чтобы не плодить лишние строки `BRIDGES_TO` в таблице `edges` и удерживать `linker.py <= 350` строк.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from backend.analyzers.bridge_linker.coverage import (
    CUSTOM_FETCH_WRAPPER_RE as _CUSTOM_FETCH_WRAPPER_RE,
    BridgeCoverageTracker,
    collect_ipc_targets,
    match_http_route as _match_http_route,
    normalize_route_mask,
    resolve_client_call_site,
)
from backend.core.config import is_reparse_or_symlink
from backend.core.models import (
    ConfidenceTier,
    EdgeType,
    GraphEdgeRecord,
    GraphNodeRecord,
    NodeType,
    RiskLevel,
)

__all__ = [
    "_CUSTOM_FETCH_WRAPPER_RE",
    "_match_http_route",
    "_resolve_router_origin_rel_path",
    "build_server_http_endpoints",
    "collect_ipc_targets",
    "extract_http_wrapper_map",
    "link_cross_language_bridges",
    "link_cross_language_bridges_with_coverage",
    "load_project_lgraph_config",
    "normalize_route_mask",
    "resolve_client_call_site",
]


def load_project_lgraph_config(project_root: Path) -> dict[str, Any]:
    """
    Читает проектный файл `lgraph.yaml` в режиме Fail-Closed:
    при ошибке YAML или неверном корневом типе выбрасывает `ValueError`, чтобы опечатка
    в отступах не обнулила `BLOCKER`-правила в БД.
    """
    cfg_path = project_root / "lgraph.yaml"
    if not cfg_path.exists():
        return {}
    if is_reparse_or_symlink(cfg_path) or not cfg_path.is_file():
        raise ValueError(f"Ошибка синтаксиса в файле конфигурации {cfg_path}: недопустимый тип файла или симлинк.")
    try:
        raw_text = cfg_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"Ошибка синтаксиса в файле конфигурации {cfg_path}: {exc}") from exc
    try:
        loaded = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ValueError(f"Ошибка синтаксиса в файле конфигурации {cfg_path}: {exc}") from exc
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ValueError(
            f"Ошибка синтаксиса в файле конфигурации {cfg_path}: корень YAML обязан быть словарём, получен {type(loaded).__name__}."
        )
    return loaded


def extract_http_wrapper_map(cfg: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Извлекает карту пользовательских HTTP-обёрток из секции `bridge_adapters.http_wrappers`."""
    adapters_cfg = (cfg.get("bridge_adapters") or {}).get("http_wrappers") or []
    wrapper_map: dict[str, dict[str, Any]] = {}
    for item in adapters_cfg:
        if isinstance(item, dict) and item.get("caller_name"):
            wrapper_map[str(item["caller_name"])] = item
    return wrapper_map


def _resolve_router_origin_rel_path(origin: str, importer_rel_path: str = "") -> list[str]:
    """Разрешает источник роутера (`.routes:router`, `..v1.routes:router`, `.:routes`) в пути `.py` файлов."""
    if ":" not in origin:
        return []
    mod_part, sym_part = [p.strip() for p in origin.split(":", 1)]
    if not mod_part:
        return []
    norm_imp = importer_rel_path.replace("\\", "/").strip("/")
    imp_dir = [p for p in norm_imp.split("/")[:-1] if p]

    if mod_part.startswith("."):
        dots = len(mod_part) - len(mod_part.lstrip("."))
        rem = mod_part[dots:].replace(".", "/").strip("/")
        tail = rem or sym_part.replace(".", "/").strip("/")
        if not norm_imp:
            return [f"{tail}.py", f"{tail}/__init__.py"] if tail else []
        up = dots - 1
        if up > len(imp_dir):
            return []
        base = "/".join(imp_dir[: len(imp_dir) - up] + ([tail] if tail else []))
        return [f"{base}.py", f"{base}/__init__.py"] if base else []

    base = mod_part.replace(".", "/").strip("/")
    if not base:
        return []
    cands = [f"{base}.py", f"{base}/__init__.py"]
    if imp_dir and not base.startswith(imp_dir[0] + "/"):
        cands.extend([f"{imp_dir[0]}/{base}.py", f"{imp_dir[0]}/{base}/__init__.py"])
    return cands


def build_server_http_endpoints(
    py_routes_by_file: dict[str, list[dict[str, Any]]],
    py_router_includes: list[dict[str, str]],
) -> dict[tuple[str, str], list[str]]:
    """Строит таблицу канонических серверных маршрутов `(METHOD, mask) -> [func_uri]` с учётом `include_router`."""
    file_router_prefixes: dict[str, list[str]] = {}
    exact_only_keys: set[str] = set()
    for inc in py_router_includes:
        origin = inc.get("imported_from", "")
        importer_rel = inc.get("importer_rel_path", "")
        prefix = inc.get("prefix", "")
        for cand_rel in _resolve_router_origin_rel_path(origin, importer_rel):
            if prefix not in file_router_prefixes.setdefault(cand_rel, []):
                file_router_prefixes[cand_rel].append(prefix)
            if importer_rel and origin.startswith("."):
                exact_only_keys.add(cand_rel)

    server_endpoints: dict[tuple[str, str], list[str]] = {}
    for rel_py, routes in py_routes_by_file.items():
        matched_prefixes = list(file_router_prefixes.get(rel_py) or [])
        if not matched_prefixes:
            for mod_key, prefs in file_router_prefixes.items():
                if mod_key not in exact_only_keys and rel_py.endswith("/" + mod_key):
                    matched_prefixes.extend(prefs)
        prefixes = matched_prefixes or [""]
        for rt in routes:
            for pref in prefixes:
                mask = normalize_route_mask(rt["path"], prepend_prefix=pref)
                key = (rt["method"].upper(), mask)
                if rt["func_uri"] not in server_endpoints.setdefault(key, []):
                    server_endpoints[key].append(rt["func_uri"])
    return server_endpoints


def link_cross_language_bridges_with_coverage(
    project_root: Path,
    py_routes_by_file: dict[str, list[dict[str, Any]]],
    py_router_includes: list[dict[str, str]],
    js_call_sites: list[dict[str, Any]],
    all_nodes: list[GraphNodeRecord],
) -> tuple[list[GraphNodeRecord], list[GraphEdgeRecord], dict[str, Any]]:
    """
    Сопоставляет межъязыковые HTTP-маршруты, каналы Electron IPC и общие схемы данных.
    Возвращает `(bridge_nodes, bridge_edges, bridge_coverage)`.
    """
    wrapper_map = extract_http_wrapper_map(load_project_lgraph_config(project_root))
    server_endpoints = build_server_http_endpoints(py_routes_by_file, py_router_includes)
    ipc_handlers, ipc_renderer_listeners = collect_ipc_targets(js_call_sites)

    bridge_nodes: list[GraphNodeRecord] = []
    bridge_edges: list[GraphEdgeRecord] = []
    tracker = BridgeCoverageTracker()
    unresolved_node_created = False

    def _ensure_unresolved_node() -> str:
        nonlocal unresolved_node_created
        uri = "dynamic://unresolved/runtime_target"
        if not unresolved_node_created:
            unresolved_node_created = True
            bridge_nodes.append(
                GraphNodeRecord(
                    uri=uri, node_type=NodeType.IPC_CHANNEL, name="Динамический адрес/канал (Runtime)",
                    c4_level=4, risk_level=RiskLevel.MEDIUM, confidence=0.35, source_module="bridge_linker",
                    summary_ru="Точный адрес или имя канала вычисляется во время работы программы из переменной. Требует ручной проверки.",
                )
            )
        return uri

    for cs in js_call_sites:
        res = resolve_client_call_site(cs, server_endpoints, ipc_handlers, ipc_renderer_listeners, wrapper_map)
        if res is None:
            continue
        status, proto = res["status"], res["protocol"]
        if status == "wrapper_passthrough":
            tracker.record_wrapper_passthrough()
            continue
        if status == "unresolved_dynamic":
            tracker.record_unresolved(
                {"protocol": proto, "caller_uri": cs["caller_uri"], "callee": cs["callee"], "arg": cs["first_arg_raw"], "line": cs["line"]}
            )
            if res["emit_unresolved_edge"]:
                bridge_edges.append(
                    GraphEdgeRecord(
                        src_uri=cs["caller_uri"], dst_uri=_ensure_unresolved_node(), edge_type=EdgeType.BRIDGES_TO,
                        confidence=0.35, confidence_tier=ConfidenceTier.UNRESOLVED_DYNAMIC, source_module="bridge_linker",
                        evidence=f"IPC dynamic call `{cs['callee']}({cs['first_arg_raw']})` at line {cs['line']}",
                        meta={"protocol": "IPC", "dynamic": True},
                    )
                )
            continue
        if status == "unmatched_static":
            tracker.record_unmatched(
                {"protocol": proto, "caller_uri": cs["caller_uri"], "callee": cs["callee"], "endpoint": res["endpoint_key"], "line": cs["line"]}
            )
            continue

        tracker.record_linked(res["tier"])
        for target_uri in res["targets"]:
            if proto == "HTTP":
                ev, meta = res["endpoint_key"], {"protocol": "HTTP", "method": res["method"], "route": res["route_mask"]}
            elif proto == "IPC":
                ev, meta = f"IPC channel '{res['route_mask']}'", {"protocol": "IPC", "channel": res["route_mask"]}
            else:
                ev, meta = f"IPC push '{res['route_mask']}'", {"protocol": "IPC_PUSH", "channel": res["route_mask"]}
            bridge_edges.append(
                GraphEdgeRecord(
                    src_uri=cs["caller_uri"], dst_uri=target_uri, edge_type=EdgeType.BRIDGES_TO,
                    confidence=res["confidence"], confidence_tier=res["tier"], source_module="bridge_linker",
                    evidence=ev, meta=meta,
                )
            )

    py_contracts: dict[str, list[str]] = {}
    fe_contracts: dict[str, list[str]] = {}
    for n in all_nodes:
        if n.node_type == NodeType.DATA_CONTRACT:
            if n.uri.startswith("py://"):
                py_contracts.setdefault(n.name, []).append(n.uri)
            elif n.uri.startswith(("ts://", "js://")):
                fe_contracts.setdefault(n.name, []).append(n.uri)

    for shared_name in sorted(set(py_contracts).intersection(fe_contracts)):
        for fe_u in fe_contracts[shared_name]:
            for py_u in py_contracts[shared_name]:
                bridge_edges.append(
                    GraphEdgeRecord(
                        src_uri=fe_u, dst_uri=py_u, edge_type=EdgeType.USES_CONTRACT,
                        confidence=0.95, confidence_tier=ConfidenceTier.VERIFIED,
                        source_module="bridge_linker", evidence=f"Shared schema `{shared_name}`",
                    )
                )

    return bridge_nodes, bridge_edges, tracker.to_dict()


def link_cross_language_bridges(
    project_root: Path,
    py_routes_by_file: dict[str, list[dict[str, Any]]],
    py_router_includes: list[dict[str, str]],
    js_call_sites: list[dict[str, Any]],
    all_nodes: list[GraphNodeRecord],
) -> tuple[list[GraphNodeRecord], list[GraphEdgeRecord]]:
    """Обратно-совместимая обёртка: возвращает `(bridge_nodes, bridge_edges)` без статистики покрытия."""
    bridge_nodes, bridge_edges, _ = link_cross_language_bridges_with_coverage(
        project_root, py_routes_by_file, py_router_includes, js_call_sites, all_nodes
    )
    return bridge_nodes, bridge_edges
