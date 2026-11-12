"""
Сшиватель межъязыковых мостов (BridgeLinker): TypeScript/JS <-> Electron IPC <-> Python FastAPI.

Почему универсального регулярного выражения недостаточно и нужен канонический шаблон + адаптеры:
1. На клиенте параметры пишутся как `${orderId}`, а в FastAPI — как `{order_id}` или `{id:int}`.
   Приведение обеих сторон к единой маске `/api/orders/{param}/confirm` с учётом HTTP-метода
   исключает ложные склейки `GET` с `DELETE`.
2. Для самописных шлюзов (таких как `apiFetch` или `appFetch`) декларативная секция
   `bridge_adapters` в `lgraph.yaml` и универсальная эвристика `*Fetch` дают высокую точность.
3. Если аргумент вызова — переменная (`ipcRenderer.invoke(dynamicName)`), анализатор честно
   помечает вызов как `unresolved_dynamic`, не выдумывая ложных связей.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from backend.core.config import is_reparse_or_symlink
from backend.core.models import (
    ConfidenceTier, EdgeType, GraphEdgeRecord, GraphNodeRecord, NodeType, RiskLevel,
)

_LEADING_BASE_INTERP_RE = re.compile(
    r"^\$\{[^}]*(?:url|host|origin|base|server|endpoint)[^}]*\}",
    re.IGNORECASE,
)
_TEMPLATE_INTERP_RE = re.compile(r"\$\{[^}]+\}")
_FASTAPI_PARAM_RE = re.compile(r"\{[^}/]+\}")
_AXIOS_METHOD_RE = re.compile(r"(?:^|\.)axios\.(get|post|put|delete|patch)$")
_CUSTOM_FETCH_WRAPPER_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*Fetch$")


def normalize_route_mask(raw_url: str, prepend_prefix: str = "") -> str:
    """
    Приводит шаблон URL клиента или маршрут FastAPI к канонической маске:
    `${API_BASE_URL}/api/orders/${orderId}/confirm?fast=1` -> `/api/orders/{param}/confirm`
    """
    cleaned = raw_url.strip().strip("\"'` ")
    cleaned = _LEADING_BASE_INTERP_RE.sub("", cleaned)
    cleaned = re.sub(r"^https?://[^/]+", "", cleaned)
    cleaned = cleaned.split("?", 1)[0].split("#", 1)[0]
    cleaned = _TEMPLATE_INTERP_RE.sub("{param}", cleaned)
    cleaned = _FASTAPI_PARAM_RE.sub("{param}", cleaned)

    if prepend_prefix:
        pref = "/" + prepend_prefix.strip("/")
        if not cleaned.startswith(pref + "/") and cleaned != pref:
            cleaned = pref + ("/" + cleaned.lstrip("/") if cleaned else "")

    norm = "/" + "/".join(seg for seg in cleaned.split("/") if seg)
    return norm


def load_project_lgraph_config(project_root: Path) -> dict[str, Any]:
    """
    Читает проектный файл `lgraph.yaml` в режиме Fail-Closed:
    если файла нет или он пуст — возвращает `{}`, но при ошибке YAML или неверном корневом типе
    выбрасывает `ValueError`, чтобы опечатка в отступах не обнулила `BLOCKER`-правила в БД.
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


def _match_http_route(
    server_endpoints: dict[tuple[str, str], list[str]], method: str, candidate_mask: str
) -> tuple[str, list[str]]:
    """Находит точный маршрут либо параметризованный шаблон `{param}` той же длины и HTTP-метода."""
    exact = server_endpoints.get((method, candidate_mask))
    if exact:
        return candidate_mask, exact
    c_segs = [s for s in candidate_mask.split("/") if s]
    best_mask, best_targets, best_static = candidate_mask, [], -1
    for (srv_m, srv_mask), targets in server_endpoints.items():
        if srv_m != method or "{param}" not in srv_mask:
            continue
        s_segs = [s for s in srv_mask.split("/") if s]
        static_cnt = sum(1 for s in s_segs if s != "{param}")
        if len(s_segs) == len(c_segs) and static_cnt > best_static and static_cnt >= 1:
            if all(ss == "{param}" or cs == ss for cs, ss in zip(c_segs, s_segs)):
                best_mask, best_targets, best_static = srv_mask, targets, static_cnt
    return best_mask, best_targets


def link_cross_language_bridges(
    project_root: Path,
    py_routes_by_file: dict[str, list[dict[str, Any]]],
    py_router_includes: list[dict[str, str]],
    js_call_sites: list[dict[str, Any]],
    all_nodes: list[GraphNodeRecord],
) -> tuple[list[GraphNodeRecord], list[GraphEdgeRecord]]:
    """
    Сопоставляет межъязыковые HTTP-маршруты, каналы Electron IPC и общие схемы данных.
    Возвращает дополнительные узлы (например, `unresolved_dynamic`) и рёбра `BRIDGES_TO` / `USES_CONTRACT`.
    """
    cfg = load_project_lgraph_config(project_root)
    adapters_cfg = (cfg.get("bridge_adapters") or {}).get("http_wrappers") or []

    # Пользовательские обёртки из `lgraph.yaml` (дополняются универсальной эвристикой `*Fetch`)
    wrapper_map: dict[str, dict[str, Any]] = {}
    for item in adapters_cfg:
        if isinstance(item, dict) and item.get("caller_name"):
            wrapper_map[str(item["caller_name"])] = item

    # 1. Вычисляем полные префиксы FastAPI роутеров из `app.include_router(router_var, prefix=...)`
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

    # 2. Строим таблицу канонических серверных маршрутов `(METHOD, mask) -> [func_uri]`
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

    # 3. Собираем обработчики Electron IPC (`ipcMain.handle/on` и клиентские слушатели `ipcRenderer.on/once`)
    ipc_handlers: dict[str, list[str]] = {}
    ipc_renderer_listeners: dict[str, list[str]] = {}
    for cs in js_call_sites:
        callee = cs["callee"]
        if callee in ("ipcMain.handle", "ipcMain.on", "electron.ipcMain.handle", "electron.ipcMain.on") and cs["first_arg_type"] in ("string", "template_string"):
            ch_name = cs["first_arg_raw"].strip("\"'` ")
            if ch_name and "${" not in ch_name and cs["caller_uri"] not in ipc_handlers.setdefault(ch_name, []):
                ipc_handlers[ch_name].append(cs["caller_uri"])
        elif callee in ("ipcRenderer.on", "ipcRenderer.once", "electron.ipcRenderer.on") and cs["first_arg_type"] in ("string", "template_string"):
            ch_name = cs["first_arg_raw"].strip("\"'` ")
            if ch_name and "${" not in ch_name and cs["caller_uri"] not in ipc_renderer_listeners.setdefault(ch_name, []):
                ipc_renderer_listeners[ch_name].append(cs["caller_uri"])

    bridge_nodes: list[GraphNodeRecord] = []
    bridge_edges: list[GraphEdgeRecord] = []
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

    # 4. Сопоставляем клиентские HTTP и IPC вызовы с сервером и Electron Main
    for cs in js_call_sites:
        callee, arg_raw, arg_type = cs["callee"], cs["first_arg_raw"], cs["first_arg_type"]
        short_callee = callee.rsplit(".", 1)[-1]

        # А) Клиентские IPC вызовы (`ipcRenderer.invoke`, `ipcRenderer.send`)
        if callee in ("ipcRenderer.invoke", "ipcRenderer.send", "electron.ipcRenderer.invoke"):
            if arg_type not in ("string", "template_string") or "${" in arg_raw:
                dyn_uri = _ensure_unresolved_node()
                bridge_edges.append(
                    GraphEdgeRecord(
                        src_uri=cs["caller_uri"],
                        dst_uri=dyn_uri,
                        edge_type=EdgeType.BRIDGES_TO,
                        confidence=0.35,
                        confidence_tier=ConfidenceTier.UNRESOLVED_DYNAMIC,
                        source_module="bridge_linker",
                        evidence=f"IPC dynamic call `{callee}({arg_raw})` at line {cs['line']}",
                        meta={"protocol": "IPC", "dynamic": True},
                    )
                )
            else:
                ch_name = arg_raw.strip("\"'` ")
                for handler_uri in ipc_handlers.get(ch_name, []):
                    bridge_edges.append(
                        GraphEdgeRecord(
                            src_uri=cs["caller_uri"],
                            dst_uri=handler_uri,
                            edge_type=EdgeType.BRIDGES_TO,
                            confidence=1.0,
                            confidence_tier=ConfidenceTier.EXACT,
                            source_module="bridge_linker",
                            evidence=f"IPC channel '{ch_name}'",
                            meta={"protocol": "IPC", "channel": ch_name},
                        )
                    )
            continue

        # А2) Серверные push-события Electron Main -> Renderer (`*.webContents.send('channel', payload)`)
        if callee == "webContents.send" or callee.endswith(".webContents.send"):
            if arg_type in ("string", "template_string") and "${" not in arg_raw:
                ch_name = arg_raw.strip("\"'` ")
                for listener_uri in ipc_renderer_listeners.get(ch_name, []):
                    bridge_edges.append(
                        GraphEdgeRecord(
                            src_uri=cs["caller_uri"],
                            dst_uri=listener_uri,
                            edge_type=EdgeType.BRIDGES_TO,
                            confidence=1.0,
                            confidence_tier=ConfidenceTier.EXACT,
                            source_module="bridge_linker",
                            evidence=f"IPC push '{ch_name}'",
                            meta={"protocol": "IPC_PUSH", "channel": ch_name},
                        )
                    )
            continue

        # Б) Клиентские HTTP-вызовы (`fetch`, `axios.*`, кастомные обёртки из `lgraph.yaml` и эвристика `*Fetch`)
        is_fetch = callee in ("fetch", "window.fetch", "globalThis.fetch")
        axios_match = _AXIOS_METHOD_RE.search(callee)
        wrapper_cfg = wrapper_map.get(callee) or wrapper_map.get(short_callee)
        is_custom_fetch_name = bool(_CUSTOM_FETCH_WRAPPER_RE.match(short_callee)) and not is_fetch

        if not (is_fetch or axios_match or wrapper_cfg or is_custom_fetch_name):
            continue

        # Пропускаем внутреннее объявление самой обёртки (где первым аргументом идёт переменная `subPath`)
        if arg_type not in ("string", "template_string"):
            continue

        http_method = axios_match.group(1).upper() if axios_match else (cs["method_hint"] or "GET")
        prepend = str(wrapper_cfg.get("prepend_prefix", "")) if wrapper_cfg else ""
        route_mask, matched_targets = _match_http_route(
            server_endpoints, http_method, normalize_route_mask(arg_raw, prepend_prefix=prepend)
        )
        used_heuristic_prefix = False
        if not matched_targets and is_custom_fetch_name and not wrapper_cfg:
            alt_mask, alt_targets = _match_http_route(
                server_endpoints, http_method, normalize_route_mask(arg_raw, prepend_prefix="/api")
            )
            if alt_targets:
                route_mask, matched_targets, used_heuristic_prefix = alt_mask, alt_targets, True
        tier = ConfidenceTier.PATTERN_MATCHED if ("{param}" in route_mask or used_heuristic_prefix) else ConfidenceTier.EXACT
        conf = 0.92 if tier == ConfidenceTier.PATTERN_MATCHED else 1.0

        for target_fn_uri in matched_targets:
            bridge_edges.append(
                GraphEdgeRecord(
                    src_uri=cs["caller_uri"],
                    dst_uri=target_fn_uri,
                    edge_type=EdgeType.BRIDGES_TO,
                    confidence=conf,
                    confidence_tier=tier,
                    source_module="bridge_linker",
                    evidence=f"{http_method} {route_mask}",
                    meta={"protocol": "HTTP", "method": http_method, "route": route_mask},
                )
            )

    # 5. Сшиваем одноимённые контракты данных (`Pydantic/SQLModel/TypedDict` <-> `TS/JS interface/type`) без потери дублей
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
                        src_uri=fe_u,
                        dst_uri=py_u,
                        edge_type=EdgeType.USES_CONTRACT,
                        confidence=0.95,
                        confidence_tier=ConfidenceTier.VERIFIED,
                        source_module="bridge_linker",
                        evidence=f"Shared schema `{shared_name}`",
                    )
                )

    return bridge_nodes, bridge_edges
