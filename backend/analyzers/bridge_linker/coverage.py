"""
Учёт покрытия клиентских вызовов (`bridge_coverage`) и каноническое сопоставление HTTP/IPC.

Почему классификация вызовов и учёт покрытия вынесены отдельно от `linker.py`:
1. Удерживает `linker.py` и `preflight.py` компактными (`<= 350` строк, `GR-LGRAPH-SIZE`) без циклов.
2. Гарантирует 100% единую логику сопоставления HTTP-маршрутов и каналов Electron IPC
   как при индексации графа, так и при сравнении с `HEAD` в `preflight.py`.
3. Внутренние вызовы `fetch(subPath)` внутри функций-обёрток (`*Fetch` / `bridge_adapters`)
   классифицируются как `wrapper_passthrough` и исключаются из знаменателя покрытия и ошибок.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from backend.core.models import ConfidenceTier

CUSTOM_FETCH_WRAPPER_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*Fetch$")
_LEADING_BASE_INTERP_RE = re.compile(r"^\$\{[^}]*(?:url|host|origin|base|server|endpoint)[^}]*\}", re.IGNORECASE)
_TEMPLATE_INTERP_RE = re.compile(r"\$\{[^}]+\}")
_FASTAPI_PARAM_RE = re.compile(r"\{[^}/]+\}")
_AXIOS_METHOD_RE = re.compile(r"(?:^|\.)axios\.(get|post|put|delete|patch)$")
_IPC_CLIENT_CALLEES: frozenset[str] = frozenset({"ipcRenderer.invoke", "ipcRenderer.send", "electron.ipcRenderer.invoke"})
_IPC_MAIN_CALLEES: frozenset[str] = frozenset({"ipcMain.handle", "ipcMain.on", "electron.ipcMain.handle", "electron.ipcMain.on"})
_IPC_LISTENER_CALLEES: frozenset[str] = frozenset({"ipcRenderer.on", "ipcRenderer.once", "electron.ipcRenderer.on"})
MAX_COVERAGE_SAMPLES: int = 15


def empty_bridge_coverage() -> dict[str, Any]:
    """Возвращает пустой канонический словарь `bridge_coverage` (0 клиентских вызовов -> ratio 1.0)."""
    return {
        "total_client_calls": 0, "linked_exact": 0, "linked_pattern": 0,
        "wrapper_passthrough": 0, "unresolved_dynamic": 0, "unmatched_static": 0,
        "coverage_ratio": 1.0, "unresolved_samples": [], "unmatched_samples": [],
    }


def normalize_route_mask(raw_url: str, prepend_prefix: str = "") -> str:
    """Приводит шаблон URL клиента или маршрут FastAPI к канонической маске `/api/orders/{param}/confirm`."""
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
    return "/" + "/".join(seg for seg in cleaned.split("/") if seg)


def match_http_route(
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


def collect_ipc_targets(js_call_sites: list[dict[str, Any]]) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Собирает обработчики Electron IPC (`ipcMain.handle/on`) и слушатели `ipcRenderer.on/once`."""
    ipc_handlers: dict[str, list[str]] = {}
    ipc_listeners: dict[str, list[str]] = {}
    for cs in js_call_sites:
        if cs["first_arg_type"] not in ("string", "template_string"):
            continue
        ch_name = cs["first_arg_raw"].strip("\"'` ")
        if not ch_name or "${" in ch_name:
            continue
        callee = cs["callee"]
        if callee in _IPC_MAIN_CALLEES:
            if cs["caller_uri"] not in ipc_handlers.setdefault(ch_name, []):
                ipc_handlers[ch_name].append(cs["caller_uri"])
        elif callee in _IPC_LISTENER_CALLEES:
            if cs["caller_uri"] not in ipc_listeners.setdefault(ch_name, []):
                ipc_listeners[ch_name].append(cs["caller_uri"])
    return ipc_handlers, ipc_listeners


def is_wrapper_passthrough_caller(caller_uri: str, wrapper_map: dict[str, dict[str, Any]]) -> bool:
    """Определяет, принадлежит ли вызов `fetch(...)` самой функции-обёртке (`wrapper_map` или `*Fetch`)."""
    if "#" not in caller_uri:
        return False
    caller_qual = caller_uri.rsplit("#", 1)[1].strip()
    caller_short = caller_qual.rsplit(".", 1)[-1]
    return bool(caller_short) and (
        caller_qual in wrapper_map
        or caller_short in wrapper_map
        or bool(CUSTOM_FETCH_WRAPPER_RE.match(caller_short))
    )


def has_static_route_segment(route_mask: str) -> bool:
    """Проверяет наличие хотя бы одного статического сегмента в канонической маске URL."""
    return any(seg != "{param}" for seg in route_mask.split("/") if seg)


def resolve_client_call_site(
    cs: dict[str, Any],
    server_endpoints: dict[tuple[str, str], list[str]],
    ipc_handlers: dict[str, list[str]],
    ipc_renderer_listeners: dict[str, list[str]],
    wrapper_map: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    """Классифицирует клиентский вызов HTTP/IPC и сопоставляет его с целевыми обработчиками."""
    callee, arg_raw, arg_type = cs["callee"], cs["first_arg_raw"], cs["first_arg_type"]
    short_callee = callee.rsplit(".", 1)[-1]

    if callee in _IPC_CLIENT_CALLEES:
        if arg_type not in ("string", "template_string") or "${" in arg_raw:
            return {
                "protocol": "IPC", "status": "unresolved_dynamic", "targets": [],
                "endpoint_key": f"IPC {arg_raw}", "method": "", "route_mask": arg_raw,
                "tier": ConfidenceTier.UNRESOLVED_DYNAMIC, "confidence": 0.35, "emit_unresolved_edge": True,
            }
        ch_name = arg_raw.strip("\"'` ")
        targets = ipc_handlers.get(ch_name, [])
        return {
            "protocol": "IPC", "status": "linked" if targets else "unmatched_static", "targets": targets,
            "endpoint_key": f"IPC {ch_name}", "method": "", "route_mask": ch_name,
            "tier": ConfidenceTier.EXACT, "confidence": 1.0, "emit_unresolved_edge": False,
        }

    if callee == "webContents.send" or callee.endswith(".webContents.send"):
        if arg_type not in ("string", "template_string") or "${" in arg_raw:
            return {
                "protocol": "IPC_PUSH", "status": "unresolved_dynamic", "targets": [],
                "endpoint_key": f"IPC_PUSH {arg_raw}", "method": "", "route_mask": arg_raw,
                "tier": ConfidenceTier.UNRESOLVED_DYNAMIC, "confidence": 0.35, "emit_unresolved_edge": False,
            }
        ch_name = arg_raw.strip("\"'` ")
        targets = ipc_renderer_listeners.get(ch_name, [])
        return {
            "protocol": "IPC_PUSH", "status": "linked" if targets else "unmatched_static", "targets": targets,
            "endpoint_key": f"IPC_PUSH {ch_name}", "method": "", "route_mask": ch_name,
            "tier": ConfidenceTier.EXACT, "confidence": 1.0, "emit_unresolved_edge": False,
        }

    is_fetch = callee in ("fetch", "window.fetch", "globalThis.fetch")
    axios_match = _AXIOS_METHOD_RE.search(callee)
    wrapper_cfg = wrapper_map.get(callee) or wrapper_map.get(short_callee)
    is_custom_fetch = bool(CUSTOM_FETCH_WRAPPER_RE.match(short_callee)) and not is_fetch
    if not (is_fetch or axios_match or wrapper_cfg or is_custom_fetch):
        return None

    is_wrapper_caller = is_wrapper_passthrough_caller(cs["caller_uri"], wrapper_map)
    if arg_type not in ("string", "template_string"):
        status = "wrapper_passthrough" if is_wrapper_caller else "unresolved_dynamic"
        return {
            "protocol": "HTTP", "status": status, "targets": [],
            "endpoint_key": f"HTTP {arg_raw}", "method": "", "route_mask": arg_raw,
            "tier": ConfidenceTier.UNRESOLVED_DYNAMIC, "confidence": 0.35, "emit_unresolved_edge": False,
        }

    http_method = axios_match.group(1).upper() if axios_match else (cs["method_hint"] or "GET")
    prepend = str(wrapper_cfg.get("prepend_prefix", "")) if wrapper_cfg else ""
    route_mask, matched_targets = match_http_route(
        server_endpoints, http_method, normalize_route_mask(arg_raw, prepend_prefix=prepend)
    )
    used_heuristic_prefix = False
    if not matched_targets and is_custom_fetch and not wrapper_cfg:
        alt_mask, alt_targets = match_http_route(
            server_endpoints, http_method, normalize_route_mask(arg_raw, prepend_prefix="/api")
        )
        if alt_targets:
            route_mask, matched_targets, used_heuristic_prefix = alt_mask, alt_targets, True

    if matched_targets:
        tier = ConfidenceTier.PATTERN_MATCHED if ("{param}" in route_mask or used_heuristic_prefix) else ConfidenceTier.EXACT
        return {
            "protocol": "HTTP", "status": "linked", "targets": matched_targets,
            "endpoint_key": f"{http_method} {route_mask}", "method": http_method, "route_mask": route_mask,
            "tier": tier, "confidence": 0.92 if tier == ConfidenceTier.PATTERN_MATCHED else 1.0,
            "emit_unresolved_edge": False,
        }

    if is_wrapper_caller and ("${" in arg_raw or not has_static_route_segment(route_mask)):
        status = "wrapper_passthrough"
    elif "${" in arg_raw and not has_static_route_segment(route_mask):
        status = "unresolved_dynamic"
    else:
        status = "unmatched_static"
    return {
        "protocol": "HTTP", "status": status, "targets": [],
        "endpoint_key": f"{http_method} {route_mask}", "method": http_method, "route_mask": route_mask,
        "tier": ConfidenceTier.UNRESOLVED_DYNAMIC, "confidence": 0.0, "emit_unresolved_edge": False,
    }


def summarize_bridge_call_sites(
    js_call_sites: list[dict[str, Any]],
    server_endpoints: dict[tuple[str, str], list[str]],
    ipc_handlers: dict[str, list[str]],
    ipc_listeners: dict[str, list[str]],
    wrapper_map: dict[str, dict[str, Any]],
) -> tuple[set[tuple[str, str, str, str]], set[tuple[str, str, str]], set[tuple[str, str, str]], set[str]]:
    """Возвращает `(linked_quads, linked_calls, unmatched_calls, unmatched_callers)` для сравнения с `HEAD`."""
    linked_quads: set[tuple[str, str, str, str]] = set()
    linked_calls: set[tuple[str, str, str]] = set()
    unmatched_calls: set[tuple[str, str, str]] = set()
    unmatched_callers: set[str] = set()
    for cs in js_call_sites:
        res = resolve_client_call_site(cs, server_endpoints, ipc_handlers, ipc_listeners, wrapper_map)
        if res is None:
            continue
        proto, src_u, ep = res["protocol"], cs["caller_uri"], res["endpoint_key"]
        if res["status"] == "linked":
            linked_calls.add((proto, src_u, ep))
            for dst_u in res["targets"]:
                linked_quads.add((proto, src_u, dst_u, ep))
        elif res["status"] == "unmatched_static":
            unmatched_calls.add((proto, src_u, ep))
            unmatched_callers.add(src_u)
    return linked_quads, linked_calls, unmatched_calls, unmatched_callers


def diff_broken_bridges_vs_head(
    head_quads: set[tuple[str, str, str, str]],
    head_unmatched: set[tuple[str, str, str]],
    curr_quads: set[tuple[str, str, str, str]],
    curr_calls: set[tuple[str, str, str]],
    curr_unmatched: set[tuple[str, str, str]],
    max_items: int = 40,
) -> list[dict[str, Any]]:
    """Находит мосты `HEAD`, исчезнувшие на текущем диске при живом несовпавшем вызове клиента."""
    def _rel(u: str) -> str:
        return u.split("://", 1)[1].split("#", 1)[0] if "://" in u and u.split("://", 1)[0] in ("py", "ts", "js") else ""

    curr_triples = {(p, s, d) for p, s, d, _ in curr_quads}
    newly_unmatched_callers = {s for _, s, _ in (curr_unmatched - head_unmatched)}
    broken: list[dict[str, Any]] = []
    for proto, src_u, dst_u, ep in sorted(head_quads):
        if (proto, src_u, dst_u) in curr_triples or (proto, src_u, ep) in curr_calls:
            continue
        if (proto, src_u, ep) in curr_unmatched:
            reason = "route_or_handler_changed_or_removed"
        elif src_u in newly_unmatched_callers:
            reason = "client_endpoint_no_longer_matches_server"
        else:
            continue
        broken.append({
            "protocol": proto, "src_uri": src_u, "src_rel_path": _rel(src_u),
            "dst_uri": dst_u, "dst_rel_path": _rel(dst_u), "endpoint": ep, "reason": reason,
        })
    return broken[:max_items]


@dataclass(slots=True)
class BridgeCoverageTracker:
    """Счётчик покрытия клиентских HTTP/IPC вызовов без создания лишних рёбер в БД."""

    linked_exact: int = 0
    linked_pattern: int = 0
    wrapper_passthrough: int = 0
    unresolved_dynamic: int = 0
    unmatched_static: int = 0
    unresolved_samples: list[dict[str, Any]] = field(default_factory=list)
    unmatched_samples: list[dict[str, Any]] = field(default_factory=list)

    def record_linked(self, tier: ConfidenceTier) -> None:
        if tier == ConfidenceTier.EXACT:
            self.linked_exact += 1
        else:
            self.linked_pattern += 1

    def record_wrapper_passthrough(self) -> None:
        self.wrapper_passthrough += 1

    def record_unresolved(self, sample: dict[str, Any]) -> None:
        self.unresolved_dynamic += 1
        if len(self.unresolved_samples) < MAX_COVERAGE_SAMPLES:
            self.unresolved_samples.append(sample)

    def record_unmatched(self, sample: dict[str, Any]) -> None:
        self.unmatched_static += 1
        if len(self.unmatched_samples) < MAX_COVERAGE_SAMPLES:
            self.unmatched_samples.append(sample)

    def to_dict(self) -> dict[str, Any]:
        # `wrapper_passthrough` исключён как из ошибок, так и из знаменателя `total_client_calls`
        total_client_calls = (
            self.linked_exact + self.linked_pattern + self.unresolved_dynamic + self.unmatched_static
        )
        linked_total = self.linked_exact + self.linked_pattern
        coverage_ratio = round(linked_total / total_client_calls, 4) if total_client_calls > 0 else 1.0
        return {
            "total_client_calls": total_client_calls, "linked_exact": self.linked_exact,
            "linked_pattern": self.linked_pattern, "wrapper_passthrough": self.wrapper_passthrough,
            "unresolved_dynamic": self.unresolved_dynamic, "unmatched_static": self.unmatched_static,
            "coverage_ratio": coverage_ratio,
            "unresolved_samples": list(self.unresolved_samples),
            "unmatched_samples": list(self.unmatched_samples),
        }
