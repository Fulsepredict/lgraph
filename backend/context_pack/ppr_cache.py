"""
Кэш легковесного снимка графа ревизии и разрежённого направленного Personalized PageRank.

Почему кэшируется полный снимок ревизии по `(db_path, project_id, index_revision)`:
1. Прямой SQL без `meta_json` и `json.loads` убирает узкое место загрузки на 50k узлах / 144k рёбрах.
2. Числовые списки переходов с демпфированием хабов `base_w / log2(2 + deg[v])` и направленными
   весами (`balanced` / `inbound` / `outbound`) преднормализуются один раз на `(revision, mode)`.
3. `threading.Lock` берётся строго на `O(1)` чтении/записи LRU-словарей, никогда не на SQL или PPR.
"""

from __future__ import annotations

import hashlib
import math
import threading
from array import array
from collections import OrderedDict
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from backend.storage.schema import open_sqlite_connection

BRIDGE_EDGE_WEIGHT: float = 2.8
DEFAULT_EDGE_WEIGHT: float = 1.0
DEFAULT_PPR_DAMPING: float = 0.82
DEFAULT_PPR_ITERATIONS: int = 16
MAX_CACHED_SNAPSHOTS: int = 4
MAX_CACHED_PPR_VECTORS: int = 64

# (множитель прямого ребра src->dst, множитель обратного ребра dst->src)
DIRECTION_MULTIPLIERS: dict[str, tuple[float, float]] = {
    "balanced": (1.0, 1.0),
    "inbound": (0.45, 1.8),
    "outbound": (1.8, 0.45),
}
_BRIDGE_EDGE_TYPES: frozenset[str] = frozenset({"BRIDGES_TO", "USES_CONTRACT"})


@dataclass(slots=True)
class ModeTransitions:
    outgoing: tuple[tuple[tuple[int, float], ...], ...]
    dangling_indices: tuple[int, ...]


@dataclass(slots=True)
class RevisionGraphSnapshot:
    db_path_resolved: str
    project_id: str
    index_revision: int
    graph_totals: tuple[int, int, int]  # (total_nodes, total_edges, total_critical_nodes)
    c4_nodes: tuple[dict[str, Any], ...]
    c3_nodes: tuple[dict[str, Any], ...]
    node_by_uri: dict[str, dict[str, Any]]
    nodes_by_rel_path: dict[str, tuple[dict[str, Any], ...]]
    rel_path_by_lower: dict[str, str]
    c4_indices_by_c3_parent: dict[str, tuple[int, ...]]
    critical_c4_indices: tuple[int, ...]
    uri_to_idx: dict[str, int]
    idx_to_uri: tuple[str, ...]
    inbound_by_dst: dict[str, tuple[str, ...]]
    outbound_by_src: dict[str, tuple[str, ...]]
    real_bridge_edges: tuple[dict[str, Any], ...]
    node_degree: tuple[int, ...]
    edge_src: array
    edge_dst: array
    edge_w: array
    transitions_by_mode: dict[str, ModeTransitions] = field(default_factory=dict)


_CACHE_LOCK = threading.Lock()
_SNAPSHOT_CACHE: OrderedDict[tuple[str, str, int, str], RevisionGraphSnapshot] = OrderedDict()
_PPR_VECTOR_CACHE: OrderedDict[tuple[str, str, int, str, str], dict[str, float]] = OrderedDict()


def clear_ppr_caches() -> None:
    """Очищает LRU-кэши снимков ревизий и векторов PPR."""
    with _CACHE_LOCK:
        _SNAPSHOT_CACHE.clear()
        _PPR_VECTOR_CACHE.clear()


def fetch_project_header(db_path: Path, project_id: str) -> dict[str, Any] | None:
    """Читает метаданные проекта и штамп `architectural_notes` в одном соединении без полного сканирования графа."""
    with closing(open_sqlite_connection(db_path)) as conn:
        row = conn.execute(
            "SELECT project_id, name, root_path, index_revision, is_stale FROM projects WHERE project_id = ?",
            (project_id,),
        ).fetchone()
        if not row:
            return None
        nt_row = conn.execute(
            "SELECT COUNT(*) AS cnt, COALESCE(MAX(updated_at_iso), '') AS max_ts, "
            "COALESCE(SUM(LENGTH(summary_ru) + LENGTH(risk_level)), 0) AS payload_len "
            "FROM architectural_notes WHERE project_id = ?",
            (project_id,),
        ).fetchone()
    hdr = dict(row)
    hdr["notes_stamp"] = f"{int(nt_row['cnt'])}:{nt_row['max_ts']}:{int(nt_row['payload_len'])}" if nt_row else "0::0"
    return hdr


def _lru_get(cache: OrderedDict[Any, Any], key: Any) -> Any:
    with _CACHE_LOCK:
        val = cache.get(key)
        if val is not None:
            cache.move_to_end(key)
        return val


def _lru_put(cache: OrderedDict[Any, Any], key: Any, value: Any, max_size: int) -> Any:
    with _CACHE_LOCK:
        existing = cache.get(key)
        if existing is not None:
            cache.move_to_end(key)
            return existing
        cache[key] = value
        while len(cache) > max_size:
            cache.popitem(last=False)
        return value


def _normalize_direction_mode(direction_mode: str) -> str:
    mode = str(direction_mode or "balanced").strip().lower()
    return mode if mode in DIRECTION_MULTIPLIERS else "balanced"


def _build_mode_transitions(
    node_count: int, node_degree: tuple[int, ...],
    edge_src: array, edge_dst: array, edge_w: array, direction_mode: str,
) -> ModeTransitions:
    fwd_mult, rev_mult = DIRECTION_MULTIPLIERS[direction_mode]
    inv_log_deg = [1.0 / math.log2(2.0 + d) for d in node_degree]
    adj_maps: list[dict[int, float]] = [{} for _ in range(node_count)]
    for s_idx, d_idx, base_w in zip(edge_src, edge_dst, edge_w):
        s_map, d_map = adj_maps[s_idx], adj_maps[d_idx]
        s_map[d_idx] = s_map.get(d_idx, 0.0) + (base_w * fwd_mult) * inv_log_deg[d_idx]
        d_map[s_idx] = d_map.get(s_idx, 0.0) + (base_w * rev_mult) * inv_log_deg[s_idx]

    outgoing_list: list[tuple[tuple[int, float], ...]] = []
    dangling: list[int] = []
    for idx, nb_map in enumerate(adj_maps):
        total_w = sum(nb_map.values()) if nb_map else 0.0
        if total_w <= 0.0:
            outgoing_list.append(())
            dangling.append(idx)
            continue
        inv_total = 1.0 / total_w
        outgoing_list.append(tuple((v, w * inv_total) for v, w in nb_map.items()))
    return ModeTransitions(outgoing=tuple(outgoing_list), dangling_indices=tuple(dangling))


def _load_revision_snapshot_from_db(
    db_path: Path, db_key: str, project_id: str, index_revision: int
) -> RevisionGraphSnapshot:
    # Читаем сырыми кортежами без `sqlite3.Row` и `meta_json` (0 вызовов `json.loads`)
    with closing(open_sqlite_connection(db_path)) as conn:
        conn.row_factory = None
        node_rows = conn.execute(
            "SELECT uri, node_type, name, rel_path, start_line, end_line, "
            "c4_level, risk_level, signature, summary_ru, parent_uri FROM nodes WHERE project_id = ?", (project_id,),
        ).fetchall()
        edge_rows = conn.execute(
            "SELECT src_uri, dst_uri, edge_type, confidence, confidence_tier, "
            "source_module, evidence FROM edges WHERE project_id = ?", (project_id,),
        ).fetchall()

    c4_list, c3_list, critical_indices, idx_to_uri_list = [], [], [], []
    node_by_uri, by_rel_tmp, rel_lower, c4_by_c3_tmp, uri_to_idx = {}, {}, {}, {}, {}
    total_critical = 0

    for row in node_rows:
        uri, ntype, rel_path = str(row[0]), str(row[1]), str(row[3] or "")
        c4_level, risk_level, parent_uri = int(row[6]), str(row[7] or "low"), str(row[10] or "")
        if risk_level == "critical":
            total_critical += 1
        rec = {
            "uri": uri, "node_type": ntype, "name": str(row[2]), "rel_path": rel_path,
            "start_line": int(row[4] or 0), "end_line": int(row[5] or 0), "c4_level": c4_level,
            "risk_level": risk_level, "signature": str(row[8] or ""), "summary_ru": str(row[9] or ""), "parent_uri": parent_uri,
        }
        node_by_uri[uri] = rec
        if ntype == "DomainModule":
            c3_list.append(rec)
        elif c4_level == 4:
            idx = len(c4_list)
            c4_list.append(rec)
            uri_to_idx[uri] = idx
            idx_to_uri_list.append(uri)
            if risk_level == "critical":
                critical_indices.append(idx)
            if rel_path:
                by_rel_tmp.setdefault(rel_path, []).append(rec)
                rel_lower.setdefault(rel_path.lower(), rel_path)
            if parent_uri.startswith("c3://"):
                c4_by_c3_tmp.setdefault(parent_uri, []).append(idx)

    idx_to_uri = tuple(idx_to_uri_list)
    degrees, edge_src, edge_dst, edge_w = [0] * len(c4_list), array("I"), array("I"), array("f")
    inbound_tmp: dict[str, list[str]] = {}
    outbound_tmp: dict[str, list[str]] = {}
    real_bridges: list[dict[str, Any]] = []

    for erow in edge_rows:
        etype, source_module = str(erow[2]), str(erow[5] or "")
        if etype == "CONTAINS" or source_module == "c4_rollup":
            continue
        raw_src, raw_dst = str(erow[0]), str(erow[1])
        s_idx, d_idx = uri_to_idx.get(raw_src), uri_to_idx.get(raw_dst)
        # Переиспользуем строки URI из `idx_to_uri` для снижения RAM на 144k рёбрах
        src_u = idx_to_uri[s_idx] if s_idx is not None else raw_src
        dst_u = idx_to_uri[d_idx] if d_idx is not None else raw_dst
        outbound_tmp.setdefault(src_u, []).append(dst_u)
        inbound_tmp.setdefault(dst_u, []).append(src_u)
        if etype in _BRIDGE_EDGE_TYPES:
            real_bridges.append({"src_uri": src_u, "dst_uri": dst_u, "edge_type": etype, "confidence": float(erow[3] or 0.0), "confidence_tier": str(erow[4] or ""), "source_module": source_module, "evidence": str(erow[6] or "")})
        if s_idx is not None and d_idx is not None and s_idx != d_idx:
            degrees[s_idx] += 1
            degrees[d_idx] += 1
            edge_src.append(s_idx)
            edge_dst.append(d_idx)
            edge_w.append(BRIDGE_EDGE_WEIGHT if etype in _BRIDGE_EDGE_TYPES else DEFAULT_EDGE_WEIGHT)

    return RevisionGraphSnapshot(
        db_key, project_id, index_revision, (len(node_rows), len(edge_rows), total_critical),
        tuple(c4_list), tuple(c3_list), node_by_uri, {k: tuple(v) for k, v in by_rel_tmp.items()},
        rel_lower, {k: tuple(v) for k, v in c4_by_c3_tmp.items()}, tuple(critical_indices),
        uri_to_idx, idx_to_uri, {k: tuple(dict.fromkeys(v)) for k, v in inbound_tmp.items()},
        {k: tuple(dict.fromkeys(v)) for k, v in outbound_tmp.items()},
        tuple(real_bridges), tuple(degrees), edge_src, edge_dst, edge_w,
    )


def get_or_load_revision_snapshot(
    db_path: Path, project_id: str, index_revision: int, notes_stamp: str = ""
) -> RevisionGraphSnapshot:
    """Возвращает снимок ревизии из LRU-кэша (max=4) или загружает его вне `_CACHE_LOCK`."""
    db_key = str(db_path.resolve())
    snap_key = (db_key, project_id, int(index_revision), str(notes_stamp or ""))
    cached = _lru_get(_SNAPSHOT_CACHE, snap_key)
    if cached is not None:
        return cached
    loaded = _load_revision_snapshot_from_db(db_path, db_key, project_id, int(index_revision))
    return _lru_put(_SNAPSHOT_CACHE, snap_key, loaded, MAX_CACHED_SNAPSHOTS)


def select_relevant_bridges(snapshot: RevisionGraphSnapshot, seed_uris: set[str]) -> list[dict[str, Any]]:
    """Возвращает межъязыковые мосты в 1-hop окрестности `seed_uris` (прямые попадания первыми)."""
    if not seed_uris:
        return list(snapshot.real_bridge_edges)
    one_hop = set(seed_uris)
    for u in seed_uris:
        one_hop.update(snapshot.outbound_by_src.get(u, ()))
        one_hop.update(snapshot.inbound_by_dst.get(u, ()))
    matched = [b for b in snapshot.real_bridge_edges if b["src_uri"] in one_hop or b["dst_uri"] in one_hop]
    matched.sort(key=lambda b: (0 if (b["src_uri"] in seed_uris or b["dst_uri"] in seed_uris) else 1, -float(b.get("confidence", 0.0)), b["src_uri"], b["dst_uri"]))
    return matched


def _get_or_build_transitions(snapshot: RevisionGraphSnapshot, direction_mode: str) -> ModeTransitions:
    with _CACHE_LOCK:
        cached = snapshot.transitions_by_mode.get(direction_mode)
    if cached is not None:
        return cached
    built = _build_mode_transitions(len(snapshot.idx_to_uri), snapshot.node_degree, snapshot.edge_src, snapshot.edge_dst, snapshot.edge_w, direction_mode)
    with _CACHE_LOCK:
        return snapshot.transitions_by_mode.setdefault(direction_mode, built)


def _run_sparse_ppr(
    node_count: int, transitions: ModeTransitions, seed_indices: list[int],
    damping: float = DEFAULT_PPR_DAMPING, iterations: int = DEFAULT_PPR_ITERATIONS,
) -> list[float]:
    if node_count == 0:
        return []
    seed_weight = (1.0 / len(seed_indices)) if seed_indices else (1.0 / node_count)
    scores = [0.0] * node_count if seed_indices else [seed_weight] * node_count
    for idx in seed_indices:
        scores[idx] = seed_weight
    outgoing, dangling, one_minus_d = transitions.outgoing, transitions.dangling_indices, 1.0 - damping
    for _ in range(iterations):
        base_mass = one_minus_d + damping * sum(scores[i] for i in dangling)
        next_scores = [0.0] * node_count if seed_indices else [base_mass / node_count] * node_count
        if seed_indices:
            tele = base_mass * seed_weight
            for idx in seed_indices:
                next_scores[idx] = tele
        for u, s_u in enumerate(scores):
            if s_u != 0.0 and outgoing[u]:
                scaled = damping * s_u
                for v, prob in outgoing[u]:
                    next_scores[v] += scaled * prob
        scores = next_scores
    return scores


def _hash_seeds(sorted_seeds: list[str], damping: float, iterations: int) -> str:
    base = "__all__" if not sorted_seeds else hashlib.sha256("\n".join(sorted_seeds).encode("utf-8")).hexdigest()[:24]
    return base if (damping == DEFAULT_PPR_DAMPING and iterations == DEFAULT_PPR_ITERATIONS) else f"{base}:{damping:.6f}:{iterations}"


def compute_cached_ppr(
    snapshot: RevisionGraphSnapshot, seed_uris: set[str], direction_mode: str = "balanced",
    damping: float = DEFAULT_PPR_DAMPING, iterations: int = DEFAULT_PPR_ITERATIONS,
) -> dict[str, float]:
    """Вычисляет или берёт из LRU-кэша (max=64) вектор PPR, всегда возвращая свежую копию словаря."""
    if not snapshot.idx_to_uri:
        return {}
    mode = _normalize_direction_mode(direction_mode)
    valid_seeds = sorted(u for u in seed_uris if u in snapshot.uri_to_idx)
    vec_key = (snapshot.db_path_resolved, snapshot.project_id, snapshot.index_revision, mode, _hash_seeds(valid_seeds, damping, iterations))
    cached = _lru_get(_PPR_VECTOR_CACHE, vec_key)
    if cached is not None:
        return dict(cached)
    transitions = _get_or_build_transitions(snapshot, mode)
    seed_idx = [snapshot.uri_to_idx[u] for u in valid_seeds]
    computed = dict(zip(snapshot.idx_to_uri, _run_sparse_ppr(len(snapshot.idx_to_uri), transitions, seed_idx, damping, iterations)))
    return dict(_lru_put(_PPR_VECTOR_CACHE, vec_key, computed, MAX_CACHED_PPR_VECTORS))


def run_ppr_from_raw_edges(
    node_uris: list[str], edges: list[dict[str, Any]], seed_uris: set[str],
    direction_mode: str = "balanced", damping: float = DEFAULT_PPR_DAMPING, iterations: int = DEFAULT_PPR_ITERATIONS,
) -> dict[str, float]:
    """Совместимый расчёт направленного hub-damped PPR по сырым спискам (масса `sum == 1.0`)."""
    unique_uris = list(dict.fromkeys(str(u) for u in node_uris))
    if not unique_uris:
        return {}
    mode = _normalize_direction_mode(direction_mode)
    uri_to_idx, n_count = {u: i for i, u in enumerate(unique_uris)}, len(unique_uris)
    degrees, edge_src, edge_dst, edge_w = [0] * n_count, array("I"), array("I"), array("f")
    for e in edges:
        etype = str(e.get("edge_type", ""))
        if etype == "CONTAINS" or e.get("source_module") == "c4_rollup":
            continue
        s_idx, d_idx = uri_to_idx.get(str(e["src_uri"])), uri_to_idx.get(str(e["dst_uri"]))
        if s_idx is not None and d_idx is not None and s_idx != d_idx:
            degrees[s_idx] += 1
            degrees[d_idx] += 1
            edge_src.append(s_idx)
            edge_dst.append(d_idx)
            edge_w.append(BRIDGE_EDGE_WEIGHT if etype in _BRIDGE_EDGE_TYPES else DEFAULT_EDGE_WEIGHT)
    transitions = _build_mode_transitions(n_count, tuple(degrees), edge_src, edge_dst, edge_w, mode)
    seed_indices = [uri_to_idx[u] for u in sorted(seed_uris) if u in uri_to_idx]
    return dict(zip(unique_uris, _run_sparse_ppr(n_count, transitions, seed_indices, damping, iterations)))
