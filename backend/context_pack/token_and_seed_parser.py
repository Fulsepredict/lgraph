"""
Калиброванный 3-корзинный токенизатор, детектор направления запроса и парсер `seed_uris`.

Почему вынесено из `builder.py`:
1. 3-корзинная оценка без внешних зависимостей устраняет занижение `-34.5%` на коде/путях.
2. Извлечение целей из `git diff` / стектрейсов и сегментный матч путей (`<= 40` seeds)
   защищают Personalized PageRank от разбухания на общих словах (`api`, `service`).
"""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

from backend.core.models import normalize_rel_path, to_project_rel_path
from backend.storage.note_telemetry_store import normalize_note_target_uri
from backend.storage.queries import GraphQueryService

TOKEN_DIV_ASCII_ALPHA_WS: float = 3.35
TOKEN_DIV_ASCII_PUNCT_DIGIT: float = 1.15
TOKEN_DIV_NON_ASCII: float = 2.75
TOKEN_SAFETY_MARGIN: float = 1.10

MAX_PATH_SEEDS_PER_QUERY: int = 40
FTS_SEED_LIMIT: int = 8

_ASCII_ALPHA_WS_BYTES: bytes = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz \t\n\r"
_ASCII_NON_ALPHA_WS_BYTES: bytes = bytes(b for b in range(128) if b not in _ASCII_ALPHA_WS_BYTES)

_EXPLICIT_DIRECTION_PREFIXES: tuple[tuple[str, str], ...] = (("impact:", "inbound"), ("understand:", "outbound"))
_INBOUND_PHRASES: tuple[str, ...] = ("кто сломается", "что сломается", "кого сломает", "who breaks", "blast radius")
_OUTBOUND_PHRASES: tuple[str, ...] = ("что понять", "как работает", "how works", "how does")
_INBOUND_WORD_RE = re.compile(r"\bcallers\b", re.IGNORECASE)
_OUTBOUND_WORD_RE = re.compile(r"\b(?:understand|callees)\b", re.IGNORECASE)

_DIFF_PLUS_RE = re.compile(r"^\+\+\+\s+(?:\"([^\"]+)\"|([^\t\r\n]+))")
_DIFF_HUNK_RE = re.compile(r"^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,(\d+))?\s+@@")
_PY_TRACEBACK_RE = re.compile(r"""File\s+["']([^"'\r\n]+)["'],\s+line\s+(\d+)""")
_JS_PAREN_TRACE_RE = re.compile(r"\(([^()\r\n]+?\.[A-Za-z][A-Za-z0-9]{0,5}):(\d+)(?::\d+)?\)")
_JS_BARE_TRACE_RE = re.compile(r"\bat\s+([^\s()\r\n]+?\.[A-Za-z][A-Za-z0-9]{0,5}):(\d+)(?::\d+)?")
_KEY_SYMBOL_TYPES: frozenset[str] = frozenset({"APIEndpoint", "IPCChannel", "DataContract"})


def estimate_tokens_raw(text: str) -> float:
    """Некруглённая 3-корзинная оценка токенов (строго аддитивна по конкатенации строк)."""
    if not text:
        return 0.0
    ascii_bytes = text.encode("ascii", "ignore")
    a_total = len(ascii_bytes)
    non_a = len(text) - a_total
    a_al = len(ascii_bytes.translate(None, _ASCII_NON_ALPHA_WS_BYTES))
    a_pu = a_total - a_al
    return (a_al / TOKEN_DIV_ASCII_ALPHA_WS) + (a_pu / TOKEN_DIV_ASCII_PUNCT_DIGIT) + (non_a / TOKEN_DIV_NON_ASCII)


def estimate_tokens_from_raw(raw_score: float) -> int:
    return max(1, int(math.ceil(raw_score * TOKEN_SAFETY_MARGIN)))


def estimate_tokens(text: str) -> int:
    """Калиброванная 3-корзинная оценка числа токенов без внешних зависимостей."""
    return estimate_tokens_from_raw(estimate_tokens_raw(text))


def _looks_like_diff_or_traceback(text: str) -> bool:
    return bool(
        ("+++ " in text and "@@ " in text)
        or _PY_TRACEBACK_RE.search(text)
        or _JS_PAREN_TRACE_RE.search(text)
        or _JS_BARE_TRACE_RE.search(text)
    )


def detect_query_direction(queries: list[str]) -> tuple[str, list[str]]:
    """Определяет направление PPR (`inbound` | `outbound` | `balanced`) и снимает префиксы `impact:`/`understand:`."""
    explicit_modes: list[str] = []
    inbound_hits = 0
    outbound_hits = 0
    cleaned: list[str] = []

    for raw in queries:
        item = raw.strip()
        if not item:
            continue
        low = item.lower()
        matched_prefix = False
        for prefix, mode in _EXPLICIT_DIRECTION_PREFIXES:
            if low.startswith(prefix):
                explicit_modes.append(mode)
                rest = item[len(prefix) :].strip()
                if rest:
                    cleaned.append(rest)
                matched_prefix = True
                break
        if matched_prefix:
            continue

        cleaned.append(item)
        # Тела diff/стектрейсов не анализируем по текстовым маркерам, чтобы слова в коде не сбивали режим
        if _looks_like_diff_or_traceback(item):
            continue
        if any(p in low for p in _INBOUND_PHRASES) or _INBOUND_WORD_RE.search(item):
            inbound_hits += 1
        if any(p in low for p in _OUTBOUND_PHRASES) or _OUTBOUND_WORD_RE.search(item):
            outbound_hits += 1

    if explicit_modes:
        return explicit_modes[0], cleaned
    if inbound_hits > outbound_hits:
        return "inbound", cleaned
    if outbound_hits > inbound_hits:
        return "outbound", cleaned
    return "balanced", cleaned


def _normalize_extracted_path(raw_path: str, project_root: Path, strip_git_b: bool = False) -> str:
    candidate = raw_path.strip().strip("\"'")
    if not candidate or candidate == "/dev/null":
        return ""
    if strip_git_b and candidate.startswith("b/"):
        candidate = candidate[2:]
    return to_project_rel_path(candidate, project_root)


def extract_diff_and_traceback_targets(
    queries: list[str],
    project_root: Path,
) -> list[tuple[str, int | None, int | None]]:
    """Парсит unified `git diff`, Python tracebacks и JS/TS stack traces в `(rel_path, start_line, end_line)`."""
    targets: list[tuple[str, int | None, int | None]] = []
    for text in queries:
        if not text:
            continue
        if "+++ " in text:
            current_path, path_had_hunk = "", False
            for line in text.splitlines():
                m_plus = _DIFF_PLUS_RE.match(line)
                if m_plus:
                    if current_path and not path_had_hunk:
                        targets.append((current_path, None, None))
                    raw_p = (m_plus.group(1) or m_plus.group(2) or "").strip()
                    current_path = _normalize_extracted_path(raw_p, project_root, strip_git_b=True)
                    path_had_hunk = False
                    continue
                if current_path:
                    m_hunk = _DIFF_HUNK_RE.match(line)
                    if m_hunk:
                        start = max(1, int(m_hunk.group(1)))
                        count = int(m_hunk.group(2)) if m_hunk.group(2) is not None else 1
                        targets.append((current_path, start, start if count <= 1 else start + count - 1))
                        path_had_hunk = True
            if current_path and not path_had_hunk:
                targets.append((current_path, None, None))

        for m_py in _PY_TRACEBACK_RE.finditer(text):
            rel = _normalize_extracted_path(m_py.group(1), project_root)
            if rel:
                ln = max(1, int(m_py.group(2)))
                targets.append((rel, ln, ln))
        for pattern in (_JS_PAREN_TRACE_RE, _JS_BARE_TRACE_RE):
            for m_js in pattern.finditer(text):
                rel = _normalize_extracted_path(m_js.group(1), project_root)
                if rel:
                    ln = max(1, int(m_js.group(2)))
                    targets.append((rel, ln, ln))
    return list(dict.fromkeys(targets))


def _resolve_rel_path_nodes(rel_path: str, snapshot: Any) -> tuple[str, tuple[dict[str, Any], ...]]:
    direct = snapshot.nodes_by_rel_path.get(rel_path)
    if direct is not None:
        return rel_path, direct
    canon = snapshot.rel_path_by_lower.get(rel_path.lower())
    return (canon, snapshot.nodes_by_rel_path.get(canon, ())) if canon is not None else (rel_path, ())


def _sort_path_seed_candidates(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        nodes,
        key=lambda nd: (
            0 if nd.get("risk_level") == "critical" else 1,
            0 if nd.get("node_type") == "File" else (1 if nd.get("node_type") in _KEY_SYMBOL_TYPES else 2),
            str(nd.get("rel_path") or ""),
            int(nd.get("start_line") or 0),
            str(nd["uri"]),
        ),
    )


def _path_matches_segment(rel_path: str, norm_q: str) -> bool:
    return rel_path == norm_q or rel_path.endswith("/" + norm_q) or f"/{norm_q}/" in f"/{rel_path}/"


def _looks_unsafe_or_external_path(raw_q: str) -> bool:
    slashed = raw_q.strip().replace("\\", "/")
    return (
        ".." in slashed.split("/")
        or slashed.lower().startswith("file://")
        or slashed.startswith(("/", "//"))
        or (len(slashed) >= 2 and slashed[1] == ":")
    )


def _register_c4_seed(
    nd: dict[str, Any], seed_uris: set[str], seed_paths: set[str], focused_c3_uris: set[str]
) -> None:
    seed_uris.add(str(nd["uri"]))
    rp = str(nd.get("rel_path") or "")
    if rp:
        seed_paths.add(rp)
    parent = str(nd.get("parent_uri") or "")
    if parent.startswith("c3://"):
        focused_c3_uris.add(parent)


def _match_exact_symbol_uri(query: str, project_root: Path, snapshot: Any) -> dict[str, Any] | None:
    norm_uri = normalize_note_target_uri(query)
    if norm_uri in snapshot.node_by_uri:
        return snapshot.node_by_uri[norm_uri]
    if "#" in query and "://" not in query:
        raw_path, sym = query.split("#", 1)
        rel = to_project_rel_path(raw_path, project_root)
        if rel and sym:
            canon_rel, _ = _resolve_rel_path_nodes(rel, snapshot)
            for scheme in ("py", "ts", "js"):
                cand = f"{scheme}://{canon_rel}#{sym}"
                if cand in snapshot.node_by_uri:
                    return snapshot.node_by_uri[cand]
    return None


def collect_seed_uris(
    project_id: str,
    queries: list[str],
    snapshot: Any,
    query_service: GraphQueryService,
    project_root: Path,
) -> tuple[set[str], set[str], set[str]]:
    """Собирает `seed_uris`, `seed_paths`, `focused_c3_uris` из diff/трейсов, URI, сегментов путей и FTS5."""
    seed_uris: set[str] = set()
    seed_paths: set[str] = set()
    focused_c3_uris: set[str] = set()

    for rel_path, start_line, end_line in extract_diff_and_traceback_targets(queries, project_root):
        canon_rel, file_nodes = _resolve_rel_path_nodes(rel_path, snapshot)
        if not file_nodes:
            continue
        if start_line is not None and end_line is not None:
            enclosed = [
                nd for nd in file_nodes
                if nd.get("node_type") != "File"
                and int(nd.get("start_line") or 0) <= end_line
                and int(nd.get("end_line") or 0) >= start_line
            ]
            chosen = enclosed or [nd for nd in file_nodes if nd.get("node_type") == "File"] or list(file_nodes[:1])
        else:
            chosen = list(file_nodes)
        for nd in _sort_path_seed_candidates(chosen)[:MAX_PATH_SEEDS_PER_QUERY]:
            _register_c4_seed(nd, seed_uris, seed_paths, focused_c3_uris)
        seed_paths.add(canon_rel)

    for q in queries:
        if _looks_like_diff_or_traceback(q):
            continue
        exact_node = _match_exact_symbol_uri(q, project_root, snapshot)
        if exact_node is not None:
            ntype, exact_uri = str(exact_node.get("node_type") or ""), str(exact_node["uri"])
            if ntype == "DomainModule":
                focused_c3_uris.add(exact_uri)
                children = [snapshot.c4_nodes[i] for i in snapshot.c4_indices_by_c3_parent.get(exact_uri, ())]
                for nd in _sort_path_seed_candidates(children)[:MAX_PATH_SEEDS_PER_QUERY]:
                    _register_c4_seed(nd, seed_uris, seed_paths, focused_c3_uris)
                continue
            if ntype != "File" and int(exact_node.get("c4_level") or 4) == 4:
                _register_c4_seed(exact_node, seed_uris, seed_paths, focused_c3_uris)
                continue

        rel_from_root = to_project_rel_path(q, project_root)
        if not rel_from_root and _looks_unsafe_or_external_path(q):
            continue
        norm_q = rel_from_root if rel_from_root else normalize_rel_path(q)
        if norm_q:
            for c3 in snapshot.c3_nodes:
                c3_rp = str(c3.get("rel_path") or "")
                if c3_rp and _path_matches_segment(c3_rp, norm_q):
                    focused_c3_uris.add(str(c3["uri"]))
            _, exact_file_nodes = _resolve_rel_path_nodes(norm_q, snapshot)
            if exact_file_nodes:
                for nd in _sort_path_seed_candidates(list(exact_file_nodes))[:MAX_PATH_SEEDS_PER_QUERY]:
                    _register_c4_seed(nd, seed_uris, seed_paths, focused_c3_uris)
                continue
            matched_c4 = [nd for rp, rns in snapshot.nodes_by_rel_path.items() if _path_matches_segment(rp, norm_q) for nd in rns]
            if matched_c4:
                for nd in _sort_path_seed_candidates(matched_c4)[:MAX_PATH_SEEDS_PER_QUERY]:
                    _register_c4_seed(nd, seed_uris, seed_paths, focused_c3_uris)

        for hit in query_service.search_nodes(project_id, q, limit=FTS_SEED_LIMIT):
            h_uri = str(hit["uri"])
            if hit.get("node_type") == "DomainModule":
                focused_c3_uris.add(h_uri)
            elif int(hit.get("c4_level", 4)) == 4:
                _register_c4_seed(hit, seed_uris, seed_paths, focused_c3_uris)

    for rp in seed_paths:
        for nd in snapshot.nodes_by_rel_path.get(rp, ()):
            parent = str(nd.get("parent_uri") or "")
            if parent.startswith("c3://"):
                focused_c3_uris.add(parent)
    return seed_uris, seed_paths, focused_c3_uris
