"""
Классификатор контрактных и внутренних правок (`signature_hash` vs `body_hash`) и снимок `HEAD` по `git cat-file --batch`.

Почему используется единый пакетный процесс `git cat-file --batch` и `git status --porcelain -z`:
1. Поштучный спавн `git show HEAD:<path>` на крупных диффах порождал бы сотни подпроцессов Windows.
   Один конвейерный запрос по `stdin`/`stdout` читает до `200` блобов `HEAD` за единицы миллисекунд
   и одновременно питает классификатор символов, проверку оборванных мостов и проверку удалённых модулей.
2. Формат `git status --porcelain -z` без экранирования возвращает оба пути (`old_path` и `new_path`)
   при переименованиях (`R`/`C`) и не теряет удалённые (`D`) файлы.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from backend.analyzers.code_graph.disk_state import JS_TS_EXTENSIONS, PY_EXTENSIONS
from backend.analyzers.code_graph.ts_js_parser import JsTsFileParseResult, parse_js_ts_file
from backend.analyzers.code_graph.ts_python_parser import PythonFileParseResult, parse_python_file
from backend.core.models import GraphNodeRecord, NodeType, RiskLevel, normalize_rel_path

MAX_BATCH_DIFF_FILES: int = 200
GIT_HEAD_CHECK_TIMEOUT_SEC: float = 2.5
GIT_BATCH_CAT_TIMEOUT_SEC: float = 8.0
GIT_STATUS_TIMEOUT_SEC: float = 5.0
_SYMBOL_NODE_TYPES: frozenset[NodeType] = frozenset(
    {NodeType.FUNCTION, NodeType.CLASS, NodeType.DATA_CONTRACT, NodeType.TEST}
)
_SYMBOL_NODE_TYPE_STRS: frozenset[str] = frozenset({"Function", "Class", "DataContract", "Test"})


@dataclass(slots=True)
class GitWorkingTreeStatus:
    """Структурированный срез незакоммиченных изменений (включая `old_path` переименований и `D`)."""

    changed_paths: list[str] = field(default_factory=list)
    deleted_paths: set[str] = field(default_factory=set)
    renamed_pairs: list[tuple[str, str]] = field(default_factory=list)
    has_uncommitted_changes: bool = False


@dataclass(slots=True)
class GitHeadSnapshot:
    """Результат единого пакетного чтения `HEAD` и сравнения символов с текущим индексом."""

    has_head: bool = False
    head_blobs: dict[str, bytes | None] = field(default_factory=dict)
    head_py_results: dict[str, PythonFileParseResult] = field(default_factory=dict)
    head_js_results: dict[str, JsTsFileParseResult] = field(default_factory=dict)
    head_symbols_by_rel: dict[str, dict[str, GraphNodeRecord]] = field(default_factory=dict)
    signature_changes: list[dict[str, Any]] = field(default_factory=list)
    body_only_changes: list[dict[str, Any]] = field(default_factory=list)


def inspect_git_working_tree(project_root: Path) -> GitWorkingTreeStatus:
    """
    Разбирает `git status --porcelain -z`, сохраняя ОБА пути (`old_path`, `new_path`) для `R`/`C`
    и помечая удалённые (`D`) файлы, чтобы `ImpactEngine` и `Preflight` не теряли оборванные импорты.
    """
    status = GitWorkingTreeStatus()
    if not (project_root / ".git").exists():
        return status
    try:
        proc = subprocess.run(
            ["git", "status", "--porcelain", "-z"],
            cwd=str(project_root),
            capture_output=True,
            timeout=GIT_STATUS_TIMEOUT_SEC,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        return status
    if proc.returncode != 0 or not proc.stdout:
        return status

    tokens = proc.stdout.split(b"\x00")
    changed: set[str] = set()
    idx = 0
    while idx < len(tokens):
        raw_entry = tokens[idx]
        idx += 1
        if not raw_entry or len(raw_entry) < 4:
            continue
        entry = raw_entry.decode("utf-8", errors="replace")
        xy = entry[:2]
        path1 = normalize_rel_path(entry[3:])
        if not path1:
            continue
        status.has_uncommitted_changes = True
        if xy[0] in ("R", "C") or xy[1] in ("R", "C"):
            old_path = ""
            if idx < len(tokens):
                old_path = normalize_rel_path(tokens[idx].decode("utf-8", errors="replace"))
                idx += 1
            changed.add(path1)
            if old_path:
                changed.add(old_path)
                if xy[0] == "R" or xy[1] == "R":
                    status.deleted_paths.add(old_path)
                    status.renamed_pairs.append((old_path, path1))
        else:
            changed.add(path1)
            if xy[0] == "D" or xy[1] == "D":
                status.deleted_paths.add(path1)

    status.changed_paths = sorted(changed)
    return status


def _has_git_head(project_root: Path) -> bool:
    if not (project_root / ".git").exists():
        return False
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            cwd=str(project_root),
            capture_output=True,
            timeout=GIT_HEAD_CHECK_TIMEOUT_SEC,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return proc.returncode == 0
    except Exception:
        return False


def _read_git_head_blobs_batch(project_root: Path, rel_paths: list[str]) -> dict[str, bytes | None] | None:
    """Читает блобы `HEAD:<rel_path>` для пакета файлов за один вызов `git cat-file --batch`."""
    if not rel_paths:
        return {}
    stdin_payload = "".join(f"HEAD:{rp}\n" for rp in rel_paths).encode("utf-8")
    try:
        proc = subprocess.run(
            ["git", "cat-file", "--batch"],
            cwd=str(project_root),
            input=stdin_payload,
            capture_output=True,
            timeout=GIT_BATCH_CAT_TIMEOUT_SEC,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        return None
    if proc.returncode != 0:
        return None

    raw = proc.stdout
    total = len(raw)
    pos = 0
    blobs: dict[str, bytes | None] = {}
    for rp in rel_paths:
        nl = raw.find(b"\n", pos)
        if nl < 0:
            return None
        header = raw[pos:nl]
        pos = nl + 1
        if header.endswith((b" missing", b" ambiguous")):
            blobs[rp] = None
            continue
        parts = header.rsplit(b" ", 2)
        if len(parts) != 3:
            return None
        try:
            size = int(parts[2])
        except ValueError:
            return None
        if pos + size > total:
            return None
        body = raw[pos : pos + size]
        pos += size
        if pos < total and raw[pos : pos + 1] == b"\n":
            pos += 1
        blobs[rp] = body if parts[1] == b"blob" else None
    return blobs


def _parse_head_file_result(
    rel_path: str, raw_bytes: bytes, snapshot: GitHeadSnapshot
) -> dict[str, GraphNodeRecord]:
    ext = Path(rel_path).suffix.lower()
    if ext in PY_EXTENSIONS:
        py_res = parse_python_file(rel_path, raw_bytes, RiskLevel.LOW)
        snapshot.head_py_results[rel_path] = py_res
        parsed_nodes = py_res.nodes
    elif ext in JS_TS_EXTENSIONS:
        js_res = parse_js_ts_file(rel_path, raw_bytes, RiskLevel.LOW)
        snapshot.head_js_results[rel_path] = js_res
        parsed_nodes = js_res.nodes
    else:
        return {}
    syms = {n.uri: n for n in parsed_nodes if n.node_type in _SYMBOL_NODE_TYPES}
    snapshot.head_symbols_by_rel[rel_path] = syms
    return syms


def analyze_head_snapshot_and_diff(
    project_root: Path,
    touched_rel_paths: set[str],
    current_nodes: list[dict[str, Any]],
) -> GitHeadSnapshot:
    """
    За ОДИН пакетный вызов `git cat-file --batch` загружает блобы `HEAD` для `touched_rel_paths`,
    сохраняет полные AST-результаты `HEAD` (маршруты, вызовы, символы) и классифицирует изменения.
    """
    snapshot = GitHeadSnapshot()
    if not touched_rel_paths or not _has_git_head(project_root):
        return snapshot
    snapshot.has_head = True

    curr_by_rel: dict[str, dict[str, dict[str, Any]]] = {}
    for nd in current_nodes:
        rp = str(nd.get("rel_path") or "")
        if rp in touched_rel_paths and nd.get("node_type") in _SYMBOL_NODE_TYPE_STRS:
            curr_by_rel.setdefault(rp, {})[str(nd["uri"])] = nd

    supported_exts = PY_EXTENSIONS | JS_TS_EXTENSIONS
    candidate_paths = [
        rp
        for rp in sorted(touched_rel_paths)
        if "\n" not in rp and "\r" not in rp and Path(rp).suffix.lower() in supported_exts
    ][:MAX_BATCH_DIFF_FILES]
    if not candidate_paths:
        return snapshot

    head_blobs = _read_git_head_blobs_batch(project_root, candidate_paths)
    if head_blobs is None:
        return snapshot
    snapshot.head_blobs = head_blobs

    for rel_path in candidate_paths:
        curr_syms = curr_by_rel.get(rel_path, {})
        head_bytes = head_blobs.get(rel_path)

        if head_bytes is None:
            for u, c_nd in sorted(curr_syms.items()):
                snapshot.signature_changes.append(
                    {
                        "uri": u,
                        "name": c_nd.get("name"),
                        "rel_path": rel_path,
                        "change_kind": "added",
                        "new_signature": c_nd.get("signature", ""),
                    }
                )
            continue

        head_syms = _parse_head_file_result(rel_path, head_bytes, snapshot)
        for u, c_nd in sorted(curr_syms.items()):
            h_nd = head_syms.get(u)
            if h_nd is None:
                snapshot.signature_changes.append(
                    {
                        "uri": u,
                        "name": c_nd.get("name"),
                        "rel_path": rel_path,
                        "change_kind": "added",
                        "new_signature": c_nd.get("signature", ""),
                    }
                )
            elif str(c_nd.get("signature_hash") or "") != h_nd.signature_hash:
                snapshot.signature_changes.append(
                    {
                        "uri": u,
                        "name": c_nd.get("name"),
                        "rel_path": rel_path,
                        "change_kind": "signature_modified",
                        "old_signature": h_nd.signature,
                        "new_signature": c_nd.get("signature", ""),
                    }
                )
            elif str(c_nd.get("body_hash") or "") != h_nd.body_hash:
                snapshot.body_only_changes.append(
                    {"uri": u, "name": c_nd.get("name"), "rel_path": rel_path}
                )

        for u, h_nd in sorted(head_syms.items()):
            if u not in curr_syms:
                snapshot.signature_changes.append(
                    {
                        "uri": u,
                        "name": h_nd.name,
                        "rel_path": rel_path,
                        "change_kind": "removed",
                        "old_signature": h_nd.signature,
                    }
                )

    return snapshot


def classify_symbol_changes_vs_git_head(
    project_root: Path,
    touched_rel_paths: set[str],
    current_nodes: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Сравнивает текущие символы в затронутых файлах с версией `HEAD` в Git (строго 1 вызов `git cat-file --batch`).
    Возвращает кортеж `(signature_changes, body_only_changes)`.
    """
    snap = analyze_head_snapshot_and_diff(project_root, touched_rel_paths, current_nodes)
    return snap.signature_changes, snap.body_only_changes
