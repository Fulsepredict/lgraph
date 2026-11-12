"""
Классификатор контрактных и внутренних правок (`signature_hash` vs `body_hash`) по `git cat-file --batch`.

Почему используется единый пакетный процесс `git cat-file --batch`:
1. Поштучный спавн `git show HEAD:<path>` на крупных диффах порождал бы сотни подпроцессов Windows.
   Один конвейерный запрос по `stdin`/`stdout` читает до `200` блобов `HEAD` за единицы миллисекунд.
2. Если изменилась только реализация цикла (`body_hash`), внешний контракт (`signature_hash`) чист;
   при изменении сигнатуры или удалении функции модуль фиксирует риск поломки потребителей.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from backend.analyzers.code_graph.disk_state import JS_TS_EXTENSIONS, PY_EXTENSIONS
from backend.analyzers.code_graph.ts_js_parser import parse_js_ts_file
from backend.analyzers.code_graph.ts_python_parser import parse_python_file
from backend.core.models import GraphNodeRecord, NodeType, RiskLevel

MAX_BATCH_DIFF_FILES: int = 200
GIT_HEAD_CHECK_TIMEOUT_SEC: float = 2.5
GIT_BATCH_CAT_TIMEOUT_SEC: float = 8.0


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


def _parse_symbols_in_memory(rel_path: str, raw_bytes: bytes) -> dict[str, GraphNodeRecord]:
    ext = Path(rel_path).suffix.lower()
    if ext in PY_EXTENSIONS:
        parsed_nodes = parse_python_file(rel_path, raw_bytes, RiskLevel.LOW).nodes
    elif ext in JS_TS_EXTENSIONS:
        parsed_nodes = parse_js_ts_file(rel_path, raw_bytes, RiskLevel.LOW).nodes
    else:
        return {}
    return {
        n.uri: n
        for n in parsed_nodes
        if n.node_type in (NodeType.FUNCTION, NodeType.CLASS, NodeType.DATA_CONTRACT, NodeType.TEST)
    }


def classify_symbol_changes_vs_git_head(
    project_root: Path,
    touched_rel_paths: set[str],
    current_nodes: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Сравнивает текущие символы в затронутых файлах с версией `HEAD` в Git.
    Возвращает кортеж `(signature_changes, body_only_changes)`.
    """
    if not touched_rel_paths or not _has_git_head(project_root):
        return [], []

    curr_by_rel: dict[str, dict[str, dict[str, Any]]] = {}
    for nd in current_nodes:
        rp = str(nd.get("rel_path") or "")
        if rp in touched_rel_paths and nd.get("node_type") in ("Function", "Class", "DataContract", "Test"):
            curr_by_rel.setdefault(rp, {})[str(nd["uri"])] = nd

    supported_exts = PY_EXTENSIONS | JS_TS_EXTENSIONS
    candidate_paths = [
        rp
        for rp in sorted(touched_rel_paths)
        if "\n" not in rp and "\r" not in rp and Path(rp).suffix.lower() in supported_exts
    ][:MAX_BATCH_DIFF_FILES]
    if not candidate_paths:
        return [], []

    head_blobs = _read_git_head_blobs_batch(project_root, candidate_paths)
    if head_blobs is None:
        return [], []

    signature_changes: list[dict[str, Any]] = []
    body_only_changes: list[dict[str, Any]] = []

    for rel_path in candidate_paths:
        curr_syms = curr_by_rel.get(rel_path, {})
        head_bytes = head_blobs.get(rel_path)

        # Новый файл, которого ещё не было в HEAD
        if head_bytes is None:
            for u, c_nd in sorted(curr_syms.items()):
                signature_changes.append(
                    {
                        "uri": u,
                        "name": c_nd.get("name"),
                        "rel_path": rel_path,
                        "change_kind": "added",
                        "new_signature": c_nd.get("signature", ""),
                    }
                )
            continue

        head_syms = _parse_symbols_in_memory(rel_path, head_bytes)

        for u, c_nd in sorted(curr_syms.items()):
            h_nd = head_syms.get(u)
            if h_nd is None:
                signature_changes.append(
                    {
                        "uri": u,
                        "name": c_nd.get("name"),
                        "rel_path": rel_path,
                        "change_kind": "added",
                        "new_signature": c_nd.get("signature", ""),
                    }
                )
            elif str(c_nd.get("signature_hash") or "") != h_nd.signature_hash:
                signature_changes.append(
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
                body_only_changes.append(
                    {
                        "uri": u,
                        "name": c_nd.get("name"),
                        "rel_path": rel_path,
                    }
                )

        for u, h_nd in sorted(head_syms.items()):
            if u not in curr_syms:
                signature_changes.append(
                    {
                        "uri": u,
                        "name": h_nd.name,
                        "rel_path": rel_path,
                        "change_kind": "removed",
                        "old_signature": h_nd.signature,
                    }
                )

    return signature_changes, body_only_changes
