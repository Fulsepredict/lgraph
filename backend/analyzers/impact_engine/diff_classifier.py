"""
Классификатор контрактных и внутренних правок (`signature_hash` vs `body_hash`) по `git show HEAD`.

Почему это важно для ИИ-агентов и владельца проекта:
Если разработчик или ИИ ускорил цикл внутри функции, меняется только `body_hash`,
а внешний контракт (`signature_hash`: имя, аргументы, возвращаемый тип и декоратор маршрута)
остаётся нетронутым. Если же изменилась сигнатура или удалена функция — модуль явно
помечает это в `signature_changes`, предупреждая о риске поломки вызывающего кода.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from backend.analyzers.code_graph.disk_state import JS_TS_EXTENSIONS, PY_EXTENSIONS
from backend.analyzers.code_graph.ts_js_parser import parse_js_ts_file
from backend.analyzers.code_graph.ts_python_parser import parse_python_file
from backend.core.models import GraphNodeRecord, NodeType, RiskLevel


def _has_git_head(project_root: Path) -> bool:
    if not (project_root / ".git").exists():
        return False
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            cwd=str(project_root),
            capture_output=True,
            timeout=2.5,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return proc.returncode == 0
    except Exception:
        return False


def _read_git_head_bytes(project_root: Path, rel_path: str) -> bytes | None:
    try:
        proc = subprocess.run(
            ["git", "show", f"HEAD:{rel_path}"],
            cwd=str(project_root),
            capture_output=True,
            timeout=3.0,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if proc.returncode == 0:
            return proc.stdout
    except Exception:
        pass
    return None


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

    signature_changes: list[dict[str, Any]] = []
    body_only_changes: list[dict[str, Any]] = []

    for rel_path in sorted(touched_rel_paths):
        ext = Path(rel_path).suffix.lower()
        if ext not in PY_EXTENSIONS and ext not in JS_TS_EXTENSIONS:
            continue

        curr_syms = curr_by_rel.get(rel_path, {})
        head_bytes = _read_git_head_bytes(project_root, rel_path)

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
