"""
Неблокирующий хук телеметрии `PostToolUse` для Google Antigravity (`hooks.json`).

Почему пишет только в `*_telemetry.sqlite3` и всегда возвращает `{}` с кодом `0`:
1. Хук вызывается синхронно после `read_file`/`edit_file` — любая ошибка или сбой I/O не должен
   блокировать цикл агента.
2. Основная БД `lgraph.sqlite3` не открывается вообще: запись идёт строго в отдельный файл
   `*_telemetry.sqlite3` через `GraphQueryService`, чтобы избежать конкуренции за блокировки SQLite.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.core.config import get_default_runtime_dir, validate_safe_project_root
from backend.core.models import to_project_rel_path
from backend.storage.queries import GraphQueryService
from backend.storage.repository import compute_project_id

READ_TOOL_NAMES: frozenset[str] = frozenset({"read_file", "view_file"})
EDIT_TOOL_NAMES: frozenset[str] = frozenset(
    {"edit_file", "write_file", "replace_file_content", "multi_replace_file_content"}
)
PATH_ARG_KEYS: tuple[str, ...] = (
    "Path",
    "AbsolutePath",
    "TargetFile",
    "path",
    "file_path",
    "target_file",
    "FilePath",
)
MAX_TASK_KEY_CHARS: int = 80


def _extract_target_path(args: dict[str, Any]) -> str:
    for key in PATH_ARG_KEYS:
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


def _resolve_workspace_and_rel_path(raw_target: str, payload: dict[str, Any]) -> tuple[Path, str] | None:
    candidates: list[str] = []
    ws_paths = payload.get("workspacePaths")
    if isinstance(ws_paths, list):
        candidates.extend(str(p).strip() for p in ws_paths if isinstance(p, str) and p.strip())
    cwd_val = payload.get("cwd")
    if isinstance(cwd_val, str) and cwd_val.strip() and cwd_val.strip() not in candidates:
        candidates.append(cwd_val.strip())

    for ws_raw in candidates:
        try:
            ws_root = validate_safe_project_root(ws_raw)
        except Exception:
            continue
        rel_path = to_project_rel_path(raw_target, ws_root)
        if rel_path:
            return ws_root, rel_path
    return None


def process_hook_payload(payload: dict[str, Any], runtime_dir: Path | None = None) -> bool:
    """Обрабатывает JSON-событие `PostToolUse` и обновляет `*_telemetry.sqlite3`."""
    if not isinstance(payload, dict) or payload.get("error"):
        return False

    tool_call = payload.get("toolCall")
    if not isinstance(tool_call, dict):
        return False

    tool_name = str(tool_call.get("name") or "").strip().lower()
    if tool_name not in READ_TOOL_NAMES and tool_name not in EDIT_TOOL_NAMES:
        return False

    args = tool_call.get("args")
    if not isinstance(args, dict):
        return False

    raw_target = _extract_target_path(args)
    if not raw_target:
        return False

    resolved = _resolve_workspace_and_rel_path(raw_target, payload)
    if resolved is None:
        return False
    ws_root, rel_path = resolved

    project_id = compute_project_id(ws_root)
    task_key = str(payload.get("conversationId") or "").strip()[:MAX_TASK_KEY_CHARS]
    effective_runtime = runtime_dir or get_default_runtime_dir()
    queries = GraphQueryService(effective_runtime / "lgraph.sqlite3")

    if tool_name in READ_TOOL_NAMES:
        queries.record_capsule_read(project_id, [rel_path], task_key=task_key)
        # Сбрасываем буфер чтения в `*_telemetry.sqlite3`, т.к. процесс хука завершается сразу после ответа
        queries.record_capsule_edits_and_score(project_id, [], task_key=task_key)
        return True

    queries.record_capsule_edits_and_score(project_id, [rel_path], task_key=task_key)
    return True


def main() -> int:
    try:
        raw_input = sys.stdin.read()
        if raw_input.strip():
            parsed = json.loads(raw_input)
            if isinstance(parsed, dict):
                process_hook_payload(parsed)
    except Exception:
        pass
    sys.stdout.write("{}\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
