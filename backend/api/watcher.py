"""
Фоновый наблюдатель файловой системы (Watchdog) с защитой от шторма событий (Debounce).

Почему здесь применён Debounce (окно тишины 450 мс) и отслеживание `.git/HEAD`:
При сохранении нескольких файлов в IDE или выполнении `git checkout` операционная система
присылает десятки файловых уведомлений подряд. Вместо запуска 30 тяжёлых пересборок подряд
наблюдатель мгновенно помечает проект флагом `is_stale = 1` и запускает одну пакетную
переиндексацию через 450 мс после последнего изменения (используя SHA-256 кэш).
"""

from __future__ import annotations

import os
import threading
from contextlib import closing
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from backend.analyzers.code_graph.scanner import index_project_directory
from backend.core.config import should_ignore_dir
from backend.storage.repository import GraphRepository
from backend.storage.schema import open_sqlite_connection

_WATCHED_SUFFIXES: frozenset[str] = frozenset(
    {".py", ".js", ".cjs", ".mjs", ".jsx", ".ts", ".tsx", ".yaml", ".yml"}
)
_DEBOUNCE_SECONDS: float = 0.45


class _DebouncedProjectHandler(FileSystemEventHandler):
    """Группирует серию быстрых правок диска в одну фоновую переиндексацию."""

    def __init__(self, project_id: str, project_root: Path, repo: GraphRepository) -> None:
        super().__init__()
        self._project_id = project_id
        self._project_root = project_root
        raw_norm = os.path.normpath(str(project_root)).replace("\\", "/").rstrip("/")
        res_norm = str(project_root.resolve()).replace("\\", "/").rstrip("/")
        self._root_prefixes: tuple[str, ...] = tuple(dict.fromkeys(p for p in (res_norm, raw_norm) if p))
        self._repo = repo
        self._lock = threading.Lock()
        self._timer: threading.Timer | None = None

    def _is_tracked_event_path(self, raw_path: str | bytes) -> bool:
        """
        Проверяет путь строго относительно `self._project_root`, чтобы родительские папки ОС
        вне корня проекта (например, `D:\\release\\my_service`) не блокировали наблюдение.
        """
        text = os.fsdecode(raw_path).strip() if raw_path else ""
        if not text:
            return False
        norm_p = os.path.normpath(text).replace("\\", "/").rstrip("/")
        cmp_p = norm_p.lower() if os.name == "nt" else norm_p

        rel_parts: list[str] | None = None
        for root_pref in self._root_prefixes:
            cmp_r = root_pref.lower() if os.name == "nt" else root_pref
            if cmp_p.startswith(cmp_r + "/"):
                rel = norm_p[len(root_pref) + 1 :]
                rel_parts = [seg for seg in rel.split("/") if seg and seg != "."]
                break
        if not rel_parts:
            return False

        # Реагируем на смену ветки Git (`.git/HEAD`), но игнорируем внутренний мусор `.git/objects`
        if rel_parts == [".git", "HEAD"]:
            return True
        if any(should_ignore_dir(p) for p in rel_parts[:-1]):
            return False
        fname = rel_parts[-1]
        if fname in (".lgraphignore", ".projectgraphignore"):
            return True
        return Path(fname).suffix.lower() in _WATCHED_SUFFIXES

    def on_any_event(self, event: FileSystemEvent) -> None:
        src = getattr(event, "src_path", "") or ""
        dest = getattr(event, "dest_path", "") or ""
        if not (self._is_tracked_event_path(src) or self._is_tracked_event_path(dest)):
            return

        self._mark_project_stale()
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
            self._timer = threading.Timer(_DEBOUNCE_SECONDS, self._run_reindex_safe)
            self._timer.daemon = True
            self._timer.start()

    def cancel_pending(self) -> None:
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None

    def _mark_project_stale(self) -> None:
        try:
            with closing(open_sqlite_connection(self._repo.db_path)) as conn:
                with conn:
                    conn.execute(
                        "UPDATE projects SET is_stale = 1 WHERE project_id = ?",
                        (self._project_id,),
                    )
        except Exception:
            pass

    def _run_reindex_safe(self) -> None:
        try:
            index_project_directory(self._project_root, self._repo)
        except Exception:
            pass


class ProjectWatcherManager:
    """Управляет жизненным циклом файловых наблюдателей для открытых проектов."""

    def __init__(self, repo: GraphRepository) -> None:
        self._repo = repo
        self._lock = threading.Lock()
        self._watchers: dict[str, tuple[Observer, _DebouncedProjectHandler]] = {}

    def ensure_watching(self, project_id: str, project_root: Path) -> None:
        with self._lock:
            if project_id in self._watchers:
                return
            handler = _DebouncedProjectHandler(project_id, project_root, self._repo)
            observer = Observer()
            observer.daemon = True
            observer.schedule(handler, str(project_root), recursive=True)
            observer.start()
            self._watchers[project_id] = (observer, handler)

    def stop_all(self) -> None:
        with self._lock:
            items = list(self._watchers.values())
            self._watchers.clear()
        for observer, handler in items:
            handler.cancel_pending()
            try:
                observer.stop()
                observer.join(timeout=2.0)
            except Exception:
                pass
