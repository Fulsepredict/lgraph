"""
Фоновый наблюдатель файловой системы (Watchdog) с защитой от шторма событий (Debounce).

Почему здесь применён Debounce (окно тишины 450 мс) и отслеживание `.git/HEAD`:
При сохранении нескольких файлов в IDE или выполнении `git checkout` операционная система
присылает десятки файловых уведомлений подряд. Вместо запуска 30 тяжёлых пересборок подряд
наблюдатель мгновенно помечает проект флагом `is_stale = 1` и запускает одну пакетную
переиндексацию через 450 мс после последнего изменения (используя SHA-256 кэш).
"""

from __future__ import annotations

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
        self._repo = repo
        self._lock = threading.Lock()
        self._timer: threading.Timer | None = None

    def on_any_event(self, event: FileSystemEvent) -> None:
        src = str(getattr(event, "src_path", "") or "")
        if not src:
            return
        norm = src.replace("\\", "/")
        parts = [p for p in norm.split("/") if p]

        # Реагируем на смену ветки Git (`.git/HEAD`), но игнорируем внутренний мусор `.git/objects`
        is_git_head = norm.endswith("/.git/HEAD")
        if not is_git_head:
            if any(should_ignore_dir(p) for p in parts[:-1]):
                return
            suffix = Path(src).suffix.lower()
            if suffix not in _WATCHED_SUFFIXES:
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
