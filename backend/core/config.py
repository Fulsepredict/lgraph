"""
Конфигурация ядра Lgraph, константы целевых лимитов и защита файлового периметра.

Почему вынесено в отдельный модуль:
Никаких «магических чисел» внутри парсеров или роутеров — все сетевые порты,
лимиты размера файлов и списки исключений управляются из единой точки.
"""

from __future__ import annotations

import os
import secrets
import stat
import subprocess
import threading
from pathlib import Path

# Выделенный локальный порт демона Lgraph (выбран 8765, чтобы не пересекаться с портами 3000/5173/8000)
DEFAULT_DAEMON_HOST: str = "127.0.0.1"
DEFAULT_DAEMON_PORT: int = 8765
TOKEN_HEADER_NAME: str = "X-Lgraph-Token"

# Текущая версия платформы и схемы парсера: при обновлении логики AST старый кэш SHA-256 обновится сам
LGRAPH_VERSION: str = "2.4.0"
PARSER_SCHEMA_VERSION: str = "2.4.0"

# Целевые архитектурные пороги по умолчанию
DEFAULT_MAX_FILE_LINES: int = 350
DEFAULT_MAX_OUTGOING_EDGES: int = 25
DEFAULT_TOKEN_BUDGET: int = 2500
MAX_TOKEN_BUDGET: int = 12000

# Защита от чтения гигантских сборок, дампов или минифицированных бандлов
MAX_SOURCE_FILE_BYTES: int = 2 * 1024 * 1024  # 2 МБ

# Папки (в нижнем регистре), которые всегда пропускаются при сканировании любых проектов
DEFAULT_IGNORED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".agent",
        ".idea",
        ".vscode",
        "node_modules",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "dist",
        "dist-electron",
        "build",
        "out",
        "release",
        "coverage",
        "htmlcov",
        ".next",
        ".nuxt",
        ".lgraph_runtime",
        "storage_data",
    }
)


def should_ignore_dir(dir_name: str) -> bool:
    """
    Регистронезависимая фильтрация служебных и релизных папок (например, `Desktop_Release`, `Release`, `.agent`).
    Почему без учёта регистра: на Windows сборочные папки часто называют с заглавных букв (`Desktop_Release`),
    и без `lower()` их дубли попадали бы в граф и список нарушений Guardrails.
    """
    low = dir_name.strip().lower()
    if not low or low in DEFAULT_IGNORED_DIRS:
        return True
    if low.endswith(("_release", "-release", "_build", "-build")) or low.startswith(("release_", "release-")):
        return True
    return False


_INDEX_LOCKS_GUARD = threading.Lock()
_PROJECT_INDEX_LOCKS: dict[str, threading.Lock] = {}


def get_project_index_lock(project_id: str) -> threading.Lock:
    """Возвращает персональную блокировку записи индекса проекта (защита от гонки Watchdog и /reindex)."""
    with _INDEX_LOCKS_GUARD:
        lock = _PROJECT_INDEX_LOCKS.get(project_id)
        if lock is None:
            lock = threading.Lock()
            _PROJECT_INDEX_LOCKS[project_id] = lock
        return lock

# Расширения бинарных и служебных файлов, не подлежащих текстовому парсингу
BINARY_OR_SKIPPED_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf",
        ".zip", ".tar", ".gz", ".7z", ".rar", ".exe", ".dll", ".pyd", ".so",
        ".dylib", ".db", ".sqlite", ".sqlite3", ".session", ".woff", ".woff2",
        ".ttf", ".eot", ".mp3", ".mp4", ".wav", ".gguf", ".bin", ".lock",
    }
)

# Флаг Windows NTFS Reparse Point (перехватывает как симлинки, так и Directory Junctions mklink /J)
WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT: int = 0x0400


def is_reparse_or_symlink(path: Path) -> bool:
    """
    Проверяет, не является ли путь символической ссылкой или NTFS Junction.
    Почему это важно: злонамеренный или битый симлинк внутри чужого репозитория
    мог бы увести сканер за пределы папки проекта (например, в системные папки Windows).
    """
    try:
        st = os.lstat(path)
    except OSError:
        return True
    if stat.S_ISLNK(st.st_mode):
        return True
    file_attrs = getattr(st, "st_file_attributes", 0)
    return bool(file_attrs & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT)


def validate_safe_project_root(raw_path: str | Path) -> Path:
    """
    Валидирует корневую директорию открываемого проекта перед индексацией.
    """
    if not raw_path or not str(raw_path).strip():
        raise ValueError("Путь к папке проекта не может быть пустым.")
    candidate = Path(str(raw_path).strip())
    if is_reparse_or_symlink(candidate):
        raise ValueError(f"Отклонено по безопасности: корень проекта не может быть симлинком/Junction ({candidate}).")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"Указанный путь не является директорией: {resolved}")
    return resolved


def get_default_runtime_dir() -> Path:
    """Возвращает рабочую папку локального демона (БД и токен доступа)."""
    env_override = os.getenv("LGRAPH_RUNTIME_DIR", "").strip()
    if env_override:
        target = Path(env_override).resolve()
    else:
        # Храним служебную БД и токен внутри корня Lgraph/.lgraph_runtime
        project_root = Path(__file__).resolve().parents[2]
        target = project_root / ".lgraph_runtime"
    target.mkdir(parents=True, exist_ok=True)
    return target


def restrict_token_file_acl(token_file: Path) -> None:
    """Ограничивает права чтения файла токена строго текущим пользователем ОС (`icacls` / `0600`)."""
    if not token_file.is_file():
        return
    if os.name == "nt":
        username = os.getenv("USERNAME", "").strip()
        if username:
            try:
                subprocess.run(
                    ["icacls", str(token_file), "/inheritance:r", "/grant:r", f"{username}:(R,W)"],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except OSError:
                pass
    else:
        try:
            os.chmod(token_file, 0o600)
        except OSError:
            pass


def ensure_local_daemon_token(runtime_dir: Path | None = None) -> str:
    """
    Создаёт или читает одноразовый локальный 256-битный токен защиты API.
    Почему нужен токен даже на 127.0.0.1: без токена любая открытая в браузере
    страница могла бы отправить фоновый запрос на localhost и прочитать карту проектов.
    """
    base_dir = runtime_dir or get_default_runtime_dir()
    base_dir.mkdir(parents=True, exist_ok=True)
    token_file = base_dir / "daemon.token"

    env_token = os.getenv("LGRAPH_API_TOKEN", "").strip()
    if len(env_token) >= 32:
        restrict_token_file_acl(token_file)
        return env_token

    if token_file.is_file():
        existing = token_file.read_text(encoding="utf-8").strip()
        if len(existing) >= 32:
            restrict_token_file_acl(token_file)
            return existing

    fresh_token = secrets.token_hex(32)
    token_file.write_text(fresh_token, encoding="utf-8")
    restrict_token_file_acl(token_file)
    return fresh_token
