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
LGRAPH_VERSION: str = "2.4.1"
PARSER_SCHEMA_VERSION: str = "2.4.1"

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
    Отклоняет UNC-пути (защита от утечки NTLM и блокировки на внешнем SMB) и промежуточные NTFS Junctions.
    """
    if raw_path is None:
        raise ValueError("Путь к папке проекта не может быть пустым.")
    raw_str = str(raw_path).strip()
    if not raw_str or "\x00" in raw_str:
        raise ValueError("Путь к папке проекта не может быть пустым или содержать нулевые байты.")

    if raw_str.startswith("\\\\") or raw_str.startswith("//") or raw_str.upper().startswith("\\\\?\\UNC\\"):
        raise ValueError(f"Отклонено по безопасности: сетевые UNC-пути запрещены ({raw_str}).")

    # Используем abspath вместо resolve, чтобы не перепрыгнуть симлинк/Junction до проверки сегментов
    abs_path = Path(os.path.abspath(raw_str))
    if os.path.lexists(abs_path) and is_reparse_or_symlink(abs_path):
        raise ValueError(f"Отклонено по безопасности: корень проекта не может быть симлинком/Junction ({abs_path}).")
    if not abs_path.is_dir():
        raise ValueError(f"Указанный путь не является директорией: {abs_path}")

    for cur in (abs_path, *abs_path.parents):
        if cur == cur.parent:
            break
        if is_reparse_or_symlink(cur):
            raise ValueError(
                f"Отклонено по безопасности: обнаружен симлинк или NTFS Junction в пути проекта ({cur})."
            )

    resolved = abs_path.resolve(strict=True)
    if str(resolved).startswith("\\\\"):
        raise ValueError(f"Отклонено по безопасности: путь разрешается в сетевой UNC-ресурс ({resolved}).")
    return resolved


def restrict_path_acl(target_path: Path, is_dir: bool = False) -> None:
    """Ограничивает права доступа к папке или файлу строго текущим пользователем ОС (`icacls` / `0700`/`0600`)."""
    if is_dir and not target_path.is_dir():
        return
    if not is_dir and not target_path.is_file():
        return
    if os.name == "nt":
        username = os.getenv("USERNAME", "").strip()
        if username:
            grant_spec = f"{username}:(OI)(CI)F" if is_dir else f"{username}:(R,W,D)"
            try:
                subprocess.run(
                    ["icacls", str(target_path), "/inheritance:r", "/grant:r", grant_spec],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except OSError:
                pass
    else:
        try:
            os.chmod(target_path, 0o700 if is_dir else 0o600)
        except OSError:
            pass


def restrict_token_file_acl(token_file: Path) -> None:
    """Ограничивает права чтения файла токена строго текущим пользователем ОС."""
    restrict_path_acl(token_file, is_dir=False)


def get_default_runtime_dir() -> Path:
    """Возвращает рабочую папку локального демона (БД и токен доступа)."""
    env_override = os.getenv("LGRAPH_RUNTIME_DIR", "").strip()
    if env_override:
        target = Path(env_override).resolve()
    else:
        project_root = Path(__file__).resolve().parents[2]
        target = project_root / ".lgraph_runtime"
    target.mkdir(parents=True, exist_ok=True)
    restrict_path_acl(target, is_dir=True)
    return target


def ensure_local_daemon_token(runtime_dir: Path | None = None) -> str:
    """
    Создаёт или читает одноразовый локальный 256-битный токен защиты API.
    Почему нужен токен даже на 127.0.0.1: без токена любая открытая в браузере
    страница могла бы отправить фоновый запрос на localhost и прочитать карту проектов.
    """
    base_dir = runtime_dir or get_default_runtime_dir()
    base_dir.mkdir(parents=True, exist_ok=True)
    restrict_path_acl(base_dir, is_dir=True)
    token_file = base_dir / "daemon.token"

    env_token = os.getenv("LGRAPH_API_TOKEN", "").strip()
    if len(env_token) >= 32:
        restrict_path_acl(token_file, is_dir=False)
        return env_token

    if token_file.is_file():
        existing = token_file.read_text(encoding="utf-8").strip()
        if len(existing) >= 32:
            restrict_path_acl(token_file, is_dir=False)
            return existing

    fresh_token = secrets.token_hex(32)
    token_file.write_text(fresh_token, encoding="utf-8")
    restrict_path_acl(token_file, is_dir=False)
    return fresh_token
