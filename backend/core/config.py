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
import tempfile
import threading
from pathlib import Path

# Выделенный локальный порт демона Lgraph (выбран 8765, чтобы не пересекаться с портами 3000/5173/8000)
DEFAULT_DAEMON_HOST: str = "127.0.0.1"
DEFAULT_DAEMON_PORT: int = 8765
TOKEN_HEADER_NAME: str = "X-Lgraph-Token"

# Текущая версия платформы и схемы парсера: при обновлении логики AST старый кэш SHA-256 обновится сам
LGRAPH_VERSION: str = "2.4.2"
PARSER_SCHEMA_VERSION: str = "2.4.2"

# Целевые архитектурные пороги по умолчанию
DEFAULT_MAX_FILE_LINES: int = 350
DEFAULT_MAX_OUTGOING_EDGES: int = 25
DEFAULT_TOKEN_BUDGET: int = 2500
MAX_TOKEN_BUDGET: int = 12000
MAX_SOURCE_FILE_BYTES: int = 2 * 1024 * 1024  # 2 МБ

# Папки (в нижнем регистре), которые всегда пропускаются при сканировании любых проектов
DEFAULT_IGNORED_DIRS: frozenset[str] = frozenset(
    {
        ".git", ".hg", ".svn", ".agent", ".idea", ".vscode", "node_modules",
        ".venv", "venv", "env", "__pycache__", ".pytest_cache", ".mypy_cache",
        ".ruff_cache", "dist", "dist-electron", "build", "out", "release",
        "coverage", "htmlcov", ".next", ".nuxt", ".lgraph_runtime", "storage_data",
    }
)


def should_ignore_dir(dir_name: str) -> bool:
    """Регистронезависимая фильтрация служебных и релизных папок (`Desktop_Release`, `.agent`, `build`)."""
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

# NameSurrogate (0x20000000) ловит Symlinks/NTFS Junctions/WSL, AppExecLink (0x8000001B) — алиасы WindowsApps;
# облачные папки OneDrive (`IO_REPARSE_TAG_CLOUD` `0x9000xxxx`), WOF и ProjFS не блокируются
WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT: int = 0x0400
WINDOWS_REPARSE_TAG_NAME_SURROGATE_BIT: int = 0x20000000
WINDOWS_REPARSE_TAG_APPEXECLINK: int = 0x8000001B


def is_reparse_or_symlink(path: Path) -> bool:
    """
    Проверяет симлинки, NTFS Junctions и AppExecLink; при `st_reparse_tag == 0` на точке
    повторной обработки срабатывает fail-closed (`True`), а OneDrive/WOF/ProjFS разрешены.
    """
    try:
        st = os.lstat(path)
    except OSError:
        return True
    if stat.S_ISLNK(st.st_mode):
        return True
    file_attrs = getattr(st, "st_file_attributes", 0)
    if not (file_attrs & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT):
        return False
    tag = int(getattr(st, "st_reparse_tag", 0) or 0)
    if tag == 0:
        return True
    return bool(tag & WINDOWS_REPARSE_TAG_NAME_SURROGATE_BIT) or tag == WINDOWS_REPARSE_TAG_APPEXECLINK


def _is_win32_local_drive_rest(rest: str) -> bool:
    return len(rest) >= 3 and rest[0].isascii() and rest[0].isalpha() and rest[1] == ":" and rest[2] == "\\"


def _normalize_win32_extended_local_path(raw_str: str) -> str:
    r"""
    Отклоняет UNC-пути и пути устройств (`\\.\`, `\??\`), снимая префикс `\\?\`
    строго для локальных дисковых путей `\\?\X:\...`.
    """
    slashed = raw_str.replace("/", "\\")
    if slashed.upper().startswith("\\\\?\\UNC\\"):
        raise ValueError(f"Отклонено по безопасности: сетевые UNC-пути запрещены ({raw_str}).")
    if raw_str.startswith("\\\\?\\"):
        rest = raw_str[4:]
        if _is_win32_local_drive_rest(rest):
            return rest
        raise ValueError(
            f"Отклонено по безопасности: сетевые UNC-пути запрещены; пути устройств не допускаются ({raw_str})."
        )
    if slashed.startswith("\\\\.\\") or slashed.startswith("\\??\\"):
        raise ValueError(
            f"Отклонено по безопасности: сетевые UNC-пути запрещены; пути устройств не допускаются ({raw_str})."
        )
    if slashed.startswith("\\\\"):
        raise ValueError(f"Отклонено по безопасности: сетевые UNC-пути запрещены ({raw_str}).")
    return raw_str


def _safe_resolve_anchor(path: Path) -> Path:
    try:
        resolved = path.resolve(strict=False)
    except OSError:
        resolved = Path(os.path.abspath(str(path)))
    raw = str(resolved)
    if raw.startswith("\\\\?\\") and _is_win32_local_drive_rest(raw[4:]):
        return Path(raw[4:])
    return resolved


def _get_denied_exact_roots(temp_root: Path | None = None) -> tuple[Path, ...]:
    t_root = temp_root if temp_root is not None else _safe_resolve_anchor(Path(tempfile.gettempdir()))
    items: list[Path] = [t_root]
    try:
        items.append(_safe_resolve_anchor(Path.home()))
    except (OSError, RuntimeError):
        pass
    return tuple(dict.fromkeys(items))


def _get_denied_subtree_roots() -> tuple[Path, ...]:
    items: list[Path] = []
    if os.name == "nt":
        for env_key, fallback in (
            ("WINDIR", r"C:\Windows"),
            ("ProgramFiles", r"C:\Program Files"),
            ("ProgramFiles(x86)", r"C:\Program Files (x86)"),
            ("ProgramData", r"C:\ProgramData"),
        ):
            items.append(_safe_resolve_anchor(Path(os.getenv(env_key, "").strip() or fallback)))
        # Запрещаем %APPDATA% (Roaming) и %LOCALAPPDATA%\Microsoft\Credentials — НИКОГДА не весь %LOCALAPPDATA%
        appdata = os.getenv("APPDATA", "").strip()
        if appdata:
            items.append(_safe_resolve_anchor(Path(appdata)))
        local_appdata = os.getenv("LOCALAPPDATA", "").strip()
        if local_appdata:
            items.append(_safe_resolve_anchor(Path(local_appdata) / "Microsoft" / "Credentials"))
    else:
        for posix_dir in ("/etc", "/proc", "/sys", "/dev"):
            p = Path(posix_dir)
            items.extend((p, _safe_resolve_anchor(p)))

    try:
        home_dir = _safe_resolve_anchor(Path.home())
        items.extend(home_dir / secret for secret in (".ssh", ".aws", ".gnupg", ".kube"))
        if os.name == "nt":
            if not os.getenv("APPDATA", "").strip():
                items.append(home_dir / "AppData" / "Roaming")
            if not os.getenv("LOCALAPPDATA", "").strip():
                items.append(home_dir / "AppData" / "Local" / "Microsoft" / "Credentials")
    except (OSError, RuntimeError):
        pass
    return tuple(dict.fromkeys(items))


DENIED_EXACT_ROOTS: tuple[Path, ...] = _get_denied_exact_roots()
DENIED_SUBTREE_ROOTS: tuple[Path, ...] = _get_denied_subtree_roots()


def _enforce_root_denylist(resolved: Path) -> None:
    """Отклоняет корни томов, exact-каталоги и системные/секретные поддеревья, пропуская дочерние папки temp."""
    if resolved == resolved.parent:
        raise ValueError(f"Отклонено по безопасности: нельзя использовать корень файловой системы ({resolved}).")
    temp_root = _safe_resolve_anchor(Path(tempfile.gettempdir()))
    if any(resolved == exact for exact in _get_denied_exact_roots(temp_root)):
        raise ValueError(f"Отклонено по безопасности: корневой служебный каталог запрещён ({resolved}).")

    # Дочерние папки tempfile.gettempdir() явно обходят OS DENIED_SUBTREE_ROOTS (/var/folders, %LOCALAPPDATA%\Temp)
    is_temp_child = resolved != temp_root and resolved.is_relative_to(temp_root)
    if not is_temp_child:
        for denied_sub in _get_denied_subtree_roots():
            if resolved == denied_sub or resolved.is_relative_to(denied_sub):
                raise ValueError(f"Отклонено по безопасности: системный или секретный каталог запрещён ({resolved}).")


def _assert_no_reparse_in_chain(abs_path: Path, existing_only: bool, label: str) -> None:
    for cur in (abs_path, *abs_path.parents):
        if cur == cur.parent:
            break
        if existing_only and not os.path.lexists(cur):
            continue
        if is_reparse_or_symlink(cur):
            raise ValueError(
                f"Отклонено по безопасности: обнаружен симлинк или NTFS Junction в {label} ({cur})."
            )


def _resolve_effective_allowed_roots(allowed_roots: list[Path] | None) -> list[Path]:
    if allowed_roots is not None:
        raw_items = [str(p).strip() for p in allowed_roots if str(p).strip()]
    else:
        raw_items = [part.strip() for part in os.getenv("LGRAPH_ALLOWED_ROOTS", "").split(os.pathsep) if part.strip()]
    return [
        _safe_resolve_anchor(Path(_normalize_win32_extended_local_path(item)).expanduser())
        for item in raw_items
    ]


def validate_safe_project_root(raw_path: str | Path, allowed_roots: list[Path] | None = None) -> Path:
    """
    Валидирует корневую директорию проекта: отклоняет UNC/device-пути, симлинки/NTFS Junctions,
    системные и секретные каталоги, а также проверяет опциональный allowlist (`LGRAPH_ALLOWED_ROOTS`).
    """
    if raw_path is None:
        raise ValueError("Путь к папке проекта не может быть пустым.")
    raw_str = str(raw_path).strip()
    if not raw_str or "\x00" in raw_str:
        raise ValueError("Путь к папке проекта не может быть пустым или содержать нулевые байты.")

    norm_str = _normalize_win32_extended_local_path(raw_str)
    # Используем abspath вместо resolve, чтобы не перепрыгнуть симлинк/Junction до проверки сегментов
    abs_path = Path(os.path.abspath(norm_str))
    if os.path.lexists(abs_path) and is_reparse_or_symlink(abs_path):
        raise ValueError(f"Отклонено по безопасности: корень проекта не может быть симлинком/Junction ({abs_path}).")
    if not abs_path.is_dir():
        raise ValueError(f"Указанный путь не является директорией: {abs_path}")

    _assert_no_reparse_in_chain(abs_path, existing_only=False, label="пути проекта")
    resolved = Path(_normalize_win32_extended_local_path(str(abs_path.resolve(strict=True))))
    _enforce_root_denylist(resolved)

    effective_allowed = _resolve_effective_allowed_roots(allowed_roots)
    if effective_allowed and not any(resolved.is_relative_to(ar) for ar in effective_allowed):
        raise ValueError(
            f"Отклонено по безопасности: путь ({resolved}) находится вне разрешённых корней (LGRAPH_ALLOWED_ROOTS)."
        )
    return resolved


def restrict_path_acl(target_path: Path, is_dir: bool = False) -> None:
    """Ограничивает права доступа к папке или файлу строго текущим пользователем ОС (`icacls` / `0700`/`0600`)."""
    if (is_dir and not target_path.is_dir()) or (not is_dir and not target_path.is_file()):
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
    """
    Возвращает рабочую папку локального демона (БД и токен доступа),
    валидируя её против UNC, симлинков/Junction и системных каталогов (без `LGRAPH_ALLOWED_ROOTS`).
    """
    env_override = os.getenv("LGRAPH_RUNTIME_DIR", "").strip()
    raw_target = env_override if env_override else str(Path(__file__).resolve().parents[2] / ".lgraph_runtime")
    if not raw_target or "\x00" in raw_target:
        raise ValueError("Путь к runtime-директории не может быть пустым или содержать нулевые байты.")

    abs_target = Path(os.path.abspath(_normalize_win32_extended_local_path(raw_target)))
    _assert_no_reparse_in_chain(abs_target, existing_only=True, label="runtime-пути")
    resolved = Path(_normalize_win32_extended_local_path(str(abs_target.resolve(strict=False))))
    _enforce_root_denylist(resolved)
    resolved.mkdir(parents=True, exist_ok=True)
    if is_reparse_or_symlink(resolved):
        raise ValueError(f"Отклонено по безопасности: runtime-директория является симлинком/Junction ({resolved}).")
    restrict_path_acl(resolved, is_dir=True)
    return resolved


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
