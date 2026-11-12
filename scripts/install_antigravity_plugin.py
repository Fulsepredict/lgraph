"""
Автоматический установщик глобальных плагинов `lgraph-intelligence` и `independent-auditor`
в среду Google Antigravity (`~/.gemini/config/plugins/`).

Почему пути подставляются скриптом при установке, а не хардкодятся в Git:
В открытом репозитории шаблоны хранят нейтральный маркер `<PATH_TO_LGRAPH>`, чтобы личные пути
разработчика не попадали в коммиты, а любой пользователь получал готовую рабочую конфигурацию под свой ПК.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_PLUGINS_DIR = PROJECT_ROOT / "antigravity-plugin"


def _python_has_mcp(py_exe: Path) -> bool:
    """Проверяет через быстрый подпроцесс, установлен ли в интерпретаторе пакет `mcp`."""
    try:
        proc = subprocess.run(
            [str(py_exe), "-c", "import mcp"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def resolve_python_executable(candidates: list[Path] | None = None) -> Path:
    if candidates is None:
        if os.name == "nt":
            venv_py = PROJECT_ROOT / "backend" / "venv" / "Scripts" / "python.exe"
        else:
            venv_py = PROJECT_ROOT / "backend" / "venv" / "bin" / "python"
        candidates = [venv_py, Path(sys.executable).resolve()]

    checked: list[str] = []
    for cand in candidates:
        if cand.is_file():
            checked.append(str(cand))
            if _python_has_mcp(cand):
                return cand

    raise RuntimeError(
        "Не найден интерпретатор Python с установленным пакетом `mcp` (>=2.0.0). "
        f"Проверены пути: {checked or ['<нет доступных файлов>']}. "
        "Сначала выполните установку зависимостей (`SETUP.bat` или `pip install -r backend/requirements.txt`)."
    )


REPARSE_TAG_MOUNT_POINT: int = getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", 0xA0000003)
REPARSE_TAG_SYMLINK: int = getattr(stat, "IO_REPARSE_TAG_SYMLINK", 0xA000000C)


def _is_reparse_link(path: Path) -> bool:
    """
    Определяет симлинки и NTFS Directory Junctions (`mklink /J`) через `os.lstat` + `st_reparse_tag`
    (совместимо с Python 3.11+ и не блокирует обычные облачные атрибуты OneDrive).
    """
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    if stat.S_ISLNK(st.st_mode):
        return True
    return getattr(st, "st_reparse_tag", 0) in (REPARSE_TAG_MOUNT_POINT, REPARSE_TAG_SYMLINK)


def _unlink_reparse_entry(entry: Path) -> None:
    """Отвязывает точку симлинка или NTFS Junction без входа во внешнюю директорию."""
    try:
        os.rmdir(entry)
    except OSError:
        entry.unlink(missing_ok=True)


def _sync_plugin_dir(src: Path, dst: Path) -> None:
    """
    Обновляет каталог плагина `dst` на месте без `os.rmdir(dst)` на корневой папке.

    Почему в 2 прохода:
    1. `topdown=True`: до спуска внутрь подпапок и до `os.chmod` отсекает (`dirs.remove`) и отвязывает
       любые вложенные симлинки и NTFS Junctions (`mklink /J`), защищая внешние файлы на 100%.
    2. `topdown=False`: удаляет устаревшие локальные файлы и пустые подпапки без `os.rmdir(dst)` на корне,
       удерживаемом `ReadDirectoryChangesW` watcher'ом запущенной Antigravity IDE (`WinError 32`).
    """
    if _is_reparse_link(dst):
        raise ValueError(f"Целевая папка плагина не может быть ссылкой или NTFS Junction: {dst}")

    dst.mkdir(parents=True, exist_ok=True)

    for root_str, dirs, files in os.walk(dst, topdown=True, followlinks=False):
        root_path = Path(root_str)
        for dirname in list(dirs):
            dst_sub = root_path / dirname
            if _is_reparse_link(dst_sub):
                dirs.remove(dirname)
                _unlink_reparse_entry(dst_sub)
        for filename in files:
            dst_file = root_path / filename
            if _is_reparse_link(dst_file):
                _unlink_reparse_entry(dst_file)

    for root_str, dirs, files in os.walk(dst, topdown=False, followlinks=False):
        root_path = Path(root_str)
        for filename in files:
            dst_file = root_path / filename
            if _is_reparse_link(dst_file):
                _unlink_reparse_entry(dst_file)
                continue
            src_equiv = src / dst_file.relative_to(dst)
            try:
                os.chmod(dst_file, stat.S_IWRITE | stat.S_IREAD)
            except OSError:
                pass
            if not src_equiv.is_file():
                dst_file.unlink()

        for dirname in dirs:
            dst_sub = root_path / dirname
            src_equiv = src / dst_sub.relative_to(dst)
            if not src_equiv.is_dir():
                try:
                    dst_sub.rmdir()
                except OSError:
                    pass

    shutil.copytree(src, dst, dirs_exist_ok=True)


def install_plugins_to_user_profile(target_plugins_root: Path | None = None) -> tuple[Path, Path]:
    raw_root = target_plugins_root or (Path.home() / ".gemini" / "config" / "plugins")
    plugins_root = Path(os.path.abspath(raw_root))
    for segment in (plugins_root, *plugins_root.parents):
        if segment == segment.parent:
            break
        if _is_reparse_link(segment):
            raise ValueError(f"Путь директории плагинов содержит ссылку или NTFS Junction: {segment}")
    plugins_root.mkdir(parents=True, exist_ok=True)

    # 1. Синхронизируем и настраиваем `lgraph-intelligence`
    lgraph_src = SOURCE_PLUGINS_DIR / "lgraph-intelligence"
    lgraph_dst = plugins_root / "lgraph-intelligence"
    _sync_plugin_dir(lgraph_src, lgraph_dst)

    mcp_cfg_path = lgraph_dst / "mcp_config.json"
    mcp_payload = {
        "mcpServers": {
            "lgraph": {
                "command": str(resolve_python_executable()),
                "args": [str((PROJECT_ROOT / "run_mcp_server.py").resolve())],
                "env": {
                    "PYTHONUTF8": "1",
                    "PYTHONIOENCODING": "utf-8",
                },
            }
        }
    }
    mcp_cfg_path.write_text(json.dumps(mcp_payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    # 2. Синхронизируем и настраиваем `independent-auditor`
    auditor_src = SOURCE_PLUGINS_DIR / "independent-auditor"
    auditor_dst = plugins_root / "independent-auditor"
    _sync_plugin_dir(auditor_src, auditor_dst)

    skill_md_path = auditor_dst / "skills" / "independent-auditor" / "SKILL.md"
    if skill_md_path.is_file():
        checklist_abs = str(
            (auditor_dst / "skills" / "independent-auditor" / "references" / "stack_checklists.md").resolve()
        )
        updated_skill = skill_md_path.read_text(encoding="utf-8").replace(
            "<USER_PLUGINS_DIR>/independent-auditor/skills/independent-auditor/references/stack_checklists.md",
            checklist_abs,
        )
        skill_md_path.write_text(updated_skill, encoding="utf-8")

    return lgraph_dst, auditor_dst


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    lg_dir, aud_dir = install_plugins_to_user_profile()
    print(f"[OK] Установлен плагин Lgraph MCP: {lg_dir}")
    print(f"[OK] Установлен плагин Independent Auditor: {aud_dir}")


if __name__ == "__main__":
    main()
