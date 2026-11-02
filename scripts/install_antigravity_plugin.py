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
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_PLUGINS_DIR = PROJECT_ROOT / "antigravity-plugin"


def resolve_python_executable() -> Path:
    if os.name == "nt":
        venv_py = PROJECT_ROOT / "backend" / "venv" / "Scripts" / "python.exe"
    else:
        venv_py = PROJECT_ROOT / "backend" / "venv" / "bin" / "python"
    return venv_py if venv_py.is_file() else Path(sys.executable).resolve()


def install_plugins_to_user_profile(target_plugins_root: Path | None = None) -> tuple[Path, Path]:
    plugins_root = target_plugins_root or (Path.home() / ".gemini" / "config" / "plugins")
    plugins_root.mkdir(parents=True, exist_ok=True)

    # 1. Копируем и настраиваем `lgraph-intelligence`
    lgraph_src = SOURCE_PLUGINS_DIR / "lgraph-intelligence"
    lgraph_dst = plugins_root / "lgraph-intelligence"
    if lgraph_dst.exists():
        shutil.rmtree(lgraph_dst)
    shutil.copytree(lgraph_src, lgraph_dst)

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

    # 2. Копируем и настраиваем `independent-auditor`
    auditor_src = SOURCE_PLUGINS_DIR / "independent-auditor"
    auditor_dst = plugins_root / "independent-auditor"
    if auditor_dst.exists():
        shutil.rmtree(auditor_dst)
    shutil.copytree(auditor_src, auditor_dst)

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
