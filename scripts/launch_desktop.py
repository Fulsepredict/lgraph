"""Бесконсольный лаунчер окна Lgraph с гарантированной очисткой `ELECTRON_RUN_AS_NODE`."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FRONTEND_DIR = PROJECT_ROOT / "frontend"
ELECTRON_EXE = FRONTEND_DIR / "node_modules" / "electron" / "dist" / "electron.exe"


def build_electron_launch_env(base_env: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ if base_env is None else base_env)
    env.pop("ELECTRON_RUN_AS_NODE", None)
    return env


def main(argv: list[str] | None = None) -> int:
    os.environ.pop("ELECTRON_RUN_AS_NODE", None)
    args = list(sys.argv[1:] if argv is None else argv)
    if not ELECTRON_EXE.is_file():
        return 1
    cmd = [str(ELECTRON_EXE), str(FRONTEND_DIR)]
    if args and args[0].strip():
        cmd.append(f"--open-project={Path(args[0].strip()).resolve()}")
    subprocess.Popen(
        cmd,
        cwd=str(FRONTEND_DIR),
        env=build_electron_launch_env(),
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
