"""
Автономная точка запуска MCP-сервера Lgraph для Antigravity, Cursor, Claude Code и Windsurf.

Почему запуск выполняется через этот скрипт, а не через `python -m backend.mcp_server.server`:
1. В Antigravity конфигурация `~/.gemini/config/mcp_config.json` поддерживает `command`, `args` и `env`,
   но НЕ поддерживает параметр `cwd`. Прямой путь к `run_mcp_server.py` сам добавляет корень `Lgraph`
   в `sys.path` при запуске из абсолютно любой рабочей папки любого проекта.
2. Поток `stdout` в протоколе MCP (`stdio`) зарезервирован исключительно под сообщения JSON-RPC.
   Здесь мы до загрузки библиотек направляем все системные логи и предупреждения строго в `sys.stderr`
   в кодировке `utf-8`, исключая обрывы связи и ошибки кодировки на русскоязычной Windows.
"""

from __future__ import annotations

import logging
import os
import sys
import warnings
from pathlib import Path


def _bootstrap_stdio_environment() -> Path:
    os.environ.setdefault("PYTHONUTF8", "1")
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")

    # Переводим только stderr в utf-8 (stdin/stdout оборачиваются самим SDK `mcp.server.stdio` на уровне fd 0/1)
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    logging.basicConfig(
        stream=sys.stderr,
        level=logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        force=True,
    )
    warnings.simplefilter("ignore")

    project_root = Path(__file__).resolve().parent
    root_str = str(project_root)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)
    return project_root


def main() -> None:
    _bootstrap_stdio_environment()
    from backend.mcp_server.server import create_lgraph_mcp_server

    server = create_lgraph_mcp_server()
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
