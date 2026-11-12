"""
Регрессионные автотесты сетевого периметра ASGI, маскировки заметок, NTFS Junctions,
передачи `ToolError` в MCP v2, межпроцессной записи SQLite WAL и гигиены `.bat`-скриптов.

Все тесты работают исключительно во временных директориях `tempfile.TemporaryDirectory()`,
не затрагивая рабочее хранилище `.lgraph_runtime` и пользовательский Рабочий стол.
"""

from __future__ import annotations

import asyncio
import ctypes
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from typing import Any
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.mcpserver.exceptions import ToolError, UnexpectedToolError

from backend.analyzers.code_graph.scanner import index_project_directory
from backend.api.main import create_lgraph_app
from backend.core.config import (
    LGRAPH_VERSION,
    TOKEN_HEADER_NAME,
    ensure_local_daemon_token,
    validate_safe_project_root,
)
from backend.mcp_server.server import create_lgraph_mcp_server
from backend.storage.queries import GraphQueryService
from backend.storage.repository import GraphRepository
from backend.storage.schema import open_sqlite_connection
from scripts.build_windows_shortcuts import (
    POWERSHELL_SHORTCUT_SCRIPT,
    resolve_shortcut_target,
)
from scripts.install_antigravity_plugin import (
    install_plugins_to_user_profile,
    resolve_python_executable,
)
from scripts.launch_desktop import build_electron_launch_env

FIXTURES_DIR = PROJECT_ROOT / "fixtures"
MCP_ENTRY_SCRIPT = str(PROJECT_ROOT / "run_mcp_server.py")


async def _send_asgi_http(
    app: Any,
    method: str,
    path: str,
    headers: list[tuple[bytes, bytes]],
    body: bytes = b"",
) -> tuple[int, bytes]:
    status_code = 500
    chunks: list[bytes] = []
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 55100),
        "server": ("127.0.0.1", 8765),
    }

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        nonlocal status_code
        if message["type"] == "http.response.start":
            status_code = int(message["status"])
        elif message["type"] == "http.response.body":
            chunks.append(message.get("body", b""))

    await app(scope, receive, send)
    return status_code, b"".join(chunks)


async def _send_asgi_websocket(
    app: Any,
    path: str,
    headers: list[tuple[bytes, bytes]],
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    scope = {
        "type": "websocket",
        "asgi": {"version": "3.0"},
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 55101),
        "server": ("127.0.0.1", 8765),
    }

    async def receive() -> dict[str, Any]:
        return {"type": "websocket.connect"}

    async def send(message: dict[str, Any]) -> None:
        events.append(message)

    await app(scope, receive, send)
    return events


class LgraphPerimeterAndWalRegressionTests(unittest.TestCase):
    def test_01_asgi_perimeter_non_ascii_token_host_and_websocket(self) -> None:
        """Проверяет P0-3: не-ASCII байты в токене -> 403 (не 500), запрет testserver по умолчанию и защиту WebSocket."""
        with tempfile.TemporaryDirectory() as tmp_str:
            runtime = Path(tmp_str)
            token = ensure_local_daemon_token(runtime)
            app = create_lgraph_app(runtime_dir=runtime, enable_watchers_default=False)
            tok_hdr = TOKEN_HEADER_NAME.lower().encode("ascii")

            # 1. Сырые не-UTF8 байты (0xFF, 0xFE, 0x80) в X-Lgraph-Token обязаны вернуть 403 JSON, а не 500 TypeError
            code_raw_bin, body_raw_bin = asyncio.run(
                _send_asgi_http(
                    app,
                    "GET",
                    "/api/projects",
                    [(b"host", b"127.0.0.1:8765"), (tok_hdr, b"\xff\xfe\x80\x99")],
                )
            )
            self.assertEqual(code_raw_bin, 403)
            self.assertIn("X-Lgraph-Token", json.loads(body_raw_bin.decode("utf-8"))["detail"])

            # 2. Кириллица UTF-8 в X-Lgraph-Token обязана вернуть 403 JSON, а не 500
            code_utf8, _ = asyncio.run(
                _send_asgi_http(
                    app,
                    "GET",
                    "/api/projects",
                    [(b"host", b"localhost:8765"), (tok_hdr, "токен-кириллица-тест".encode("utf-8"))],
                )
            )
            self.assertEqual(code_utf8, 403)

            # 3. Host: testserver по умолчанию запрещён даже при валидном токене
            code_testserver_denied, _ = asyncio.run(
                _send_asgi_http(
                    app,
                    "GET",
                    "/api/projects",
                    [(b"host", b"testserver"), (tok_hdr, token.encode("ascii"))],
                )
            )
            self.assertEqual(code_testserver_denied, 403)

            # 4. При явном флаге allow_testserver=True или LGRAPH_ALLOW_TESTSERVER=1 хост testserver разрешается
            app_test = create_lgraph_app(
                runtime_dir=runtime,
                enable_watchers_default=False,
                allow_testserver=True,
            )
            code_testserver_ok, _ = asyncio.run(
                _send_asgi_http(
                    app_test,
                    "GET",
                    "/api/projects",
                    [(b"host", b"testserver"), (tok_hdr, token.encode("ascii"))],
                )
            )
            self.assertEqual(code_testserver_ok, 200)

            with patch.dict(os.environ, {"LGRAPH_ALLOW_TESTSERVER": "1"}):
                code_env_ok, _ = asyncio.run(
                    _send_asgi_http(
                        app,
                        "GET",
                        "/api/projects",
                        [(b"host", b"testserver"), (tok_hdr, token.encode("ascii"))],
                    )
                )
                self.assertEqual(code_env_ok, 200)

            # 5. GET /api/health и OPTIONS доступны без токена на локальном Host
            code_health, health_body = asyncio.run(
                _send_asgi_http(app, "GET", "/api/health", [(b"host", b"127.0.0.1:8765")])
            )
            self.assertEqual(code_health, 200)
            self.assertEqual(json.loads(health_body.decode("utf-8"))["version"], LGRAPH_VERSION)

            # 6. WebSocket без токена или с не-ASCII токеном закрывается до accept с кодом 1008
            ws_no_tok = asyncio.run(
                _send_asgi_websocket(app, "/ws", [(b"host", b"127.0.0.1:8765")])
            )
            self.assertEqual(ws_no_tok[0]["type"], "websocket.close")
            self.assertEqual(ws_no_tok[0]["code"], 1008)
            self.assertFalse(any(ev["type"] == "websocket.accept" for ev in ws_no_tok))

            ws_bad_tok = asyncio.run(
                _send_asgi_websocket(app, "/ws", [(b"host", b"127.0.0.1:8765"), (tok_hdr, b"\xff\xfe")])
            )
            self.assertEqual(ws_bad_tok[0]["type"], "websocket.close")
            self.assertEqual(ws_bad_tok[0]["code"], 1008)

    def test_02_note_secret_redaction_and_zombie_cleanup(self) -> None:
        """Проверяет P0-1: маскировку секретов в save_architectural_note и полное удаление заметки при summary_ru=''."""
        fixture = FIXTURES_DIR / "polyglot_rest_basic"
        with tempfile.TemporaryDirectory() as tmp_str:
            db_path = Path(tmp_str) / "notes_sec.sqlite3"
            repo = GraphRepository(db_path)
            queries = GraphQueryService(db_path)

            rep = index_project_directory(fixture, repo)
            pid = str(rep["project_id"])
            target_uri = "py://backend/routes_orders.py#confirm_order"

            raw_secret = "sk-live99887766554433221100abcdefghij"
            queries.save_architectural_note(
                project_id=pid,
                target_uri=target_uri,
                summary_ru=f"Ключ шлюза оплаты {raw_secret} маркерархитектуры",
                risk_level="critical",
            )

            node_after_save = queries.get_node_by_uri(pid, target_uri)
            self.assertIsNotNone(node_after_save)
            assert node_after_save is not None
            self.assertIn("<REDACTED_SECRET>", node_after_save["summary_ru"])
            self.assertNotIn(raw_secret, node_after_save["summary_ru"])

            with closing(open_sqlite_connection(db_path)) as conn:
                raw_note = conn.execute(
                    "SELECT summary_ru FROM architectural_notes WHERE project_id = ? AND target_uri = ?",
                    (pid, target_uri),
                ).fetchone()
                raw_fts = conn.execute(
                    "SELECT summary_ru FROM nodes_fts WHERE project_id = ? AND uri = ?",
                    (pid, target_uri),
                ).fetchone()
            self.assertIsNotNone(raw_note)
            self.assertNotIn(raw_secret, str(raw_note["summary_ru"]))
            self.assertNotIn(raw_secret, str(raw_fts["summary_ru"]))
            self.assertEqual(len(queries.search_nodes(pid, "маркерархитектуры")), 1)

            # Очищаем текст заметки при сохранении risk_level='critical' (сценарий кнопки Сохранить в UI)
            queries.save_architectural_note(
                project_id=pid,
                target_uri=target_uri,
                summary_ru="   ",
                risk_level="critical",
            )
            cleared_node = queries.get_node_by_uri(pid, target_uri)
            assert cleared_node is not None
            self.assertEqual(cleared_node["summary_ru"], "")
            self.assertEqual(queries.search_nodes(pid, "маркерархитектуры"), [])
            self.assertEqual(queries.get_architectural_notes(pid), [])

            # Повторная переиндексация НЕ должна воскрешать удалённый текст заметки
            index_project_directory(fixture, repo)
            after_reindex = queries.get_node_by_uri(pid, target_uri)
            assert after_reindex is not None
            self.assertEqual(after_reindex["summary_ru"], "")
            self.assertEqual(after_reindex["risk_level"], "critical")

            # Полная очистка заметки без risk_level удаляет запись из таблицы architectural_notes
            c3_uri = "c3://domain/backend"
            queries.save_architectural_note(pid, c3_uri, "Временная заметка домена", "")
            queries.save_architectural_note(pid, c3_uri, "", "")
            with closing(open_sqlite_connection(db_path)) as conn:
                cnt = conn.execute(
                    "SELECT COUNT(*) AS c FROM architectural_notes WHERE project_id = ? AND target_uri = ?",
                    (pid, c3_uri),
                ).fetchone()["c"]
            self.assertEqual(cnt, 0)

    def test_03_validate_safe_project_root_unc_and_intermediate_ntfs_junction(self) -> None:
        """Проверяет P1-7: отклонение UNC-путей, нулевых байтов и промежуточных NTFS Junctions (mklink /J)."""
        for bad_input in (
            "",
            "   ",
            "valid_dir\x00injected",
            r"\\evil-smb-server\share\repo",
            "//evil-smb-server/share/repo",
            r"\\?\UNC\evil-smb-server\share\repo",
        ):
            with self.assertRaises(ValueError, msg=f"Должен быть отклонён вход: {bad_input!r}"):
                validate_safe_project_root(bad_input)

        if os.name == "nt":
            with tempfile.TemporaryDirectory() as tmp_str:
                tmp = Path(tmp_str)
                outside_target = tmp / "outside_vault"
                nested_proj = outside_target / "inner_project"
                nested_proj.mkdir(parents=True)
                (nested_proj / "app.py").write_text("x = 1\n", encoding="utf-8")

                safe_parent = tmp / "workspace"
                safe_parent.mkdir()
                junction_path = safe_parent / "linked_vault"

                mk = subprocess.run(
                    ["cmd", "/c", "mklink", "/J", str(junction_path), str(outside_target)],
                    capture_output=True,
                    check=False,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                self.assertEqual(
                    mk.returncode,
                    0,
                    f"Не удалось создать тестовый NTFS Junction: {mk.stderr.decode('cp866', errors='replace')}",
                )
                try:
                    # 1. Прямой корень-Junction обязан отклоняться
                    with self.assertRaises(ValueError):
                        validate_safe_project_root(junction_path)

                    # 2. Вложенная обычная папка ВНУТРИ родительского Junction обязана отклоняться!
                    intermediate_target = junction_path / "inner_project"
                    self.assertTrue(intermediate_target.is_dir())
                    with self.assertRaises(ValueError):
                        validate_safe_project_root(intermediate_target)
                finally:
                    if junction_path.exists() or os.path.lexists(junction_path):
                        os.rmdir(junction_path)

    def test_04_mcp_v2_tool_error_preserves_russian_message_and_rest_422(self) -> None:
        """Проверяет P1-2: возврат русского текста через ToolError (is_error=True) в MCP v2 и HTTP 422 в REST API."""
        async def _mcp_scenario() -> None:
            with tempfile.TemporaryDirectory() as tmp_str:
                tmp = Path(tmp_str)
                mcp = create_lgraph_mcp_server(runtime_dir=tmp)

                # Прямой вызов MCPServer.call_tool поднимает ToolError (не UnexpectedToolError)
                with self.assertRaises(ToolError) as ctx_err:
                    await mcp.call_tool("open_or_index_project", {"project_root": r"\\server\share\proj"})
                self.assertNotIsInstance(ctx_err.exception, UnexpectedToolError)
                self.assertIn("UNC", str(ctx_err.exception))

                # Сквозной вызов через реальный JSON-RPC stdio транспорт возвращает is_error=True с русским текстом
                env = dict(os.environ)
                env["LGRAPH_RUNTIME_DIR"] = str(tmp)
                params = StdioServerParameters(
                    command=sys.executable,
                    args=[MCP_ENTRY_SCRIPT],
                    env=env,
                    cwd=str(tmp),
                )
                async with stdio_client(params) as (read_stream, write_stream):
                    async with ClientSession(read_stream, write_stream) as session:
                        await session.initialize()

                        unc_res = await session.call_tool(
                            "open_or_index_project",
                            {"project_root": r"\\server\share\proj"},
                        )
                        self.assertTrue(unc_res.is_error)
                        unc_text = "\n".join(getattr(c, "text", "") for c in (unc_res.content or []))
                        self.assertNotEqual(unc_text.strip(), "Error executing tool open_or_index_project")
                        self.assertIn("сетевые UNC-пути запрещены", unc_text)

                        risk_res = await session.call_tool(
                            "save_architectural_note",
                            {
                                "project_root_or_id": str(FIXTURES_DIR / "polyglot_rest_basic"),
                                "target_uri": "py://backend/routes_orders.py",
                                "summary_ru": "Тест",
                                "risk_level": "invalid_tier",
                            },
                        )
                        self.assertTrue(risk_res.is_error)
                        risk_text = "\n".join(getattr(c, "text", "") for c in (risk_res.content or []))
                        self.assertNotEqual(risk_text.strip(), "Error executing tool save_architectural_note")
                        self.assertIn("Параметр risk_level должен быть одним из", risk_text)

                # Проверка REST API: синтаксическая ошибка конфигурации возвращает HTTP 422 с текстом, а не 500
                token = ensure_local_daemon_token(tmp)
                app = create_lgraph_app(runtime_dir=tmp, enable_watchers_default=False)
                tok_hdr = TOKEN_HEADER_NAME.lower().encode("ascii")
                payload_bytes = json.dumps(
                    {"root_path": str(FIXTURES_DIR / "polyglot_rest_basic"), "enable_watcher": False}
                ).encode("utf-8")

                with patch(
                    "backend.api.main.index_project_directory",
                    side_effect=ValueError("Некорректный синтаксис YAML в lgraph.yaml"),
                ):
                    code_422, body_422 = await _send_asgi_http(
                        app,
                        "POST",
                        "/api/projects/open",
                        [
                            (b"host", b"127.0.0.1:8765"),
                            (tok_hdr, token.encode("ascii")),
                            (b"content-type", b"application/json"),
                        ],
                        body=payload_bytes,
                    )
                self.assertEqual(code_422, 422)
                self.assertIn("lgraph.yaml", json.loads(body_422.decode("utf-8"))["detail"])

        asyncio.run(_mcp_scenario())

    def test_05_multiprocess_sqlite_wal_begin_immediate_stress(self) -> None:
        """Проверяет P1-3: 2 реальных параллельных процесса (save_full_index_atomic + save_architectural_note) без SQLITE_BUSY."""
        fixture = FIXTURES_DIR / "polyglot_rest_basic"
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            db_path = tmp / "wal_mp.sqlite3"
            repo = GraphRepository(db_path)
            queries = GraphQueryService(db_path)

            init_rep = index_project_directory(fixture, repo)
            pid = str(init_rep["project_id"])
            target_uri = "py://backend/routes_orders.py#confirm_order"

            indexer_code = (
                "import sys; from pathlib import Path\n"
                "sys.path.insert(0, sys.argv[1])\n"
                "from backend.core.models import GraphEdgeRecord, GraphNodeRecord, EdgeType, NodeType\n"
                "from backend.storage.repository import GraphRepository\n"
                "repo = GraphRepository(Path(sys.argv[2]))\n"
                "pid, target_uri = sys.argv[3], sys.argv[4]\n"
                "nodes = [\n"
                "    GraphNodeRecord(uri=target_uri, node_type=NodeType.FUNCTION, name='confirm_order', rel_path='backend/routes_orders.py'),\n"
                "    *[GraphNodeRecord(uri=f'py://mod_{k}.py', node_type=NodeType.FILE, name=f'mod_{k}.py', rel_path=f'mod_{k}.py') for k in range(25)]\n"
                "]\n"
                "edges = [GraphEdgeRecord(src_uri=f'py://mod_{k}.py', dst_uri=target_uri, edge_type=EdgeType.CALLS) for k in range(25)]\n"
                "for _ in range(30):\n"
                "    repo.save_full_index_atomic(pid, nodes, edges, [])\n"
            )

            notes_code = (
                "import sys; from pathlib import Path\n"
                "sys.path.insert(0, sys.argv[1])\n"
                "from backend.storage.queries import GraphQueryService\n"
                "queries = GraphQueryService(Path(sys.argv[2]))\n"
                "pid, target_uri = sys.argv[3], sys.argv[4]\n"
                "for step in range(30):\n"
                "    queries.save_architectural_note(pid, target_uri, f'Межпроцессная заметка #{step}', 'critical')\n"
            )

            common_args = [str(PROJECT_ROOT), str(db_path), pid, target_uri]
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            p_idx = subprocess.Popen(
                [sys.executable, "-c", indexer_code, *common_args],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=flags,
            )
            p_note = subprocess.Popen(
                [sys.executable, "-c", notes_code, *common_args],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=flags,
            )

            _, err_idx = p_idx.communicate(timeout=40)
            _, err_note = p_note.communicate(timeout=40)

            self.assertEqual(p_idx.returncode, 0, f"Процесс индексатора упал: {err_idx}")
            self.assertEqual(p_note.returncode, 0, f"Процесс заметок упал: {err_note}")

            final_node = queries.get_node_by_uri(pid, target_uri)
            self.assertIsNotNone(final_node)
            assert final_node is not None
            self.assertEqual(final_node["summary_ru"], "Межпроцессная заметка #29")
            self.assertEqual(final_node["risk_level"], "critical")

            proj_info = repo.get_project(pid)
            assert proj_info is not None
            self.assertGreaterEqual(int(proj_info["index_revision"]), 31)

    def test_06_windows_bat_ascii_crlf_and_desktop_launcher_hygiene(self) -> None:
        """Проверяет P0-2 и P2-4: 100% 7-bit ASCII + CRLF в .bat, сброс ELECTRON_RUN_AS_NODE и проверку mcp."""
        for bat_name in ("SETUP.bat", "START_APP.bat"):
            bat_bytes = (PROJECT_ROOT / bat_name).read_bytes()
            non_ascii = [b for b in bat_bytes if b >= 0x80]
            self.assertEqual(non_ascii, [], f"В {bat_name} обнаружены не-ASCII байты: {non_ascii[:10]}")
            self.assertIn(b"\r\n", bat_bytes, f"В {bat_name} отсутствуют переводы строк CRLF")
            # Проверяем отсутствие голых LF или CR (каждая строка заканчивается строго на \r\n)
            stripped_crlf = bat_bytes.replace(b"\r\n", b"")
            self.assertNotIn(b"\n", stripped_crlf, f"В {bat_name} найдены строки с LF без CRLF")
            self.assertNotIn(b"\r", stripped_crlf, f"В {bat_name} найдены одиночные CR")

            bat_text = bat_bytes.decode("ascii")
            self.assertIn("set ELECTRON_RUN_AS_NODE=", bat_text)

        setup_text = (PROJECT_ROOT / "SETUP.bat").read_text(encoding="ascii")
        self.assertGreaterEqual(setup_text.count("if errorlevel 1"), 6)
        self.assertIn("build_windows_shortcuts.py", setup_text)
        self.assertIn("install_antigravity_plugin.py", setup_text)

        gitattr_text = (PROJECT_ROOT / ".gitattributes").read_text(encoding="ascii")
        self.assertIn("*.bat text eol=crlf", gitattr_text)
        self.assertIn("*.cmd text eol=crlf", gitattr_text)
        self.assertIn("*.ps1 text eol=crlf", gitattr_text)

        # Проверка очистки ELECTRON_RUN_AS_NODE в launch_desktop.py
        clean_env = build_electron_launch_env({"ELECTRON_RUN_AS_NODE": "1", "KEEP_VAR": "ok"})
        self.assertNotIn("ELECTRON_RUN_AS_NODE", clean_env)
        self.assertEqual(clean_env["KEEP_VAR"], "ok")

        # Проверка выбора pythonw.exe + launch_desktop.py и фоллбэка на START_APP.bat
        with tempfile.TemporaryDirectory() as tmp_str:
            fake_root = Path(tmp_str)
            (fake_root / "START_APP.bat").write_text("@echo off\r\n", encoding="ascii")
            tgt_fallback, args_fallback, _ = resolve_shortcut_target(fake_root)
            self.assertEqual(tgt_fallback, fake_root / "START_APP.bat")
            self.assertEqual(args_fallback, "")

            pyw = fake_root / "backend" / "venv" / "Scripts" / "pythonw.exe"
            elec = fake_root / "frontend" / "node_modules" / "electron" / "dist" / "electron.exe"
            lnch = fake_root / "scripts" / "launch_desktop.py"
            pyw.parent.mkdir(parents=True)
            elec.parent.mkdir(parents=True)
            lnch.parent.mkdir(parents=True)
            pyw.write_bytes(b"MZ")
            elec.write_bytes(b"MZ")
            lnch.write_text("# launcher\n", encoding="utf-8")

            tgt_pyw, args_pyw, work_pyw = resolve_shortcut_target(fake_root)
            self.assertEqual(tgt_pyw, pyw)
            self.assertIn("launch_desktop.py", args_pyw)
            self.assertEqual(work_pyw, fake_root / "frontend")

            # Проверка отклонения интерпретатора без установленного пакета mcp
            with patch("scripts.install_antigravity_plugin._python_has_mcp", return_value=False):
                with self.assertRaises(RuntimeError) as err_ctx:
                    resolve_python_executable(candidates=[pyw])
                self.assertIn("mcp", str(err_ctx.exception))

    def test_07_windows_shortcut_utf8_cyrillic_and_locked_plugin_sync(self) -> None:
        """Проверяет UTF-8 вывод PowerShell на кириллическом Desktop при PYTHONUTF8=1 и обновление плагина под WinError 32."""
        non_ascii_ps = [ch for ch in POWERSHELL_SHORTCUT_SCRIPT if ord(ch) >= 128]
        self.assertEqual(non_ascii_ps, [], f"Скрипт PowerShell обязан быть 7-bit ASCII: {non_ascii_ps}")
        self.assertIn("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8", POWERSHELL_SHORTCUT_SCRIPT)

        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)

            # 1. Реальная генерация ярлыка в папке с кириллицей и апострофом под дочерним Python с PYTHONUTF8=1
            if os.name == "nt":
                cyrillic_desk = tmp / "Рабочий стол Dev's Тест"
                fake_winapps = tmp / "WindowsApps"
                cyrillic_desk.mkdir(parents=True)
                fake_winapps.mkdir(parents=True)

                child_code = (
                    "import sys; from pathlib import Path\n"
                    "sys.path.insert(0, sys.argv[1])\n"
                    "from scripts.build_windows_shortcuts import create_desktop_shortcut_and_cli\n"
                    "lnk, cli = create_desktop_shortcut_and_cli(Path(sys.argv[2]), Path(sys.argv[3]))\n"
                    "assert lnk is not None and lnk.is_file(), f'Bad lnk: {lnk}'\n"
                    "assert cli is not None and cli.is_file(), f'Bad cli: {cli}'\n"
                    "print(str(lnk))\n"
                )
                child_env = dict(os.environ)
                child_env["PYTHONUTF8"] = "1"
                proc = subprocess.run(
                    [sys.executable, "-c", child_code, str(PROJECT_ROOT), str(cyrillic_desk), str(fake_winapps)],
                    env=child_env,
                    capture_output=True,
                    encoding="utf-8",
                    errors="strict",
                    timeout=25,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                self.assertEqual(
                    proc.returncode,
                    0,
                    f"Генерация ярлыка упала при PYTHONUTF8=1:\nSTDOUT: {proc.stdout}\nSTDERR: {proc.stderr}",
                )
                self.assertNotIn("UnicodeDecodeError", proc.stderr)
                self.assertTrue((cyrillic_desk / "Lgraph.lnk").is_file())
                self.assertGreater((cyrillic_desk / "Lgraph.lnk").stat().st_size, 0)
                self.assertTrue((fake_winapps / "lgraph.cmd").is_file())
                cmd_bytes = (fake_winapps / "lgraph.cmd").read_bytes()
                self.assertIn(b"\r\n", cmd_bytes)
                self.assertNotIn(b"\r\r\n", cmd_bytes, "В lgraph.cmd не должно быть двойных переводов \\r\\r\\n")
                self.assertIn("Рабочий стол Dev's Тест", proc.stdout)

            # 2. Обновление плагинов при открытом Win32-дескрипторе директории + защита от вложенного NTFS Junction
            plugins_root = tmp / "plugins_profile"
            lg_dst, aud_dst = install_plugins_to_user_profile(target_plugins_root=plugins_root)

            stale_file = lg_dst / "obsolete_legacy.txt"
            stale_dir = lg_dst / "obsolete_subdir"
            stale_dir.mkdir(parents=True)
            stale_file.write_text("stale", encoding="utf-8")
            (stale_dir / "old.txt").write_text("old", encoding="utf-8")

            outside_canary_dir = tmp / "outside_protected_vault"
            outside_canary_dir.mkdir(parents=True)
            canary_file = outside_canary_dir / "canary.txt"
            canary_file.write_text("DO_NOT_DELETE", encoding="utf-8")

            nested_junction = lg_dst / "nested_vault_junction"
            parent_junction = tmp / "parent_junction_root"

            open_handles: list[int] = []
            kernel32: Any = None
            if os.name == "nt":
                mk_nested = subprocess.run(
                    ["cmd", "/c", "mklink", "/J", str(nested_junction), str(outside_canary_dir)],
                    capture_output=True,
                    check=False,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                self.assertEqual(mk_nested.returncode, 0)
                mk_parent = subprocess.run(
                    ["cmd", "/c", "mklink", "/J", str(parent_junction), str(plugins_root)],
                    capture_output=True,
                    check=False,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                self.assertEqual(mk_parent.returncode, 0)

                # Родительский NTFS Junction в пути target_plugins_root обязан отклоняться до записи
                with self.assertRaises(ValueError):
                    install_plugins_to_user_profile(target_plugins_root=parent_junction / "nested")

                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel32.CreateFileW.argtypes = [
                    ctypes.c_wchar_p,
                    ctypes.c_uint32,
                    ctypes.c_uint32,
                    ctypes.c_void_p,
                    ctypes.c_uint32,
                    ctypes.c_uint32,
                    ctypes.c_void_p,
                ]
                kernel32.CreateFileW.restype = ctypes.c_void_p
                kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
                kernel32.CloseHandle.restype = ctypes.c_int

                file_list_directory = 0x0001
                share_rw_no_delete = 0x0001 | 0x0002
                open_existing = 3
                flag_backup_semantics = 0x02000000
                invalid_handle = ctypes.c_void_p(-1).value

                locked_probe = tmp / "locked_probe_dir"
                locked_probe.mkdir()
                for dir_to_lock in (locked_probe, lg_dst, aud_dst / "skills"):
                    handle = kernel32.CreateFileW(
                        str(dir_to_lock),
                        file_list_directory,
                        share_rw_no_delete,
                        None,
                        open_existing,
                        flag_backup_semantics,
                        None,
                    )
                    self.assertNotEqual(handle, invalid_handle, f"Не удалось открыть Win32-дескриптор {dir_to_lock}")
                    open_handles.append(int(handle))

                # Доказываем, что без FILE_SHARE_DELETE ядро Windows действительно блокирует os.rmdir (WinError 32)
                with self.assertRaises(PermissionError):
                    os.rmdir(locked_probe)

            try:
                lg_dst_2, aud_dst_2 = install_plugins_to_user_profile(target_plugins_root=plugins_root)
                self.assertEqual(lg_dst_2, lg_dst)
                self.assertEqual(aud_dst_2, aud_dst)
                self.assertFalse(stale_file.exists())
                self.assertFalse(stale_dir.exists())
                self.assertFalse(os.path.lexists(nested_junction))
                self.assertTrue(canary_file.is_file(), "Файл во внешней целевой папке Junction обязан остаться целым!")
                self.assertEqual(canary_file.read_text(encoding="utf-8"), "DO_NOT_DELETE")

                mcp_cfg = json.loads((lg_dst / "mcp_config.json").read_text(encoding="utf-8"))
                self.assertIn("lgraph", mcp_cfg["mcpServers"])
                self.assertTrue(str(mcp_cfg["mcpServers"]["lgraph"]["args"][0]).endswith("run_mcp_server.py"))

                aud_skill = (aud_dst / "skills" / "independent-auditor" / "SKILL.md").read_text(encoding="utf-8")
                self.assertNotIn("<USER_PLUGINS_DIR>", aud_skill)
                self.assertIn("stack_checklists.md", aud_skill)
            finally:
                if kernel32 is not None:
                    for handle in open_handles:
                        kernel32.CloseHandle(ctypes.c_void_p(handle))
                if os.path.lexists(parent_junction):
                    os.rmdir(parent_junction)
                if os.path.lexists(nested_junction):
                    os.rmdir(nested_junction)


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    runner = unittest.TextTestRunner(stream=sys.stdout, verbosity=2)
    prog = unittest.main(testRunner=runner, exit=False)
    sys.exit(0 if prog.result.wasSuccessful() else 1)
