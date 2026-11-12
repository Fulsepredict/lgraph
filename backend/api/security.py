"""
Защита локального сетевого периметра демона Lgraph (чистый ASGI Fail-Closed Middleware).

Почему реализован как чистый ASGI-класс без `BaseHTTPMiddleware`:
1. Единый барьер защищает как обычные запросы `http`, так и `websocket`-соединения (пропуская `lifespan`).
2. Сравнение `X-Lgraph-Token` выполняется строго в сырых байтах (`bytes`), поэтому любые не-ASCII
   байты (`0x80..0xFF`) гарантированно возвращают `HTTP 403` (или закрывают `websocket` до `accept`),
   никогда не вызывая `TypeError -> HTTP 500` внутри `secrets.compare_digest`.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Iterable
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from backend.core.config import TOKEN_HEADER_NAME

_BASE_ALLOWED_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost"})
_WS_POLICY_VIOLATION_CODE: int = 1008


def _extract_raw_header(headers: Iterable[tuple[bytes, bytes]], target_lower: bytes) -> bytes:
    for h_name, h_val in headers:
        if bytes(h_name).lower() == target_lower:
            return bytes(h_val)
    return b""


class LocalPerimeterMiddleware:
    """Отклоняет любые HTTP и WebSocket обращения без валидного локального `Host` и `X-Lgraph-Token`."""

    def __init__(self, app: ASGIApp, expected_token: str, allow_testserver: bool = False) -> None:
        if not expected_token or len(expected_token.strip()) < 16:
            raise ValueError("Токен безопасности демона Lgraph не может быть пустым или коротким.")
        self.app = app
        self._expected_bytes: bytes = expected_token.strip().encode("utf-8")
        self._token_header_bytes: bytes = TOKEN_HEADER_NAME.lower().encode("ascii")
        self._allow_testserver: bool = bool(allow_testserver)

    def _is_host_allowed(self, raw_host_bytes: bytes) -> bool:
        try:
            host_str = raw_host_bytes.decode("latin-1").strip().lower()
        except UnicodeDecodeError:
            return False
        host_only = host_str.split(":", 1)[0].strip()
        if host_only in _BASE_ALLOWED_HOSTS:
            return True
        if host_only == "testserver":
            return self._allow_testserver or os.getenv("LGRAPH_ALLOW_TESTSERVER", "").strip() == "1"
        return False

    @staticmethod
    async def _reject(scope: Scope, receive: Receive, send: Send, detail: str) -> None:
        if scope.get("type") == "websocket":
            await send({"type": "websocket.close", "code": _WS_POLICY_VIOLATION_CODE, "reason": detail})
            return
        response = JSONResponse(status_code=403, content={"detail": detail})
        await response(scope, receive, send)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        scope_type = scope.get("type")
        if scope_type not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        raw_headers = scope.get("headers") or ()

        # 1. Защита от DNS Rebinding: сверяем заголовок Host без номера порта
        if not self._is_host_allowed(_extract_raw_header(raw_headers, b"host")):
            await self._reject(
                scope,
                receive,
                send,
                "Отклонено по безопасности: недопустимый заголовок Host.",
            )
            return

        # 2. Разрешаем CORS preflight и минимальный локальный пинг готовности `GET /api/health`
        if scope_type == "http":
            method = str(scope.get("method") or "").upper()
            path = str(scope.get("path") or "")
            if method == "OPTIONS" or (method == "GET" and path == "/api/health"):
                await self.app(scope, receive, send)
                return

        # 3. Строгая байтовая сверка `X-Lgraph-Token` за константное время
        provided_bytes = _extract_raw_header(raw_headers, self._token_header_bytes).strip()
        if not provided_bytes or not secrets.compare_digest(provided_bytes, self._expected_bytes):
            await self._reject(
                scope,
                receive,
                send,
                "Доступ запрещён: отсутствует или не совпадает заголовок X-Lgraph-Token.",
            )
            return

        await self.app(scope, receive, send)
