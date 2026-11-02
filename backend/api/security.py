"""
Защита локального сетевого периметра демона Lgraph (Fail-Closed Middleware).

Почему одного прослушивания `127.0.0.1` недостаточно для безопасности:
Злонамеренный сайт, открытый в обычном браузере разработчика, может попытаться обратиться
к `http://127.0.0.1:8765` (Cross-Site Request / DNS Rebinding). Проверка заголовка `Host`
и секретного токена `X-Lgraph-Token` через `secrets.compare_digest` гарантирует, что к карте
архитектуры имеют доступ только окно нашего Electron-приложения и локальный агент.
"""

from __future__ import annotations

import secrets
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from backend.core.config import TOKEN_HEADER_NAME

_ALLOWED_HOSTS: frozenset[str] = frozenset(
    {
        "127.0.0.1",
        "localhost",
        "testserver",  # Для изолированных in-memory автотестов FastAPI TestClient
    }
)


class LocalPerimeterMiddleware(BaseHTTPMiddleware):
    """Отклоняет любые запросы без валидного локального `Host` и `X-Lgraph-Token`."""

    def __init__(self, app, expected_token: str) -> None:  # type: ignore[no-untyped-def]
        super().__init__(app)
        if not expected_token or len(expected_token) < 16:
            raise ValueError("Токен безопасности демона Lgraph не может быть пустым или коротким.")
        self._expected_token = expected_token

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # 1. Защита от DNS Rebinding: проверяем заголовок Host без номера порта
        raw_host = (request.headers.get("host") or "").split(":", 1)[0].strip().lower()
        if raw_host not in _ALLOWED_HOSTS:
            return JSONResponse(
                status_code=403,
                content={"detail": "Отклонено по безопасности: недопустимый заголовок Host."},
            )

        # 2. Разрешаем CORS preflight и минимальный локальный пинг готовности `/api/health`
        if request.method == "OPTIONS" or request.url.path == "/api/health":
            return await call_next(request)

        # 3. Строгая проверка секретного заголовка `X-Lgraph-Token` за константное время
        provided_token = (request.headers.get(TOKEN_HEADER_NAME) or "").strip()
        if not provided_token or not secrets.compare_digest(provided_token, self._expected_token):
            return JSONResponse(
                status_code=403,
                content={"detail": "Доступ запрещён: отсутствует или не совпадает заголовок X-Lgraph-Token."},
            )

        return await call_next(request)
