"""HTTP-surface tests for the real app (M01-T04): /healthz, JSON 404, JSON 500.

Supersedes ``tests/test_healthz_placeholder.py`` (removed along with the
placeholder bootstrap it locked in). The requests run through
``httpx.AsyncClient`` with an ASGI transport against the in-process app.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from imap_mcp_gateway.config.env import Settings
from imap_mcp_gateway.web.server import create_app


@pytest.fixture
def app(tmp_path: Path) -> FastAPI:
    """The production app under test, pointed at a temp data dir."""
    return create_app(Settings(data_dir=tmp_path))


def _client(app: FastAPI, *, raise_app_exceptions: bool = True) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=raise_app_exceptions)
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


async def test_healthz_returns_200_ok_shape(app: FastAPI) -> None:
    async with _client(app) as client:
        response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_unknown_route_returns_json_404_shape(app: FastAPI) -> None:
    async with _client(app) as client:
        response = await client.get("/definitely-not-a-route")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == {
        "error": "not_found",
        "path": "/definitely-not-a-route",
    }


async def test_docs_and_openapi_endpoints_disabled(app: FastAPI) -> None:
    """No unauthenticated schema surface: docs/redoc/OpenAPI routes stay off."""
    async with _client(app) as client:
        for path in ("/docs", "/redoc", "/openapi.json"):
            response = await client.get(path)
            assert response.status_code == 404
            assert response.headers["content-type"].startswith("application/json")
            assert response.json() == {"error": "not_found", "path": path}


async def test_unhandled_error_returns_json_500_without_traceback(
    tmp_path: Path,
) -> None:
    app = create_app(Settings(data_dir=tmp_path))

    @app.get("/_test/boom")
    async def boom() -> dict[str, str]:
        """Test-only route raising to trigger the unhandled-error path."""
        raise RuntimeError("secret boom detail")

    # raise_app_exceptions=False: the app sends the JSON 500 and re-raises
    # (ServerErrorMiddleware behaviour) — the transport returns the response.
    async with _client(app, raise_app_exceptions=False) as client:
        response = await client.get("/_test/boom")
    assert response.status_code == 500
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == {"error": "internal_error"}
    body = response.text
    assert "Traceback" not in body
    assert "RuntimeError" not in body
    assert "boom" not in body


async def test_unhandled_error_reraises_for_server_logging(tmp_path: Path) -> None:
    """The 500 handler is a ServerErrorMiddleware handler: body sent, then re-raise.

    Locks the wiring that keeps the error loggable server-side (uvicorn logs the
    re-raised exception) — a handler registered per-class in ExceptionMiddleware
    would silently swallow it and still pass the body-shape test above.
    """
    app = create_app(Settings(data_dir=tmp_path))

    @app.get("/_test/boom")
    async def boom() -> dict[str, str]:
        """Test-only route raising to trigger the unhandled-error path."""
        raise RuntimeError("secret boom detail")

    with pytest.raises(RuntimeError):
        async with _client(app) as client:  # raise_app_exceptions=True (default)
            await client.get("/_test/boom")
