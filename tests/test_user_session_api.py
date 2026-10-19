"""Cross-surface session/CSRF bootstrap endpoint matrix (M07-T01).

The two SPA session endpoints — ``GET /api/me/session`` and
``GET /api/admin/session`` — are the CSRF-token bootstrap for the cookie
surfaces. This module pins their SHARED contract directly (the login /
logout behaviour lives in ``test_user_account_api.py`` and
``test_admin_auth.py``):

- a valid cookie gets back the session's own ``csrf`` payload member, and
  the signed cookie decoded in the test matches byte for byte;
- BOTH responses pin ``Cache-Control: no-store``;
- no / invalid / expired / wrong-kind cookie is the uniform
  ``401 {"error": "unauthorized"}``;
- ``GET /api/admin/session`` DELIBERATELY 401s a Bearer admin key (a
  header caller is CSRF-exempt and must never be handed a token);
- the bootstrapped token is not decorative: it authorizes a real mutation
  end to end on each surface.
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from imap_mcp_gateway.config.env import Settings
from imap_mcp_gateway.config.paths import Paths, build_paths
from imap_mcp_gateway.crypto.hash import hash_secret
from imap_mcp_gateway.crypto.keys import generate_admin_key
from imap_mcp_gateway.store.admin_key import save_admin_key_hash
from imap_mcp_gateway.store.users import create_user
from imap_mcp_gateway.store.wrap_key import ensure_wrap_key
from imap_mcp_gateway.web.server import create_app
from imap_mcp_gateway.web.session import (
    ADMIN_COOKIE_NAME,
    SESSION_KIND_ADMIN,
    SESSION_KIND_USER,
    USER_COOKIE_NAME,
)

# --- fixtures --------------------------------------------------------------------


@pytest.fixture(scope="module")
def admin_key() -> str:
    """One admin key for the module (key generation is cheap)."""
    return generate_admin_key()


@pytest.fixture(scope="module")
def admin_record(admin_key: str) -> str:
    """The scrypt record for :func:`admin_key` (one expensive scrypt run)."""
    return hash_secret(admin_key)


@pytest.fixture
def paths(tmp_path: Path) -> Paths:
    return build_paths(tmp_path)


@pytest.fixture
def app(tmp_path: Path, paths: Paths, admin_record: str) -> FastAPI:
    """One app over a fresh DATA_DIR, wrap key + admin key hash installed."""
    ensure_wrap_key(paths)
    save_admin_key_hash(paths, admin_record)
    return create_app(Settings(data_dir=tmp_path))


def _client(app: FastAPI) -> httpx.AsyncClient:
    """An in-process client over the app (cookies persist within the client)."""
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    )


@asynccontextmanager
async def _user_session(
    app: FastAPI, paths: Paths, name: str = "alice"
) -> AsyncIterator[tuple[httpx.AsyncClient, str, str]]:
    """A cookie-session user client plus its ``(user_id, csrf)`` values."""
    record, _key = create_user(paths, name)
    cookie, csrf = app.state.session_signer.create_session(
        SESSION_KIND_USER, sub=record.id
    )
    client = _client(app)
    client.cookies.set(USER_COOKIE_NAME, cookie)
    try:
        yield client, record.id, csrf
    finally:
        await client.aclose()


def _decode_jar(app: FastAPI, client: httpx.AsyncClient, cookie_name: str) -> dict[str, Any]:
    """Unseal a session cookie already held by the client (GET sets none)."""
    payload = app.state.session_signer.unseal(client.cookies[cookie_name])
    assert payload is not None
    return dict(payload)


# --- user session bootstrap ------------------------------------------------------


async def test_user_session_returns_the_cookie_csrf_token(
    app: FastAPI, paths: Paths
) -> None:
    """``GET /api/me/session`` echoes the cookie payload's ``csrf``, no-store."""
    async with _user_session(app, paths) as (client, _user_id, csrf):
        response = await client.get("/api/me/session")
        # The token equals the signed cookie's own payload member.
        payload = _decode_jar(app, client, USER_COOKIE_NAME)
    assert response.status_code == 200
    assert response.json() == {"csrf_token": csrf}
    assert "no-store" in response.headers["cache-control"].lower()
    assert payload["kind"] == SESSION_KIND_USER
    assert payload["csrf"] == csrf


async def test_user_session_bearer_less_invalid_and_expired_are_401(
    app: FastAPI, paths: Paths
) -> None:
    """No / invalid / expired / wrong-kind user cookie -> uniform 401."""
    signer = app.state.session_signer
    async with _client(app) as client:
        # No cookie at all.
        absent = await client.get("/api/me/session")
        assert absent.status_code == 401
        assert absent.json() == {"error": "unauthorized"}

        # Present but not a valid signed cookie.
        client.cookies.set(USER_COOKIE_NAME, "not-a-signed-cookie")
        invalid = await client.get("/api/me/session")
        assert invalid.status_code == 401
        assert invalid.json() == {"error": "unauthorized"}

        # Structurally valid but EXPIRED (exp in the past).
        expired = signer.seal(
            {
                "kind": SESSION_KIND_USER,
                "sub": "whoever",
                "csrf": "token",
                "exp": str(int(time.time()) - 3600),
            }
        )
        client.cookies.set(USER_COOKIE_NAME, expired)
        assert (await client.get("/api/me/session")).status_code == 401

        # Right shape, WRONG kind (an admin cookie must not bootstrap a user).
        wrong_kind = signer.seal(
            {
                "kind": SESSION_KIND_ADMIN,
                "csrf": "token",
                "exp": str(int(time.time()) + 3600),
            }
        )
        client.cookies.set(USER_COOKIE_NAME, wrong_kind)
        assert (await client.get("/api/me/session")).status_code == 401


async def test_user_bootstrapped_token_authorizes_a_mutation(
    app: FastAPI, paths: Paths
) -> None:
    """The bootstrapped token is usable end to end (activate the AEK)."""
    async with _user_session(app, paths) as (client, _user_id, _csrf):
        token = (await client.get("/api/me/session")).json()["csrf_token"]
        # A client that only knows the token (no cookie plumbing) mutates.
        async with _client(app) as spaclient:
            spaclient.cookies.set(
                USER_COOKIE_NAME, client.cookies[USER_COOKIE_NAME]
            )
            activated = await spaclient.post(
                "/api/me/accounts/activate",
                headers={"X-CSRF-Token": token},
            )
    assert activated.status_code == 200
    assert activated.json()["account_encryption_key"]


# --- admin session bootstrap -----------------------------------------------------


async def test_admin_session_returns_the_cookie_csrf_token(
    app: FastAPI, admin_key: str
) -> None:
    """``GET /api/admin/session`` echoes the cookie payload's ``csrf``."""
    async with _client(app) as client:
        login = await client.post("/api/admin/login", data={"key": admin_key})
        assert login.status_code == 200
        assert login.json() == {"status": "ok"}
        response = await client.get("/api/admin/session")
        payload = _decode_jar(app, client, ADMIN_COOKIE_NAME)
    assert response.status_code == 200
    assert "no-store" in response.headers["cache-control"].lower()
    assert payload["kind"] == SESSION_KIND_ADMIN
    assert response.json() == {"csrf_token": payload["csrf"]}


async def test_admin_session_rejects_a_bearer_caller(
    app: FastAPI, admin_key: str
) -> None:
    """A Bearer admin key is DELIBERATELY 401 — it is CSRF-exempt (no token).

    ``require_admin`` would accept the header, but a header caller has no
    session cookie and therefore no CSRF token to bootstrap; handing one out
    would be meaningless (and would blur the cookie-only contract).
    """
    async with _client(app) as client:
        response = await client.get(
            "/api/admin/session",
            headers={"Authorization": f"Bearer {admin_key}"},
        )
    assert response.status_code == 401
    assert response.json() == {"error": "unauthorized"}


async def test_admin_session_invalid_expired_and_wrong_kind_are_401(
    app: FastAPI,
) -> None:
    """No / invalid / expired / user-kind admin cookie -> uniform 401."""
    signer = app.state.session_signer
    async with _client(app) as client:
        absent = await client.get("/api/admin/session")
        assert absent.status_code == 401
        assert absent.json() == {"error": "unauthorized"}

        client.cookies.set(ADMIN_COOKIE_NAME, "not-a-signed-cookie")
        assert (await client.get("/api/admin/session")).status_code == 401

        expired = signer.seal(
            {
                "kind": SESSION_KIND_ADMIN,
                "csrf": "token",
                "exp": str(int(time.time()) - 3600),
            }
        )
        client.cookies.set(ADMIN_COOKIE_NAME, expired)
        assert (await client.get("/api/admin/session")).status_code == 401

        wrong_kind = signer.seal(
            {
                "kind": SESSION_KIND_USER,
                "sub": "whoever",
                "csrf": "token",
                "exp": str(int(time.time()) + 3600),
            }
        )
        client.cookies.set(ADMIN_COOKIE_NAME, wrong_kind)
        assert (await client.get("/api/admin/session")).status_code == 401


async def test_admin_bootstrapped_token_authorizes_a_mutation(
    app: FastAPI, admin_key: str
) -> None:
    """The bootstrapped admin token authorizes a mutating admin route.

    ``POST /api/admin/logout`` is the cheapest mutation needing CSRF; using
    the bootstrapped token proves the endpoint is a real bootstrap, not a
    token-shaped stub.
    """
    async with _client(app) as client:
        assert (
            await client.post("/api/admin/login", data={"key": admin_key})
        ).status_code == 200
        token = (await client.get("/api/admin/session")).json()["csrf_token"]
        logged_out = await client.post(
            "/api/admin/logout", headers={"X-CSRF-Token": token}
        )
    assert logged_out.status_code == 200
    assert logged_out.json() == {"status": "ok"}
    assert ADMIN_COOKIE_NAME in logged_out.headers["set-cookie"]
