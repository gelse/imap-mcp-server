"""SPA shell serving tests (M07-T05).

The Jinja2 pages are gone: ``/admin`` and ``/user`` (and every deep link
below them) serve the built single-page application's ``index.html``, and
``/assets`` mounts the content-hashed build output. This suite pins that
serving contract:

- the serving matrix — every admin/user path answers 200 ``text/html`` with
  the SAME shell body and ``Cache-Control: no-store``;
- the asset mount — 200 with ``Cache-Control: public, max-age=31536000,
  immutable`` for a hashed file, 404 for a missing one;
- the JSON 404 contract outside the SPA prefixes is untouched;
- the method boundary — non-GET on a SPA path answers FastAPI's default
  405 (the old server-rendered POST routes are gone);
- the shell and the served asset carry no secret material;
- the browser-security headers (CSP, nosniff, frame denial, no-referrer)
  are present on the shell, and the admin no-store pin still holds on
  ``/api/admin*``;
- a missing dist fails LOUD with the fixed 500 JSON shape.

The tests use the SHARED synthetic ``spa_dist`` fixture (tests/conftest.py):
the real ``frontend/dist`` is a gitignored npm build artifact, so the unit
suite stays hermetic and toolchain-free.
"""

from __future__ import annotations

import re
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from imap_mcp_gateway.config.env import Settings
from imap_mcp_gateway.web.server import create_app

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("scrypt hash record", re.compile(r"scrypt\$")),
    ("key material", re.compile(r"\b(?:adm_|usr_)[A-Za-z0-9_-]{20,}")),
    ("64-hex secret", re.compile(r"(?<![0-9a-f])[0-9a-f]{64,}")),
)
"""The banned secret shapes: a hash record, key material, a hex secret."""

EXPECTED_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
    "base-uri 'none'; frame-ancestors 'none'"
)
"""The conservative CSP (M07-T05) — no ``'unsafe-inline'`` anywhere."""

SHELL_PATHS: tuple[str, ...] = (
    "/admin",
    "/admin/",
    "/admin/login",
    "/admin/users",
    "/admin/users/x",
    "/admin/users/new",
    "/user",
    "/user/",
    "/user/login",
    "/user/accounts/new",
    "/user/accounts/x",
    "/user/settings",
)
"""Every path that must render the one SPA shell."""


@pytest.fixture
def app(tmp_path: Path, spa_dist: Path) -> FastAPI:
    """An app whose SPA dist is the shared synthetic fixture."""
    return create_app(Settings(data_dir=tmp_path, spa_dist_dir=spa_dist))


def _client(app: FastAPI) -> httpx.AsyncClient:
    """An in-process client over the app (cookies persist within the client)."""
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


def _assert_secret_free(label: str, body: str) -> None:
    """Assert one body carries none of the banned secret shapes."""
    for name, pattern in _SECRET_PATTERNS:
        assert pattern.search(body) is None, f"{label}: {name} in body"


# --- the serving matrix ---------------------------------------------------------


@pytest.mark.parametrize("path", SHELL_PATHS)
async def test_every_admin_and_user_path_serves_the_spa_shell(
    app: FastAPI, spa_dist: Path, path: str
) -> None:
    """The shell is served for every admin/user path — one body, never cached."""
    expected = (spa_dist / "index.html").read_text(encoding="utf-8")
    async with _client(app) as client:
        response = await client.get(path)
    assert response.status_code == 200, path
    assert "text/html" in response.headers["content-type"], path
    assert response.headers["cache-control"] == "no-store", path
    assert response.text == expected, path


async def test_deep_link_under_the_admin_prefix_serves_the_same_shell(
    app: FastAPI, spa_dist: Path
) -> None:
    """A published deep link renders the SPA (the SPA resolves it client-side)."""
    expected = (spa_dist / "index.html").read_text(encoding="utf-8")
    async with _client(app) as client:
        deep = await client.get("/admin/users/deep/link/42")
    assert deep.status_code == 200
    assert deep.text == expected


# --- the asset mount ------------------------------------------------------------


async def test_hashed_assets_are_served_with_the_immutable_cache_policy(
    app: FastAPI,
) -> None:
    """``/assets`` serves the hashed build output with the immutable policy."""
    async with _client(app) as client:
        asset = await client.get("/assets/app-abc123.js")
    assert asset.status_code == 200
    assert asset.headers["cache-control"] == "public, max-age=31536000, immutable"


async def test_a_missing_asset_is_a_plain_text_404(app: FastAPI) -> None:
    """A missing asset is Starlette's plain-text 404.

    The asset mount never passes through the app's exception handlers, so
    this 404 is NOT the JSON ``not_found`` shape — an accepted and
    documented divergence from the app-level 404 contract.
    """
    async with _client(app) as client:
        missing = await client.get("/assets/not-there-123456.js")
    assert missing.status_code == 404
    assert "not_found" not in missing.text


# --- the JSON 404 contract outside the SPA prefixes ------------------------------


async def test_the_json_404_contract_is_unchanged_outside_the_spa_prefixes(
    app: FastAPI,
) -> None:
    """Paths outside /admin, /user and /assets still answer the JSON 404."""
    async with _client(app) as client:
        root = await client.get("/")
        missing_api = await client.get("/api/definitely-missing")
    assert root.status_code == 404
    assert root.json() == {"error": "not_found", "path": "/"}
    assert missing_api.status_code == 404
    assert missing_api.json() == {"error": "not_found", "path": "/api/definitely-missing"}


# --- the method boundary --------------------------------------------------------


async def test_non_get_on_a_spa_path_answers_405(app: FastAPI) -> None:
    """The old server-rendered POST routes are gone: non-GET answers 405.

    The shape is FastAPI's default ``{"detail": "Method Not Allowed"}`` —
    deliberately not re-pinned to the gateway's ``{"error": ...}`` shape
    (the same shape unmatched methods already produce elsewhere).
    """
    async with _client(app) as client:
        created = await client.post("/admin/users", json={"name": "x"})
        stale = await client.post("/user/settings/rotate-key")
    assert created.status_code == 405
    assert created.json() == {"detail": "Method Not Allowed"}
    assert stale.status_code == 405
    assert stale.json() == {"detail": "Method Not Allowed"}


# --- secret-free shell ----------------------------------------------------------


async def test_the_shell_and_its_assets_carry_no_secret_material(
    app: FastAPI,
) -> None:
    """The shell is served to EVERY visitor — it must carry nothing secret.

    This is the M07-T05 replacement for the retired "every page is secret
    free and JavaScript free" invariant (see the regression note at the
    bottom of this module): the JS-free half is superseded by the SPA
    itself (the bundled JS is the product, and the build audit scans it),
    while the secret-free half is pinned here — on the shell AND on the
    asset body it references.
    """
    async with _client(app) as client:
        admin_shell = await client.get("/admin")
        user_shell = await client.get("/user")
        asset = await client.get("/assets/app-abc123.js")
    for label, body in (
        ("GET /admin", admin_shell.text),
        ("GET /user", user_shell.text),
        ("GET /assets/app-abc123.js", asset.text),
    ):
        _assert_secret_free(label, body)


# --- browser-security headers ---------------------------------------------------


async def test_the_shell_carries_the_browser_security_headers(
    app: FastAPI,
) -> None:
    """CSP, nosniff, frame denial and no-referrer are on the shell."""
    async with _client(app) as client:
        shell = await client.get("/admin")
    assert shell.headers["Content-Security-Policy"] == EXPECTED_CSP
    assert shell.headers["X-Content-Type-Options"] == "nosniff"
    assert shell.headers["X-Frame-Options"] == "DENY"
    assert shell.headers["Referrer-Policy"] == "no-referrer"
    assert shell.headers["Cache-Control"] == "no-store"


async def test_the_admin_no_store_pin_still_covers_the_api_surface(
    app: FastAPI,
) -> None:
    """The SPA cutover did not weaken the admin no-store middleware."""
    async with _client(app) as client:
        unauthorized = await client.get("/api/admin/health")
    assert unauthorized.status_code == 401
    assert unauthorized.headers["cache-control"] == "no-store"


# --- a missing dist fails loud --------------------------------------------------


async def test_a_missing_dist_fails_loud_with_the_fixed_500_shape(
    tmp_path: Path,
) -> None:
    """No dist -> the fixed 500 JSON shape, not a half-broken page.

    The dist is read LAZILY per request, so an app built without one is
    constructible (every unit test does exactly that) — but a request for
    a shell page fails loud, with the gateway's fixed ``internal_error``
    body and no path or OS detail in it.
    """
    absent = tmp_path / "no-such-dist"
    app = create_app(Settings(data_dir=tmp_path, spa_dist_dir=absent))
    async with _client(app) as client:
        response = await client.get("/admin")
    assert response.status_code == 500
    assert response.json() == {"error": "internal_error"}


# --- regression notes ------------------------------------------------------------


"""
Regression notes (M07-T05) — the deliberate supersessions this task pins:

1. **The JS-free invariant is retired.** The old HTML suites asserted that
   every served page was JavaScript-free. That is deliberately SUPERSEDED:
   the SPA's bundled JavaScript IS the product. The invariant's secret-free
   half survives in ``test_the_shell_and_its_assets_carry_no_secret_material``
   (plus the built-bundle audit in ``frontend/scripts/audit-dist.mjs``);
   the JS-free half is replaced by the frontend's own Vitest suite.
2. **Page gating is gone.** An unauthenticated ``GET /admin`` used to
   answer a 303 to the login page; it now answers the 200 shell. The
   authentication gate is the API's uniform 401 — the shell carries no
   data. The deep links that used to 404 now render the shell, and the SPA
   renders its own not-found view from the API's 404.
3. **The one-shot form tickets are gone.** The server-rendered mutating
   forms carried a per-form one-shot ticket; that machinery died with the
   HTML routes. The JSON mutations were never ticket-guarded — the
   API-level auth + CSRF protections are unchanged.
4. **The server-side ``confirm_name`` is gone.** The destructive-action
   confirmation moved into the SPA's type-to-confirm dialog. The API
   never had a ``confirm_name`` guard and none was added.
"""
