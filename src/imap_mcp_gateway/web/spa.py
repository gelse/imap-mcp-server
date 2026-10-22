"""Single-page-application serving for the admin and user surfaces (M07-T05).

The Jinja2 pages are GONE: ``/admin`` and ``/user`` — and every deep link
below them — now serve the BUILT SPA's ``index.html`` (the Vue 3 + Vite
bundle of M07-T02/T03/T04). Three serving rules make that cutover safe:

- **The shell is read LAZILY, per request** (``index.html`` is read from
  ``settings.spa_dist_dir`` inside the handler). Nothing stats the dist at
  app-construction time, so an app built without a dist — every unit test
  that does not exercise the shell — stays constructible. A missing or
  unreadable ``index.html`` fails LOUD with the fixed 500 JSON shape
  (``{"error": "internal_error"}``) instead of a half-broken page.
- **The shell is never cached**: ``Cache-Control: no-store`` is set
  explicitly here (the admin surface's ASGI middleware already pins it for
  ``/admin*``; the user paths get it from this module — the parity the old
  per-route pins had).
- **The hashed assets are immutable**: ``/assets`` is a ``StaticFiles``
  mount whose responses carry ``Cache-Control: public, max-age=31536000,
  immutable``. Only Vite's content-hashed files live under ``assets/``, so
  the name changes whenever the bytes do.

``check_dir=False`` on the assets mount is MANDATORY: the mount is built
inside ``create_app``, which every existing unit test calls without a
dist. The default ``check_dir=True`` would raise at app-construction time
and break the whole suite; with it disabled a missing assets directory
degrades to request-time 404s (see the asset 404 note below).

Only GET (and the HEAD Starlette derives from it) exists on these paths.
The old server-rendered POST routes are gone, so a stale client gets
FastAPI's default 405 JSON (``{"detail": "Method Not Allowed"}``). The
published deep links keep working: the same paths serve the shell, and the
SPA resolves the route client-side.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import Request
from fastapi.responses import HTMLResponse
from starlette.exceptions import HTTPException
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.types import Receive, Scope, Send

from imap_mcp_gateway.config.env import Settings
from imap_mcp_gateway.web.middleware.admin_auth import AdminHTTPError

SHELL_PREFIXES = ("/admin", "/user")
"""The URL prefixes whose GETs serve the SPA shell."""

IMMUTABLE_CACHE_CONTROL = "public, max-age=31536000, immutable"
"""The cache policy for the content-hashed asset mount."""

NO_STORE_CACHE_CONTROL = "no-store"
"""The shell's cache policy — the shell is never cached by a browser."""


def _read_index_html(settings: Settings) -> str:
    """Read ``index.html`` from the dist directory; fail loud when absent.

    The read happens per request (see the module docstring): a dist that
    appears (or disappears) between two requests is picked up immediately,
    and an app built without one never fails at construction time.
    """
    index_path = Path(settings.spa_dist_dir) / "index.html"
    try:
        return index_path.read_text(encoding="utf-8")
    except OSError as exc:
        # Fail loud with the fixed 500 shape (no path, no OS detail in the
        # body): a missing dist is a deployment fault, not a user error.
        raise AdminHTTPError(500, "internal_error") from exc


async def spa_shell(request: Request) -> Response:
    """Serve the SPA shell for any admin/user path (auth-free by design).

    The shell carries no data and no key material: the SPA bootstraps its
    session and CSRF token from the JSON API (``/api/admin/session`` /
    ``/api/me/session``). Serving it to an unauthenticated visitor is
    therefore safe — the API remains the only source of truth.
    """
    settings: Settings = request.app.state.settings
    return HTMLResponse(
        _read_index_html(settings),
        headers={"Cache-Control": NO_STORE_CACHE_CONTROL},
    )


class ImmutableAssets(StaticFiles):
    """``StaticFiles`` that pins the immutable cache policy on every hit.

    The policy is safe because ONLY content-hashed build artifacts live
    under ``assets/`` — a changed file gets a new name, so a cached copy
    can never go stale.

    A missing asset answers Starlette's PLAIN-TEXT 404, not the app's
    JSON ``not_found`` shape: the mount owns its own error surface (the
    app-level JSON 404 contract stays "unchanged outside the mount").
    Starlette 1.8 propagates the ``HTTPException`` out of ``__call__``,
    where it would reach the application's status-code handler — so the
    conversion is made EXPLICITLY here.
    """

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        """Serve the asset; answer a missing one with a plain-text 404."""
        try:
            await super().__call__(scope, receive, send)
        except HTTPException as exc:
            if exc.status_code != 404:
                raise
            response = PlainTextResponse("Not Found", status_code=404)
            await response(scope, receive, send)

    async def get_response(self, path: str, scope: Scope) -> Response:
        """Serve the asset and pin ``Cache-Control`` on the response."""
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = IMMUTABLE_CACHE_CONTROL
        return response


def build_spa_routes() -> list[Route]:
    """The shell routes: ``/admin``, ``/user`` and their catch-alls.

    The catch-all is a ``{path:path}`` route, so EVERY deep link renders
    the same shell (the SPA resolves the route client-side) — that is what
    keeps the published deep links working after the cutover. ``/admin/``
    (with the trailing slash) matches the catch-all with an empty path, so
    it is served too — no redirect dance.
    """
    routes: list[Route] = []
    for prefix in SHELL_PREFIXES:
        routes.append(Route(prefix, spa_shell, methods=["GET"]))
        routes.append(Route(f"{prefix}/{{path:path}}", spa_shell, methods=["GET"]))
    return routes


def build_assets_mount(settings: Settings) -> Mount:
    """The ``/assets`` mount for the hashed build output.

    ``check_dir=False`` — see the module docstring: the mount is built at
    app-construction time and a missing assets directory must degrade to
    request-time 404s, never to a construction-time failure.
    """
    assets_dir = Path(settings.spa_dist_dir) / "assets"
    return Mount(
        "/assets",
        app=ImmutableAssets(directory=str(assets_dir), check_dir=False),
    )
