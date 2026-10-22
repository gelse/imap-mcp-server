"""FastAPI application factory for the gateway's HTTP surface.

``create_app`` assembles the production app: the ``/healthz`` router plus a
fixed JSON error contract. FastAPI/Starlette's defaults do not qualify — the
unmatched-route 404 renders framework-default text and unhandled errors would
leak debug details — so the gateway pins both shapes itself:

- unknown routes -> ``404 {"error": "not_found", "path": "<requested path>"}``;
- unhandled exceptions -> ``500 {"error": "internal_error"}`` with NO stack
  trace or exception detail in the body (the exception is still re-raised
  after the response so the server logs it server-side).

Docs/OpenAPI endpoints are disabled: no milestone calls for an unauthenticated
API-schema surface, and the HTTP surface grows behind auth from M02 on.

M02-T03 adds the admin surface: the ``/api/admin`` JSON router (its auth
enforcement lives inside that module), the fixed ``AdminHTTPError`` JSON
error contract, the per-boot session signer and rate limiter on
``app.state`` (both memory-only), and the ASGI middleware pinning
``Cache-Control: no-store`` on every admin response. M04-T04 mounts the
user self-service JSON API under ``/api/me``
(its auth/CSRF enforcement lives in the user router; its activation and
rotation responses pin ``Cache-Control: no-store`` per response). M05-T01
mounts the ``/mcp`` MCP gateway (the raw-ASGI sub-app from
:func:`imap_mcp_gateway.mcp.gateway.create_mcp_gateway`) as an exact-path
``Route``; its ``tool_host_factory`` defaults to a fail-closed placeholder
until M05-T02 supplies the real one. M06-T02 adds the user-login rate
limiter on ``app.state`` (a separate instance from the admin surface's, so
the two lockouts cannot cross-fire) and the outermost
:class:`~imap_mcp_gateway.web.middleware.security_headers.
SecurityHeadersMiddleware` pinning ``nosniff``/``X-Frame-Options``/
``Referrer-Policy``/``Content-Security-Policy`` on every HTTP response.

M07-T05 REPLACES the server-rendered admin/user pages with the built
single-page application: ``/admin`` and ``/user`` (and every deep link
below them) serve the SPA shell, and ``/assets`` mounts the hashed build
output — see :mod:`imap_mcp_gateway.web.spa`. The Jinja2 templates and the
three HTML view modules are gone; the JSON APIs under ``/api/*`` and
``/mcp`` are untouched.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.routing import Route
from starlette.types import Lifespan

from imap_mcp_gateway import __version__
from imap_mcp_gateway.config.env import Settings
from imap_mcp_gateway.mcp.gateway import ToolHost, ToolHostFactory, create_mcp_gateway
from imap_mcp_gateway.store.user_schema import UserMetadata
from imap_mcp_gateway.web.admin.router import router as admin_api_router
from imap_mcp_gateway.web.middleware.admin_auth import (
    AdminHTTPError,
    AdminRateLimiter,
    NoStoreCacheHeadersMiddleware,
    admin_http_error_handler,
)
from imap_mcp_gateway.web.middleware.security_headers import SecurityHeadersMiddleware
from imap_mcp_gateway.web.middleware.user_auth import USER_LOGIN_FAILURE_LIMIT
from imap_mcp_gateway.web.routers.health import router as health_router
from imap_mcp_gateway.web.session import SessionSigner
from imap_mcp_gateway.web.spa import build_assets_mount, build_spa_routes
from imap_mcp_gateway.web.user.router import router as user_api_router


async def _not_found_handler(request: Request, _exc: Exception) -> JSONResponse:
    """Return the fixed JSON 404 shape (echoes the requested path only)."""
    return JSONResponse(
        {"error": "not_found", "path": str(request.url.path)},
        status_code=404,
    )


async def _internal_error_handler(_request: Request, _exc: Exception) -> JSONResponse:
    """Return the fixed JSON 500 shape; no exception detail reaches the body."""
    return JSONResponse({"error": "internal_error"}, status_code=500)


class _PlaceholderToolHostFactory:
    """Fail-closed wiring sentinel for the M05-T02 ``ToolHostFactory`` seam.

    Not a tool host implementation: any authenticated session-opening request
    raises here, and the gateway's host-start failure handler answers a 500
    JSON-RPC ``"Tool host failed to start"`` — ``/mcp`` refuses service
    instead of half-serving a session until M05-T02 drops the real factory
    in via ``app.run``.
    """

    async def create(self, user: UserMetadata, session_id: str) -> ToolHost:
        raise RuntimeError("MCP gateway not configured (M05-T02 drop-in)")


def create_app(
    settings: Settings,
    *,
    lifespan: Lifespan[FastAPI] | None = None,
    tool_host_factory: ToolHostFactory | None = None,
) -> FastAPI:
    """Build the gateway's FastAPI app; ``lifespan`` is supplied by ``app.run``.

    ``tool_host_factory`` is the M05-T02 seam: the ``/mcp`` gateway is built
    from it (or from the fail-closed :class:`_PlaceholderToolHostFactory`
    until the real factory is dropped in) and attached as an exact-path
    ``Route`` — never a ``Mount``, which compiles to ``/mcp/{path}`` and
    would 307-redirect ``/mcp`` to ``/mcp/`` before the gateway's auth gate.
    """
    application = FastAPI(
        title="imap-mcp-gateway",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    application.state.settings = settings
    # Admin web shell (M02-T03): the session signer holds the per-boot random
    # HMAC secret in memory only (a restart invalidates every cookie, forcing
    # re-login); the rate limiter keeps per-IP failure counters for the same
    # process lifetime. Neither is ever persisted.
    application.state.session_signer = SessionSigner()
    application.state.admin_rate_limiter = AdminRateLimiter()
    # M06-T02: the user-login limiter is a SEPARATE instance from the admin
    # one — one surface's hostile traffic must not lock the other surface's
    # operator out (a cross-surface lockout DoS). Memory-only, same as the
    # admin limiter: nothing persists across restarts.
    application.state.user_login_rate_limiter = AdminRateLimiter(
        limit=USER_LOGIN_FAILURE_LIMIT
    )
    application.include_router(health_router)
    application.include_router(admin_api_router)  # /api/admin/* (M02-T03)
    # Importing the user router registers the M04-T03 account-store AEK
    # rotation hook (the router's store.accounts import) — production wiring.
    application.include_router(user_api_router)  # /api/me/* (M04-T04)
    # M07-T05: the SPA shell replaces the deleted Jinja2 admin/user pages.
    # The shell routes and the hashed-asset mount are ordinary routes, so
    # the JSON 404 catch-all keeps swallowing everything outside /admin,
    # /user and /assets.
    application.router.routes.extend(build_spa_routes())
    application.router.routes.append(build_assets_mount(settings))
    factory: ToolHostFactory = tool_host_factory or _PlaceholderToolHostFactory()
    # M05-T01: MCP gateway mount — exact-path Route (not Mount)
    application.router.routes.append(Route("/mcp", create_mcp_gateway(factory)))
    application.add_exception_handler(AdminHTTPError, admin_http_error_handler)
    # Cache-Control: no-store on every /api/admin and /admin response.
    application.add_middleware(NoStoreCacheHeadersMiddleware)
    # M06-T02: uniform browser-security headers on EVERY HTTP response.
    # Added AFTER the no-store middleware so it sits OUTERMOST in the stack
    # (Starlette prepends): its send-wrapper wraps the inner one, and its
    # setdefault semantics leave the no-store and per-route headers intact.
    application.add_middleware(SecurityHeadersMiddleware)
    # A status-keyed handler takes precedence over exception-class handlers in
    # Starlette's ExceptionMiddleware, so unmatched routes (Router.not_found
    # raises HTTPException(404)) get the JSON shape, not the default body.
    application.add_exception_handler(404, _not_found_handler)
    # The Exception key wires this handler into ServerErrorMiddleware: our
    # body is sent first, then the exception is re-raised for the server log.
    application.add_exception_handler(Exception, _internal_error_handler)
    return application
