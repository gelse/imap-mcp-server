"""Admin JSON API: login, logout, session bootstrap, and the health ping (M02-T03).

Routes — the complete admin API surface of this milestone:

- ``POST /api/admin/login`` — exchanges the admin key (``key`` form field)
  for a signed, httpOnly session cookie; rate-limited per IP, uniform on
  failure;
- ``POST /api/admin/logout`` — admin-authenticated; invalidates the session
  cookie (CSRF-verified when cookie-authenticated, Bearer exempt);
- ``GET  /api/admin/session`` — cookie-session CSRF bootstrap (M07-T01):
  the session's CSRF token for the SPA, or the uniform 401;
- ``GET  /api/admin/health`` — authenticated ping, ``{"status": "ok"}``.

M03-T02 mounts the user-management sub-router here::

    from imap_mcp_gateway.web.admin.user_router import router as users_router
    router.include_router(users_router, prefix="/users")

(see the real ``include_router`` call below; its routes live in
``web/admin/user_router.py``). No route in this module ever returns key
material — the user-management router returns the one-time login key only
in its own create/rotate response bodies.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from imap_mcp_gateway.web.admin.user_router import router as users_router
from imap_mcp_gateway.web.middleware.admin_auth import (
    AdminAuthDep,
    AdminHTTPError,
    AdminRateLimiter,
    admin_session,
    client_ip,
    verify_presented_admin_key,
)
from imap_mcp_gateway.web.routers.csrf import CsrfDep
from imap_mcp_gateway.web.session import (
    ADMIN_COOKIE_NAME,
    SESSION_KIND_ADMIN,
    SessionSigner,
)

router = APIRouter(prefix="/api/admin", tags=["admin"])

# The M03 placeholder, now real: /api/admin + /users (routes in user_router.py).
router.include_router(users_router, prefix="/users")


async def _login_key(request: Request) -> str:
    """Extract the ``key`` form field; any malformed body reads as absent.

    A malformed body must produce the same uniform failed-login response as
    a wrong key, so parse errors are swallowed here rather than surfacing
    as a 422 validation error.
    """
    try:
        form = await request.form()
        value = form.get("key")
    except Exception:  # a hostile/undecodable body is just a failed login
        return ""
    return value if isinstance(value, str) else ""


@router.post("/login")
async def login(request: Request) -> JSONResponse:
    """Exchange the admin key for a signed httpOnly session cookie.

    The lockout gate reserves an attempt slot atomically BEFORE the body is
    read, so concurrent in-flight logins from one IP can never outnumber
    the limit. Failures are uniform — ``401 {"error": "unauthorized"}``
    whether the key is wrong, unknown, missing, or the body is unreadable —
    and counted per IP (the reserved slot becomes the failure record);
    successes hand the slot back. Success sets the cookie with ``HttpOnly``
    and ``SameSite=strict``; no plaintext key material ever appears in any
    response. The scrypt KDF runs in the threadpool so a verification never
    blocks the event loop for other requests.
    """
    limiter: AdminRateLimiter = request.app.state.admin_rate_limiter
    ip = client_ip(request)
    if not limiter.try_acquire(ip):
        raise AdminHTTPError(
            429,
            "rate_limited",
            headers={"Retry-After": str(limiter.retry_after(ip))},
        )
    presented = await _login_key(request)
    if not await run_in_threadpool(verify_presented_admin_key, request, presented):
        raise AdminHTTPError(401, "unauthorized")  # the slot stays: a failure
    limiter.release(ip)
    signer: SessionSigner = request.app.state.session_signer
    cookie_value, _csrf_token = signer.create_session(SESSION_KIND_ADMIN)
    response = JSONResponse({"status": "ok"})
    response.set_cookie(
        ADMIN_COOKIE_NAME,
        cookie_value,
        max_age=signer.ttl_seconds,
        path="/",
        httponly=True,
        samesite="strict",
    )
    return response


@router.post("/logout")
async def logout(_auth: AdminAuthDep, _csrf: CsrfDep) -> JSONResponse:
    """Invalidate the admin session cookie (admin-authenticated, CSRF-checked).

    With a Bearer header the CSRF check is exempt by convention; with a
    cookie session the request must carry the session's CSRF token. The
    response deletes the cookie either way.
    """
    response = JSONResponse({"status": "ok"})
    response.delete_cookie(ADMIN_COOKIE_NAME, path="/")
    return response


@router.get("/session")
async def session_bootstrap(request: Request) -> JSONResponse:
    """Cookie-session CSRF bootstrap for the SPA (M07-T01).

    SPA-only consumer contract: the route reads ``admin_session(request)``
    directly instead of depending on :data:`AdminAuthDep`, so it answers the
    uniform ``401 {"error": "unauthorized"}`` for every absent, invalid,
    expired or wrong-kind cookie — and DELIBERATELY for a Bearer caller too:
    a header-authenticated caller is CSRF-exempt by convention and needs no
    CSRF token, so it must not be handed one. Valid cookie ->
    ``200 {"csrf_token": <payload["csrf"]>}`` with ``Cache-Control:
    no-store`` set explicitly (belt-and-braces alongside the app-wide admin
    no-store middleware). No rate-limiter interaction: invalid cookies fail
    closed WITHOUT counting (the M02 convention — they require forging an
    HMAC, not guessing a key). Route order is irrelevant (exact path, no
    ``/api/admin/{...}`` catch-all exists).
    """
    payload = admin_session(request)
    if payload is None:
        raise AdminHTTPError(401, "unauthorized")
    response = JSONResponse({"csrf_token": payload["csrf"]})
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/health")
async def admin_health(_auth: AdminAuthDep) -> dict[str, str]:
    """Authenticated liveness ping for the admin API (the only GET surface)."""
    return {"status": "ok"}
