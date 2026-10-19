"""Admin authentication dependency, rate limiting, and header middleware (M02-T03).

Auth contract: requests presenting ``Authorization: Bearer <admin key>`` are
verified in constant time against the stored ``admin-key.hash`` record via
``crypto.hash.verify_secret``; browsers instead carry the signed
``imapgw_admin`` session cookie (:mod:`imap_mcp_gateway.web.session`). Every
``/api/admin/*`` route sits behind :func:`require_admin`, which fails closed
as ``401 {"error": "unauthorized"}`` — the body never contains key material
and never distinguishes wrong key from unknown key from absent key.

The M07-T05 SPA shell (``/admin*``) is deliberately NOT behind this gate:
the shell carries no data (the SPA bootstraps its session from the gated
``GET /api/admin/session``), and serving it to every visitor is what keeps
the published deep links working.

Rate limiting: per-IP sliding-window failure counters — 5 failures within
10 minutes lock the IP out with ``429`` until the failures age out of the
window (self-healing cooldown). The gate RESERVES an attempt slot
atomically (``AdminRateLimiter.try_acquire``), so concurrent in-flight
attempts from one IP can never outnumber the limit across ``await``
points. Only *presented but invalid* credentials
count: a wrong Bearer key or a failed login POST. Requests without
credentials, and invalid/replayed session cookies (which would require
forging an HMAC-SHA256 tag, not guessing a key), fail closed without
counting — otherwise a browser holding a stale cookie across a restart
would lock its operator out. The client IP is the socket peer only:
``X-Forwarded-For`` is deliberately not honored because no trusted-proxy
contract exists in this milestone, so that header is attacker-controlled.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from imap_mcp_gateway.config.paths import Paths
from imap_mcp_gateway.crypto.hash import verify_secret
from imap_mcp_gateway.store.admin_key import load_admin_key_hash
from imap_mcp_gateway.web.session import (
    ADMIN_COOKIE_NAME,
    SESSION_KIND_ADMIN,
    SessionSigner,
)

FAILURE_LIMIT = 5
"""Failed attempts per IP within the window before lockout (M02 contract)."""

FAILURE_WINDOW_SECONDS = 600.0
"""Sliding lockout window: 10 minutes."""

_MAX_TRACKED_IPS = 4096
"""FIFO cap on tracked IPs so hostile traffic cannot grow the table unboundedly."""

_ADMIN_PATH_PREFIXES = ("/api/admin", "/admin")
"""URL prefixes whose responses always carry ``Cache-Control: no-store``."""


class AdminHTTPError(Exception):
    """Admin-surface failure rendered by the handler below as ``{"error": ...}``.

    The gateway pins fixed JSON error bodies (see ``web/server.py``); admin
    auth errors join that ``{"error": ...}`` contract instead of FastAPI's
    default ``{"detail": ...}`` shape.
    """

    def __init__(
        self,
        status_code: int,
        error: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(error)
        self.status_code = status_code
        self.error = error
        self.headers = headers


async def admin_http_error_handler(
    _request: Request, exc: Exception
) -> JSONResponse:
    """Render :class:`AdminHTTPError` as the fixed JSON shape, headers included.

    Starlette's handler registry types the second parameter ``Exception``;
    the registered exception class guarantees an :class:`AdminHTTPError`.
    """
    assert isinstance(exc, AdminHTTPError)
    return JSONResponse(
        {"error": exc.error},
        status_code=exc.status_code,
        headers=exc.headers,
    )


@dataclass(frozen=True, slots=True)
class AdminAuth:
    """Result of a successful :func:`require_admin` check.

    ``via`` is ``"bearer"`` or ``"cookie"``. ``csrf_token`` carries the
    session's CSRF token for cookie-authenticated requests and is ``None``
    for Bearer, which is exempt from CSRF by convention (see
    ``web/routers/csrf.py``).
    """

    via: str
    csrf_token: str | None


class AdminRateLimiter:
    """Per-IP sliding-window lockout for failed admin authentications.

    Failure timestamps are kept per IP and expire after the window, so the
    lockout self-heals: once every failure has aged out, the IP may try
    again. Gates acquire an attempt slot ATOMICALLY (``try_acquire``) —
    check and reserve happen under one lock acquisition, so no number of
    concurrent in-flight requests from one IP can slip past the limit while
    their verifications are still awaiting. A slot converts into the
    failure record when the attempt fails, and is handed back via
    :meth:`release` when it succeeds — exactly the failed attempts consume
    the failure budget. The gate is checked BEFORE credential verification
    — during a cooldown even a valid key gets ``429``. All state is in
    memory only; nothing persists across restarts.
    """

    def __init__(
        self,
        *,
        limit: int = FAILURE_LIMIT,
        window_seconds: float = FAILURE_WINDOW_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._limit = limit
        self._window = window_seconds
        self._clock = clock
        self._failures: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def try_acquire(self, ip: str) -> bool:
        """Atomically check the lockout gate and reserve one attempt slot.

        ``False`` iff ``ip`` is locked out (limit reached within the
        window); otherwise a slot is appended under the same lock, closing
        the check-then-act gap an ``await`` (form-body read, threadpool
        KDF) would otherwise open between gate and failure recording.
        """
        with self._lock:
            now = self._clock()
            entries = self._prune(ip, now)
            if len(entries) >= self._limit:
                return False
            entries.append(now)
            self._failures[ip] = entries
            # FIFO eviction bounds memory under hostile traffic; entries also
            # self-prune on touch, so eviction never breaks window semantics.
            while len(self._failures) > _MAX_TRACKED_IPS:
                del self._failures[next(iter(self._failures))]
            return True

    def release(self, ip: str) -> None:
        """Hand back the reserved attempt slot for ``ip`` (attempt succeeded).

        Popping the NEWEST entry is conservative under concurrency: if
        another request's real failure landed in between, that one is
        removed instead of the reservation — an over-count at worst (the
        slot ages out of the window regardless), never an under-count.
        """
        with self._lock:
            entries = self._failures.get(ip)
            if entries:
                entries.pop()

    def retry_after(self, ip: str) -> int:
        """Seconds until ``ip``'s lockout lifts (for the 429 ``Retry-After``)."""
        with self._lock:
            now = self._clock()
            entries = self._prune(ip, now)
            if not entries:
                return 0
            return max(1, int(self._window - (now - entries[0])) + 1)

    def _prune(self, ip: str, now: float) -> deque[float]:
        """Drop ``ip``'s expired failures and return the remaining deque."""
        entries = self._failures.get(ip, deque())
        while entries and now - entries[0] >= self._window:
            entries.popleft()
        return entries


def client_ip(request: Request) -> str:
    """Return the socket peer's IP (see the module docstring on X-Forwarded-For)."""
    return request.client.host if request.client is not None else "unknown"


def verify_presented_admin_key(request: Request, presented: str) -> bool:
    """Constant-time check of ``presented`` against the stored hash record.

    The record is read from disk on each check — a ~100-byte read, noise
    next to the scrypt work — so the auth gate always sees exactly the
    record the startup gate wrote, with the same strict validation applied
    by ``verify_secret`` before its KDF. Any unusable store (missing
    record, unreadable or non-ASCII file) fails closed: nothing verifies.
    """
    paths = Paths(request.app.state.settings.data_dir)
    try:
        stored = load_admin_key_hash(paths)
    except (OSError, UnicodeDecodeError):
        return False
    if stored is None:
        return False
    return verify_secret(presented, stored)


def admin_session(request: Request) -> dict[str, str] | None:
    """Return the verified admin session payload from the cookie, or ``None``.

    Only a signature-valid, unexpired cookie whose ``kind`` is the admin
    kind counts; a future user-kind session or arbitrary junk never
    authenticates as admin. Invalid cookies are not counted as rate-limit
    failures (see the module docstring).
    """
    cookie = request.cookies.get(ADMIN_COOKIE_NAME)
    if not cookie:
        return None
    signer: SessionSigner = request.app.state.session_signer
    payload = signer.unseal(cookie)
    if payload is None or payload.get("kind") != SESSION_KIND_ADMIN:
        return None
    if not payload.get("csrf"):
        return None
    return payload


async def require_admin(request: Request) -> AdminAuth:
    """FastAPI dependency enforcing admin auth on every protected route.

    Gate order: lockout first (``429`` with ``Retry-After``), then the
    Bearer header, then the session cookie. The gate atomically reserves an
    attempt slot; a failed Bearer check keeps the slot (the counted
    failure) while every other exit hands it back — so missing credentials
    and invalid cookies fail closed without counting. All error exits are
    the uniform ``401 {"error": "unauthorized"}``.
    """
    limiter: AdminRateLimiter = request.app.state.admin_rate_limiter
    ip = client_ip(request)
    if not limiter.try_acquire(ip):
        raise AdminHTTPError(
            429,
            "rate_limited",
            headers={"Retry-After": str(limiter.retry_after(ip))},
        )
    scheme, _, presented = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() == "bearer" and presented:
        # The scrypt KDF runs in the threadpool so a verification never
        # blocks the event loop for other requests.
        verified = await run_in_threadpool(
            verify_presented_admin_key, request, presented.strip()
        )
        if verified:
            limiter.release(ip)
            return AdminAuth(via="bearer", csrf_token=None)
        raise AdminHTTPError(401, "unauthorized")  # the slot stays: a failure
    limiter.release(ip)  # not a key attempt: no failure budget consumed
    session = admin_session(request)
    if session is not None:
        # admin_session guarantees a non-empty "csrf" member.
        return AdminAuth(via="cookie", csrf_token=session["csrf"])
    raise AdminHTTPError(401, "unauthorized")


class NoStoreCacheHeadersMiddleware:
    """Pure-ASGI middleware pinning ``Cache-Control: no-store`` on admin responses.

    Every response produced under ``/api/admin`` and ``/admin`` — success,
    auth error, or not-found — carries the header, so no browser or proxy
    ever caches an auth-bearing page or body. (The one shape outside this
    wrapper's reach is a 500 emitted by the outermost ServerErrorMiddleware
    for a failure in the middleware stack itself; its body is the fixed,
    secret-free ``internal_error`` JSON.) Implemented at the ASGI layer
    rather than per-route so the guarantee cannot be forgotten by a future
    route.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not str(scope.get("path", "")).startswith(
            _ADMIN_PATH_PREFIXES
        ):
            await self.app(scope, receive, send)
            return

        async def send_with_no_store(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)["Cache-Control"] = "no-store"
            await send(message)

        await self.app(scope, receive, send_with_no_store)


AdminAuthDep = Annotated[AdminAuth, Depends(require_admin)]
"""Annotated admin-auth dependency (Annotated keeps lint-friendly signatures)."""
