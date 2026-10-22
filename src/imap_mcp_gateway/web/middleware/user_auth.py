"""Shared user-key authentication primitive (M03-T04).

The single gate both the user web surface (M04: ``require_user`` over the
``imapgw_user`` cookie session) and the ``/mcp`` surface (M05:
``require_user_key_header`` header auth) build on, plus the framework-free scan
primitive underneath both:

- :func:`authenticate_user_key` — scan-and-verify over the user registry;
- :func:`user_from_bearer` — header extraction plus the scan;
- :func:`authenticate_key_header` — the rate-limited ``/mcp`` gate (M05-T01)
  built on both of the above;
- :func:`require_user` — the FastAPI cookie-session dependency;
- :func:`same_origin` — the login-CSRF ``Origin``-vs-``Host`` guard used by
  the JSON user login (``POST /api/me/login``), moved here from the
  now-deleted ``web/user/views.py`` so no dangling import survives the
  M07-T05 HTML removal.

Deliberate, documented deviations from the milestone's literal text:

- **Return type.** The milestone wrote ``authenticate_user_key(...) ->
  UserRecord | None`` while also requiring "returned user objects contain
  no ``login_key_hash`` or ``aek`` fields". ``UserRecord`` cannot satisfy
  both (its ``login_key_hash`` is a required field), so — following the
  M03-T01 ``list_users`` precedent — every function here returns the
  credential-free :class:`~imap_mcp_gateway.store.user_schema.UserMetadata`
  projection instead: hash or key material cannot leave the store layer by
  construction.

- **Uniform 401, never 404.** The milestone's "deleted users fail 404
  rather than 401 (avoids enumeration)" is self-refuting — distinguishing
  deleted from unknown IS the enumeration oracle. Every failure here is
  indistinguishable: ``None`` from the primitives; the identical
  ``401 {"error": "unauthorized"}`` from :func:`require_user` for absent,
  malformed, invalidly-signed, wrong-kind or expired cookies, unknown
  users, disabled users AND deleted users alike. This matches the actual
  M02-T03 admin gate, which likewise answers every auth failure with the
  one uniform 401 body (its ``429`` comes only from the rate limiter).

- **``paths`` parameter, sync primitive.** The milestone sketched
  ``async authenticate_user_key(presented: str)``; like every store/crypto
  helper (``verify_login_key``, ``verify_secret``) it is a plain
  synchronous function taking ``paths: Paths`` first (the store-layer
  convention), so M05 can call it without a request object. The async
  dependencies run it via :func:`starlette.concurrency.run_in_threadpool`
  so scrypt never blocks the event loop (the M02-T03 login convention).

Trade-offs:

- **O(users) scan.** Verification walks the credential-free listing and
  runs one scrypt comparison per active user (per-key salts make an index
  impossible without changing storage). Linear cost is a documented
  trade-off for admin-managed user counts (tens); an indexed lookup can
  replace the walk later without any signature change.

- **Full scan, no short-circuit.** The scan verifies EVERY active
  candidate even after a match. Short-circuiting on the first match would
  let authentication time reveal the matched user's registry position —
  an ordering side channel; a full scan costs the same total scrypt work
  regardless of which candidate matches, so timing is uniform in the
  match position. At admin-managed counts on rate-limited surfaces the
  extra work is acceptable.

- **No rate limiting here.** Per the milestone split, lockout lives at
  the HTTP surfaces built on this gate — the ``/mcp`` header gate
  (:func:`authenticate_key_header`), the M04-T04 JSON routes' shared
  ``require_user``, and the ``POST /api/me/login`` route (its own limiter
  instance, :data:`USER_LOGIN_FAILURE_LIMIT`, M06-T02) — not in the
  shared primitive.

Failure handling: every failure path — including a corrupt or unreadable
registry (where admin surfaces fail loud) — resolves to ``None`` / the
uniform 401, never an exception and never a distinguishable response. The
401 reuses
:class:`~imap_mcp_gateway.web.middleware.admin_auth.AdminHTTPError`, whose
handler ``create_app`` registers app-wide: one fixed JSON error shape
across the whole gateway.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import Depends, Request
from starlette.concurrency import run_in_threadpool

from imap_mcp_gateway.config.paths import Paths
from imap_mcp_gateway.store import users as users_store
from imap_mcp_gateway.store.user_schema import UserMetadata
from imap_mcp_gateway.web.middleware.admin_auth import (
    AdminHTTPError,
    AdminRateLimiter,
    client_ip,
)
from imap_mcp_gateway.web.session import (
    SESSION_KIND_USER,
    USER_COOKIE_NAME,
    SessionSigner,
)

USER_LOGIN_FAILURE_LIMIT = 8
"""Failed ``POST /api/me/login`` attempts per IP before lockout (M06-T02).

A SEPARATE limiter instance from the admin surface's
:data:`~imap_mcp_gateway.web.middleware.admin_auth.FAILURE_LIMIT` (5): sharing
one counter would let hostile traffic against the login surface lock the
operator out of the admin UI, and vice versa — a cross-surface lockout DoS.
The value is bounded on both sides: ABOVE the six failed logins one e2e
session makes from a single IP (so the suite never trips its own lockout —
``tests/e2e/scenarios/test_user_lifecycle.py``, ``test_self_service.py``,
``test_reset_semantics.py``), and BELOW the ten rapid failures the M06-T02
regression suite requires to yield ``429`` (the ninth attempt locks out).
The window matches the admin surface (10 minutes); the wiring lives in
``web/user/router.py`` and ``web/server.py``.
"""


def authenticate_user_key(paths: Paths, presented: str) -> UserMetadata | None:
    """Return the active user owning ``presented``, else ``None``.

    Walks the credential-free registry listing, keeps only ``active`` users
    as candidates, and delegates each comparison to the store's constant-
    time verifier :func:`imap_mcp_gateway.store.users.verify_login_key` —
    one scrypt run per candidate with ``hmac.compare_digest`` semantics
    inside. See the module docstring for the O(users) and full-scan (no
    short-circuit) trade-offs. Never raises and never distinguishes
    failures: an empty registry, garbage input of any type or shape, and a
    corrupt or unreadable registry all resolve to ``None``.
    """
    try:
        match: UserMetadata | None = None
        for meta in users_store.list_users(paths):
            if meta.status != "active":
                continue  # only active users are authentication candidates
            # Full scan: every active candidate is verified, so the total
            # work never depends on where the match sits (module docstring).
            if users_store.verify_login_key(paths, meta.id, presented):
                match = meta
        return match
    except (ValueError, OSError):
        # ValueError: schema-invalid record content (pydantic's
        # ValidationError subclasses ValueError; so does UnicodeDecodeError).
        # OSError: an unreadable record file. The auth gate fails closed on
        # registry corruption; admin reads stay fail-loud by store contract.
        return None


def _presented_user_key(request: Request) -> str | None:
    """Extract the presented login key from the request headers, or ``None``.

    Precedence: an ``Authorization`` header decides whenever present —
    ``Bearer <key>`` yields its key, any other scheme (``Basic``, ...) is
    rejected outright even when ``X-Api-Key`` is also set. ``X-Api-Key`` is
    consulted only in the absence of ``Authorization``. Rationale: one
    deterministic rule (mirroring the admin gate's Authorization-only
    contract) under which two presented credentials can never be mixed
    into a negotiation a hostile client could steer.

    Structural strictness for Bearer (exactly one space after the scheme;
    a non-empty token without surrounding whitespace) makes malformed
    shapes fail closed; ``X-Api-Key`` is a bare value, so surrounding
    whitespace is trimmed (HTTP field-value semantics) before the
    emptiness check. Duplicate headers of either kind are ambiguous and
    rejected.
    """
    authorization = request.headers.getlist("authorization")
    if len(authorization) > 1:
        return None
    if authorization:
        scheme, separator, token = authorization[0].partition(" ")
        if (
            not separator
            or scheme.lower() != "bearer"
            or not token
            or token.strip() != token
        ):
            return None
        return token
    api_keys = request.headers.getlist("x-api-key")
    if len(api_keys) > 1:
        return None
    if api_keys:
        trimmed = api_keys[0].strip()
        return trimmed or None
    return None


async def user_from_bearer(request: Request) -> UserMetadata | None:
    """Authenticate a request by login-key header; ``None`` on any failure.

    Accepts ``Authorization: Bearer <key>`` and ``X-Api-Key: <key>``
    (precedence and malformed-shape rules in
    :func:`_presented_user_key`), then delegates to
    :func:`authenticate_user_key` (scrypt in the threadpool). Uniform
    ``None`` on every failure — the consuming surface decides the response
    shape (M05 answers with the uniform 401).
    """
    presented = _presented_user_key(request)
    if presented is None:
        return None
    paths = Paths(request.app.state.settings.data_dir)
    return await run_in_threadpool(authenticate_user_key, paths, presented)


async def authenticate_key_header(
    request: Request, limiter: AdminRateLimiter
) -> UserMetadata:
    """The rate-limited ``/mcp`` header-auth gate (M05-T01); raises on failure.

    Accepts ``Authorization: Bearer <key>`` and ``X-Api-Key: <key>`` with the
    same precedence and malformed-shape rules as :func:`user_from_bearer`.
    Gate order mirrors :func:`require_admin` (the admin surface): lockout
    first — during a cooldown even a valid key gets ``429`` — then the
    header, then the scan. The limiter is a parameter, not ``app.state``
    state, because the ``/mcp`` gateway is a mounted raw-ASGI sub-app that
    owns its own per-surface limiter instance (``create_mcp_gateway``
    constructs one; a mounting app may inject a clock-controlled instance).

    Failure mapping — every failure is the identical uniform
    ``401 {"error": "unauthorized"}`` (never a 404, no key echo, no
    enumeration oracle):

    - absent or malformed credentials: fail closed WITHOUT consuming the
      reserved attempt slot (require_admin's doctrine — credentials that
      were never presented cannot count as guessing attempts);
    - presented but invalid credentials: unknown keys, wrong-format keys
      and **admin keys** consume the slot. The admin-key rejection on
      ``/mcp`` is by construction — :func:`authenticate_user_key` scans
      only the user registry, so an ``adm_`` key can never verify here; the
      gateway never falls back to admin auth (the admin surface and the MCP
      surface share no credential);
    - disabled (or deleted) users: the scan resolves to ``None`` — the same
      uniform 401, slot consumed (their key is presented-but-invalid now).

    On success returns the credential-free
    :class:`~imap_mcp_gateway.store.user_schema.UserMetadata` — the
    isolation principal the gateway attaches to ``scope["state"]`` and hands
    to the per-user tool host.
    """
    ip = client_ip(request)
    if not limiter.try_acquire(ip):
        raise AdminHTTPError(
            429,
            "rate_limited",
            headers={"Retry-After": str(limiter.retry_after(ip))},
        )
    presented = _presented_user_key(request)
    if presented is None:
        limiter.release(ip)  # nothing presented: not a guessing attempt
        raise AdminHTTPError(401, "unauthorized")
    paths = Paths(request.app.state.settings.data_dir)
    user = await run_in_threadpool(authenticate_user_key, paths, presented)
    if user is None:
        raise AdminHTTPError(401, "unauthorized")  # the slot stays: a failure
    limiter.release(ip)
    return user


async def require_user_key_header(request: Request) -> UserMetadata:
    """FastAPI dependency enforcing ``/mcp`` auth by login-key header.

    The ``Depends(require_user_key_header)`` form of
    :func:`authenticate_key_header` (exported as :data:`UserKeyHeaderDep`)
    for any FastAPI-routed surface: it reads the per-surface rate limiter
    from ``app.state.mcp_rate_limiter``, which the mounting app must
    install. The mounted ``/mcp`` gateway itself calls
    :func:`authenticate_key_header` directly with the limiter
    ``create_mcp_gateway`` owns — one gate implementation, two wiring
    shapes.
    """
    limiter: AdminRateLimiter = request.app.state.mcp_rate_limiter
    return await authenticate_key_header(request, limiter)


def user_session(request: Request) -> dict[str, str] | None:
    """Return the verified user session payload from the cookie, or ``None``.

    Mirror of the admin gate's ``admin_session``: only a signature-valid,
    unexpired ``imapgw_user`` cookie whose ``kind`` is the user kind and
    whose ``sub`` (user id) and ``csrf`` members are non-empty counts.
    An admin-kind session — or arbitrary junk — never authenticates as a
    user. Whether ``sub`` names an existing, active user is checked by
    :func:`require_user` against the store, not here.
    """
    cookie = request.cookies.get(USER_COOKIE_NAME)
    if not cookie:
        return None
    signer: SessionSigner = request.app.state.session_signer
    payload = signer.unseal(cookie)
    if payload is None or payload.get("kind") != SESSION_KIND_USER:
        return None
    if not payload.get("sub") or not payload.get("csrf"):
        return None
    return payload


@dataclass(frozen=True, slots=True)
class UserAuth:
    """Result of a successful :func:`require_user` check.

    ``user`` is the credential-free metadata of the authenticated user.
    ``via`` names the credential transport (``"cookie"`` — the only path
    today; the field keeps the admin ``AdminAuth`` shape so an M04 CSRF
    dependency can distinguish transports the same way ``verify_csrf``
    does). ``csrf_token`` carries the session's CSRF token.
    """

    user: UserMetadata
    via: str
    csrf_token: str | None


async def require_user(request: Request) -> UserAuth:
    """FastAPI dependency enforcing user auth via the ``imapgw_user`` cookie.

    The signed cookie is verified, its ``sub`` re-resolved against the
    registry, and the user must still exist and be ``active`` — so
    deleting or disabling a user kills an outstanding session immediately.
    (Rotation deliberately does not: it invalidates the *key*, while the
    disable/delete levers kill sessions; see the ``SESSION_KIND_USER``
    contract in ``web/session.py``.) Rate limiting is intentionally absent
    — the HTTP surfaces built on this gate apply their own (module
    docstring).

    EVERY failure — absent, empty, malformed, invalidly-signed,
    wrong-kind or expired cookie; deleted or disabled user; unreadable
    registry — raises the uniform ``401 {"error": "unauthorized"}``
    (:class:`AdminHTTPError`, rendered by the app-wide handler): no
    failure ever distinguishes a deleted user from an unknown one, so the
    response cannot serve as an enumeration oracle (module docstring,
    "Uniform 401").
    """
    session = user_session(request)
    if session is None:
        raise AdminHTTPError(401, "unauthorized")
    paths = Paths(request.app.state.settings.data_dir)
    try:
        record = await run_in_threadpool(users_store.get_user, paths, session["sub"])
    except (ValueError, OSError):
        # Registry-invalid id inside a (validly-signed) cookie, or an
        # unreadable record: the gate fails closed, never a 500/404.
        raise AdminHTTPError(401, "unauthorized") from None
    if record is None or record.status != "active":
        # Deleted (None) and disabled users are the same uniform 401.
        raise AdminHTTPError(401, "unauthorized")
    return UserAuth(
        user=UserMetadata.from_record(record),
        via="cookie",
        csrf_token=session["csrf"],
    )


def same_origin(request: Request) -> bool:
    """False only when the request carries a CROSS-SITE ``Origin`` header.

    Login-CSRF guard for the credential-presenting user login POST — the
    M07-T01 JSON ``POST /api/me/login`` (relocated from the now-deleted
    ``web/user/views.py``): a browser attaches ``Origin`` to every form
    submission, so a cross-site login form — which would log the
    victim into an attacker-chosen account whose key the attacker knows,
    ready to capture credentials the victim later stores — is recognizable
    and must be rejected (with the same uniform failed-login answer as every
    other login failure, never a distinct error that maps the guard).
    Requests WITHOUT ``Origin`` are allowed: same-origin navigations, non-
    browser clients, and proxies that strip the header — the check only ever
    narrows the browser-delivered cross-site case. The comparison is the
    ``Origin`` authority against the request ``Host`` (browsers normalize
    default ports out of ``Origin``, matching a bare ``Host``).
    """
    origin = request.headers.get("origin")
    if not origin:
        return True
    host = request.headers.get("host")
    if not host:
        return False
    try:
        origin_host = urlsplit(origin).netloc
    except ValueError:  # a malformed Origin is not proof of same-origin
        return False
    return origin_host == host


UserAuthDep = Annotated[UserAuth, Depends(require_user)]
"""Annotated user-auth dependency (Annotated keeps lint-friendly signatures)."""


UserKeyHeaderDep = Annotated[UserMetadata, Depends(require_user_key_header)]
"""Annotated ``/mcp`` header-auth dependency (see :func:`require_user_key_header`)."""
