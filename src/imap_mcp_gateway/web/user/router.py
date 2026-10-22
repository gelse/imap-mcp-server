"""User self-service JSON API under ``/api/me`` (M04-T04; session surface M07-T01).

Routes — the session pair is cookie-only (no auth dependency; it READS the
session to bootstrap the SPA's CSRF token), the rest are user-authenticated
(:data:`UserAuthDep`, the M03-T04 ``require_user`` cookie-session gate, which
answers every absent, invalid, deleted or DISABLED session with the uniform
``401``):

- ``GET    /api/me/session`` — CSRF bootstrap (M07-T01): the verified
  ``imapgw_user`` cookie's CSRF token, or the uniform ``401``; cookie-only
  by design (a Bearer caller needs no CSRF token and is answered 401);
- ``POST   /api/me/login`` — JSON user login (M07-T01; the ONLY user login
  surface since M07-T05 removed the HTML form): the SAME rate limiter
  (:data:`~imap_mcp_gateway.web.middleware.user_auth.USER_LOGIN_FAILURE_LIMIT`
  budget) and the same
  :func:`~imap_mcp_gateway.web.middleware.user_auth.same_origin` guard; sets
  the ``imapgw_user`` cookie and returns the CSRF token in the body;
- ``POST   /api/me/logout`` — CSRF-required cookie deletion (M07-T01);
- ``GET    /api/me`` — profile, ``key_generation``, ``aek_active`` and the
  account list as metadata only
  (:func:`imap_mcp_gateway.web.user.serializers.to_profile_view`);
- ``POST   /api/me/accounts`` — create an account; on the user's FIRST add
  (``user.json.aek is None``) the AEK is activated first and its plaintext
  hex is returned exactly once as ``account_encryption_key`` alongside the
  created account metadata — later adds never carry AEK material; a
  post-activation store-write failure answers the failure-safe 500 that
  still discloses the already-persisted AEK (M07-T01, port of the M04-T05
  view's one AEK-loss-window guard);
- ``PATCH  /api/me/accounts/{account_id}`` — partial update; credential
  fields are write-only (accepted, encrypted in memory, never returned; an
  omitted password keeps the stored ciphertext);
- ``DELETE /api/me/accounts/{account_id}`` — remove the account (204);
- ``POST   /api/me/accounts/activate`` — explicit AEK activation; returns
  the AEK hex exactly once without creating an account (a second call is
  ``409 aek_already_active`` — re-activation must never replace the key
  existing ciphertext depends on);
- ``POST   /api/me/rotate-key`` — regenerate the login key; returns the new
  ``usr_`` key exactly once. The AEK blob and the account store are
  untouched (the store guarantees it; tests pin it).

Import side effect (M04-T03 carry-forward): importing
:mod:`imap_mcp_gateway.store.accounts` below registers the account store as
the AEK-rotation re-encryption participant (its import-time
``register_reencrypt_hook`` call). This router (with its sibling
``serializers``, which imports ``AccountMetadata``) is the FIRST production
importer of that module — without the ``web.user`` import chain
``rotate_aek`` would rewrap the blob while silently leaving
``accounts.json`` under the old key. ``tests/test_user_account_api.py``
proves the wiring through this production import path (a fresh subprocess
importing only ``web.server``) and exercises the rotation re-encryption end
to end.

Authorization invariant (enforced in the STORE layer, not just routes):
every account operation passes the authenticated ``user_id`` and resolves
paths only under that user's directory (M04-T03 per-user path isolation).
An id belonging to another user is indistinguishable from a missing one:
the fixed ``404 not_found`` (no enumeration oracle), logged with the
reserved ``[security]`` tag. Client-supplied ids are sanitized before
logging (``log.py``'s log-forging note).

CSRF (the M02-T03/M03-T04 convention, applied to user sessions): every
mutating route is CSRF-checked (:data:`UserCsrfDep`) — a cookie session
must present its per-session token (``X-CSRF-Token`` header or the
``csrf_token`` form field, constant-time compared). There is no Bearer
exemption here because :func:`require_user` is cookie-only — nothing on
this surface authenticates by header credential, so every request IS a
cookie session.

Rate limiting (as M02-T03/M06-T02): the M02-T03 mechanism is the per-IP
failure-counter lockout for PRESENTED-BUT-INVALID credentials. The
cookie-session routes have no credential-verification path at all (invalid
cookies fail closed WITHOUT counting, the M02-T03 convention — they require
forging an HMAC, not guessing a key), so the limiter has no counting events
there. The one credential-presenting route of this surface — the M07-T01
``POST /api/me/login`` — applies the user-login limiter: one
:data:`~imap_mcp_gateway.web.middleware.user_auth.USER_LOGIN_FAILURE_LIMIT`
budget (``app.state.user_login_rate_limiter``), so hostile traffic against
the login surface counts against a single per-IP lockout.

Response discipline: EVERY ``/api/me`` response pins
``Cache-Control: no-store`` — the activation/rotation responses and every
``POST /accounts`` response (which may carry the one-time AEK) must not be
cacheable, and the remaining auth-bearing metadata bodies get the same
parity the admin surface enforces by middleware. Request bodies are parsed
and validated
manually against the pydantic request models so malformed bodies answer
with the pinned ``400 invalid_request`` inside the fixed ``{"error": ...}``
contract, never FastAPI's framework-default 422 (the M03-T02 convention —
scoped to this router only). Store calls run through
:func:`starlette.concurrency.run_in_threadpool` so scrypt/AES work never
blocks the event loop.
"""

from __future__ import annotations

import hmac
import re
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError
from starlette.concurrency import run_in_threadpool

from imap_mcp_gateway.config.paths import Paths
from imap_mcp_gateway.log import get_logger
from imap_mcp_gateway.store import (
    accounts as accounts_store,  # import registers the M04-T03 re-encrypt hook
)
from imap_mcp_gateway.store import users as users_store
from imap_mcp_gateway.store.accounts import (
    AccountMetadata,
    ImapAccount,
    encrypt_account_record,
)
from imap_mcp_gateway.store.upstream_format import encrypt_field
from imap_mcp_gateway.web.middleware.admin_auth import (
    AdminHTTPError,
    AdminRateLimiter,
    client_ip,
)
from imap_mcp_gateway.web.middleware.user_auth import (
    UserAuth,
    UserAuthDep,
    authenticate_user_key,
    require_user,
    same_origin,
    user_session,
)
from imap_mcp_gateway.web.session import (
    SESSION_KIND_USER,
    USER_COOKIE_NAME,
    SessionSigner,
)
from imap_mcp_gateway.web.user.serializers import (
    CreateAccountBody,
    UpdateAccountBody,
    to_account_view,
    to_profile_view,
)

router = APIRouter(prefix="/api/me", tags=["user"])

log = get_logger(__name__)

_PATCHABLE_FIELDS = (
    "name",
    "host",
    "port",
    "user",
    "tls",
    "allow_start_tls",
    "email",
    "save_to_sent",
    "sent_folder",
    "default_bcc",
    "allowed_from",
)
"""Non-credential fields :func:`_apply_update` overlays onto the record."""

_SAFE_LOG_ID_RE = re.compile(r"^[0-9a-zA-Z_-]{1,128}$")
"""Account ids safe to echo into a log line (everything else is masked)."""


async def verify_user_csrf(
    request: Request,
    auth: Annotated[UserAuth, Depends(require_user)],
) -> None:
    """Reject cookie-authenticated mutations that omit the session CSRF token.

    Direct port of the admin surface's convention
    (:func:`imap_mcp_gateway.web.routers.csrf.verify_csrf`): the presented
    token — the ``csrf_token`` form field or the ``X-CSRF-Token`` header —
    must match the session's token, compared in constant time. ``require_user``
    is cookie-only, so there is no Bearer exemption branch: anonymous
    requests already failed the shared ``require_user`` sub-dependency with
    the uniform 401.
    """
    presented = request.headers.get("x-csrf-token")
    if not presented:
        try:
            form = await request.form()
            value = form.get("csrf_token")
        except Exception:  # a hostile/undecodable body simply fails the check
            value = None
        presented = value if isinstance(value, str) else ""
    if not presented or auth.csrf_token is None:
        raise AdminHTTPError(403, "forbidden")
    if not hmac.compare_digest(
        presented.encode("utf-8"), auth.csrf_token.encode("utf-8")
    ):
        raise AdminHTTPError(403, "forbidden")


UserCsrfDep = Annotated[None, Depends(verify_user_csrf)]
"""Annotated user-CSRF dependency (Annotated keeps lint-friendly signatures)."""


def _paths(request: Request) -> Paths:
    """The request's ``Paths`` (the web-layer convention, as in ``admin_auth``)."""
    return Paths(request.app.state.settings.data_dir)


async def _json_body(request: Request) -> Any:
    """Decode the request body as JSON; anything undecodable is a 400.

    Parity with ``web/admin/user_router._json_body``: malformed bodies join
    the fixed ``{"error": ...}`` contract instead of FastAPI's 422 (module
    docstring).
    """
    try:
        return await request.json()
    except Exception:  # a hostile/undecodable body is simply an invalid request
        raise AdminHTTPError(400, "invalid_request") from None


def _validated_body[ModelT: BaseModel](model: type[ModelT], payload: Any) -> ModelT:
    """Validate a decoded JSON body against a request model; 400 on mismatch.

    Parity with ``web/admin/user_router._validated_body``: missing fields,
    wrong types, empty strings and unknown (``extra="forbid"``) fields all
    land here.
    """
    try:
        return model.model_validate(payload)
    except ValidationError:
        raise AdminHTTPError(400, "invalid_request") from None


def _no_store(response: JSONResponse) -> JSONResponse:
    """Pin ``Cache-Control: no-store`` (one-time-material responses)."""
    response.headers["Cache-Control"] = "no-store"
    return response


def _safe_log_id(value: str) -> str:
    """Mask a client-supplied id unless it is plain log-safe text."""
    return value if _SAFE_LOG_ID_RE.fullmatch(value) else "<unparsed>"


def _account_miss(op: str, user_id: str, account_id: str) -> None:
    """Log a ``[security]`` line for an account not found under the caller.

    Cross-user access is DESIGNED to be indistinguishable from a miss (both
    are the fixed 404 — checking another user's directory would itself be an
    enumeration oracle), so every account-scoped 404 is logged here: the
    attempt named an id that does not exist under the authenticated user's
    directory, which is exactly the cross-user case when it is one.
    """
    log.warning(
        "[security] account not found under authenticated user's directory",
        extra={
            "fields": {
                "op": op,
                "user_id": user_id,
                "account_id": _safe_log_id(account_id),
            },
        },
    )


def _seal(plaintext: str, aek_hex: str | None) -> str:
    """Encrypt one submitted credential; ``aek_hex`` must be available.

    ``aek_hex is None`` is a router bug guard (the caller computes
    ``needs_aek`` from the same body it passes here), never a client error.
    """
    if aek_hex is None:
        raise RuntimeError("AEK required to seal a submitted credential")
    return encrypt_field(aek_hex, plaintext)


def _apply_update(
    existing: ImapAccount, body: UpdateAccountBody, aek_hex: str | None
) -> ImapAccount:
    """Merge a partial update onto the stored record (credentials write-only).

    Non-credential fields are overlaid when provided. The IMAP ``password``,
    when provided, is sealed under the AEK (an empty string encrypts like
    upstream's ``addAccount``); when omitted the stored ciphertext stays
    untouched. A provided ``smtp`` block replaces the block's coordination
    fields (``host``/``port``/``secure`` — required, see
    :class:`UpdateAccountBody`) while its credentials are sticky: omitted
    ``user`` keeps the stored one, omitted ``password`` keeps the stored
    ciphertext, and an EMPTY ``password`` stores the store's documented
    empty "no credential" value (upstream only ever writes ``smtp.password``
    when one was configured — parity with the create path in
    :func:`imap_mcp_gateway.store.accounts.encrypt_account_record`). The
    merged data is re-validated through the strict store schema, so a
    drift-shaped record fails loud before anything is persisted.
    """
    # Dump with field names (not aliases): the overlay below uses the
    # snake_case field names, and mixing an alias key with its field-name
    # twin is rejected by the strict store schema (extra="forbid"), so a
    # PATCH touching an alias-backed field (allow_start_tls, save_to_sent,
    # sent_folder, default_bcc, allowed_from) would otherwise 500. The
    # record is re-validated with populate_by_name=True, which accepts the
    # field names.
    data: dict[str, Any] = existing.model_dump(exclude_none=True)
    for field in _PATCHABLE_FIELDS:
        value = getattr(body, field)
        if value is not None:
            data[field] = value
    if body.password is not None:
        data["password"] = _seal(body.password, aek_hex)
    if body.smtp is not None:
        stored_smtp = data.get("smtp")
        stored_smtp = dict(stored_smtp) if isinstance(stored_smtp, dict) else {}
        merged_smtp: dict[str, Any] = {
            "host": body.smtp.host,
            "port": body.smtp.port,
            "secure": body.smtp.secure,
        }
        if body.smtp.user is not None:
            merged_smtp["user"] = body.smtp.user
        elif "user" in stored_smtp:
            merged_smtp["user"] = stored_smtp["user"]
        if body.smtp.password:  # a real value: seal it
            merged_smtp["password"] = _seal(body.smtp.password, aek_hex)
        elif body.smtp.password is not None:
            # Explicitly empty: the store's documented "no credential" value
            # (never sealed into ciphertext — create-path parity).
            merged_smtp["password"] = ""
        elif stored_smtp.get("password"):
            merged_smtp["password"] = stored_smtp["password"]
        data["smtp"] = merged_smtp
    return ImapAccount.model_validate(data)


@router.get("")
async def me(request: Request, auth: UserAuthDep) -> JSONResponse:
    """The authenticated user's profile and account list — metadata only."""
    paths = _paths(request)
    accounts = await run_in_threadpool(accounts_store.list_accounts, paths, auth.user.id)
    record = await run_in_threadpool(users_store.get_user, paths, auth.user.id)
    if record is None or record.status != "active":
        # require_user resolved this user moments ago: a None/disabled record
        # means the session was killed in between — the uniform 401.
        raise AdminHTTPError(401, "unauthorized")
    # jsonable_encoder renders the profile's ``created_at`` datetime the same
    # way FastAPI would for a dict return (JSONResponse itself does not).
    return _no_store(
        JSONResponse(
            jsonable_encoder(
                to_profile_view(auth.user, accounts, aek_active=record.aek is not None)
            )
        )
    )


@router.get("/session")
async def session_bootstrap(request: Request) -> JSONResponse:
    """CSRF bootstrap for the SPA (M07-T01) — parallel of the admin endpoint.

    Cookie-only BY DESIGN: the route reads ``user_session(request)`` directly
    instead of depending on :data:`UserAuthDep`, so it answers the uniform
    ``401 {"error": "unauthorized"}`` for every absent, invalid, expired,
    wrong-kind or dead-user cookie — and deliberately for a Bearer caller
    too (a header-authenticated caller needs no CSRF token and must not be
    handed one; there is no user Bearer surface that could consume it).
    Valid cookie -> ``200 {"csrf_token": <payload["csrf"]>}`` with
    ``Cache-Control: no-store`` pinned explicitly (there is no middleware
    no-store on ``/api/me`` — the per-response pin is the only guarantee).
    No rate-limiter interaction: invalid cookies fail closed without
    counting (the M02 convention — they require forging an HMAC, not
    guessing a key).
    """
    payload = user_session(request)
    if payload is None:
        raise AdminHTTPError(401, "unauthorized")
    return _no_store(JSONResponse({"csrf_token": payload["csrf"]}))


@router.post("/login")
async def login(request: Request) -> JSONResponse:
    """Exchange the presented login key for a signed httpOnly session cookie.

    The JSON user login (M07-T01) — and since M07-T05 the ONLY user login
    surface: body ``{"key": str}``, one store primitive, one rate limiter,
    one same-origin guard, one cookie — so the SPA draws from ONE per-IP
    login budget and enforces ONE login-CSRF rule.

    Gate order:

    - lockout FIRST — an atomic slot reservation on
      ``app.state.user_login_rate_limiter`` before any ``await``; during a
      cooldown even the correct key gets ``429`` + ``Retry-After``;
    - the body is decoded manually: anything undecodable, non-object,
      wrong-typed or carrying extra fields is a FAILED LOGIN (uniform 401
      with the slot released), never FastAPI's 422 and never a distinct
      ``invalid_request`` — the uniform failure shape;
    - the SAME
      :func:`~imap_mcp_gateway.web.middleware.user_auth.same_origin` guard —
      a cross-site ``Origin`` is the login-CSRF vector: rejected with the
      uniform 401 and the slot released (a structural rejection, not a key
      guess);
    - an absent/empty key likewise releases the slot (nothing was
      presented);
    - ``authenticate_user_key`` runs in the threadpool (scrypt); a
      presented-but-invalid key KEEPS the slot (the counted failure) while
      success hands it back.

    Success sets the ``imapgw_user`` cookie (``HttpOnly``,
    ``SameSite=strict``, ``path=/``, Max-Age = the signer's TTL) and answers
    ``200 {"status": "ok", "csrf_token": <token>}`` with
    ``Cache-Control: no-store`` — the CSRF token doubles as the
    ``GET /api/me/session`` value, so a client never needs a second
    round-trip. No plaintext key material ever appears in any response.
    """
    limiter: AdminRateLimiter = request.app.state.user_login_rate_limiter
    ip = client_ip(request)
    if not limiter.try_acquire(ip):
        raise AdminHTTPError(
            429,
            "rate_limited",
            headers={"Retry-After": str(limiter.retry_after(ip))},
        )
    try:
        payload = await request.json()
    except Exception:  # a hostile/undecodable body is just a failed login
        payload = None
    presented = ""
    if (
        isinstance(payload, dict)
        and set(payload) == {"key"}
        and isinstance(payload["key"], str)
    ):
        presented = payload["key"]
    if not same_origin(request):
        # A cross-site login is the login-CSRF vector: reject it with the
        # same uniform failed-login answer (no distinct, mappable error).
        limiter.release(ip)  # structural rejection — not a key guess
        raise AdminHTTPError(401, "unauthorized")
    if not presented:
        limiter.release(ip)  # nothing presented: not a guessing attempt
        raise AdminHTTPError(401, "unauthorized")
    match = await run_in_threadpool(authenticate_user_key, _paths(request), presented)
    if match is None:
        raise AdminHTTPError(401, "unauthorized")  # the slot stays: a failure
    limiter.release(ip)
    signer: SessionSigner = request.app.state.session_signer
    cookie_value, csrf_token = signer.create_session(SESSION_KIND_USER, sub=match.id)
    response = _no_store(JSONResponse({"status": "ok", "csrf_token": csrf_token}))
    response.set_cookie(
        USER_COOKIE_NAME,
        cookie_value,
        max_age=signer.ttl_seconds,
        path="/",
        httponly=True,
        samesite="strict",
    )
    return response


@router.post("/logout")
async def logout(auth: UserAuthDep, _csrf: UserCsrfDep) -> JSONResponse:
    """Invalidate the user session cookie (user-authenticated, CSRF-checked).

    M07-T01, mirroring the admin surface's ``POST /api/admin/logout``: the
    cookie session must present its CSRF token (``UserCsrfDep`` — there is
    no Bearer exemption because ``require_user`` is cookie-only), every
    failure is the existing uniform 401/403 shape, and the success response
    deletes the ``imapgw_user`` cookie (``path=/``, parity with the login
    that set it) with ``Cache-Control: no-store``.
    """
    response = _no_store(JSONResponse({"status": "ok"}))
    response.delete_cookie(USER_COOKIE_NAME, path="/")
    return response


@router.post("/accounts", status_code=201)
async def create_account(
    request: Request, auth: UserAuthDep, _csrf: UserCsrfDep
) -> JSONResponse:
    """Create an account; the FIRST add discloses the AEK exactly once.

    Check order: auth/CSRF (dependencies) -> body (400, no state change) ->
    user still active (401) -> lazy AEK activation (only when
    ``user.json.aek is None``; a concurrent first-add loser gets
    ``409 aek_already_active`` and retries with no account created) ->
    in-memory encryption of the credentials under the unwrapped AEK
    (:func:`users_store.with_aek`, buffer zeroized after) -> store write.

    The response always pins ``Cache-Control: no-store`` (this route MAY
    carry the one-time AEK) and returns the credential-free account
    metadata; ``account_encryption_key`` appears exactly once — in the body
    of the add that performed the activation.
    """
    body = _validated_body(CreateAccountBody, await _json_body(request))
    paths = _paths(request)
    user_id = auth.user.id
    record = await run_in_threadpool(users_store.get_user, paths, user_id)
    if record is None or record.status != "active":
        # require_user resolved this user moments ago: a None/disabled record
        # means the session was killed in between — the uniform 401.
        raise AdminHTTPError(401, "unauthorized")
    activated_aek: str | None = None
    if record.aek is None:
        try:
            activated_aek = await run_in_threadpool(
                users_store.activate_aek, paths, user_id
            )
        except users_store.AEKAlreadyActiveError:
            # A concurrent first-add activated the AEK between our read and
            # this call: we are the loser, and the key existing ciphertext
            # depends on must not be replaced. 409 (the same answer the
            # explicit activation route gives) — the client retries and the
            # retry adds the account under the now-active AEK.
            raise AdminHTTPError(409, "aek_already_active") from None
        except FileNotFoundError:
            raise AdminHTTPError(401, "unauthorized") from None

    payload = body.model_dump(by_alias=True, exclude_none=True)

    def build() -> ImapAccount:
        return users_store.with_aek(
            paths, user_id, lambda aek: encrypt_account_record(payload, bytes(aek).hex())
        )

    try:
        stored = await run_in_threadpool(build)
    except FileNotFoundError:
        raise AdminHTTPError(401, "unauthorized") from None
    try:
        stored = await run_in_threadpool(
            accounts_store.put_account, paths, user_id, stored
        )
    except Exception:
        if activated_aek is None:
            raise
        # Failure-safe disclosure (the one AEK-loss window, M07-T01 port of
        # the M04-T05 view's guard): the fresh AEK is ALREADY persisted
        # (wrapped) at this point, so swallowing its plaintext on a
        # store-write failure would leave every future credential encrypted
        # under a key the user never saw — and nothing could ever re-display
        # it. Fail loud (500) but still disclose the one-time key; the
        # account add itself can be retried. The exception never escapes to
        # the app-wide 500 handler (which would DROP the key). The key is
        # never logged — the log line carries only the op and user id.
        log.exception(
            "account store write failed after AEK activation",
            extra={"fields": {"op": "create", "user_id": user_id}},
        )
        return _no_store(
            JSONResponse(
                {
                    "error": "internal_error",
                    "account_encryption_key": activated_aek,
                },
                status_code=500,
            )
        )
    payload_response: dict[str, Any] = {
        "account": to_account_view(AccountMetadata.from_record(stored))
    }
    if activated_aek is not None:
        payload_response["account_encryption_key"] = activated_aek
    return _no_store(JSONResponse(payload_response, status_code=201))


@router.patch("/accounts/{account_id}")
async def update_account(
    request: Request,
    account_id: str,
    auth: UserAuthDep,
    _csrf: UserCsrfDep,
) -> JSONResponse:
    """Partially update the user's account; credentials are write-only.

    A foreign or missing id is the same ``404`` (logged ``[security]``, see
    :func:`_account_miss`). The AEK is unwrapped only when the body actually
    seals a credential (an empty SMTP password means "no credential", not a
    value to seal); otherwise the stored ciphertexts are carried through
    untouched.
    """
    body = _validated_body(UpdateAccountBody, await _json_body(request))
    paths = _paths(request)
    user_id = auth.user.id
    existing = await run_in_threadpool(
        accounts_store.get_account, paths, user_id, account_id
    )
    if existing is None:
        _account_miss("update", user_id, account_id)
        raise AdminHTTPError(404, "not_found")
    needs_aek = body.password is not None or (
        body.smtp is not None and bool(body.smtp.password)
    )

    def merge(aek_hex: str | None) -> ImapAccount:
        return _apply_update(existing, body, aek_hex)

    if needs_aek:
        try:
            updated = await run_in_threadpool(
                users_store.with_aek, paths, user_id, lambda aek: merge(aek.hex())
            )
        except FileNotFoundError:
            raise AdminHTTPError(401, "unauthorized") from None
    else:
        updated = await run_in_threadpool(merge, None)
    stored = await run_in_threadpool(
        accounts_store.put_account, paths, user_id, updated
    )
    return _no_store(
        JSONResponse({"account": to_account_view(AccountMetadata.from_record(stored))})
    )


@router.delete("/accounts/{account_id}", status_code=204)
async def delete_account(
    request: Request, account_id: str, auth: UserAuthDep, _csrf: UserCsrfDep
) -> Response:
    """Remove the user's account (204, empty body); a foreign/missing id is 404."""
    try:
        await run_in_threadpool(
            accounts_store.delete_account, _paths(request), auth.user.id, account_id
        )
    except FileNotFoundError:
        _account_miss("delete", auth.user.id, account_id)
        raise AdminHTTPError(404, "not_found") from None
    return Response(status_code=204)


@router.post("/accounts/activate")
async def activate_account_encryption(
    request: Request, auth: UserAuthDep, _csrf: UserCsrfDep
) -> JSONResponse:
    """Activate the AEK explicitly; the plaintext hex is shown exactly once.

    No account is created. A user whose AEK is already active gets
    ``409 aek_already_active`` — re-activation must never silently replace
    the key existing account ciphertext depends on (that is rotation's job,
    with full re-encryption).
    """
    try:
        plaintext = await run_in_threadpool(
            users_store.activate_aek, _paths(request), auth.user.id
        )
    except users_store.AEKAlreadyActiveError:
        raise AdminHTTPError(409, "aek_already_active") from None
    except FileNotFoundError:
        raise AdminHTTPError(401, "unauthorized") from None
    return _no_store(JSONResponse({"account_encryption_key": plaintext}))


@router.post("/rotate-key")
async def rotate_key(
    request: Request, auth: UserAuthDep, _csrf: UserCsrfDep
) -> JSONResponse:
    """Regenerate the login key; the new plaintext is shown exactly once.

    The stored hash is replaced and ``key_generation`` bumped atomically by
    the store; the AEK blob and every account keep working unchanged (the
    login key and the AEK are fully independent — the M04 invariant, pinned
    by tests).
    """
    try:
        record, plaintext = await run_in_threadpool(
            users_store.rotate_login_key, _paths(request), auth.user.id
        )
    except FileNotFoundError:
        raise AdminHTTPError(401, "unauthorized") from None
    return _no_store(
        JSONResponse(
            {
                "id": record.id,
                "key_generation": record.key_generation,
                "login_key": plaintext,
            }
        )
    )
