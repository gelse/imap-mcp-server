"""Admin authentication and web shell tests (M02-T03; SPA cutover M07-T05).

Coverage per the M02-T03 verification requirements:

1. Bearer auth on ``GET /api/admin/health``: correct key -> 200, wrong key
   -> 401, missing key -> 401;
2. rate limiting: 5 failed logins per IP within the 10-minute window lock
   the IP out with 429 — even for the CORRECT key — and the lockout
   self-heals once the failures age out of the sliding window; a committed
   concurrency test proves parallel bursts cannot outnumber the limit
   (atomic slot reservation);
3. cookie flow: a successful login sets a signed httpOnly ``imapgw_admin``
   cookie which grants access to the admin JSON API; the SPA shell at
   ``/admin`` is served to EVERY visitor (it carries no data — the SPA
   bootstraps its session from ``/api/admin/session``); logout invalidates
   the cookie;
4. uniform failed-login responses: wrong key, unknown key, empty key, a
   missing field and a missing body all produce the identical 401 body,
   with no existence hints and no key material;
5. the served SPA shell renders without any ``adm_``/``usr_`` prefix or
   plaintext key material anywhere in the HTML (and the reserved
   ``imapgw_user`` cookie is never set);
6. ``Cache-Control: no-store`` on every auth-bearing response;
7. CSRF: cookie-authenticated POSTs require the session token (missing or
   wrong token -> 403, valid token -> accepted); Bearer-authenticated
   calls are exempt by convention;
8. the deferred hash-record validation (M02-T02 -> M02-T03): strict
   structural parsing plus scrypt parameter bounds run BEFORE the KDF on
   the auth path, and the same validation gates the startup path —
   malformed/oversized records are rejected without running scrypt;
9. the fixed admin surface: the M02-T03 trio plus exactly the M03-T02
   user-management routes, the M07-T01 ``GET /api/admin/session`` bootstrap
   and the M07-T05 SPA shell routes (``/admin`` and its ``{path:path}``
   catch-all), all of the JSON routes admin-gated (the session endpoint
   deliberately answers a Bearer caller with the uniform 401 — a header
   caller is CSRF-exempt and needs no token).

All HTTP tests run in-process via ``httpx.AsyncClient`` over an ASGI
transport (the pattern of tests/test_healthz.py).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from imap_mcp_gateway.config.env import Settings
from imap_mcp_gateway.config.paths import build_paths
from imap_mcp_gateway.crypto import hash as crypto_hash
from imap_mcp_gateway.crypto.hash import hash_secret, is_valid_record
from imap_mcp_gateway.crypto.keys import generate_admin_key
from imap_mcp_gateway.store.admin_key import (
    AdminKeyHashCorruptedError,
    ensure_admin_key,
    save_admin_key_hash,
)
from imap_mcp_gateway.web.middleware.admin_auth import FAILURE_LIMIT, AdminRateLimiter
from imap_mcp_gateway.web.server import create_app
from imap_mcp_gateway.web.session import (
    ADMIN_COOKIE_NAME,
    USER_COOKIE_NAME,
    SessionSigner,
)

_SALT_OK = "A" * 22  # canonical base64url of a 16-byte salt
_DIGEST_OK = "B" * 43  # canonical base64url of a 32-byte digest


def _scrypt_record(n: int, r: int, p: int) -> str:
    """A structurally valid-shaped scrypt record with the given parameters."""
    return f"scrypt${n}${r}${p}${_SALT_OK}${_DIGEST_OK}"


class FakeClock:
    """Controllable monotonic clock for rate-limiter window tests."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture(scope="module")
def admin_key() -> str:
    """One admin key for the whole module (key generation is cheap)."""
    return generate_admin_key()


@pytest.fixture(scope="module")
def admin_record(admin_key: str) -> str:
    """The scrypt record for :func:`admin_key` (the one expensive scrypt run)."""
    return hash_secret(admin_key)


@pytest.fixture
def app(tmp_path: Path, admin_record: str, spa_dist: Path) -> FastAPI:
    """A fresh app (own session signer + rate limiter) over a seeded hash file.

    The SPA dist is the synthetic fixture's: the admin surface serves the
    single-page shell at ``/admin`` (M07-T05), so the app under test needs
    a dist to answer the shell legs.
    """
    save_admin_key_hash(build_paths(tmp_path), admin_record)
    return create_app(Settings(data_dir=tmp_path, spa_dist_dir=spa_dist))


def _client(app: FastAPI) -> httpx.AsyncClient:
    """An in-process client over the app (cookies persist within the client)."""
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


async def _login(client: httpx.AsyncClient, key: str) -> httpx.Response:
    """Perform the login POST exactly as the browser form does (form-encoded)."""
    return await client.post("/api/admin/login", data={"key": key})


async def _session_csrf(client: httpx.AsyncClient) -> str:
    """The logged-in client's CSRF token via ``GET /api/admin/session``.

    M07-T01 replaced the HTML csrf_token scrape of ``/admin/`` with the
    dedicated cookie-session bootstrap endpoint (the SPA's own path).
    """
    response = await client.get("/api/admin/session")
    assert response.status_code == 200, response.text
    token = response.json()["csrf_token"]
    assert isinstance(token, str) and token
    return token


# --- 1. Bearer authentication ---------------------------------------------------


async def test_health_bearer_correct_ok_wrong_and_missing_unauthorized(
    app: FastAPI, admin_key: str
) -> None:
    async with _client(app) as client:
        ok = await client.get(
            "/api/admin/health", headers={"Authorization": f"Bearer {admin_key}"}
        )
        wrong = await client.get(
            "/api/admin/health",
            headers={"Authorization": f"Bearer {generate_admin_key()}"},
        )
        missing = await client.get("/api/admin/health")
    assert ok.status_code == 200
    assert ok.json() == {"status": "ok"}
    assert wrong.status_code == 401
    assert wrong.json() == {"error": "unauthorized"}
    assert missing.status_code == 401
    assert missing.json() == {"error": "unauthorized"}
    for response in (ok, wrong, missing):  # no key material in any body
        assert "adm_" not in response.text
        assert admin_key not in response.text


# --- 2. Rate limiting: lockout window and self-healing cooldown -----------------


async def test_five_failures_lock_out_ip_until_window_expires(
    app: FastAPI, admin_key: str
) -> None:
    clock = FakeClock()
    app.state.admin_rate_limiter = AdminRateLimiter(clock=clock)

    async with _client(app) as client:
        for _ in range(5):
            response = await _login(client, "adm_" + "0" * 43)
            assert response.status_code == 401
        # 6th attempt: locked out — even the CORRECT key gets 429, with Retry-After.
        locked = await _login(client, admin_key)
        assert locked.status_code == 429
        assert locked.json() == {"error": "rate_limited"}
        assert int(locked.headers["Retry-After"]) == 601
        # Bearer attempts from the locked IP are locked out too.
        bearer_locked = await client.get(
            "/api/admin/health", headers={"Authorization": f"Bearer {admin_key}"}
        )
        assert bearer_locked.status_code == 429
        # Sliding window: once the failures age out, access heals without restart.
        clock.advance(601)
        healed = await _login(client, admin_key)
        assert healed.status_code == 200


async def test_concurrent_logins_cannot_outnumber_the_lockout_limit(
    app: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Committed regression test for the atomic lockout gate.

    The gate reserves attempt slots atomically before any ``await``, so a
    burst of parallel logins from one IP can never slip past the limit
    while their verifications are in flight: exactly ``limit`` attempts
    reach the KDF (401), the rest are rejected 429 before any scrypt work.
    """
    kdf_calls: list[int] = []
    real_derive = crypto_hash._derive

    def counting_derive(
        plaintext: str, *, salt: bytes, n: int, r: int, p: int
    ) -> bytes:
        kdf_calls.append(n)  # list.append is thread-safe (GIL)
        return real_derive(plaintext, salt=salt, n=n, r=r, p=p)

    monkeypatch.setattr(crypto_hash, "_derive", counting_derive)

    async with _client(app) as client:
        responses = await asyncio.gather(
            *(_login(client, "adm_" + "0" * 43) for _ in range(20))
        )
    non_429 = [response for response in responses if response.status_code != 429]
    assert len(non_429) == FAILURE_LIMIT
    assert all(response.status_code == 401 for response in non_429)
    assert len(kdf_calls) == FAILURE_LIMIT  # bounded scrypt work per burst


# --- 3. Cookie flow: login -> admin API access -> logout invalidates --------------


async def test_login_sets_httponly_cookie_grants_admin_and_logout_invalidates(
    app: FastAPI, admin_key: str
) -> None:
    async with _client(app) as client:
        # M07-T05: the SPA shell is served to every visitor — it carries no
        # data, so there is nothing to gate (the API is the only source of
        # truth and answers a uniform 401 to an unauthenticated caller).
        shell = await client.get("/admin/")
        assert shell.status_code == 200
        assert "text/html" in shell.headers["content-type"]
        assert shell.headers["cache-control"] == "no-store"

        login = await _login(client, admin_key)
        assert login.status_code == 200
        set_cookie = login.headers["set-cookie"]
        assert set_cookie.startswith(f"{ADMIN_COOKIE_NAME}=")
        assert "httponly" in set_cookie.lower()
        assert "samesite=strict" in set_cookie.lower()
        assert USER_COOKIE_NAME not in set_cookie  # reserved cookie stays unused

        # The session now authorizes the admin API.
        assert (await _session_csrf(client))  # the bootstrap endpoint answers
        # The shell is still the same shell for a logged-in visitor.
        login_page = await client.get("/admin/login")
        assert login_page.status_code == 200
        assert "text/html" in login_page.headers["content-type"]

        # Logout: the CSRF token comes from the M07-T01 session endpoint.
        token = await _session_csrf(client)
        logout = await client.post(
            "/api/admin/logout", data={"csrf_token": token}
        )
        assert logout.status_code == 200
        assert ADMIN_COOKIE_NAME in logout.headers["set-cookie"]  # deletion cookie
        assert "max-age=0" in logout.headers["set-cookie"].lower()

        # The session is invalidated: the API answers the uniform 401 …
        after = await client.get("/api/admin/session")
        assert after.status_code == 401
        assert after.json() == {"error": "unauthorized"}
        # … while the (data-free) shell is still served.
        assert (await client.get("/admin/")).status_code == 200


async def test_login_path_serves_the_spa_shell_without_auth(app: FastAPI) -> None:
    """M07-T05: ``/admin/login`` is a SPA route, not a form.

    The old login FORM is gone — the path now serves the same shell as every
    other admin route (the SPA renders its login view client-side), so the
    response carries no form action and no key material.
    """
    async with _client(app) as client:
        page = await client.get("/admin/login")
    assert page.status_code == 200
    assert "text/html" in page.headers["content-type"]
    assert page.headers["cache-control"] == "no-store"
    assert 'action="/api/admin/login"' not in page.text


# --- 4. Uniform failed-login responses ------------------------------------------


async def test_failed_logins_are_uniform(app: FastAPI) -> None:
    """Wrong key, unknown key, empty key, missing field, no body: identical 401.

    All five variants fail from the same IP (5 <= limit, so no 429 mixes in)
    and must be byte-identical — no signal whether a key exists or not.
    """
    variants: list[tuple[str, dict[str, str] | None]] = [
        ("wrong-key", {"key": "adm_" + "0" * 43}),
        ("unknown-key", {"key": "usr_" + "1" * 43}),
        ("empty-key", {"key": ""}),
        ("missing-field", {"unrelated": "x"}),
        ("no-body", None),
    ]
    async with _client(app) as client:
        responses = [
            (
                name,
                await (
                    client.post("/api/admin/login", data=fields)
                    if fields is not None
                    else client.post("/api/admin/login")
                ),
            )
            for name, fields in variants
        ]
    texts = {response.text for _, response in responses}
    assert len(texts) == 1  # every variant: the exact same body
    for name, response in responses:
        assert response.status_code == 401, name
        assert response.json() == {"error": "unauthorized"}, name
        assert "adm_" not in response.text, name


# --- 5. No secrets in the served shell -------------------------------------------


async def test_spa_shell_and_admin_responses_render_without_key_material(
    app: FastAPI, admin_key: str
) -> None:
    """The shell and the admin responses carry no key material.

    M07-T05 replaced the Jinja2 templates with the SPA shell: the shell is
    served to every visitor, so it must never carry anything secret — not
    the admin key, not a user key, not a hash record.
    """
    async with _client(app) as client:
        shell = await client.get("/admin")
        login_response = await _login(client, admin_key)
        health = await client.get(
            "/api/admin/health", headers={"Authorization": f"Bearer {admin_key}"}
        )
    for response in (shell, login_response, health):
        assert "adm_" not in response.text
        assert "usr_" not in response.text
        assert admin_key not in response.text
        assert admin_key.removeprefix("adm_") not in response.text


# --- 6. Cache-Control: no-store on auth-bearing responses ------------------------


async def test_no_store_on_all_auth_bearing_responses(
    app: FastAPI, admin_key: str
) -> None:
    async with _client(app) as client:
        # M07-T05: the shell responses are 200 (not the old 303 redirects) and
        # still carry no-store — the shell is never cached by a browser.
        assert (
            await client.get("/admin/login")
        ).headers["cache-control"] == "no-store"
        failed = await _login(client, "adm_" + "0" * 43)  # failure 1
        assert failed.status_code == 401
        assert failed.headers["cache-control"] == "no-store"
        await _login(client, admin_key)  # success; the slot is handed back
        home = await client.get("/admin/")
        assert home.status_code == 200
        assert home.headers["cache-control"] == "no-store"
        health = await client.get(
            "/api/admin/health", headers={"Authorization": f"Bearer {admin_key}"}
        )
        assert health.status_code == 200
        assert health.headers["cache-control"] == "no-store"
        unknown = await client.get("/api/admin/does-not-exist")
        assert unknown.status_code == 404
        assert unknown.headers["cache-control"] == "no-store"
        forbidden = await client.post("/api/admin/logout")  # cookie, no CSRF
        assert forbidden.status_code == 403
        assert forbidden.headers["cache-control"] == "no-store"
        for _ in range(4):  # failures 2-5: the IP reaches the limit
            assert (await _login(client, "adm_" + "0" * 43)).status_code == 401
        locked = await _login(client, admin_key)  # 6th attempt: cooldown
        assert locked.status_code == 429
        assert locked.headers["cache-control"] == "no-store"
    # A fresh client (same app-wide IP table) still gets no-store on the
    # shell while the IP is cooling down.
    async with _client(app) as client:
        shell = await client.get("/admin/")
        assert shell.status_code == 200
        assert shell.headers["cache-control"] == "no-store"


# --- 7. CSRF enforcement on cookie-authenticated POSTs ---------------------------


async def test_csrf_required_for_cookie_post_and_exempt_for_bearer(
    app: FastAPI, admin_key: str
) -> None:
    async with _client(app) as client:
        await _login(client, admin_key)
        token = await _session_csrf(client)

        missing = await client.post("/api/admin/logout")
        assert missing.status_code == 403
        assert missing.json() == {"error": "forbidden"}
        wrong = await client.post(
            "/api/admin/logout", data={"csrf_token": "0" * 43}
        )
        assert wrong.status_code == 403
        valid = await client.post("/api/admin/logout", data={"csrf_token": token})
        assert valid.status_code == 200  # this logout consumed the session

        # Fresh session for the header-carried token variant (tokens are
        # per-session, so a new login means a new token).
        await _login(client, admin_key)
        token_after = await _session_csrf(client)
        via_header = await client.post(
            "/api/admin/logout", headers={"X-CSRF-Token": token_after}
        )
        assert via_header.status_code == 200

    # Bearer-authenticated POSTs are exempt from CSRF by convention.
    async with _client(app) as client:
        bearer = await client.post(
            "/api/admin/logout", headers={"Authorization": f"Bearer {admin_key}"}
        )
        assert bearer.status_code == 200

    # Anonymous POSTs never reach the CSRF check: they get the uniform 401.
    async with _client(app) as client:
        anonymous = await client.post("/api/admin/logout")
        assert anonymous.status_code == 401
        assert anonymous.json() == {"error": "unauthorized"}


# --- 8. Deferred hash-record validation (M02-T02 -> M02-T03) ---------------------


def test_kdf_parameters_bounded_before_kdf_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Malformed/oversized records fail closed WITHOUT running scrypt.

    The pre-KDF validation is the point of the deferred M02-T02 item: an
    attacker-influenced record with e.g. N=2^27 must cost nothing, not a
    multi-gigabyte scrypt allocation per attempt. The spy proves no KDF call
    happens for rejected records, while a valid record still reaches it.
    """
    valid = hash_secret("x")  # built before the spy: setup is not under test
    calls: list[int] = []
    real_derive = crypto_hash._derive

    def spy_derive(plaintext: str, *, salt: bytes, n: int, r: int, p: int) -> bytes:
        calls.append(n)
        return real_derive(plaintext, salt=salt, n=n, r=r, p=p)

    monkeypatch.setattr(crypto_hash, "_derive", spy_derive)

    assert crypto_hash.verify_secret("x", _scrypt_record(2**27, 8, 1)) is False
    assert crypto_hash.verify_secret("x", _scrypt_record(3, 8, 1)) is False
    assert crypto_hash.verify_secret("x", _scrypt_record(2**15, 0, 1)) is False
    assert crypto_hash.verify_secret("x", _scrypt_record(2**15, 8, 2)) is False
    assert crypto_hash.verify_secret("x", "scrypt$32768$8$1$short") is False
    assert calls == []  # no KDF work for any rejected record

    assert crypto_hash.verify_secret("x", valid) is True
    assert calls == [2**15]  # valid records DO run the KDF, with bounded params


def test_is_valid_record_accepts_generated_and_rejects_tampered() -> None:
    assert is_valid_record(hash_secret("x"))
    assert not is_valid_record(_scrypt_record(2**17, 8, 1))
    assert not is_valid_record("scrypt$32768$8$1$short")
    assert not is_valid_record("garbage")
    assert not is_valid_record("")


@pytest.mark.parametrize(
    "record",
    [
        _scrypt_record(2**27, 8, 1),
        _scrypt_record(2**15, 8, 2),
        "scrypt$32768$8$1$short",
    ],
    ids=["oversized-n", "out-of-bounds-p", "truncated"],
)
def test_invalid_record_on_disk_fails_loud_at_startup(tmp_path: Path, record: str) -> None:
    """The same validation gates startup: invalid records abort the boot.

    Symmetric gates: whatever ``verify_secret`` rejects pre-KDF, the startup
    gate refuses too (fail loud, evidence preserved, never rotated).
    """
    paths = build_paths(tmp_path)
    hash_path = paths.admin_key_hash_path()
    hash_path.parent.mkdir(parents=True)
    hash_path.write_text(record, encoding="ascii")

    with pytest.raises(AdminKeyHashCorruptedError, match="corrupted admin key hash"):
        ensure_admin_key(paths)

    assert hash_path.read_text(encoding="ascii") == record  # never rotated


async def test_hostile_record_on_disk_fails_closed_unauthorized(tmp_path: Path) -> None:
    """With a hostile record stored, every key is rejected 401 — no 500, no hang."""
    save_admin_key_hash(build_paths(tmp_path), _scrypt_record(2**27, 8, 1))
    app = create_app(Settings(data_dir=tmp_path))
    async with _client(app) as client:
        response = await client.get(
            "/api/admin/health", headers={"Authorization": f"Bearer adm_{'0' * 43}"}
        )
    assert response.status_code == 401
    assert response.json() == {"error": "unauthorized"}


# --- 9. Surface exposure: the fixed admin surface ---------------------------------


def _collect_admin_routes(routes: Iterable[Any]) -> set[tuple[str, frozenset[str]]]:
    """Collect ``(path, methods)`` of admin routes, descending into inclusions.

    FastAPI 0.143 keeps ``include_router`` results as ``_IncludedRouter``
    wrappers inside ``app.routes``; their prefix-applied routes come from
    ``effective_candidates()`` (yielding context wrappers that expose
    ``.path``/``.methods``). Directly-attached routes stay plain APIRoutes.
    The walk handles both shapes so the assertion covers the real surface.
    """
    collected: set[tuple[str, frozenset[str]]] = set()
    for route in routes:
        if hasattr(route, "effective_candidates"):  # fastapi _IncludedRouter
            collected |= _collect_admin_routes(route.effective_candidates())
            continue
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if not isinstance(path, str) or not path.startswith(("/api/admin", "/admin")):
            continue
        collected.add((path, frozenset((methods or set()) - {"HEAD"})))
    return collected


async def test_admin_surface_exposes_only_the_fixed_routes(app: FastAPI) -> None:
    admin_routes = _collect_admin_routes(app.routes)
    assert admin_routes == {
        ("/api/admin/login", frozenset({"POST"})),
        ("/api/admin/logout", frozenset({"POST"})),
        ("/api/admin/session", frozenset({"GET"})),
        ("/api/admin/health", frozenset({"GET"})),
        # The M03-T02 user-management routes:
        ("/api/admin/users", frozenset({"GET"})),
        ("/api/admin/users", frozenset({"POST"})),
        ("/api/admin/users/{user_id}", frozenset({"GET"})),
        ("/api/admin/users/{user_id}", frozenset({"DELETE"})),
        ("/api/admin/users/{user_id}/rotate-key", frozenset({"POST"})),
        ("/api/admin/users/{user_id}/status", frozenset({"POST"})),
        # The M07-T05 SPA shell: the Jinja2 pages are gone, so the ONLY
        # non-JSON admin surface is the shell (plus its catch-all, which
        # keeps every published deep link serving the SPA).
        ("/admin", frozenset({"GET"})),
        ("/admin/{path:path}", frozenset({"GET"})),
    }
    async with _client(app) as client:
        users = await client.get("/api/admin/users")  # new in M03-T02, still gated
    assert users.status_code == 401
    assert users.json() == {"error": "unauthorized"}


# --- Fixed cookie-name contract and session signer behaviour ---------------------


def test_cookie_name_contract() -> None:
    """Both names declared (fixed contract); only the admin cookie is active."""
    assert ADMIN_COOKIE_NAME == "imapgw_admin"
    assert USER_COOKIE_NAME == "imapgw_user"


def test_session_signer_round_trip_and_cross_app_rejection() -> None:
    """Sign, verify, and reject: fresh per-boot secrets invalidate old cookies."""
    first = SessionSigner()
    cookie, csrf = first.create_session("admin")
    payload = first.unseal(cookie)
    assert payload is not None
    assert payload["kind"] == "admin"
    assert payload["csrf"] == csrf

    # A different per-boot signer (fresh random secret) rejects the cookie:
    assert SessionSigner().unseal(cookie) is None
    # Single-character mutation anywhere fails:
    sibling = "A" if cookie[-1] != "A" else "B"
    assert first.unseal(cookie[:-1] + sibling) is None
    assert first.unseal("not-a-cookie") is None
    # Expired sessions fail:
    expired_signer = SessionSigner(ttl_seconds=-1)
    expired_cookie, _ = expired_signer.create_session("admin")
    assert expired_signer.unseal(expired_cookie) is None


async def test_non_admin_or_csrf_less_session_cookies_do_not_authenticate(
    app: FastAPI,
) -> None:
    """Only a kind=admin session WITH a CSRF token authenticates as admin.

    The kind/csrf gate in ``admin_session`` is an authorization control:
    a future user-kind session (the M03 variant) and an admin-kind session
    missing its CSRF token must never grant admin access.

    M07-T05: the page gating is gone (the SPA shell is served to every
    visitor), so the cross-kind/csrf purpose is preserved on the API
    surface — the session bootstrap and the health probe both answer the
    uniform 401 — while the shell stays a 200 (it carries no data).
    """
    signer: SessionSigner = app.state.session_signer
    exp = str(int(time.time()) + 3600)
    for payload in (
        {"kind": "user", "csrf": "token", "exp": exp},
        {"kind": "admin", "csrf": "", "exp": exp},
    ):
        async with _client(app) as client:
            client.cookies.set(ADMIN_COOKIE_NAME, signer.seal(payload))
            session = await client.get("/api/admin/session")
            assert session.status_code == 401  # not authenticated as admin
            assert session.json() == {"error": "unauthorized"}
            health = await client.get("/api/admin/health")
            assert health.status_code == 401
            shell = await client.get("/admin/")
            assert shell.status_code == 200  # the shell is data-free
