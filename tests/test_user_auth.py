"""User-key authentication primitive tests (M03-T04).

Coverage per the M03-T04 acceptance criteria and the security scrutiny
list:

1. ``authenticate_user_key`` outcome matrix: the current key authenticates
   (as credential-free ``UserMetadata``); wrong-shaped, wrong-prefix
   (``adm_``), wrong-type, oversized and non-ASCII garbage all resolve to
   ``None`` without raising; a multi-user store resolves the right owner;
   an empty registry resolves to ``None``; a corrupt registry fails
   closed;
2. disabled users never authenticate (re-enabling restores access);
3. rotation invalidates the old key immediately; the new key
   authenticates with ``key_generation`` bumped;
4. header parsing matrix for ``user_from_bearer``: Bearer and ``X-Api-Key``
   forms, Authorization-wins precedence, Basic/other-scheme rejection,
   malformed shapes (bare scheme, empty/whitespace tokens, duplicate
   headers, non-ASCII values) — all ``None``, and the header-gated probe
   route renders every one as the identical uniform 401;
5. ``require_user`` cookie sessions: happy path (signed ``imapgw_user``
   cookie with kind/sub/csrf) and the failure matrix (absent/empty,
   garbage, admin-kind, missing/empty sub or csrf, expired, cross-signer,
   unknown user — every one the identical uniform 401, never 404), plus
   stale cookies of deleted and disabled users (deleted → 401, never
   404);
6. admin-cookie regression on the real app: the M02-T03 admin login/cookie
   flow is untouched (only ``imapgw_admin`` is set; ``imapgw_user``
   never) and a user-kind cookie grants nothing on the admin API (the
   SPA shell itself is served to every visitor — it carries no data);
7. structural check: returned user objects carry exactly the metadata
   fields — no ``login_key_hash``, no ``aek``, no key material anywhere.

All HTTP tests run in-process via ``httpx.AsyncClient`` over an ASGI
transport (the pattern of tests/test_admin_auth.py).
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request

from imap_mcp_gateway.config.env import Settings
from imap_mcp_gateway.config.paths import Paths, build_paths
from imap_mcp_gateway.crypto.hash import hash_secret
from imap_mcp_gateway.crypto.keys import generate_admin_key
from imap_mcp_gateway.store.admin_key import save_admin_key_hash
from imap_mcp_gateway.store.user_schema import UserMetadata
from imap_mcp_gateway.store.users import (
    create_user,
    delete_user,
    disable_user,
    enable_user,
    rotate_login_key,
)
from imap_mcp_gateway.web.middleware.admin_auth import (
    AdminHTTPError,
    admin_http_error_handler,
)
from imap_mcp_gateway.web.middleware.user_auth import (
    UserAuthDep,
    authenticate_user_key,
    user_from_bearer,
)
from imap_mcp_gateway.web.server import create_app
from imap_mcp_gateway.web.session import (
    ADMIN_COOKIE_NAME,
    SESSION_KIND_ADMIN,
    SESSION_KIND_USER,
    USER_COOKIE_NAME,
    SessionSigner,
)

_ONE_MB_KEY = "x" * 1_000_001
"""A ≥1 MB garbage input (acceptance: huge strings must not throw)."""


# --- fixtures -----------------------------------------------------------------


@pytest.fixture(scope="module")
def registry(tmp_path_factory: pytest.TempPathFactory) -> tuple[Paths, str, str]:
    """A read-only store with two active users: ``(paths, alice_key, bob_key)``."""
    paths = build_paths(tmp_path_factory.mktemp("user-auth"))
    _alice_record, alice_key = create_user(paths, "alice")
    _bob_record, bob_key = create_user(paths, "bob")
    return paths, alice_key, bob_key


def _probe_app(paths: Paths) -> FastAPI:
    """A minimal app wiring both auth dependencies over one store.

    ``/bearer`` exposes the raw ``user_from_bearer`` outcome; ``/gate``
    shows how a consuming surface maps ``None`` to the uniform 401;
    ``/require`` is guarded by :data:`UserAuthDep` (cookie sessions). The
    app-wide ``AdminHTTPError`` handler is registered exactly as
    ``create_app`` does, so error bodies can be asserted byte-for-byte.
    """
    app = FastAPI()
    app.state.settings = Settings(data_dir=paths.data_dir)
    app.state.session_signer = SessionSigner()
    app.add_exception_handler(AdminHTTPError, admin_http_error_handler)

    @app.get("/bearer")
    async def bearer_probe(request: Request) -> dict[str, Any]:
        user = await user_from_bearer(request)
        return {
            "found": user is not None,
            "user": user.model_dump(mode="json") if user else None,
        }

    @app.get("/gate")
    async def gated_probe(request: Request) -> dict[str, str]:
        user = await user_from_bearer(request)
        if user is None:
            raise AdminHTTPError(401, "unauthorized")
        return {"status": "ok"}

    @app.get("/require")
    async def require_probe(user: UserAuthDep) -> dict[str, Any]:
        return {
            "user": user.user.model_dump(mode="json"),
            "via": user.via,
            "csrf": user.csrf_token,
        }

    return app


@pytest.fixture(scope="module")
def probe_app(registry: tuple[Paths, str, str]) -> FastAPI:
    """The probe app over the module-scoped two-user registry."""
    paths, _alice_key, _bob_key = registry
    return _probe_app(paths)


def _client(app: FastAPI) -> httpx.AsyncClient:
    """An in-process client over the app (cookies persist within the client)."""
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


# --- 1. authenticate_user_key: outcome matrix ----------------------------------


def test_current_key_authenticates_as_credential_free_metadata(
    registry: tuple[Paths, str, str],
) -> None:
    paths, alice_key, _bob_key = registry

    user = authenticate_user_key(paths, alice_key)

    assert user is not None
    assert user.name == "alice"
    assert user.status == "active"
    assert user.key_generation == 1
    # Exactly the metadata fields — the acceptance criterion "no hash or
    # key fields" holds structurally, not just by omission.
    assert set(UserMetadata.model_fields) == {
        "id",
        "name",
        "created_at",
        "key_generation",
        "status",
        "account_count",
    }
    assert not hasattr(user, "login_key_hash")
    assert not hasattr(user, "aek")
    assert "scrypt$" not in user.model_dump_json()
    assert "usr_" not in user.model_dump_json()


def test_multi_user_scan_names_the_right_owner(
    registry: tuple[Paths, str, str],
) -> None:
    paths, alice_key, bob_key = registry

    alice = authenticate_user_key(paths, alice_key)
    bob = authenticate_user_key(paths, bob_key)

    assert alice is not None and alice.name == "alice"
    assert bob is not None and bob.name == "bob"
    assert alice.id != bob.id


def test_admin_formatted_key_never_authenticates_as_user_key(
    registry: tuple[Paths, str, str],
) -> None:
    """Scrutiny point: an ``adm_`` key is not a user key, ever."""
    paths, _alice_key, _bob_key = registry
    assert authenticate_user_key(paths, generate_admin_key()) is None


def test_empty_registry_authenticates_nothing(tmp_path: Path) -> None:
    assert authenticate_user_key(build_paths(tmp_path), "usr_" + "A" * 43) is None


@pytest.mark.parametrize(
    "garbage",
    [
        None,
        123,
        3.14,
        True,
        b"usr_bytes-not-str",
        {"kind": "user"},
        ["usr_list"],
        "",
        "garbage",
        "usr_" + "A" * 43,
        "adm_" + "A" * 43,
        _ONE_MB_KEY,
        "ключ-🔐",
    ],
    ids=[
        "none",
        "int",
        "float",
        "bool",
        "bytes",
        "dict",
        "list",
        "empty",
        "garbage",
        "usr-shaped-wrong",
        "adm-shaped",
        "one-mb",
        "non-ascii-emoji",
    ],
)
def test_garbage_input_never_throws(
    registry: tuple[Paths, str, str], garbage: Any
) -> None:
    """Acceptance: never throws on garbage input — every variant is ``None``."""
    paths, _alice_key, _bob_key = registry
    assert authenticate_user_key(paths, garbage) is None


def test_corrupt_registry_fails_closed_without_raising(tmp_path: Path) -> None:
    """A schema-invalid record file closes the gate (uniform ``None``)."""
    paths = build_paths(tmp_path)
    record, key = create_user(paths, "frank")
    paths.user_record_path(record.id).write_text("not json", encoding="utf-8")

    assert authenticate_user_key(paths, key) is None


# --- 2. disabled users never authenticate ---------------------------------------


def test_disabled_user_never_authenticates_until_re_enabled(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)
    record, key = create_user(paths, "dana")

    assert authenticate_user_key(paths, key) is not None
    disable_user(paths, record.id)
    assert authenticate_user_key(paths, key) is None  # disabled: no auth
    enable_user(paths, record.id)
    assert authenticate_user_key(paths, key) is not None  # key survived


# --- 3. rotation invalidation sequence ------------------------------------------


def test_rotation_invalidates_old_key_immediately(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)
    record, old_key = create_user(paths, "erin")

    assert authenticate_user_key(paths, old_key) is not None
    rotated, new_key = rotate_login_key(paths, record.id)

    assert authenticate_user_key(paths, old_key) is None  # old key is dead now
    user = authenticate_user_key(paths, new_key)
    assert user is not None
    assert user.id == record.id
    assert user.key_generation == rotated.key_generation == 2


# --- 4. user_from_bearer: header parsing matrix ---------------------------------


async def test_bearer_and_api_key_forms_authenticate(
    probe_app: FastAPI, registry: tuple[Paths, str, str]
) -> None:
    _paths, alice_key, _bob_key = registry
    async with _client(probe_app) as client:
        bearer = await client.get(
            "/bearer", headers={"Authorization": f"Bearer {alice_key}"}
        )
        api_key = await client.get("/bearer", headers={"X-Api-Key": alice_key})
        lower_scheme = await client.get(
            "/bearer", headers={"Authorization": f"bearer {alice_key}"}
        )
    assert bearer.status_code == 200
    assert bearer.json()["found"] is True
    assert bearer.json()["user"]["name"] == "alice"
    assert alice_key not in bearer.text  # no key material echoes back
    assert api_key.json()["found"] is True
    assert lower_scheme.json()["found"] is True  # scheme match is case-insensitive


async def test_authorization_wins_over_x_api_key(
    probe_app: FastAPI, registry: tuple[Paths, str, str]
) -> None:
    """Absolute precedence: a present Authorization header decides, always."""
    _paths, alice_key, bob_key = registry
    async with _client(probe_app) as client:
        auth_wins = await client.get(
            "/bearer",
            headers={"Authorization": f"Bearer {alice_key}", "X-Api-Key": bob_key},
        )
        wrong_bearer = await client.get(
            "/bearer",
            headers={
                "Authorization": f"Bearer {generate_admin_key()}",
                "X-Api-Key": alice_key,
            },
        )
        basic = await client.get(
            "/bearer",
            headers={"Authorization": "Basic dXNlcjpwYXNz", "X-Api-Key": alice_key},
        )
    assert auth_wins.json()["user"]["name"] == "alice"
    assert wrong_bearer.json()["found"] is False  # valid X-Api-Key cannot rescue
    assert basic.json()["found"] is False  # non-Bearer scheme rejects outright


async def test_api_key_value_is_whitespace_trimmed(
    probe_app: FastAPI, registry: tuple[Paths, str, str]
) -> None:
    """``X-Api-Key`` is a bare value: OWS around it is transport noise."""
    _paths, alice_key, _bob_key = registry
    async with _client(probe_app) as client:
        padded = await client.get("/bearer", headers={"X-Api-Key": f"  {alice_key} "})
    assert padded.json()["found"] is True


async def test_malformed_header_shapes_never_authenticate(
    probe_app: FastAPI, registry: tuple[Paths, str, str]
) -> None:
    """Every malformed shape is ``None`` — including ones holding the REAL key.

    Strict Bearer structure (exactly one space, no surrounding whitespace
    on the token) means even a valid key inside a malformed shape fails.
    """
    _paths, alice_key, _bob_key = registry
    shapes: list[dict[str, str]] = [
        {},
        {"Authorization": "Bearer"},
        {"Authorization": "Bearer "},
        {"Authorization": " "},
        {"Authorization": f"Bearer  {alice_key}"},  # double space
        {"Authorization": f"Bearer {alice_key} "},  # trailing space
        {"Authorization": f"Bearer\t{alice_key}"},  # tab separator
        {"Authorization": f" {alice_key}"},  # no scheme
        {"Authorization": "Token abc"},
        {"Authorization": "Basic dXNlcjpwYXNz"},
        {"X-Api-Key": ""},
        {"X-Api-Key": "   "},
        {"X-Api-Key": "usr_wrong-key"},
    ]
    raw_shapes: list[list[tuple[bytes, bytes]]] = [
        # httpx rejects non-ASCII *str* values client-side; raw bytes reach
        # the app (Starlette decodes latin-1) and must fail closed there.
        [(b"authorization", b"Bearer \xfc\xfexc0de")],
        [(b"x-api-key", b"\xfc\xfexc0de")],
    ]
    async with _client(probe_app) as client:
        for headers in shapes:
            response = await client.get("/bearer", headers=headers)
            assert response.status_code == 200, headers
            assert response.json() == {"found": False, "user": None}, headers
        for raw_headers in raw_shapes:
            response = await client.get("/bearer", headers=raw_headers)
            assert response.status_code == 200, raw_headers
            assert response.json() == {"found": False, "user": None}, raw_headers


async def test_duplicate_headers_are_rejected(
    probe_app: FastAPI, registry: tuple[Paths, str, str]
) -> None:
    """Ambiguous duplicate credentials fail closed — even when identical."""
    _paths, alice_key, _bob_key = registry
    async with _client(probe_app) as client:
        dup_auth = await client.get(
            "/bearer",
            headers=[
                ("authorization", f"Bearer {alice_key}"),
                ("authorization", f"Bearer {alice_key}"),
            ],
        )
        dup_api_key = await client.get(
            "/bearer",
            headers=[("x-api-key", alice_key), ("x-api-key", alice_key)],
        )
    assert dup_auth.json()["found"] is False
    assert dup_api_key.json()["found"] is False


async def test_header_gate_maps_every_failure_to_uniform_401(
    probe_app: FastAPI, registry: tuple[Paths, str, str]
) -> None:
    """The consuming surface's ``None`` → uniform 401 mapping (M05's shape)."""
    _paths, alice_key, _bob_key = registry
    bodies: set[str] = set()
    async with _client(probe_app) as client:
        ok = await client.get("/gate", headers={"Authorization": f"Bearer {alice_key}"})
        assert ok.status_code == 200
        assert ok.json() == {"status": "ok"}
        for headers in (
            {},
            {"Authorization": "Basic dXNlcjpwYXNz"},
            {"Authorization": f"Bearer {'usr_' + 'F' * 43}"},
        ):
            denied = await client.get("/gate", headers=headers)
            assert denied.status_code == 401, headers
            assert denied.json() == {"error": "unauthorized"}, headers
            bodies.add(denied.text)
    assert len(bodies) == 1  # byte-identical failures, no enumeration oracle


# --- 5. require_user: cookie sessions --------------------------------------------


async def test_require_user_happy_path(
    probe_app: FastAPI, registry: tuple[Paths, str, str]
) -> None:
    paths, alice_key, _bob_key = registry
    alice = authenticate_user_key(paths, alice_key)
    assert alice is not None
    signer: SessionSigner = probe_app.state.session_signer
    cookie, csrf = signer.create_session(SESSION_KIND_USER, sub=alice.id)

    async with _client(probe_app) as client:
        client.cookies.set(USER_COOKIE_NAME, cookie)
        response = await client.get("/require")

    assert response.status_code == 200
    body = response.json()
    assert body["via"] == "cookie"
    assert body["csrf"] == csrf
    assert body["user"]["id"] == alice.id
    assert body["user"]["name"] == "alice"
    assert "scrypt$" not in response.text and alice_key not in response.text


async def test_require_user_rejects_invalid_sessions_uniformly(probe_app: FastAPI) -> None:
    """Every invalid session is the identical 401 — never a 404, never a hint."""
    signer: SessionSigner = probe_app.state.session_signer
    other_signer = SessionSigner()  # a different per-boot secret
    exp = str(int(time.time()) + 3600)
    cases: dict[str, str] = {
        "absent": "",
        "garbage": "not-a-cookie",
        "admin-kind": signer.seal({"kind": SESSION_KIND_ADMIN, "csrf": "t", "exp": exp}),
        "missing-sub": signer.seal({"kind": SESSION_KIND_USER, "csrf": "t", "exp": exp}),
        "empty-sub": signer.seal(
            {"kind": SESSION_KIND_USER, "sub": "", "csrf": "t", "exp": exp}
        ),
        "missing-csrf": signer.seal({"kind": SESSION_KIND_USER, "sub": "ghost", "exp": exp}),
        "empty-csrf": signer.seal(
            {"kind": SESSION_KIND_USER, "sub": "ghost", "csrf": "", "exp": exp}
        ),
        "unknown-user": signer.create_session(SESSION_KIND_USER, sub="ghost")[0],
        "traversal-sub": signer.create_session(
            SESSION_KIND_USER, sub="../../etc/passwd"
        )[0],  # registry-invalid id inside a valid signature: 401, never 500
        # Same signer, valid signature — but the exp claim is in the past,
        # so this exercises the expiry branch (not the HMAC rejection).
        "expired": signer.seal(
            {
                "kind": SESSION_KIND_USER,
                "sub": "ghost",
                "csrf": "t",
                "exp": str(int(time.time()) - 1),
            }
        ),
        "cross-signer": other_signer.create_session(SESSION_KIND_USER, sub="ghost")[0],
    }
    bodies: set[str] = set()
    async with _client(probe_app) as client:
        for name, cookie in cases.items():
            client.cookies.set(USER_COOKIE_NAME, cookie)
            response = await client.get("/require")
            assert response.status_code == 401, name
            assert response.json() == {"error": "unauthorized"}, name
            bodies.add(response.text)
    assert len(bodies) == 1  # byte-identical failures


async def test_stale_cookie_of_deleted_user_is_uniform_401_never_404(
    tmp_path: Path,
) -> None:
    """Scrutiny point: deletion kills the session — 401, never 404."""
    paths = build_paths(tmp_path)
    record, _key = create_user(paths, "grace")
    app = _probe_app(paths)
    signer: SessionSigner = app.state.session_signer
    cookie, _csrf = signer.create_session(SESSION_KIND_USER, sub=record.id)
    delete_user(paths, record.id)

    async with _client(app) as client:
        client.cookies.set(USER_COOKIE_NAME, cookie)
        response = await client.get("/require")

    assert response.status_code == 401
    assert response.json() == {"error": "unauthorized"}


async def test_stale_cookie_of_disabled_user_is_401(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)
    record, _key = create_user(paths, "henry")
    app = _probe_app(paths)
    signer: SessionSigner = app.state.session_signer
    cookie, _csrf = signer.create_session(SESSION_KIND_USER, sub=record.id)
    disable_user(paths, record.id)

    async with _client(app) as client:
        client.cookies.set(USER_COOKIE_NAME, cookie)
        response = await client.get("/require")

    assert response.status_code == 401
    assert response.json() == {"error": "unauthorized"}


# --- 6. admin-cookie regression on the real app ----------------------------------


@pytest.fixture(scope="module")
def admin_key() -> str:
    """One admin key for the module (key generation is cheap)."""
    return generate_admin_key()


@pytest.fixture(scope="module")
def admin_record(admin_key: str) -> str:
    """The scrypt record for :func:`admin_key` (the one expensive scrypt run)."""
    return hash_secret(admin_key)


@pytest.fixture
def gateway_app(tmp_path: Path, admin_record: str, spa_dist: Path) -> FastAPI:
    """The real ``create_app`` over a seeded admin hash file."""
    save_admin_key_hash(build_paths(tmp_path), admin_record)
    return create_app(Settings(data_dir=tmp_path, spa_dist_dir=spa_dist))


async def test_admin_login_cookie_flow_untouched(
    gateway_app: FastAPI, admin_key: str
) -> None:
    """Activating ``imapgw_user`` must not disturb the admin cookie path."""
    async with _client(gateway_app) as client:
        login = await client.post("/api/admin/login", data={"key": admin_key})
        assert login.status_code == 200
        set_cookie = login.headers["set-cookie"]
        assert set_cookie.startswith(f"{ADMIN_COOKIE_NAME}=")
        assert "httponly" in set_cookie.lower()
        assert "samesite=strict" in set_cookie.lower()
        assert USER_COOKIE_NAME not in set_cookie  # user cookie stays unused here

        # M07-T05: /admin serves the SPA shell (no server-side page gating).
        home = await client.get("/admin/")
        assert home.status_code == 200
        assert "text/html" in home.headers["content-type"]
        health = await client.get("/api/admin/health")
        assert health.status_code == 200


async def test_user_kind_cookie_grants_nothing_on_admin_surface(
    gateway_app: FastAPI,
) -> None:
    """Cross-kind isolation: a valid user session is not an admin session.

    M07-T05: the page gating is gone, so the cross-kind purpose is pinned
    on the API surface (the session bootstrap and the health probe both
    answer the uniform 401); the shell itself stays a 200 — it is
    data-free and the SPA renders its login view client-side.
    """
    signer: SessionSigner = gateway_app.state.session_signer
    user_cookie, _csrf = signer.create_session(SESSION_KIND_USER, sub="someone")

    async with _client(gateway_app) as client:
        client.cookies.set(USER_COOKIE_NAME, user_cookie)
        session = await client.get("/api/admin/session")
        health = await client.get("/api/admin/health")
        shell = await client.get("/admin/")

    assert session.status_code == 401  # not authenticated as admin
    assert session.json() == {"error": "unauthorized"}
    assert health.status_code == 401
    assert health.json() == {"error": "unauthorized"}
    assert shell.status_code == 200
