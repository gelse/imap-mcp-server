"""Security regression tests (M06-T02): the hardening pass, pinned.

Focused cases per the M06-T02 verification requirements:

1. log redaction: ``RedactFilter`` scrubs ``adm_``/``usr_``/64-hex/``scrypt$``
   from the message, ``fields``, ``tag`` and exception text — while the ONE
   exempt first-boot admin-key line survives (the operator's only delivery
   channel), a forged ``[mcp:…]`` relay line imitating that wording is still
   scrubbed, and a record with broken ``args`` never crashes the stream;
2. uniform 401 bodies: every auth failure on the admin, user and MCP
   surfaces is the identical ``{"error": "unauthorized"}`` — no key echo,
   no cause distinction, no enumeration oracle;
3. serializer leak scan: no unauthenticated route body carries ``scrypt$``,
   key MATERIAL, or 64-hex secrets — extended by M06-T04 (the final
   acceptance gate) to the AUTHENTICATED surfaces: the same detectors over
   the admin routes and the SPA shell behind a valid admin key, and the
   ``/api/me`` JSON plus the user SPA shell behind a real user's cookie
   session, every swept response pinned to its SUCCESS status, and a
   detector test feeding REAL generated artifacts (hash records, keys, the
   wrap key, a wrapped blob, keyfile content) to the sweep assertion so it
   cannot go vacuous;
4. header parsing rejects odd auth schemes (non-Bearer ``Authorization``,
   Bearer without a token, whitespace-padded Bearer, duplicate headers)
   without falling through to another credential;
5. ``DATA_DIR`` file modes: directories ``0700``, secret files ``0600``;
6. rate limits per surface: user login locks at
   :data:`USER_LOGIN_FAILURE_LIMIT` (8) while the admin surface (5) and
   ``/mcp`` (5) keep their own independent counters — 8 user failures (which
   already exceed the admin limit) never lock the admin surface out, and a
   successful login hands its reserved slot back;
7. security headers: ``nosniff`` / ``X-Frame-Options: DENY`` /
   ``Referrer-Policy: no-referrer`` / ``Content-Security-Policy`` on every
   response, with the admin ``Cache-Control: no-store`` preserved;
8. tool-host env allowlist: the Node child env is EXACTLY the six
   documented variables — no AEK, wrap key, ``DATA_DIR`` or any other
   parent secret.

All HTTP tests run in-process via ``httpx.AsyncClient`` over an ASGI
transport (the pattern of tests/test_admin_auth.py); ``pytest.ini`` sets
``asyncio_mode = auto``.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from imap_mcp_gateway.config.env import Settings
from imap_mcp_gateway.config.paths import build_paths
from imap_mcp_gateway.crypto.hash import hash_secret
from imap_mcp_gateway.crypto.keys import generate_admin_key
from imap_mcp_gateway.log import REDACTION_TOKEN, RedactFilter, redact_text
from imap_mcp_gateway.mcp.session_registry import SessionRegistry
from imap_mcp_gateway.mcp.tool_host import NodeToolHost
from imap_mcp_gateway.store.admin_key import ensure_admin_key, save_admin_key_hash
from imap_mcp_gateway.store.fs_safe import PRIVATE_DIR_MODE, SECRET_FILE_MODE
from imap_mcp_gateway.store.session_keyfile import cleanup_key_file, materialize_key_file
from imap_mcp_gateway.store.users import activate_aek, create_user, get_user
from imap_mcp_gateway.store.wrap_key import ensure_wrap_key
from imap_mcp_gateway.web.middleware.admin_auth import FAILURE_LIMIT, AdminRateLimiter
from imap_mcp_gateway.web.middleware.user_auth import USER_LOGIN_FAILURE_LIMIT
from imap_mcp_gateway.web.server import create_app

USER_KEY_RE = re.compile(r"^usr_[A-Za-z0-9_-]{43}$")
# Full key MATERIAL (prefix + the base64url body), not the bare prefix.
KEY_MATERIAL_RE = re.compile(r"\b(?:adm_|usr_)[A-Za-z0-9_-]{20,}")
# A run of 64+ lowercase-hex chars, whatever it is glued to on the right (the
# AEK / wrap-key spelling; matches log.py's ``_HEX64_RE``).
HEX64_RE = re.compile(r"(?<![0-9a-f])[0-9a-f]{64,}")
# A wrapped-AEK blob: base64(iv):base64(tag):base64(ciphertext), standard
# base64 with padding, each field >= 16 chars (crypto/wrap.py:wrap_key).
WRAPPED_BLOB_RE = re.compile(
    r"[A-Za-z0-9+/]{16,}={0,2}:[A-Za-z0-9+/]{16,}={0,2}:[A-Za-z0-9+/]{16,}={0,2}"
)

_SALT = "A" * 22  # canonical base64url of a 16-byte salt
_DIGEST = "B" * 43  # canonical base64url of a 32-byte digest
_VALID_RECORD = f"scrypt$32768$8$1${_SALT}${_DIGEST}"


class FakeClock:
    """Controllable monotonic clock for rate-limiter window tests."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


# --- shared fixtures ------------------------------------------------------------


@pytest.fixture(scope="module")
def admin_key() -> str:
    """One admin key for the whole module (key generation is cheap)."""
    return generate_admin_key()


@pytest.fixture(scope="module")
def admin_record(admin_key: str) -> str:
    """The scrypt record for :func:`admin_key` (one expensive scrypt run)."""
    return hash_secret(admin_key)


@pytest.fixture
def app(tmp_path: Path, admin_record: str, spa_dist: Path) -> FastAPI:
    """A fresh app (own session signer + BOTH limiters) over a seeded hash.

    The SPA dist is the synthetic fixture's: the shell pages (``/admin``,
    ``/user``) are part of the swept surfaces (M07-T05).
    """
    save_admin_key_hash(build_paths(tmp_path), admin_record)
    return create_app(Settings(data_dir=tmp_path, spa_dist_dir=spa_dist))


def _client(app: FastAPI) -> httpx.AsyncClient:
    """An in-process client over the app (cookies persist within the client)."""
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


def _assert_no_secret_material(label: str, body: str) -> None:
    """Assert one response body carries none of the banned secret shapes.

    The M06-T02 leak-scan detectors — ``scrypt$`` records (admin-key and
    login-key hashes), ``adm_``/``usr_`` key material, 64-hex secrets (the
    wrap key, the AEK, the session ``.key`` file) and wrapped-AEK blobs —
    applied to an AUTHENTICATED body (M06-T04). Every failing assert
    carries ``label`` as its message.
    """
    assert "scrypt$" not in body, label
    assert KEY_MATERIAL_RE.search(body) is None, label
    assert HEX64_RE.search(body) is None, label
    assert WRAPPED_BLOB_RE.search(body) is None, label


# --- 1. log redaction -----------------------------------------------------------


def test_redact_text_scrubs_every_secret_shape() -> None:
    """The four shapes — ``adm_``/``usr_``/64-hex/``scrypt$`` — become tokens."""
    admin_key_text = "adm_" + "A" * 43
    user_key_text = "usr_" + "B" * 43
    hex_secret = "c" * 64
    blob = (
        f"start {admin_key_text} mid {user_key_text} "
        f"{hex_secret} {_VALID_RECORD} end"
    )

    redacted = redact_text(blob)

    assert REDACTION_TOKEN in redacted
    for secret in (admin_key_text, user_key_text, hex_secret, _VALID_RECORD):
        assert secret not in redacted


def test_redact_text_leaves_ordinary_text_alone() -> None:
    """No false positives on paths, uuids (dashed, not a 64-hex run) or prose."""
    ordinary = (
        "[boot] starting imap-mcp-gateway data_dir=/data version=1.0.0 "
        "session_id=3f2504e0-4f89-11d3-9a0c-0305e82c3301 user_id=u1"
    )
    assert redact_text(ordinary) == ordinary


def test_redact_filter_scrubs_message_fields_tag_and_exception(
    captured_log_lines: tuple[logging.Logger, list[str]],
) -> None:
    """One record carrying a secret on EVERY channel leaves none of them."""
    logger, lines = captured_log_lines
    admin_key_text = "adm_" + "D" * 43
    user_key_text = "usr_" + "E" * 43
    hex_secret = "f" * 64

    try:
        raise ValueError(f"boom with {admin_key_text} and {hex_secret}")
    except ValueError:
        logger.exception(
            "[security] failure for %s record %s",
            user_key_text,
            _VALID_RECORD,
            extra={"tag": f"mcp:{hex_secret}", "fields": {"key": admin_key_text}},
        )

    (line,) = lines
    for secret in (admin_key_text, user_key_text, hex_secret, _VALID_RECORD):
        assert secret not in line
    assert line.count(REDACTION_TOKEN) >= 4  # message, fields, tag, exc_text


def test_exempt_admin_key_line_survives_redaction(
    captured_log_lines: tuple[logging.Logger, list[str]],
) -> None:
    """The first-boot admin-key delivery line keeps its plaintext (M02-T02).

    This is the ONE exemption: it is the operator's only channel for the key,
    and ``tests/test_admin_key_lifecycle.py`` pins the exact wording. The
    exemption is MESSAGE-only: a secret on any other channel of the same
    record (``fields``, ``tag``, exception text) is still scrubbed.
    """
    logger, lines = captured_log_lines
    admin_key_text = "adm_" + "F" * 43
    other_key_text = "usr_" + "G" * 43

    try:
        raise ValueError(f"boom with {other_key_text}")
    except ValueError:
        logger.exception(
            "[auth] admin key created — store it now; "
            "it will not be shown again: %s",
            admin_key_text,
            extra={"tag": f"mcp:{other_key_text}", "fields": {"key": other_key_text}},
        )

    (line,) = lines
    assert admin_key_text in line  # the message survives — the exempt one-time line
    assert "admin key created" in line
    # Everything else on the same exempt record is still redacted.
    assert other_key_text not in line
    assert line.count(REDACTION_TOKEN) >= 3  # fields, tag, exception text


def test_forged_relay_line_cannot_smuggle_secrets_via_the_exempt_wording(
    captured_log_lines: tuple[logging.Logger, list[str]],
) -> None:
    """A hostile child echoing the exempt wording is still scrubbed.

    The M05 stderr relay emits ``log.info("[mcp:%s] %s", userId, text)``, so
    a relayed line ALWAYS starts with ``[mcp:`` — the prefix-matched
    exemption cannot fire, even when the child's text repeats the exempt
    admin-key wording verbatim.
    """
    logger, lines = captured_log_lines
    admin_key_text = "adm_" + "0" * 43

    logger.info(
        "[mcp:%s] %s",
        "u1",
        f"[auth] admin key created — it will not be shown again: {admin_key_text}",
    )

    (line,) = lines
    assert admin_key_text not in line  # the forged key never lands
    assert "[mcp:u1]" in line  # the relay tag survives
    assert REDACTION_TOKEN in line


def test_redact_filter_survives_broken_record_args() -> None:
    """A %-format mismatch neither raises nor skips redaction (never-raise).

    The filter runs from arbitrary call sites, so a record whose ``args`` do
    not match ``msg`` must fall back to the raw text AND still get scrubbed,
    rather than propagating a ``TypeError`` out of the logging call.
    """
    secret = "adm_" + "A" * 43
    record = logging.LogRecord(
        name="tests.broken-args",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=f"[security] attempt for {secret} by %s and %s",
        args=("only-one-arg",),  # two placeholders, one argument → TypeError
        exc_info=None,
    )

    assert RedactFilter().filter(record) is True  # never raises, always keeps
    assert secret not in record.msg  # the raw fallback was still redacted
    assert record.args == ()  # args cleared, so a later format() cannot raise


# --- 2. uniform 401 bodies ------------------------------------------------------


async def test_every_auth_failure_is_the_same_uniform_401_body(
    app: FastAPI, admin_key: str
) -> None:
    """Admin, user and MCP surfaces answer failures with one identical body."""
    async with _client(app) as client:
        wrong_bearer = await client.get(
            "/api/admin/health", headers={"Authorization": "Bearer adm_wrong"}
        )
        missing_admin = await client.get("/api/admin/health")
        wrong_login = await client.post("/api/admin/login", data={"key": "adm_wrong"})
        # The user JSON API route is registered at exactly "/api/me" (a
        # trailing slash would 307-redirect before auth ever runs).
        missing_user = await client.get("/api/me")
        odd_scheme = await client.get(
            "/api/admin/health", headers={"Authorization": "Basic dXNlcjpwdw=="}
        )

    for response in (wrong_bearer, missing_admin, wrong_login, missing_user, odd_scheme):
        assert response.status_code == 401
        assert response.json() == {"error": "unauthorized"}


async def test_mcp_surface_answers_the_same_uniform_401(app: FastAPI) -> None:
    """``/mcp`` failures share the one body — no key echo, no cause split."""
    async with _client(app) as client:
        no_creds = await client.post(
            "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"}
        )
        wrong_key = await client.post(
            "/mcp",
            headers={"Authorization": "Bearer usr_wrong"},
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        )

    for response in (no_creds, wrong_key):
        assert response.status_code == 401
        assert response.json() == {"error": "unauthorized"}


# --- 3. serializer leak scan ----------------------------------------------------


async def test_no_unauthenticated_route_body_emits_secret_material(
    app: FastAPI, admin_key: str, tmp_path: Path
) -> None:
    """A sweep of unauthenticated bodies never carries secret material.

    The milestone's leak check at the HTTP seam: the SPA shell pages, auth
    failures and health responses must not contain ``scrypt$`` hash
    records, key material, wrapped-AEK blobs, or 64+-hex secrets. (The
    one-time secret DISCLOSURES are the sanctioned ones and are covered by
    the API suites; they are not reachable unauthenticated.)
    """
    paths = build_paths(tmp_path)
    create_user(paths, "sweep-user")
    ensure_wrap_key(paths)

    async with _client(app) as client:
        responses = [
            await client.get("/healthz"),
            await client.get("/admin"),
            await client.post("/api/admin/login", data={"key": admin_key}),
            await client.get("/user"),
            await client.post("/api/me/login", json={"key": "usr_wrong"}),
            await client.get("/api/admin/health"),
        ]

    for response in responses:
        body = response.text
        assert "scrypt$" not in body
        assert KEY_MATERIAL_RE.search(body) is None
        assert HEX64_RE.search(body) is None
        assert WRAPPED_BLOB_RE.search(body) is None


async def test_no_authenticated_admin_route_body_emits_secret_material(
    app: FastAPI, admin_key: str, tmp_path: Path
) -> None:
    """A sweep of ADMIN-authenticated bodies never carries secret material.

    The M06-T04 counterpart of the unauthenticated sweep above: every
    admin surface reached with a REAL admin key — the JSON API by
    ``Authorization: Bearer``, the SPA shell through the session cookie
    that ``POST /api/admin/login`` mints from the same key — must be free
    of ``scrypt$`` records, key material, wrapped-AEK blobs and 64-hex
    secrets. Each response is additionally pinned to its SUCCESS status,
    so an accidental 401/404 can never pass the sweep as a secret-free
    error page. The swept user record has its AEK ACTIVATED, so the detail
    serializer is exercised with the wrapped blob actually present in the
    store shape it must refuse to emit.
    """
    paths = build_paths(tmp_path)
    record, _key = create_user(paths, "admin-sweep-user")
    ensure_wrap_key(paths)
    activate_aek(paths, record.id)  # the record's aek blob exists (mutation target)

    async with _client(app) as client:
        login = await client.post("/api/admin/login", data={"key": admin_key})
        shell = await client.get("/admin")
        deep_link = await client.get(f"/admin/users/{record.id}")
        bearer = {"Authorization": f"Bearer {admin_key}"}
        health = await client.get("/api/admin/health", headers=bearer)
        listing = await client.get("/api/admin/users", headers=bearer)
        detail = await client.get(f"/api/admin/users/{record.id}", headers=bearer)

    swept = [
        ("POST /api/admin/login", login, 200),
        ("GET /admin", shell, 200),
        ("GET /admin/users/{user_id}", deep_link, 200),
        ("GET /api/admin/health", health, 200),
        ("GET /api/admin/users", listing, 200),
        ("GET /api/admin/users/{user_id}", detail, 200),
    ]
    for label, response, expected in swept:
        assert response.status_code == expected, f"{label}: {response.text}"
        _assert_no_secret_material(label, response.text)

    # Anchors: these are the REAL authenticated payloads, not error pages.
    assert any(user["id"] == record.id for user in listing.json())
    assert detail.json()["id"] == record.id


async def test_no_authenticated_user_route_body_emits_secret_material(
    app: FastAPI, tmp_path: Path
) -> None:
    """A sweep of USER-authenticated bodies never carries secret material.

    The user half of the M06-T04 sweep: a real ``usr_`` key logs in through
    ``POST /api/me/login`` (the cookie session's CSRF token comes from the
    M07-T01 ``GET /api/me/session`` bootstrap), then the ``/api/me`` JSON
    surface — profile, account create — and the user SPA shell are swept
    with the same banned shapes as everywhere else. Setup activates the AEK
    up front, so NO swept response is a one-time disclosure: the sanctioned
    AEK/key reveals (the M04-T05 recorder's domain) stay outside this set,
    and ``POST /api/me/accounts`` must answer with metadata only.
    """
    paths = build_paths(tmp_path)
    record, user_key = create_user(paths, "user-sweep-user")
    ensure_wrap_key(paths)
    activate_aek(paths, record.id)

    async with _client(app) as client:
        login = await client.post("/api/me/login", json={"key": user_key})
        assert login.status_code == 200, login.text

        session = await client.get("/api/me/session")
        assert session.status_code == 200, session.text
        csrf = session.json()["csrf_token"]
        assert isinstance(csrf, str) and csrf
        client.headers["X-CSRF-Token"] = csrf

        created = await client.post(
            "/api/me/accounts",
            json={
                "name": "Sweep Account",
                "host": "imap.example.com",
                "port": 993,
                "user": "sweep@example.com",
                "password": "swept-credential-value",
                "tls": True,
            },
        )
        assert created.status_code == 201, created.text
        account_id = str(created.json()["account"]["id"])
        profile = await client.get("/api/me")
        shell = await client.get("/user")
        deep_link = await client.get(f"/user/accounts/{account_id}")
        settings_shell = await client.get("/user/settings")

    swept = [
        ("POST /api/me/login", login, 200),
        ("GET /api/me/session", session, 200),
        ("POST /api/me/accounts", created, 201),
        ("GET /api/me", profile, 200),
        ("GET /user", shell, 200),
        ("GET /user/accounts/{account_id}", deep_link, 200),
        ("GET /user/settings", settings_shell, 200),
    ]
    for label, response, expected in swept:
        assert response.status_code == expected, f"{label}: {response.text}"
        _assert_no_secret_material(label, response.text)

    # Anchors: the real metadata payloads reached the serializers, and the
    # create response carried NO one-time AEK now that setup activated it.
    payload = created.json()
    assert "account_encryption_key" not in payload
    assert payload["account"]["name"] == "Sweep Account"
    profile_payload = profile.json()
    assert profile_payload["account_count"] == 1
    assert [account["id"] for account in profile_payload["accounts"]] == [account_id]


def test_leak_sweep_detectors_catch_every_real_secret_artifact(
    admin_record: str, tmp_path: Path
) -> None:
    """Every banned artifact — as REAL generated material — trips the sweep.

    The two HTTP sweeps above prove no route EMITS these shapes; this test
    proves the detectors actually RECOGNIZE them (a mistuned regex would
    make both sweeps vacuous). Each artifact is produced by the production
    crypto/store code — the admin scrypt record, a user's stored login-key
    record and plaintext key, the on-disk wrap key, the persisted wrapped-
    AEK blob, and the materialized session ``.key`` content — and feeding
    it to the sweep assertion must raise, naming the artifact.
    """
    paths = build_paths(tmp_path)
    ensure_wrap_key(paths)
    record, user_key = create_user(paths, "detector-probe")
    aek_hex = activate_aek(paths, record.id)
    stored = get_user(paths, record.id)
    assert stored is not None and stored.aek is not None
    keyfile = materialize_key_file(paths, record.id, aek_hex)
    artifacts = {
        "admin-key hash record": admin_record,
        "login-key hash record": stored.login_key_hash,
        "login key material": user_key,
        "wrap-key value": paths.wrap_key_path().read_text(),
        "wrapped AEK blob": stored.aek.blob,
        "keyfile material": keyfile.read_text(),
    }
    cleanup_key_file(paths, record.id)

    for artifact_label, artifact in artifacts.items():
        with pytest.raises(AssertionError) as exc_info:
            _assert_no_secret_material(artifact_label, f"body {artifact} body")
        # The helper's failing assert names the artifact (pytest appends its
        # usual rewrite detail around the custom message).
        assert artifact_label in str(exc_info.value)


# --- 4. odd auth schemes rejected -----------------------------------------------


async def test_odd_authorization_shapes_fail_closed_without_fallback(
    app: FastAPI,
) -> None:
    """Non-Bearer, tokenless, padded and duplicate headers never authenticate.

    ``_presented_user_key``/``require_admin`` precedence: ``Authorization``
    decides whenever present, so ``Basic`` fails closed rather than falling
    through to a second credential — two presented credentials can never be
    mixed into a negotiation a hostile client could steer.
    """
    async with _client(app) as client:
        basic = await client.get(
            "/api/admin/health", headers={"Authorization": "Basic dXNlcjpwdw=="}
        )
        tokenless = await client.get(
            "/api/admin/health", headers={"Authorization": "Bearer"}
        )
        padded = await client.get(
            "/api/admin/health", headers={"Authorization": "Bearer  key with spaces"}
        )
        duplicate = await client.get(
            "/api/admin/health",
            headers=[("authorization", "Bearer a"), ("authorization", "Bearer b")],
        )

    for response in (basic, tokenless, padded, duplicate):
        assert response.status_code == 401
        assert response.json() == {"error": "unauthorized"}


# --- 5. DATA_DIR file modes -----------------------------------------------------


def test_data_dir_secret_files_are_0600_and_dirs_0700(tmp_path: Path) -> None:
    """Every secret-bearing file is ``0600``; every private dir ``0700``."""
    paths = build_paths(tmp_path)
    ensure_admin_key(paths)
    ensure_wrap_key(paths)
    record, _key = create_user(paths, "mode-probe")

    def _mode(path: Path) -> int:
        return path.stat().st_mode & 0o777

    assert _mode(paths.admin_key_hash_path()) == SECRET_FILE_MODE
    assert _mode(paths.wrap_key_path()) == SECRET_FILE_MODE
    assert _mode(paths.user_record_path(record.id)) == SECRET_FILE_MODE
    assert _mode(paths.config_dir()) == PRIVATE_DIR_MODE
    assert _mode(paths.users_dir()) == PRIVATE_DIR_MODE
    assert _mode(paths.user_dir(record.id)) == PRIVATE_DIR_MODE


# --- 6. rate limits per surface -------------------------------------------------


async def test_ten_rapid_user_login_failures_lock_out_with_429(app: FastAPI) -> None:
    """The M06-T02 acceptance case: 10 rapid failures yield 429.

    The user-login limiter locks at :data:`USER_LOGIN_FAILURE_LIMIT` (8), so
    attempts 9 and 10 are refused with ``Retry-After`` — before any scrypt
    work (the gate precedes verification).
    """
    async with _client(app) as client:
        responses = [
            await client.post("/api/me/login", json={"key": "usr_wrong"})
            for _ in range(10)
        ]

    assert [r.status_code for r in responses[:USER_LOGIN_FAILURE_LIMIT]] == [
        401
    ] * USER_LOGIN_FAILURE_LIMIT
    assert [r.status_code for r in responses[USER_LOGIN_FAILURE_LIMIT:]] == [429, 429]
    locked = responses[-1]
    assert locked.json() == {"error": "rate_limited"}
    assert int(locked.headers["Retry-After"]) >= 1


async def test_user_login_lockout_never_locks_the_admin_surface(
    app: FastAPI, admin_key: str
) -> None:
    """Two SEPARATE limiter instances: one surface's lockout is not the other's.

    The limiter reserves on the way in and only counts a failure once it has
    been recorded, so ``USER_LOGIN_FAILURE_LIMIT`` failures are admitted (401)
    and the NEXT attempt is refused (429) — hence the ``+ 1``. That 8 failures
    already exceed the admin limit (5): if both surfaces shared one counter,
    the admin check below would be ``429``.
    """
    async with _client(app) as client:
        for _ in range(USER_LOGIN_FAILURE_LIMIT + 1):
            locked = await client.post("/api/me/login", json={"key": "usr_wrong"})
        assert locked.status_code == 429  # the user surface is locked out

        admin_ok = await client.get(
            "/api/admin/health", headers={"Authorization": f"Bearer {admin_key}"}
        )
        assert admin_ok.status_code == 200  # the admin surface is untouched


async def test_successful_user_login_releases_its_rate_limit_slot(
    tmp_path: Path,
) -> None:
    """A correct key hands its reserved slot back — only failures consume budget.

    With the limit shrunk to 3 and a clock we control: two failures, a
    success (releases its slot), then ONE more failure exhausts the budget
    (the three failed attempts), and the next attempt — even the correct
    key — is refused during the cooldown.
    """
    paths = build_paths(tmp_path)
    _record, key = create_user(paths, "rate-probe")
    app = create_app(Settings(data_dir=tmp_path))
    clock = FakeClock()
    app.state.user_login_rate_limiter = AdminRateLimiter(limit=3, clock=clock)

    async with _client(app) as client:
        for _ in range(2):
            failed = await client.post("/api/me/login", json={"key": "usr_wrong"})
            assert failed.status_code == 401
        ok = await client.post("/api/me/login", json={"key": key})
        assert ok.status_code == 200  # success: slot released
        assert ok.json()["status"] == "ok"
        assert "imapgw_user" in ok.headers["set-cookie"]
        third = await client.post("/api/me/login", json={"key": "usr_wrong"})
        assert third.status_code == 401  # the 3rd counted failure
        # Cooldown reached: even the correct key is refused now.
        blocked = await client.post("/api/me/login", json={"key": key})
        assert blocked.status_code == 429
        clock.advance(601)  # the failures age out of the 10-minute window
        healed = await client.post("/api/me/login", json={"key": key})
        assert healed.status_code == 200  # self-healing lockout


async def test_mcp_surface_has_its_own_rate_limit(tmp_path: Path) -> None:
    """``/mcp`` locks out after ITS own limit — a third independent counter."""
    paths = build_paths(tmp_path)
    save_admin_key_hash(paths, hash_secret(generate_admin_key()))
    gateway_app = create_app(Settings(data_dir=tmp_path))

    async with _client(gateway_app) as client:
        statuses = [
            (
                await client.post(
                    "/mcp",
                    headers={"Authorization": "Bearer usr_wrong"},
                    json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                )
            ).status_code
            for _ in range(FAILURE_LIMIT + 2)
        ]

    assert statuses[:FAILURE_LIMIT] == [401] * FAILURE_LIMIT
    assert statuses[FAILURE_LIMIT:] == [429, 429]


# --- 7. security headers --------------------------------------------------------


async def test_security_headers_present_on_every_response(app: FastAPI) -> None:
    """``nosniff`` / frame denial / no-referrer / CSP on success AND error paths."""
    async with _client(app) as client:
        ok = await client.get("/healthz")
        unauthorized = await client.get("/api/admin/health")
        not_found = await client.get("/definitely-missing")
        user_shell = await client.get("/user")
        admin_shell = await client.get("/admin")

    for response in (ok, unauthorized, not_found, user_shell, admin_shell):
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["Referrer-Policy"] == "no-referrer"
        assert response.headers["Content-Security-Policy"] == (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'"
        )
    # The admin no-store pin survives the outer security-headers layer.
    assert unauthorized.headers["Cache-Control"] == "no-store"


# --- 8. tool-host env allowlist -------------------------------------------------


def test_tool_host_child_env_is_exactly_the_documented_allowlist(
    tmp_path: Path,
) -> None:
    """The Node child env is EXACTLY six variables — no secrets, no ``DATA_DIR``.

    M06-T02's confirm-only rework of the M05-T02 allowlist: the regression
    pins the exact key set so a future "just pass one more var" edit fails
    loudly here first.
    """
    paths = build_paths(tmp_path)
    record, key = create_user(paths, "env-probe")
    assert USER_KEY_RE.fullmatch(key)
    host = NodeToolHost(
        settings=Settings(data_dir=tmp_path),
        paths=paths,
        user_id=record.id,
        session_id="s" * 32,
        registry=SessionRegistry(paths),
    )

    env = host._child_env()

    assert set(env) == {
        "HOME",
        "IMAP_DOWNLOAD_DIR",
        "IMAP_UPLOAD_TTL_MS",
        "IMAP_MAX_UPLOAD_SIZE",
        "PATH",
        "LANG",
    }
    # No secret material or gateway-internal paths reach the child.
    assert "DATA_DIR" not in env
    assert env["HOME"] == str(paths.user_dir(record.id).resolve())
    assert record.id in env["HOME"]
    assert key not in str(env)
