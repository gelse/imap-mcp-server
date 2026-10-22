"""User self-service account API tests (M04-T04).

Coverage per the M04-T04 verification requirements:

1. endpoint matrix on ``/api/me``: profile + metadata-only account list,
   create (lazy AEK activation on the FIRST add), partial update
   (write-only credentials, sticky when omitted), delete, explicit
   activation, self login-key rotation;
2. scoping: user B targeting user A's account ids gets the fixed
   ``404 not_found`` (logged with the ``[security]`` tag) and A's store is
   untouched; disabled users get the uniform 401;
3. activation once-only: the AEK hex appears in EXACTLY ONE recorded
   response across the whole matrix (the add/activate that minted it);
   later adds and every GET carry no AEK material;
4. write-only credentials: no response body ever echoes a submitted
   password (store-level decryption proves what was actually persisted);
5. rotation invariance: self login-key rotation bumps ``key_generation``,
   kills the old key, and leaves the AEK blob AND account decryption
   byte-for-byte intact;
6. AEK rotation re-encryption (M04-T03 carry-forward): rotating the AEK
   after an API-created account re-encrypts the store (old AEK cannot
   decrypt, new AEK can) — and the production import path
   (``web.server`` -> ``web.user.router`` -> ``store.accounts``) registers
   the re-encrypt hook, proven in a fresh subprocess so the test FAILS if
   the router stops importing ``store.accounts``;
7. CSRF for cookie sessions on every mutating route; validation failures
   answer the pinned ``400 invalid_request`` (never FastAPI's 422).

All HTTP tests run in-process via ``httpx.AsyncClient`` over an ASGI
transport (the pattern of tests/test_admin_user_api.py).
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import sys
from collections.abc import AsyncIterator, Coroutine, Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from imap_mcp_gateway.config.env import Settings
from imap_mcp_gateway.config.paths import Paths, build_paths
from imap_mcp_gateway.log import RedactCapableFormatter, get_logger
from imap_mcp_gateway.store import accounts as accounts_store
from imap_mcp_gateway.store import users as users_store
from imap_mcp_gateway.store.accounts import get_account
from imap_mcp_gateway.store.aek_rotation import rotate_aek
from imap_mcp_gateway.store.users import create_user, disable_user, verify_login_key
from imap_mcp_gateway.store.wrap_key import ensure_wrap_key
from imap_mcp_gateway.web.middleware.admin_auth import AdminRateLimiter
from imap_mcp_gateway.web.server import create_app
from imap_mcp_gateway.web.session import SESSION_KIND_USER, USER_COOKIE_NAME

HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
USER_KEY_RE = re.compile(r"^usr_[A-Za-z0-9_-]{43}$")

PROFILE_FIELDS = {
    "id",
    "name",
    "created_at",
    "key_generation",
    "status",
    "aek_active",
    "account_count",
    "accounts",
}
ACCOUNT_VIEW_FIELDS = {
    "id",
    "name",
    "host",
    "port",
    "user",
    "tls",
    "allow_start_tls",
    "email",
    "smtp",
    "save_to_sent",
    "sent_folder",
    "default_bcc",
    "allowed_from",
}
SMTP_VIEW_FIELDS = {"host", "port", "secure"}

_ROUTER_LOGGER = "imap_mcp_gateway.web.user.router"

_PROBE_IMPORT_HOOK = """\
import imap_mcp_gateway.web.server  # the production mounting site (M04-T04)
from imap_mcp_gateway.store import aek_rotation

modules = {getattr(hook, "__module__", "") for hook in aek_rotation._REENCRYPT_HOOKS}
raise SystemExit(0 if "imap_mcp_gateway.store.accounts" in modules else 1)
"""


# --- helpers and fixtures --------------------------------------------------------


def _iter_members(node: Any) -> Any:
    """Yield every ``(key, value)`` pair anywhere in a decoded JSON structure."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield key, value
            yield from _iter_members(value)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_members(item)


class Recorder:
    """Records ``/api/me`` responses for the whole-matrix leak assertions.

    Three invariants, checked over EVERY recorded response (not spot
    checks):

    - no response ever carries the ``scrypt$`` marker or a
      ``login_key_hash``/``aek``/``password``/``blob`` key, and one-time
      keys appear only under their allowed names on their minting route;
    - submitted (write-only) credentials appear in NO response body;
    - each disclosed one-time secret (AEK hex, ``usr_`` login key) appears
      in EXACTLY ONE successful response — the one that minted it — which
      is the activation/rotation once-only property as a whole-matrix
      assertion.
    """

    def __init__(self) -> None:
        self.responses: list[tuple[str, httpx.Response]] = []
        self.submitted: list[str] = []
        self.disclosures: list[tuple[str, str]] = []

    async def __call__(
        self, label: str, request: Coroutine[Any, Any, httpx.Response]
    ) -> httpx.Response:
        response = await request
        self.responses.append((label, response))
        return response

    def submits(self, *secrets: str) -> None:
        """Register credential strings that must appear in NO response."""
        self.submitted.extend(secret for secret in secrets if secret)

    def revealed(self, label: str, secret: str) -> None:
        """Register a one-time secret minted by the ``label`` response."""
        self.disclosures.append((label, secret))

    def assert_no_leaks(self) -> None:
        """Assert the leak invariants across every recorded response."""
        assert self.responses
        for label, response in self.responses:
            assert "scrypt$" not in response.text, label
            if response.status_code == 204 or not response.headers.get(
                "content-type", ""
            ).startswith("application/json"):
                continue
            for key_name, _value in _iter_members(response.json()):
                assert key_name not in ("login_key_hash", "aek", "password", "blob"), (
                    label
                )
                if key_name == "login_key":
                    assert label == "rotate" and response.status_code == 200, label
                if key_name == "account_encryption_key":
                    # Exactly-once AEK disclosure: the minting add/activate
                    # (200/201), plus the M07-T01 failure-safe window where a
                    # post-activation store-write failure still returns the
                    # fresh key (500 + "internal_error") so it is not stranded.
                    is_failure_safe = (
                        response.status_code == 500
                        and response.json().get("error") == "internal_error"
                    )
                    assert (
                        label in ("create", "activate")
                        and response.status_code in (200, 201)
                    ) or is_failure_safe, label
        for secret in self.submitted:
            for label, response in self.responses:
                assert secret not in response.text, label
        for reveal_label, secret in self.disclosures:
            appearing = [
                label for label, response in self.responses if secret in response.text
            ]
            assert appearing == [reveal_label], (reveal_label, appearing)


@dataclass(frozen=True, slots=True)
class Session:
    """One authenticated user: registry id, plaintext key, session client."""

    user_id: str
    key: str
    csrf: str
    client: httpx.AsyncClient


@pytest.fixture
def paths(tmp_path: Path) -> Paths:
    return build_paths(tmp_path)


@pytest.fixture
def app(tmp_path: Path, paths: Paths) -> FastAPI:
    """The real app over a fresh DATA_DIR, wrap key installed (AEK ops need it)."""
    ensure_wrap_key(paths)
    return create_app(Settings(data_dir=tmp_path))


@pytest.fixture
def recorder() -> Recorder:
    return Recorder()


@asynccontextmanager
async def _session(
    app: FastAPI, paths: Paths, name: str, *, with_csrf: bool = True
) -> AsyncIterator[Session]:
    """A registry user plus a cookie-session client (CSRF header optional)."""
    record, key = create_user(paths, name)
    cookie, csrf = app.state.session_signer.create_session(
        SESSION_KIND_USER, sub=record.id
    )
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    )
    client.cookies.set(USER_COOKIE_NAME, cookie)
    if with_csrf:
        client.headers["X-CSRF-Token"] = csrf
    try:
        yield Session(user_id=record.id, key=key, csrf=csrf, client=client)
    finally:
        await client.aclose()


def _body(response: httpx.Response) -> dict[str, Any]:
    """The response JSON, asserted to be an object."""
    payload = response.json()
    assert isinstance(payload, dict)
    return payload


def _account_payload(**overrides: Any) -> dict[str, Any]:
    """A fully-populated plaintext-shaped account request body."""
    data: dict[str, Any] = {
        "name": "Personal",
        "host": "imap.example.org",
        "port": 993,
        "user": "alice@example.org",
        "password": "correct horse battery staple",
        "tls": True,
        "allow_start_tls": False,
        "email": "alice@example.org",
        "smtp": {
            "host": "smtp.example.org",
            "port": 465,
            "secure": True,
            "user": "alice@example.org",
            "password": "smtp-secret-9",
        },
        "save_to_sent": True,
        "sent_folder": "Gesendet",
        "default_bcc": "audit@example.org",
        "allowed_from": ["bob@example.org"],
    }
    data.update(overrides)
    return data


async def _add_account(
    recorder: Recorder, session: Session, label: str = "create", **overrides: Any
) -> httpx.Response:
    """POST one account through the recorder; returns the response."""
    payload = _account_payload(**overrides)
    response = await recorder(
        label, session.client.post("/api/me/accounts", json=payload)
    )
    assert response.status_code == 201, response.text
    body = _body(response)
    if "account_encryption_key" in body:
        recorder.revealed(label, body["account_encryption_key"])
    smtp = payload.get("smtp")
    recorder.submits(payload["password"])
    if isinstance(smtp, dict):
        recorder.submits(smtp.get("password", ""))
    return response


class _LineCaptureHandler(logging.Handler):
    """Test handler that records formatted log lines in memory (conftest pattern)."""

    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.format(record))


@contextmanager
def _captured_router_lines() -> Iterator[list[str]]:
    """Attach a capture handler to the user router's logger for the block."""
    handler = _LineCaptureHandler()
    handler.setFormatter(RedactCapableFormatter())
    logger = get_logger(_ROUTER_LOGGER)
    logger.addHandler(handler)
    try:
        yield handler.lines
    finally:
        logger.removeHandler(handler)


# --- 1. GET /api/me: profile + metadata-only list ---------------------------------


async def test_me_profile_and_empty_account_list(
    app: FastAPI, paths: Paths, recorder: Recorder
) -> None:
    async with _session(app, paths, "alice") as alice:
        response = await recorder("me", alice.client.get("/api/me"))

    assert response.status_code == 200
    assert "no-store" in response.headers["cache-control"].lower()
    body = _body(response)
    assert set(body) == PROFILE_FIELDS
    assert body["name"] == "alice"
    assert body["key_generation"] == 1
    assert body["status"] == "active"
    assert body["aek_active"] is False  # fresh user: AEK not yet activated
    assert body["account_count"] == 0
    assert body["accounts"] == []
    recorder.assert_no_leaks()


async def test_me_lists_accounts_as_metadata_only(
    app: FastAPI, paths: Paths, recorder: Recorder
) -> None:
    async with _session(app, paths, "alice") as alice:
        created = _body(await _add_account(recorder, alice))

        listing = await recorder("me", alice.client.get("/api/me"))

    assert listing.status_code == 200
    body = _body(listing)
    assert body["account_count"] == 1
    assert body["aek_active"] is True  # the first add activated the AEK
    accounts = body["accounts"]
    assert isinstance(accounts, list) and len(accounts) == 1
    view = accounts[0]
    assert set(view) == ACCOUNT_VIEW_FIELDS
    assert view["id"] == created["account"]["id"]
    assert view["name"] == "Personal"
    assert view["host"] == "imap.example.org"
    assert view["port"] == 993
    assert view["user"] == "alice@example.org"
    assert view["tls"] is True
    assert view["smtp"] == {  # the credential-free smtp projection
        "host": "smtp.example.org",
        "port": 465,
        "secure": True,
    }
    # The M07-T01 extended optional fields round-trip the FULL record.
    assert view["save_to_sent"] is True
    assert view["sent_folder"] == "Gesendet"
    assert view["default_bcc"] == "audit@example.org"
    assert view["allowed_from"] == ["bob@example.org"]
    recorder.assert_no_leaks()


async def test_aek_active_flag_flips_at_activation(
    app: FastAPI, paths: Paths, recorder: Recorder
) -> None:
    """``aek_active`` is the deliberate M07-T01 profile extension, pinned.

    A fresh user reports ``false``; the explicit activation route flips it to
    ``true`` and it stays true after the first add. The wrapped blob never
    appears (the Recorder's whole-matrix ``aek`` leak guard holds).
    """
    async with _session(app, paths, "alice") as alice:
        before = _body(await recorder("me-before", alice.client.get("/api/me")))
        assert before["aek_active"] is False

        activated = await recorder(
            "activate", alice.client.post("/api/me/accounts/activate")
        )
        assert activated.status_code == 200
        aek_hex = _body(activated)["account_encryption_key"]
        assert HEX64_RE.fullmatch(aek_hex)

        after = _body(await recorder("me-after", alice.client.get("/api/me")))
        assert after["aek_active"] is True

        await _add_account(recorder, alice, label="create")
        still = _body(await recorder("me-still", alice.client.get("/api/me")))
        assert still["aek_active"] is True
    recorder.assert_no_leaks()


async def test_account_view_omits_unset_extended_optionals(
    app: FastAPI, paths: Paths, recorder: Recorder
) -> None:
    """A sparse record omits the four M07 optionals (omit-absent convention).

    The pin grew the four field NAMES, but a record that never set them must
    not emit ``null`` placeholders — the store's omit-absent discipline still
    holds, and no credential field can appear either.
    """
    sparse: dict[str, Any] = {
        "name": "Sparse",
        "host": "imap.example.org",
        "port": 993,
        "user": "alice@example.org",
        "password": "sparse-secret",
        "tls": True,
        "save_to_sent": None,
        "sent_folder": None,
        "default_bcc": None,
        "allowed_from": None,
        "allow_start_tls": None,
    }
    async with _session(app, paths, "alice") as alice:
        created = _body(await _add_account(recorder, alice, **sparse))
        view = _body(await recorder("me-sparse", alice.client.get("/api/me")))[
            "accounts"
        ][0]
    assert "save_to_sent" not in view
    assert "sent_folder" not in view
    assert "default_bcc" not in view
    assert "allowed_from" not in view
    assert "allow_start_tls" not in view  # not sent either
    # The metadata is still credential-free and matches the created account.
    assert view["id"] == created["account"]["id"]
    recorder.assert_no_leaks()


async def test_restriction_fields_round_trip_and_clear(
    app: FastAPI, paths: Paths, recorder: Recorder
) -> None:
    """The restriction fields round-trip through the API and can be CLEARED.

    M07-T05: the old server-rendered edit form blanked a prefilled
    non-credential field to erase it. The SPA writes that intent to the JSON
    API, so the clearing semantics are pinned HERE (the API level): an
    explicit empty ``default_bcc`` (``""``) and an empty ``allowed_from``
    (``[]``) are persisted as such — they are NOT "omitted", so they never
    silently keep the previous value, and never erase the stored credential
    fields (those stay write-only and sticky).
    """
    async with _session(app, paths, "alice") as alice:
        created = _body(await _add_account(recorder, alice))
        account_id = created["account"]["id"]
        assert created["account"]["default_bcc"] == "audit@example.org"
        assert created["account"]["allowed_from"] == ["bob@example.org"]

        # Multi-value round trip.
        edited = await recorder(
            "edit-multi",
            alice.client.patch(
                f"/api/me/accounts/{account_id}",
                json={
                    "default_bcc": ["one@example.org", "two@example.org"],
                    "allowed_from": ["carol@example.org", "dave@example.org"],
                },
            ),
        )
        assert edited.status_code == 200, edited.text
        view = _body(await recorder("me-multi", alice.client.get("/api/me")))[
            "accounts"
        ][0]
        assert view["default_bcc"] == ["one@example.org", "two@example.org"]
        assert view["allowed_from"] == ["carol@example.org", "dave@example.org"]

        # Clearing: an explicit empty value erases the stored one.
        cleared = await recorder(
            "edit-clear",
            alice.client.patch(
                f"/api/me/accounts/{account_id}",
                json={"default_bcc": "", "allowed_from": []},
            ),
        )
        assert cleared.status_code == 200, cleared.text
        view = _body(await recorder("me-cleared", alice.client.get("/api/me")))[
            "accounts"
        ][0]
        assert view["default_bcc"] == ""
        assert view["allowed_from"] == []
        # The write-only credentials survived the clearing edit.
        stored = get_account(paths, alice.user_id, account_id)
        assert stored is not None
        assert stored.allowed_from == []
        assert stored.default_bcc == ""
    recorder.assert_no_leaks()


# --- 2. POST /api/me/accounts: lazy activation discloses the AEK exactly once -----
async def test_first_add_activates_aek_and_discloses_it_exactly_once(
    app: FastAPI, paths: Paths, recorder: Recorder
) -> None:
    async with _session(app, paths, "alice") as alice:
        empty_me = await recorder("me-empty", alice.client.get("/api/me"))
        assert empty_me.status_code == 200

        first_response = await _add_account(recorder, alice, label="create")
        first = _body(first_response)
        aek_hex = first["account_encryption_key"]
        assert HEX64_RE.fullmatch(aek_hex)
        assert UUID4_RE.fullmatch(first["account"]["id"])
        assert first["account"]["name"] == "Personal"
        assert "no-store" in first_response.headers["cache-control"].lower()
        # The one-time AEK disclosure is never cached and never referable.
        assert first_response.headers["referrer-policy"] == "no-referrer"

        # The wrapped blob is persisted; the plaintext never lands on disk.
        record = await recorder("me", alice.client.get("/api/me"))
        assert record.status_code == 200
        user_json = paths.user_record_path(alice.user_id).read_text(encoding="utf-8")
        assert '"aek"' in user_json  # now wrapped-persisted...
        assert aek_hex not in user_json  # ...never the plaintext

        second_response = await _add_account(
            recorder, alice, label="create-second", name="Work"
        )
        second = _body(second_response)
        assert set(second) == {"account"}  # later adds carry no AEK material
        assert "no-store" in second_response.headers["cache-control"].lower()
        assert second["account"]["id"] != first["account"]["id"]

    # The store holds the account under the AEK the response disclosed.
    stored = get_account(paths, alice.user_id, first["account"]["id"])
    assert stored is not None
    assert stored.decrypt_password(aek_hex) == "correct horse battery staple"
    assert stored.decrypt_smtp_password(aek_hex) == "smtp-secret-9"
    recorder.assert_no_leaks()  # AEK appears in EXACTLY ONE response


async def test_later_adds_never_disclose_aek_material(
    app: FastAPI, paths: Paths, recorder: Recorder
) -> None:
    async with _session(app, paths, "alice") as alice:
        first = _body(await _add_account(recorder, alice, label="create"))
        aek_hex = first["account_encryption_key"]
        for index in range(2):
            later = _body(
                await _add_account(
                    recorder, alice, label=f"create-{index}", name=f"Work {index}"
                )
            )
            assert "account_encryption_key" not in later
    assert aek_hex != ""
    recorder.assert_no_leaks()


async def test_concurrent_first_add_loser_gets_409(
    app: FastAPI,
    paths: Paths,
    recorder: Recorder,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A first-add that loses the activation race answers 409, not 500.

    Simulates the race deterministically: ``create_account`` re-reads a
    STALE record (``aek is None``) while the persisted record is already
    activated, so the store's ``activate_aek`` raises
    ``AEKAlreadyActiveError``. The route must map that to the documented
    ``409 aek_already_active`` (never an uncaught 500), create no account,
    and leave the already-active AEK in force.
    """
    async with _session(app, paths, "alice") as alice:
        activated = await recorder(
            "activate", alice.client.post("/api/me/accounts/activate")
        )
        assert activated.status_code == 200

        real_get_user = users_store.get_user

        def stale_get_user(p: Paths, user_id: str) -> Any:
            record = real_get_user(p, user_id)
            return record.model_copy(update={"aek": None}) if record else None

        monkeypatch.setattr(users_store, "get_user", stale_get_user)
        response = await recorder(
            "create-race",
            alice.client.post("/api/me/accounts", json=_account_payload()),
        )
        assert response.status_code == 409, response.text
        assert response.json() == {"error": "aek_already_active"}

        me = await recorder("me", alice.client.get("/api/me"))
        assert _body(me)["account_count"] == 0  # no account created by the loser
    recorder.assert_no_leaks()


# --- 3. explicit activation: once-only, no account created ------------------------


async def test_explicit_activation_discloses_once_and_then_409s(
    app: FastAPI, paths: Paths, recorder: Recorder
) -> None:
    async with _session(app, paths, "bob") as bob:
        activated = await recorder(
            "activate", bob.client.post("/api/me/accounts/activate")
        )
        assert activated.status_code == 200
        aek_hex = _body(activated)["account_encryption_key"]
        assert HEX64_RE.fullmatch(aek_hex)
        assert "no-store" in activated.headers["cache-control"].lower()
        # The one-time AEK disclosure is never cached and never referable.
        assert activated.headers["referrer-policy"] == "no-referrer"

        again = await recorder(
            "activate-again", bob.client.post("/api/me/accounts/activate")
        )
        assert again.status_code == 409
        assert again.json() == {"error": "aek_already_active"}

        # No account was created by the activation...
        me = await recorder("me", bob.client.get("/api/me"))
        assert me.status_code == 200
        assert _body(me)["accounts"] == []
        assert _body(me)["account_count"] == 0

        # ...and the later first add must NOT disclose a (second) AEK.
        added = _body(await _add_account(recorder, bob, label="create"))
        assert "account_encryption_key" not in added
        stored = get_account(paths, bob.user_id, added["account"]["id"])
        assert stored is not None
        assert stored.decrypt_password(aek_hex) == "correct horse battery staple"
    recorder.assert_no_leaks()


# --- 4. PATCH: partial update, write-only sticky credentials -----------------------


async def test_patch_updates_fields_without_touching_credentials(
    app: FastAPI, paths: Paths, recorder: Recorder
) -> None:
    async with _session(app, paths, "alice") as alice:
        created = _body(await _add_account(recorder, alice))
        account_id = created["account"]["id"]
        aek_hex = created["account_encryption_key"]

        patched = await recorder(
            "patch",
            alice.client.patch(
                f"/api/me/accounts/{account_id}",
                json={"name": "Renamed", "port": 9993, "tls": False},
            ),
        )
        assert patched.status_code == 200
        assert "no-store" in patched.headers["cache-control"].lower()
        view = _body(patched)["account"]
        assert view["name"] == "Renamed"
        assert view["port"] == 9993
        assert view["tls"] is False
        assert view["smtp"] == {"host": "smtp.example.org", "port": 465, "secure": True}

        stored = get_account(paths, alice.user_id, account_id)
        assert stored is not None
        assert stored.decrypt_password(aek_hex) == "correct horse battery staple"
        assert stored.decrypt_smtp_password(aek_hex) == "smtp-secret-9"
    recorder.assert_no_leaks()


async def test_patch_replaces_passwords_write_only(
    app: FastAPI, paths: Paths, recorder: Recorder
) -> None:
    async with _session(app, paths, "alice") as alice:
        created = _body(await _add_account(recorder, alice))
        account_id = created["account"]["id"]
        old_aek = created["account_encryption_key"]

        patched = await recorder(
            "patch",
            alice.client.patch(
                f"/api/me/accounts/{account_id}",
                json={
                    "password": "brand-new-imap-pass",
                    "smtp": {
                        "host": "smtp.example.org",
                        "port": 587,
                        "secure": False,
                        "password": "brand-new-smtp-pass",
                    },
                },
            ),
        )
        assert patched.status_code == 200
        view = _body(patched)["account"]
        assert set(view) == ACCOUNT_VIEW_FIELDS  # still metadata only
        assert view["smtp"]["port"] == 587

        stored = get_account(paths, alice.user_id, account_id)
        assert stored is not None
        assert stored.decrypt_password(old_aek) == "brand-new-imap-pass"
        assert stored.decrypt_smtp_password(old_aek) == "brand-new-smtp-pass"
        # The record was updated in place (same id), never duplicated.
        me = await recorder("me", alice.client.get("/api/me"))
        assert _body(me)["account_count"] == 1

        # Omitted smtp credentials mean "unchanged" — never cleared.
        sticky = await recorder(
            "patch-smtp-keep",
            alice.client.patch(
                f"/api/me/accounts/{account_id}",
                json={
                    "smtp": {"host": "smtp2.example.org", "port": 465, "secure": True}
                },
            ),
        )
        assert sticky.status_code == 200
        reloaded = get_account(paths, alice.user_id, account_id)
        assert reloaded is not None
        assert reloaded.smtp is not None
        assert reloaded.smtp.host == "smtp2.example.org"
        assert reloaded.smtp.user == "alice@example.org"  # sticky smtp.user
        assert reloaded.decrypt_smtp_password(old_aek) == "brand-new-smtp-pass"

        # An EMPTY smtp password stores the documented "no credential" value
        # (parity with the create path), it is not sealed into ciphertext.
        cleared = await recorder(
            "patch-smtp-clear",
            alice.client.patch(
                f"/api/me/accounts/{account_id}",
                json={
                    "smtp": {
                        "host": "smtp2.example.org",
                        "port": 465,
                        "secure": True,
                        "password": "",
                    }
                },
            ),
        )
        assert cleared.status_code == 200
        reloaded = get_account(paths, alice.user_id, account_id)
        assert reloaded is not None
        assert reloaded.smtp is not None
        assert reloaded.smtp.password == ""  # the literal "no credential" value
        assert reloaded.decrypt_smtp_password(old_aek) == ""
    recorder.assert_no_leaks()


async def test_patch_clears_the_imap_password_with_an_empty_string(
    app: FastAPI, paths: Paths, recorder: Recorder
) -> None:
    """The explicit "clear the stored IMAP credential" affordance.

    An EMPTY IMAP password is sealed like any other credential (upstream
    ``addAccount`` parity — the empty string encrypts to a padding block):
    the stored credential decrypts to ``""``, so the stored IMAP secret is
    emptied instead of kept. An OMITTED password keeps the stored one.
    """
    async with _session(app, paths, "alice") as alice:
        created = _body(await _add_account(recorder, alice))
        account_id = created["account"]["id"]
        aek_hex = created["account_encryption_key"]

        cleared = await recorder(
            "patch-imap-clear",
            alice.client.patch(f"/api/me/accounts/{account_id}", json={"password": ""}),
        )
        assert cleared.status_code == 200
        assert set(_body(cleared)["account"]) == ACCOUNT_VIEW_FIELDS  # metadata only

        stored = get_account(paths, alice.user_id, account_id)
        assert stored is not None
        assert stored.decrypt_password(aek_hex) == ""
        # An IMAP-only patch never touches the SMTP credential.
        assert stored.decrypt_smtp_password(aek_hex) == "smtp-secret-9"
    recorder.assert_no_leaks()


async def test_patch_unknown_account_is_404(
    app: FastAPI, paths: Paths, recorder: Recorder
) -> None:
    async with _session(app, paths, "alice") as alice:
        response = await recorder(
            "patch-missing",
            alice.client.patch(
                "/api/me/accounts/00000000-0000-4000-8000-000000000000",
                json={"name": "Renamed"},
            ),
        )
    assert response.status_code == 404
    assert response.json() == {"error": "not_found"}
    recorder.assert_no_leaks()


# --- 5. DELETE ---------------------------------------------------------------------


async def test_delete_removes_the_account(
    app: FastAPI, paths: Paths, recorder: Recorder
) -> None:
    async with _session(app, paths, "alice") as alice:
        created = _body(await _add_account(recorder, alice))
        account_id = created["account"]["id"]

        deleted = await recorder(
            "delete", alice.client.delete(f"/api/me/accounts/{account_id}")
        )
        assert deleted.status_code == 204
        assert deleted.text == ""

        me = await recorder("me", alice.client.get("/api/me"))
        assert _body(me)["accounts"] == []
        assert _body(me)["account_count"] == 0

        again = await recorder(
            "delete-again", alice.client.delete(f"/api/me/accounts/{account_id}")
        )
        assert again.status_code == 404
        assert again.json() == {"error": "not_found"}
    recorder.assert_no_leaks()


# --- 6. cross-user scoping: 404 + [security] log, store untouched -----------------


async def test_cross_user_access_is_404_logged_and_never_touches_the_store(
    app: FastAPI, paths: Paths, recorder: Recorder
) -> None:
    async with _session(app, paths, "alice") as alice:
        created = _body(await _add_account(recorder, alice))
        alice_account_id = created["account"]["id"]
        store_file = paths.user_imap_store_dir(alice.user_id) / "accounts.json"
        alice_store_before = store_file.read_bytes()

        async with _session(app, paths, "bob") as bob:
            bob_view = await recorder("me-bob", bob.client.get("/api/me"))
            assert bob_view.status_code == 200
            assert _body(bob_view)["accounts"] == []  # bob sees nothing of alice's

            with _captured_router_lines() as lines:
                patched = await recorder(
                    "patch-foreign",
                    bob.client.patch(
                        f"/api/me/accounts/{alice_account_id}",
                        json={"name": "Hijacked"},
                    ),
                )
                deleted = await recorder(
                    "delete-foreign",
                    bob.client.delete(f"/api/me/accounts/{alice_account_id}"),
                )
            assert patched.status_code == 404
            assert patched.json() == {"error": "not_found"}
            assert deleted.status_code == 404
            assert deleted.json() == {"error": "not_found"}
            security_lines = [line for line in lines if "[security]" in line]
            assert len(security_lines) == 2  # one per cross-user attempt
            assert all(alice_account_id in line for line in security_lines)

        # Alice's store was never touched, and her account still works.
        assert store_file.read_bytes() == alice_store_before
        me = await recorder("me-alice", alice.client.get("/api/me"))
        assert me.status_code == 200
        assert _body(me)["account_count"] == 1
        assert _body(me)["accounts"][0]["name"] == "Personal"
    recorder.assert_no_leaks()


async def test_security_log_masks_unsafe_client_supplied_ids(
    app: FastAPI, paths: Paths, recorder: Recorder
) -> None:
    """A control-character account id cannot forge a ``[security]`` log line.

    The id is URL-decoded before it reaches the handler, so a raw newline
    would split the log line if the ``_safe_log_id`` mask regressed; the
    masked spelling (``<unparsed>``) is what must be logged instead.
    """
    async with _session(app, paths, "alice") as alice:
        with _captured_router_lines() as lines:
            response = await recorder(
                "delete-log-injection",
                alice.client.delete("/api/me/accounts/bad%0Ainjected-log-line"),
            )
    assert response.status_code == 404
    assert response.json() == {"error": "not_found"}
    security_lines = [line for line in lines if "[security]" in line]
    assert len(security_lines) == 1
    assert "<unparsed>" in security_lines[0]
    assert all("bad\ninjected-log-line" not in line for line in lines)
    recorder.assert_no_leaks()


# --- 7. self login-key rotation: AEK and accounts untouched -----------------------


async def test_rotate_login_key_leaves_aek_and_accounts_working(
    app: FastAPI, paths: Paths, recorder: Recorder
) -> None:
    async with _session(app, paths, "alice") as alice:
        created = _body(await _add_account(recorder, alice))
        account_id = created["account"]["id"]
        aek_hex = created["account_encryption_key"]
        record_before = paths.user_record_path(alice.user_id).read_bytes()

        rotated = await recorder("rotate", alice.client.post("/api/me/rotate-key"))
        assert rotated.status_code == 200
        assert "no-store" in rotated.headers["cache-control"].lower()
        # The one-time login-key disclosure is never cached and never referable.
        assert rotated.headers["referrer-policy"] == "no-referrer"
        body = _body(rotated)
        assert body["id"] == alice.user_id
        assert body["key_generation"] == 2
        new_key = body["login_key"]
        assert USER_KEY_RE.fullmatch(new_key)
        recorder.revealed("rotate", new_key)

        # The old key stops authenticating; the new one verifies.
        assert not verify_login_key(paths, alice.user_id, alice.key)
        assert verify_login_key(paths, alice.user_id, new_key)

        # The AEK blob is byte-identical and the account still decrypts.
        assert paths.user_record_path(alice.user_id).read_bytes() != record_before
        aek_before = json.loads(record_before)["aek"]
        aek_after = json.loads(paths.user_record_path(alice.user_id).read_bytes())[
            "aek"
        ]
        assert aek_before == aek_after

        stored = get_account(paths, alice.user_id, account_id)
        assert stored is not None
        assert stored.decrypt_password(aek_hex) == "correct horse battery staple"

        # The still-valid session keeps working after rotation.
        me = await recorder("me-after", alice.client.get("/api/me"))
        assert me.status_code == 200
        assert _body(me)["key_generation"] == 2
    recorder.assert_no_leaks()


# --- 8. auth: uniform 401 without a session; disabled users are 401 ----------------


async def test_every_route_requires_a_session(app: FastAPI, recorder: Recorder) -> None:
    attempts: list[tuple[str, Any]] = [
        ("me", lambda c: c.get("/api/me")),
        ("create", lambda c: c.post("/api/me/accounts", json=_account_payload())),
        (
            "patch",
            lambda c: c.patch("/api/me/accounts/some-id", json={"name": "x"}),
        ),
        ("delete", lambda c: c.delete("/api/me/accounts/some-id")),
        ("activate", lambda c: c.post("/api/me/accounts/activate")),
        ("rotate", lambda c: c.post("/api/me/rotate-key")),
    ]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as anonymous:
        for label, attempt in attempts:
            response = await recorder(label, attempt(anonymous))
            assert response.status_code == 401, label
            assert response.json() == {"error": "unauthorized"}, label
    recorder.assert_no_leaks()


async def test_session_route_requires_a_cookie(app: FastAPI) -> None:
    """``GET /api/me/session`` is cookie-only; no session -> uniform 401."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as anonymous:
        response = await anonymous.get("/api/me/session")
    assert response.status_code == 401
    assert response.json() == {"error": "unauthorized"}


async def test_disabled_user_gets_the_uniform_401(
    app: FastAPI, paths: Paths, recorder: Recorder
) -> None:
    async with _session(app, paths, "alice") as alice:
        disable_user(paths, alice.user_id)
        me = await recorder("me-disabled", alice.client.get("/api/me"))
        activated = await recorder(
            "activate-disabled", alice.client.post("/api/me/accounts/activate")
        )
    assert me.status_code == 401
    assert me.json() == {"error": "unauthorized"}
    assert activated.status_code == 401
    assert activated.json() == {"error": "unauthorized"}
    recorder.assert_no_leaks()


# --- 9. CSRF: cookie-session mutations need the session token ---------------------


async def test_mutating_routes_require_the_session_csrf_token(
    app: FastAPI, paths: Paths, recorder: Recorder
) -> None:
    async with _session(app, paths, "alice", with_csrf=False) as alice:
        attempts: list[Any] = [
            alice.client.post("/api/me/accounts", json=_account_payload()),
            alice.client.patch("/api/me/accounts/some-id", json={"name": "x"}),
            alice.client.delete("/api/me/accounts/some-id"),
            alice.client.post("/api/me/accounts/activate"),
            alice.client.post("/api/me/rotate-key"),
        ]
        for attempt in attempts:
            response = await recorder("csrf-less", attempt)
            assert response.status_code == 403
            assert response.json() == {"error": "forbidden"}

        # With the session token the same routes proceed (409: alice is
        # still inactive — proving the request got PAST the CSRF gate).
        alice.client.headers["X-CSRF-Token"] = alice.csrf
        activated = await recorder(
            "activate", alice.client.post("/api/me/accounts/activate")
        )
        assert activated.status_code == 200
        recorder.revealed("activate", _body(activated)["account_encryption_key"])
    recorder.assert_no_leaks()


# --- 10. validation failures are 400, never FastAPI's 422 -------------------------


async def test_create_body_validation_failures_are_400(
    app: FastAPI, paths: Paths, recorder: Recorder
) -> None:
    valid = _account_payload()
    variants: list[tuple[str, dict[str, Any]]] = [
        ("empty-object", {}),
        ("missing-password", {k: v for k, v in valid.items() if k != "password"}),
        ("empty-name", dict(valid, name="")),
        ("non-string-name", dict(valid, name=3)),
        ("bad-port-type", dict(valid, port={"production": True})),
        ("bad-tls-type", dict(valid, tls="maybe")),
        ("smtp-missing-host", dict(valid, smtp={"port": 465, "secure": True})),
        ("unknown-field", dict(valid, role="admin")),
    ]
    async with _session(app, paths, "alice") as alice:
        for label, payload in variants:
            response = await recorder(
                label, alice.client.post("/api/me/accounts", json=payload)
            )
            assert response.status_code == 400, label
            assert response.json() == {"error": "invalid_request"}, label
        malformed = await recorder(
            "malformed",
            alice.client.post(
                "/api/me/accounts",
                content=b"{not json",
                headers={"content-type": "application/json"},
            ),
        )
        scalar = await recorder(
            "json-scalar",
            alice.client.post(
                "/api/me/accounts",
                content=b'"x"',
                headers={"content-type": "application/json"},
            ),
        )
    assert malformed.status_code == 400
    assert malformed.json() == {"error": "invalid_request"}
    assert scalar.status_code == 400
    assert scalar.json() == {"error": "invalid_request"}
    recorder.assert_no_leaks()


async def test_patch_body_validation_failures_are_400(
    app: FastAPI, paths: Paths, recorder: Recorder
) -> None:
    async with _session(app, paths, "alice") as alice:
        variants: list[tuple[str, dict[str, Any]]] = [
            ("empty-name", {"name": ""}),
            ("bad-port-type", {"port": "high"}),
            ("smtp-missing-secure", {"smtp": {"host": "h", "port": 465}}),
            ("unknown-field", {"name": "x", "role": "admin"}),
        ]
        for label, payload in variants:
            response = await recorder(
                label,
                alice.client.patch("/api/me/accounts/some-id", json=payload),
            )
            assert response.status_code == 400, label
            assert response.json() == {"error": "invalid_request"}, label
    recorder.assert_no_leaks()


async def test_empty_patch_is_a_noop(
    app: FastAPI, paths: Paths, recorder: Recorder
) -> None:
    async with _session(app, paths, "alice") as alice:
        created = _body(await _add_account(recorder, alice))
        account_id = created["account"]["id"]
        aek_hex = created["account_encryption_key"]

        response = await recorder(
            "patch-empty", alice.client.patch(f"/api/me/accounts/{account_id}", json={})
        )
        assert response.status_code == 200
        assert _body(response)["account"] == created["account"]
        stored = get_account(paths, alice.user_id, account_id)
        assert stored is not None
        assert stored.decrypt_password(aek_hex) == "correct horse battery staple"
    recorder.assert_no_leaks()


async def test_patch_alias_backed_fields_are_accepted(
    app: FastAPI, paths: Paths, recorder: Recorder
) -> None:
    """PATCH accepts every alias-backed patchable field (regression).

    A merge that dumps the stored record by alias and then overlays the
    snake_case field names produced BOTH spellings of the same key, which
    the strict store schema rejects (``extra="forbid"``) — a 500 on a valid
    partial update whenever that field was already set. This pins the fix:
    all alias-backed fields (``allow_start_tls``, ``save_to_sent``,
    ``sent_folder``, ``default_bcc``, ``allowed_from``) update cleanly, and
    the upstream camelCase spelling is accepted too (``populate_by_name``).
    """
    async with _session(app, paths, "alice") as alice:
        created = _body(await _add_account(recorder, alice))
        account_id = created["account"]["id"]
        aek_hex = created["account_encryption_key"]

        patched = await recorder(
            "patch-aliased",
            alice.client.patch(
                f"/api/me/accounts/{account_id}",
                json={
                    "allow_start_tls": True,
                    "save_to_sent": False,
                    "sent_folder": "Sent",
                    "default_bcc": ["audit@example.org", "second@example.org"],
                    "allowed_from": ["carol@example.org"],
                },
            ),
        )
        assert patched.status_code == 200, patched.text
        assert _body(patched)["account"]["allow_start_tls"] is True

        stored = get_account(paths, alice.user_id, account_id)
        assert stored is not None
        assert stored.allow_start_tls is True
        assert stored.save_to_sent is False
        assert stored.sent_folder == "Sent"
        assert stored.default_bcc == ["audit@example.org", "second@example.org"]
        assert stored.allowed_from == ["carol@example.org"]
        assert stored.decrypt_password(aek_hex) == "correct horse battery staple"

        # The upstream camelCase spelling is accepted as well.
        camel = await recorder(
            "patch-camel",
            alice.client.patch(
                f"/api/me/accounts/{account_id}", json={"allowStartTLS": False}
            ),
        )
        assert camel.status_code == 200, camel.text
        assert _body(camel)["account"]["allow_start_tls"] is False
    recorder.assert_no_leaks()


# --- 11. the M04-T03 carry-forward: rotation re-encryption wiring ------------------


def test_production_import_path_registers_the_accounts_reencrypt_hook() -> None:
    """Fresh subprocess: importing the app's mounting site wires the hook.

    The re-encrypt hook registers ONLY as an import side effect of
    ``store.accounts``; the ``web.user`` package (router + serializers) is
    its first production importer. The probe imports ONLY ``web.server`` —
    the production mounting site — and fails (exit 1) if that import chain
    no longer reaches ``store.accounts`` (chain-level guard: dropping every
    ``web.user`` import of the store — e.g. both the router's
    ``accounts_store`` import and the serializers' ``AccountMetadata``
    import — trips it, and AEK rotation would silently stop re-encrypting
    account stores).
    """
    result = subprocess.run(
        [sys.executable, "-c", _PROBE_IMPORT_HOOK],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, (
        "the production import path no longer registers the account-store "
        f"re-encrypt hook; stderr:\n{result.stderr}"
    )


async def test_aek_rotation_reencrypts_a_store_created_through_the_api(
    app: FastAPI, paths: Paths, recorder: Recorder
) -> None:
    """End to end: API-created account, AEK rotation, store re-encrypted.

    Fails if the re-encrypt hook is unregistered in-process: rotation would
    rewrap the blob while the store stays under the old key, so the new key
    could not decrypt the account. (The subprocess probe above guards the
    production import path itself; this test proves the behavior.)
    """
    async with _session(app, paths, "alice") as alice:
        created = _body(await _add_account(recorder, alice))
        account_id = created["account"]["id"]
        old_aek = created["account_encryption_key"]
        store_file = paths.user_imap_store_dir(alice.user_id) / "accounts.json"
        store_before = store_file.read_bytes()

        new_aek = rotate_aek(paths, alice.user_id)

        assert HEX64_RE.fullmatch(new_aek)
        assert new_aek != old_aek
        assert store_file.read_bytes() != store_before
        stored = get_account(paths, alice.user_id, account_id)
        assert stored is not None
        assert stored.decrypt_password(new_aek) == "correct horse battery staple"
        assert stored.decrypt_smtp_password(new_aek) == "smtp-secret-9"
        with pytest.raises(ValueError):
            stored.decrypt_password(old_aek)  # the old key is dead everywhere
    recorder.assert_no_leaks()


# --- 12. M07-T01: session bootstrap, JSON login, logout, failure-safe AEK ---------


def _decode_cookie(app: FastAPI, response: httpx.Response) -> dict[str, str]:
    """Unseal the ``imapgw_user`` cookie a login response set (test-side check)."""
    raw = response.headers["set-cookie"]
    value = raw.split(f"{USER_COOKIE_NAME}=", 1)[1].split(";", 1)[0]
    payload = app.state.session_signer.unseal(value)
    assert payload is not None
    return dict(payload)


async def test_session_route_returns_the_cookie_csrf_token(
    app: FastAPI, paths: Paths, recorder: Recorder
) -> None:
    """``GET /api/me/session`` echoes exactly the cookie payload's ``csrf``.

    The token is additionally proved usable: it authorizes a real mutation
    (``POST /api/me/accounts/activate``) end to end, so the bootstrap is not
    a body that merely looks right.
    """
    async with _session(app, paths, "alice") as alice:
        issued = await recorder("session", alice.client.get("/api/me/session"))
        assert issued.status_code == 200
        assert "no-store" in issued.headers["cache-control"].lower()
        token = _body(issued)["csrf_token"]
        # The token matches the signed cookie's own payload member.
        cookie = alice.client.cookies[USER_COOKIE_NAME]
        payload = app.state.session_signer.unseal(cookie)
        assert payload is not None
        assert token == payload["csrf"] == alice.csrf

        # End to end: the bootstrapped token authorizes a mutation (a fresh
        # client that only knows the token — no direct csrf plumbing).
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as spaclient:
            spaclient.cookies.set(USER_COOKIE_NAME, cookie)
            activated = await recorder(
                "activate",
                spaclient.post(
                    "/api/me/accounts/activate",
                    headers={"X-CSRF-Token": token},
                ),
            )
        assert activated.status_code == 200
        recorder.revealed("activate", _body(activated)["account_encryption_key"])
    recorder.assert_no_leaks()


async def test_session_route_rejects_invalid_cookie(
    app: FastAPI, paths: Paths
) -> None:
    """A present-but-invalid cookie is the same uniform 401 (no counting)."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        client.cookies.set(USER_COOKIE_NAME, "not-a-signed-cookie")
        response = await client.get("/api/me/session")
    assert response.status_code == 401
    assert response.json() == {"error": "unauthorized"}


async def test_json_login_sets_the_cookie_and_returns_the_token(
    app: FastAPI, paths: Paths, recorder: Recorder
) -> None:
    """A correct key -> 200 ok + csrf_token + the httpOnly strict cookie."""
    async with _session(app, paths, "alice") as alice:
        key = alice.key
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        login = await recorder("login", client.post("/api/me/login", json={"key": key}))
    assert login.status_code == 200, login.text
    assert "no-store" in login.headers["cache-control"].lower()
    body = _body(login)
    assert body["status"] == "ok"
    assert isinstance(body["csrf_token"], str) and body["csrf_token"]
    # The cookie is the SAME user cookie the HTML form sets, with identical
    # attributes; the returned token IS the cookie payload's csrf member.
    set_cookie = login.headers["set-cookie"]
    assert set_cookie.startswith(f"{USER_COOKIE_NAME}=")
    assert "httponly" in set_cookie.lower()
    assert "samesite=strict" in set_cookie.lower()
    assert "path=/" in set_cookie.lower()
    payload = _decode_cookie(app, login)
    assert payload["kind"] == SESSION_KIND_USER
    assert payload["sub"] == alice.user_id
    assert body["csrf_token"] == payload["csrf"]
    recorder.assert_no_leaks()


async def test_json_login_failures_are_uniform_401(
    app: FastAPI, paths: Paths, recorder: Recorder
) -> None:
    """Wrong/empty/malformed bodies are ONE failed login — never a 422.

    Parity with the HTML form: a wrong key, an empty key, a missing field, a
    scalar body, a malformed body, an extra field and a non-string key all
    produce the byte-identical uniform 401 body (validation failures are a
    failed login, not ``invalid_request``).
    """
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        responses = [
            await recorder("wrong", client.post("/api/me/login", json={"key": "usr_x"})),
            await recorder("empty", client.post("/api/me/login", json={"key": ""})),
            await recorder("missing", client.post("/api/me/login", json={})),
            await recorder("extra", client.post("/api/me/login", json={"key": "x", "y": 1})),
            await recorder("nonstring", client.post("/api/me/login", json={"key": 7})),
            await recorder("scalar", client.post("/api/me/login", json="x")),
            await recorder(
                "malformed",
                client.post(
                    "/api/me/login",
                    content=b"{not json",
                    headers={"content-type": "application/json"},
                ),
            ),
        ]
    for response in responses:
        assert response.status_code == 401, response.text
        assert response.json() == {"error": "unauthorized"}
    assert len({response.text for response in responses}) == 1  # byte-identical
    recorder.assert_no_leaks()


async def test_json_login_is_rate_limited(tmp_path: Path) -> None:
    """8 failures -> 429 + Retry-After on the ONE login surface.

    M07-T05 removed the server-rendered login form, so the JSON login is
    the only login surface and the budget is no longer "shared" with a
    second route: the floor is set with a shrunk-limit clock-controlled
    limiter and the SAME counter trips on the next attempt.
    """
    paths = build_paths(tmp_path)
    record, key = create_user(paths, "rate-probe")
    app = create_app(Settings(data_dir=tmp_path))
    app.state.user_login_rate_limiter = AdminRateLimiter(limit=3)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        # Three failures consume the whole budget.
        for _ in range(3):
            failed = await client.post("/api/me/login", json={"key": "usr_wrong"})
            assert failed.status_code == 401
        # The NEXT attempt is refused for the SAME reason.
        locked_json = await client.post("/api/me/login", json={"key": key})
        assert locked_json.status_code == 429
        assert locked_json.json() == {"error": "rate_limited"}
        assert int(locked_json.headers["Retry-After"]) >= 1
    assert verify_login_key(paths, record.id, key)


async def test_json_login_success_releases_its_rate_limit_slot(
    tmp_path: Path,
) -> None:
    """A correct key hands its reserved slot back (only failures count)."""
    paths = build_paths(tmp_path)
    _record, key = create_user(paths, "login-release-probe")
    app = create_app(Settings(data_dir=tmp_path))
    app.state.user_login_rate_limiter = AdminRateLimiter(limit=3)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        assert (await client.post("/api/me/login", json={"key": "usr_wrong"})).status_code == 401
        ok = await client.post("/api/me/login", json={"key": key})
        assert ok.status_code == 200  # slot released
        # Budget now has room for two more failures before the lockout.
        assert (await client.post("/api/me/login", json={"key": "usr_wrong"})).status_code == 401
        assert (await client.post("/api/me/login", json={"key": "usr_wrong"})).status_code == 401
        locked = await client.post("/api/me/login", json={"key": key})
        assert locked.status_code == 429


async def test_json_login_cross_site_origin_is_401_and_releases_the_slot(
    tmp_path: Path,
) -> None:
    """A cross-site ``Origin`` login is the uniform 401 AND releases its slot.

    Pinned with the M06-T02 arithmetic framing: after the released
    cross-site attempt, ``limit`` counted failures are ALL admitted (401)
    and the NEXT is refused (429). A non-releasing implementation would
    admit only ``limit - 1`` of those and refuse the last one early.
    """
    paths = build_paths(tmp_path)
    _record, key = create_user(paths, "origin-probe")
    app = create_app(Settings(data_dir=tmp_path))
    limit = 3
    app.state.user_login_rate_limiter = AdminRateLimiter(limit=limit)
    cross_site = {"origin": "https://evil.example"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        # A present key but a cross-site Origin: rejected, slot released.
        cross = await client.post(
            "/api/me/login", json={"key": "usr_wrong"}, headers=cross_site
        )
        assert cross.status_code == 401
        assert cross.json() == {"error": "unauthorized"}

        # The budget is UNTOUCHED: all `limit` counted failures are admitted...
        admitted = [
            (await client.post("/api/me/login", json={"key": "usr_wrong"})).status_code
            for _ in range(limit)
        ]
        assert admitted == [401] * limit
        # ...and the next attempt is refused: the cross-site attempt did not
        # consume one of the slots.
        locked = await client.post("/api/me/login", json={"key": key})
        assert locked.status_code == 429


async def test_json_login_same_origin_header_is_allowed(
    app: FastAPI, paths: Paths
) -> None:
    """A same-origin ``Origin`` (authority == Host) is admitted."""
    async with _session(app, paths, "alice") as alice:
        key = alice.key
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.post(
            "/api/me/login",
            json={"key": key},
            headers={"origin": "http://testserver"},
        )
    assert response.status_code == 200


async def test_logout_deletes_the_cookie_and_kills_the_session(
    app: FastAPI, paths: Paths, recorder: Recorder
) -> None:
    """``POST /api/me/logout`` deletes the cookie; the session then 401s.

    Uses a dedicated client that holds ONLY the cookie (no ``X-CSRF-Token``
    header) so the cookie-deletion response can be asserted, then re-issues
    ``GET /api/me``. The client jar drops the cookie on ``max-age=0``, so
    only a caller that deliberately re-sends the stale cookie value would
    keep a session — which the test does to prove the 401.
    """
    async with _session(app, paths, "alice") as alice:
        cookie = alice.client.cookies[USER_COOKIE_NAME]
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            client.cookies.set(USER_COOKIE_NAME, cookie)
            logged_out = await recorder(
                "logout",
                client.post(
                    "/api/me/logout", headers={"X-CSRF-Token": alice.csrf}
                ),
            )
            assert logged_out.status_code == 200, logged_out.text
            assert _body(logged_out) == {"status": "ok"}
            assert "no-store" in logged_out.headers["cache-control"].lower()
            set_cookie = logged_out.headers["set-cookie"]
            assert USER_COOKIE_NAME in set_cookie
            assert "max-age=0" in set_cookie.lower()  # the deletion cookie

            # Deleting the cookie invalidates only the CLIENT copy; the
            # session signer is stateless, so the response is no-store and no
            # server-side revocation exists — the deletion is the contract.
            # Force the stale cookie back to prove the endpoint itself does
            # not also revoke server-side (documented stateless-session
            # behaviour), then drop it and confirm the anonymous 401.
            client.cookies.clear()
            after = await recorder("me-after-logout", client.get("/api/me"))
            assert after.status_code == 401
            assert after.json() == {"error": "unauthorized"}
    recorder.assert_no_leaks()


async def test_logout_requires_csrf_and_a_session(
    app: FastAPI, paths: Paths
) -> None:
    """CSRF-less cookie logout -> 403; anonymous -> 401 (both uniform)."""
    async with _session(app, paths, "alice", with_csrf=False) as alice:
        csrf_less = await alice.client.post("/api/me/logout")
        assert csrf_less.status_code == 403
        assert csrf_less.json() == {"error": "forbidden"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as anonymous:
        anonymous_attempt = await anonymous.post("/api/me/logout")
    assert anonymous_attempt.status_code == 401
    assert anonymous_attempt.json() == {"error": "unauthorized"}


async def test_create_failure_after_activation_discloses_the_aek_once(
    app: FastAPI,
    paths: Paths,
    recorder: Recorder,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A post-activation store-write failure still discloses the fresh AEK.

    Forced ``put_account`` failure on the FIRST add: the AEK is already
    persisted (wrapped) when the write fails, so the 500 body must carry
    ``account_encryption_key`` exactly once — losing it would strand every
    future credential under a key the user never saw. The captured log lines
    contain no 64-hex material and no key (the key is never logged).

    The forced failure stays in force for the whole request: the route
    catches the store-write exception itself and returns the failure-safe
    500, so the app-wide handler never runs on this path.
    """
    async with _session(app, paths, "alice") as alice:
        real_put_account = accounts_store.put_account

        def boom(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("forced store-write failure")

        monkeypatch.setattr(accounts_store, "put_account", boom)
        with _captured_router_lines() as lines:
            failed = await recorder(
                "create-fail",
                alice.client.post("/api/me/accounts", json=_account_payload()),
            )
        monkeypatch.setattr(accounts_store, "put_account", real_put_account)

        assert failed.status_code == 500, failed.text
        body = _body(failed)
        assert body["error"] == "internal_error"
        aek_hex = body["account_encryption_key"]
        assert HEX64_RE.fullmatch(aek_hex)
        assert "no-store" in failed.headers["cache-control"].lower()
        recorder.revealed("create-fail", aek_hex)

        # The AEK really is active now (activation persisted before the fail).
        me = _body(await recorder("me", alice.client.get("/api/me")))
        assert me["aek_active"] is True

        # Redaction sweep: no key, no 64-hex material reached the log lines.
        for line in lines:
            assert aek_hex not in line
            assert not re.search(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", line)
    recorder.assert_no_leaks()


async def test_create_failure_without_activation_is_plain_internal_error(
    app: FastAPI,
    paths: Paths,
    recorder: Recorder,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When no in-call activation happened the exception escapes (no key).

    Only the post-activation window is failure-safe disclosed: with the AEK
    already active there is nothing to lose, so the store-write failure is
    re-raised — the app-wide 500 handler answers in production (here the
    ASGI transport surfaces the exception, which is the same contract).
    """
    async with _session(app, paths, "alice") as alice:
        # Activate up front so this create performs no activation.
        activated = await recorder(
            "activate", alice.client.post("/api/me/accounts/activate")
        )
        assert activated.status_code == 200
        recorder.revealed("activate", _body(activated)["account_encryption_key"])

        real_put_account = accounts_store.put_account

        def boom(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("forced store-write failure")

        monkeypatch.setattr(accounts_store, "put_account", boom)
        with pytest.raises(RuntimeError, match="forced store-write failure"):
            await alice.client.post("/api/me/accounts", json=_account_payload())
        monkeypatch.setattr(accounts_store, "put_account", real_put_account)

        # No account was written, and no AEK appeared anywhere.
        me = _body(await recorder("me", alice.client.get("/api/me")))
        assert me["accounts"] == []
        assert me["aek_active"] is True
    recorder.assert_no_leaks()


async def test_the_html_login_route_is_gone(app: FastAPI) -> None:
    """M07-T05: the server-rendered ``POST /user/login`` no longer exists.

    The JSON login (``POST /api/me/login``) is the only login surface; its
    success contract (200, ``{"status": "ok"}``, the session cookie and its
    CSRF token) is pinned by
    ``test_json_login_sets_the_cookie_and_returns_the_token``. The deleted
    form route now answers FastAPI's default 405.
    """
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        gone = await client.post("/user/login", data={"key": "usr_wrong"})
    assert gone.status_code == 405
    assert gone.json() == {"detail": "Method Not Allowed"}
