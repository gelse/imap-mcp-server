"""Admin user-management API tests (M03-T02).

Coverage per the M03-T02 verification requirements:

1. create: 201 with the one-time ``usr_`` key, ``key_generation`` 1 and the
   id/name echoed; ``DATA_DIR/users/<id>/user.json`` exists afterwards;
2. the one-time-key invariant across a request sequence: listings and
   detail views never carry the key; rotation mints a different key, bumps
   ``key_generation``, and the old key stops verifying (store-level
   ``verify_login_key``) while the new one authenticates;
3. detail/rotate/status/delete on missing users return 404 ``not_found``;
   a status flip returns 200 with the updated metadata view; an invalid
   status is 400; delete is 204, a subsequent GET is 404 and the user
   directory is gone; registry-invalid ids are 404 while a present-but-
   schema-invalid record fails loud (500), never a masked 404;
4. every route returns 401 without an admin session (the full route list);
5. every mutating route rejects a cookie session without the CSRF token
   (403) and accepts it with the token; Bearer stays CSRF-exempt;
6. validation failures are 400, not FastAPI's default 422: empty/missing
   name, non-string name, unknown body fields and malformed bodies on
   create; invalid/missing status and malformed bodies on the status route;
7. the secret-leak invariant over the WHOLE endpoint matrix: every recorded
   response body is free of the ``scrypt$`` marker and of
   ``login_key_hash``/``aek`` keys, and plaintext ``usr_`` keys appear only
   in the create/rotate bodies that minted them;
8. the stored ``account_count`` follows the real account store: an add (and
   a delete) through ``/api/me/accounts`` moves the admin views' count to
   the real number, a deliberately stale stored count is reconciled by
   the admin read surfaces (JSON detail and list), and a corrupt account
   store fails those surfaces loud (500, never a masked 404).

All HTTP tests run in-process via ``httpx.AsyncClient`` over an ASGI
transport (the pattern of tests/test_admin_auth.py).
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator, Coroutine
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from imap_mcp_gateway.config.env import Settings
from imap_mcp_gateway.config.paths import Paths, build_paths
from imap_mcp_gateway.crypto.hash import hash_secret
from imap_mcp_gateway.crypto.keys import generate_admin_key
from imap_mcp_gateway.store import users as users_store
from imap_mcp_gateway.store.accounts import (
    encrypt_account_record,
    list_accounts,
    put_account,
)
from imap_mcp_gateway.store.admin_key import save_admin_key_hash
from imap_mcp_gateway.store.user_schema import UserMetadata
from imap_mcp_gateway.store.users import create_user, verify_login_key
from imap_mcp_gateway.store.wrap_key import ensure_wrap_key
from imap_mcp_gateway.web.admin.serializers import to_admin_user_view
from imap_mcp_gateway.web.server import create_app
from imap_mcp_gateway.web.session import SESSION_KIND_USER, USER_COOKIE_NAME

USER_KEY_RE = re.compile(r"^usr_[A-Za-z0-9_-]{43}$")
USER_ID_RE = re.compile(r"^[a-z0-9-]{1,64}$")
METADATA_FIELDS = {
    "id",
    "name",
    "status",
    "key_generation",
    "account_count",
    "created_at",
}


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
    """Records admin-API responses and minted keys for the leak assertions.

    The whole-matrix invariant (checked by ``assert_no_leaks`` over every
    recorded response, not spot checks): no response ever carries the
    ``scrypt$`` marker or a ``login_key_hash``/``aek`` key, and plaintext
    ``usr_`` keys appear only in the key-revealing responses (create /
    rotate), each holding a key the test registered via ``minted``.
    """

    KEY_REVEALING = frozenset({"create", "rotate"})

    def __init__(self) -> None:
        self.responses: list[tuple[str, httpx.Response]] = []
        self.keys: list[str] = []

    async def __call__(
        self, label: str, request: Coroutine[Any, Any, httpx.Response]
    ) -> httpx.Response:
        response = await request
        self.responses.append((label, response))
        return response

    def minted(self, plaintext: str) -> None:
        """Register a plaintext key that a create/rotate response revealed."""
        self.keys.append(plaintext)

    def assert_no_leaks(self) -> None:
        """Assert the no-leak invariant across every recorded response."""
        assert self.responses
        for label, response in self.responses:
            assert "scrypt$" not in response.text, label
            # only a SUCCESSFUL create/rotate reveals a key; failed attempts
            # (401/403/400) reveal nothing and are still plaintext-checked.
            reveals = label in self.KEY_REVEALING and response.status_code in (200, 201)
            if not reveals:
                for plaintext in self.keys:
                    assert plaintext not in response.text, label
            if response.status_code == 204 or not response.headers.get(
                "content-type", ""
            ).startswith("application/json"):
                continue
            for key_name, _value in _iter_members(response.json()):
                assert key_name not in ("login_key_hash", "aek"), label
                if not reveals:
                    assert key_name != "login_key", label
                else:
                    body = response.json()
                    assert isinstance(body, dict)
                    # a revealed key must be one the test registered via minted()
                    assert body["login_key"] in self.keys, label


@pytest.fixture(scope="module")
def admin_key() -> str:
    """One admin key for the whole module (key generation is cheap)."""
    return generate_admin_key()


@pytest.fixture(scope="module")
def admin_record(admin_key: str) -> str:
    """The scrypt record for the admin key (the one expensive scrypt run)."""
    return hash_secret(admin_key)


@pytest.fixture
def app(tmp_path: Path, admin_record: str) -> FastAPI:
    """A fresh app (own session signer + rate limiter) over a seeded hash file."""
    save_admin_key_hash(build_paths(tmp_path), admin_record)
    return create_app(Settings(data_dir=tmp_path))


@pytest.fixture
def recorder() -> Recorder:
    """A fresh response recorder per test."""
    return Recorder()


def _client(app: FastAPI) -> httpx.AsyncClient:
    """An in-process client over the app (cookies persist within the client)."""
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


async def _login_and_token(client: httpx.AsyncClient, admin_key: str) -> str:
    """Log the client in as admin and return the session's CSRF token.

    Since M07-T01 the token comes from ``GET /api/admin/session`` — the
    cookie-session bootstrap endpoint the SPA uses — instead of scraping the
    ``csrf_token`` input out of the ``/admin/`` HTML page (deleted in
    M07-T05).
    """
    login = await client.post("/api/admin/login", data={"key": admin_key})
    assert login.status_code == 200
    session = await client.get("/api/admin/session")
    assert session.status_code == 200, session.text
    token = session.json()["csrf_token"]
    assert isinstance(token, str) and token
    return token


@pytest.fixture
async def admin_client(
    app: FastAPI, admin_key: str
) -> AsyncIterator[httpx.AsyncClient]:
    """A cookie-session client sending the session CSRF token on every request."""
    async with _client(app) as client:
        client.headers["X-CSRF-Token"] = await _login_and_token(client, admin_key)
        yield client


def _body(response: httpx.Response) -> dict[str, Any]:
    """The response JSON, asserted to be an object."""
    payload = response.json()
    assert isinstance(payload, dict)
    return payload


async def _create(
    recorder: Recorder, client: httpx.AsyncClient, name: str
) -> httpx.Response:
    """POST one create request through the recorder."""
    return await recorder(
        "create", client.post("/api/admin/users", json={"name": name})
    )


# --- 1. create / list / detail ---------------------------------------------------


async def test_create_returns_key_once_and_persists_record(
    admin_client: httpx.AsyncClient, recorder: Recorder, tmp_path: Path
) -> None:
    response = await _create(recorder, admin_client, "alice")

    assert response.status_code == 201
    body = _body(response)
    assert USER_ID_RE.fullmatch(body["id"])
    assert body["name"] == "alice"
    assert body["key_generation"] == 1
    assert USER_KEY_RE.fullmatch(body["login_key"])
    # The minting response is the ONE disclosure of the login key: it is
    # never cached and never leaks its URL through a Referer (M07-T05 pins
    # the no-store/no-referrer pair that the deleted key-display page had).
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"
    recorder.minted(body["login_key"])
    assert Paths(tmp_path).user_record_path(body["id"]).is_file()
    recorder.assert_no_leaks()


async def test_list_returns_sorted_metadata_views(
    admin_client: httpx.AsyncClient, recorder: Recorder
) -> None:
    first = _body(await _create(recorder, admin_client, "alice"))
    second = _body(await _create(recorder, admin_client, "bob"))
    recorder.minted(first["login_key"])
    recorder.minted(second["login_key"])

    response = await recorder("list", admin_client.get("/api/admin/users"))

    assert response.status_code == 200
    users = response.json()
    assert isinstance(users, list)
    assert [user["id"] for user in users] == sorted([first["id"], second["id"]])
    by_id = {user["id"]: user for user in users}
    assert by_id[first["id"]]["name"] == "alice"
    assert by_id[second["id"]]["name"] == "bob"
    for user in users:
        assert set(user) == METADATA_FIELDS
        assert user["status"] == "active"
        assert user["key_generation"] == 1
        assert user["account_count"] == 0
    recorder.assert_no_leaks()


async def test_detail_returns_single_metadata_view(
    admin_client: httpx.AsyncClient, recorder: Recorder
) -> None:
    created = _body(await _create(recorder, admin_client, "alice"))
    recorder.minted(created["login_key"])

    response = await recorder(
        "detail", admin_client.get(f"/api/admin/users/{created['id']}")
    )

    assert response.status_code == 200
    body = _body(response)
    assert set(body) == METADATA_FIELDS
    assert body["id"] == created["id"]
    assert body["name"] == "alice"
    recorder.assert_no_leaks()


# --- 2. the one-time-key invariant across a request sequence ---------------------


async def test_one_time_key_invariant_across_request_sequence(
    admin_client: httpx.AsyncClient, recorder: Recorder, tmp_path: Path
) -> None:
    created = _body(await _create(recorder, admin_client, "alice"))
    user_id, key = created["id"], created["login_key"]
    recorder.minted(key)

    listing = await recorder("list", admin_client.get("/api/admin/users"))
    detail = await recorder("detail", admin_client.get(f"/api/admin/users/{user_id}"))
    assert listing.status_code == detail.status_code == 200
    assert key not in listing.text
    assert key not in detail.text
    assert "login_key" not in listing.text
    assert "login_key" not in detail.text

    rotated = await recorder(
        "rotate", admin_client.post(f"/api/admin/users/{user_id}/rotate-key")
    )
    assert rotated.status_code == 200
    # The rotation's one-time key is disclosed once, uncached, unreferable.
    assert rotated.headers["cache-control"] == "no-store"
    assert rotated.headers["referrer-policy"] == "no-referrer"
    rotated_body = _body(rotated)
    new_key = rotated_body["login_key"]
    assert USER_KEY_RE.fullmatch(new_key)
    assert new_key != key
    assert rotated_body["id"] == user_id
    assert rotated_body["key_generation"] == 2
    recorder.minted(new_key)

    paths = Paths(tmp_path)
    assert not verify_login_key(paths, user_id, key)  # old key dead immediately
    assert verify_login_key(paths, user_id, new_key)  # new key authenticates

    listing_after = await recorder("list-after", admin_client.get("/api/admin/users"))
    detail_after = await recorder(
        "detail-after", admin_client.get(f"/api/admin/users/{user_id}")
    )
    assert key not in listing_after.text and new_key not in listing_after.text
    assert key not in detail_after.text and new_key not in detail_after.text
    recorder.assert_no_leaks()


# --- 3. missing users, status flips, delete, corrupt records ----------------------


async def test_missing_user_routes_return_not_found(
    admin_client: httpx.AsyncClient, recorder: Recorder
) -> None:
    missing = "ghost"
    responses = [
        await recorder("detail", admin_client.get(f"/api/admin/users/{missing}")),
        await recorder(
            "rotate-missing",
            admin_client.post(f"/api/admin/users/{missing}/rotate-key"),
        ),
        await recorder(
            "status",
            admin_client.post(
                f"/api/admin/users/{missing}/status", json={"status": "active"}
            ),
        ),
        await recorder("delete", admin_client.delete(f"/api/admin/users/{missing}")),
    ]
    for response in responses:
        assert response.status_code == 404
        assert response.json() == {"error": "not_found"}
    recorder.assert_no_leaks()


async def test_status_flip_returns_updated_metadata_view(
    admin_client: httpx.AsyncClient, recorder: Recorder
) -> None:
    created = _body(await _create(recorder, admin_client, "alice"))
    recorder.minted(created["login_key"])
    url = f"/api/admin/users/{created['id']}/status"

    disabled = await recorder(
        "status", admin_client.post(url, json={"status": "disabled"})
    )
    assert disabled.status_code == 200
    disabled_body = _body(disabled)
    assert disabled_body["status"] == "disabled"
    assert set(disabled_body) == METADATA_FIELDS

    enabled = await recorder("status", admin_client.post(url, json={"status": "active"}))
    assert enabled.status_code == 200
    assert _body(enabled)["status"] == "active"
    recorder.assert_no_leaks()


async def test_delete_removes_directory_and_record(
    admin_client: httpx.AsyncClient, recorder: Recorder, tmp_path: Path
) -> None:
    created = _body(await _create(recorder, admin_client, "alice"))
    user_id, key = created["id"], created["login_key"]
    recorder.minted(key)
    user_dir = Paths(tmp_path).user_dir(user_id)
    assert user_dir.is_dir()

    deleted = await recorder(
        "delete", admin_client.delete(f"/api/admin/users/{user_id}")
    )
    assert deleted.status_code == 204
    assert deleted.text == ""

    detail = await recorder(
        "detail-after", admin_client.get(f"/api/admin/users/{user_id}")
    )
    assert detail.status_code == 404
    assert detail.json() == {"error": "not_found"}
    assert not user_dir.exists()
    assert not verify_login_key(Paths(tmp_path), user_id, key)
    recorder.assert_no_leaks()


async def test_invalid_id_404_but_corrupt_record_fails_loud(
    app: FastAPI, admin_key: str, tmp_path: Path, recorder: Recorder
) -> None:
    """Registry-invalid ids are 404; a schema-invalid record fails loud.

    A ``ValueError`` from the path layer's id validation names a user that
    can never exist (404), while a present-but-schema-invalid ``user.json``
    is corruption the store contract fails loud on: the router must NOT
    mask it as a missing user, so it propagates to the 500 handler.
    """
    headers = {"Authorization": f"Bearer {admin_key}"}
    corrupt_dir = Paths(tmp_path).user_dir("corrupt")
    corrupt_dir.mkdir(parents=True)
    (corrupt_dir / "user.json").write_bytes(b'{"garbage": true}')

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        detail = await recorder(
            "detail", client.get("/api/admin/users/Alice", headers=headers)
        )
        assert detail.status_code == 404
        assert detail.json() == {"error": "not_found"}
        rotated = await recorder(
            "rotate-missing",
            client.post("/api/admin/users/Alice/rotate-key", headers=headers),
        )
        assert rotated.status_code == 404
        assert rotated.json() == {"error": "not_found"}

        corrupted = await recorder(
            "corrupt-detail",
            client.get("/api/admin/users/corrupt", headers=headers),
        )
        assert corrupted.status_code == 500
        assert corrupted.json() == {"error": "internal_error"}
        # the identical fail-loud split lives in the rotate/status handlers
        rotated_corrupt = await recorder(
            "rotate-corrupt",
            client.post("/api/admin/users/corrupt/rotate-key", headers=headers),
        )
        assert rotated_corrupt.status_code == 500
        assert rotated_corrupt.json() == {"error": "internal_error"}
        status_corrupt = await recorder(
            "status-corrupt",
            client.post(
                "/api/admin/users/corrupt/status",
                json={"status": "disabled"},
                headers=headers,
            ),
        )
        assert status_corrupt.status_code == 500
        assert status_corrupt.json() == {"error": "internal_error"}
    recorder.assert_no_leaks()


# --- 4. auth: every route requires the admin session ------------------------------


async def test_every_route_requires_admin(app: FastAPI, recorder: Recorder) -> None:
    attempts: list[tuple[str, str, str, dict[str, Any]]] = [
        ("create", "post", "/api/admin/users", {"json": {"name": "alice"}}),
        ("list", "get", "/api/admin/users", {}),
        ("detail", "get", "/api/admin/users/ghost", {}),
        ("rotate", "post", "/api/admin/users/ghost/rotate-key", {}),
        ("status", "post", "/api/admin/users/ghost/status", {"json": {}}),
        ("delete", "delete", "/api/admin/users/ghost", {}),
    ]
    async with _client(app) as client:
        for label, method, url, kwargs in attempts:
            response = await recorder(label, getattr(client, method)(url, **kwargs))
            assert response.status_code == 401, label
            assert response.json() == {"error": "unauthorized"}, label
    recorder.assert_no_leaks()


# --- 5. CSRF: mutating routes vs cookie sessions and Bearer -----------------------


async def test_mutating_routes_require_csrf_for_cookie_sessions(
    app: FastAPI, admin_key: str, recorder: Recorder
) -> None:
    async with _client(app) as client:
        token = await _login_and_token(client, admin_key)
        attempts = [
            client.post("/api/admin/users", json={"name": "alice"}),
            client.post("/api/admin/users/ghost/rotate-key"),
            client.post("/api/admin/users/ghost/status", json={"status": "active"}),
            client.delete("/api/admin/users/ghost"),
        ]
        for attempt in attempts:
            response = await recorder("csrf-less", attempt)
            assert response.status_code == 403
            assert response.json() == {"error": "forbidden"}

        client.headers["X-CSRF-Token"] = token
        created = await _create(recorder, client, "alice")
        assert created.status_code == 201
        recorder.minted(_body(created)["login_key"])
        user_id = _body(created)["id"]
        flipped = await recorder(
            "status",
            client.post(f"/api/admin/users/{user_id}/status", json={"status": "disabled"}),
        )
        assert flipped.status_code == 200
        removed = await recorder("delete", client.delete(f"/api/admin/users/{user_id}"))
        assert removed.status_code == 204
    recorder.assert_no_leaks()


async def test_bearer_requests_are_csrf_exempt(
    app: FastAPI, admin_key: str, recorder: Recorder
) -> None:
    headers = {"Authorization": f"Bearer {admin_key}"}
    async with _client(app) as client:
        created = await recorder(
            "create",
            client.post("/api/admin/users", json={"name": "alice"}, headers=headers),
        )
        assert created.status_code == 201
        user_id = _body(created)["id"]
        recorder.minted(_body(created)["login_key"])
        removed = await recorder(
            "delete", client.delete(f"/api/admin/users/{user_id}", headers=headers)
        )
        assert removed.status_code == 204
    recorder.assert_no_leaks()


# --- 6. validation failures are 400, not 422 ---------------------------------------


async def test_create_body_validation_failures_are_400(
    admin_client: httpx.AsyncClient, recorder: Recorder
) -> None:
    variants: list[tuple[str, dict[str, Any]]] = [
        ("missing-name", {"json": {}}),
        ("empty-name", {"json": {"name": ""}}),
        ("non-string-name", {"json": {"name": 3}}),
        ("unknown-field", {"json": {"name": "alice", "role": "admin"}}),
        ("json-array", {"json": ["alice"]}),
        (
            "malformed",
            {"content": b"not json", "headers": {"content-type": "application/json"}},
        ),
        (
            "json-scalar",
            {"content": b'"alice"', "headers": {"content-type": "application/json"}},
        ),
    ]
    for label, kwargs in variants:
        response = await recorder(
            label, admin_client.post("/api/admin/users", **kwargs)
        )
        assert response.status_code == 400, label
        assert response.json() == {"error": "invalid_request"}, label
    recorder.assert_no_leaks()


async def test_status_body_validation_failures_are_400(
    admin_client: httpx.AsyncClient, recorder: Recorder
) -> None:
    created = _body(await _create(recorder, admin_client, "alice"))
    recorder.minted(created["login_key"])
    url = f"/api/admin/users/{created['id']}/status"
    variants: list[tuple[str, dict[str, Any]]] = [
        ("missing-status", {"json": {}}),
        ("invalid-status", {"json": {"status": "paused"}}),
        ("non-string-status", {"json": {"status": 1}}),
        ("unknown-field", {"json": {"status": "active", "force": True}}),
        (
            "malformed",
            {"content": b"{", "headers": {"content-type": "application/json"}},
        ),
    ]
    for label, kwargs in variants:
        response = await recorder(label, admin_client.post(url, **kwargs))
        assert response.status_code == 400, label
        assert response.json() == {"error": "invalid_request"}, label
    recorder.assert_no_leaks()


# --- 7. serializer unit test --------------------------------------------------------


def test_to_admin_user_view_projects_record_and_metadata(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)
    record, _ = create_user(paths, "alice")

    from_record = to_admin_user_view(record)
    from_metadata = to_admin_user_view(UserMetadata.from_record(record))

    assert from_record == from_metadata
    assert set(from_record) == METADATA_FIELDS
    assert from_record["name"] == "alice"
    assert from_record["status"] == "active"
    assert from_record["key_generation"] == 1
    assert from_record["account_count"] == 0
    assert "login_key_hash" not in from_record
    assert "aek" not in from_record
    assert "login_key" not in from_record


# --- 8. stored account_count tracks the real account store -------------------------


def _create_account_payload() -> dict[str, Any]:
    """A minimal plaintext-shaped account body (add + store seeding)."""
    return {
        "name": "Personal",
        "host": "imap.example.org",
        "port": 993,
        "user": "alice@example.org",
        "password": "correct horse battery staple",
        "tls": True,
    }


async def test_admin_account_count_tracks_account_add_and_delete(
    app: FastAPI,
    admin_client: httpx.AsyncClient,
    recorder: Recorder,
    tmp_path: Path,
) -> None:
    """The admin views' stored ``account_count`` follows real add/delete.

    A user adds (and later deletes) an account through the real
    ``/api/me/accounts`` flow; the admin JSON detail AND list views must
    show the REAL number of stored accounts at every step, and the count
    must return to its previous value after the delete. Pins the stored-
    counter defect: ``user.json.account_count`` used to stay 0 forever
    (forwarded untouched by ``to_admin_user_view``).
    """
    paths = build_paths(tmp_path)
    ensure_wrap_key(paths)  # the first add lazily activates the AEK
    created = _body(await _create(recorder, admin_client, "alice"))
    recorder.minted(created["login_key"])
    user_id = created["id"]

    baseline = await recorder("detail", admin_client.get(f"/api/admin/users/{user_id}"))
    assert _body(baseline)["account_count"] == 0

    cookie, csrf = app.state.session_signer.create_session(
        SESSION_KIND_USER, sub=user_id
    )
    user_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    )
    user_client.cookies.set(USER_COOKIE_NAME, cookie)
    user_client.headers["X-CSRF-Token"] = csrf
    try:
        added = await user_client.post(
            "/api/me/accounts", json=_create_account_payload()
        )
        assert added.status_code == 201, added.text
        account_id = _body(added)["account"]["id"]
        real = len(list_accounts(paths, user_id))
        assert real == 1  # the store really holds one account now

        detail = await recorder(
            "detail-after-add", admin_client.get(f"/api/admin/users/{user_id}")
        )
        detail_body = _body(detail)
        assert detail_body["account_count"] == real
        # count only — an admin view must never expose account content
        assert set(detail_body) == METADATA_FIELDS

        listing = await recorder("list-after-add", admin_client.get("/api/admin/users"))
        listed = {user["id"]: user for user in listing.json()}
        assert listed[user_id]["account_count"] == real

        deleted = await user_client.delete(f"/api/me/accounts/{account_id}")
        assert deleted.status_code == 204, deleted.text
        assert len(list_accounts(paths, user_id)) == 0

        after_delete = await recorder(
            "detail-after-delete", admin_client.get(f"/api/admin/users/{user_id}")
        )
        assert _body(after_delete)["account_count"] == 0  # back to the baseline
    finally:
        await user_client.aclose()
    recorder.assert_no_leaks()


async def test_admin_views_reconcile_a_stale_stored_account_count(
    admin_client: httpx.AsyncClient,
    recorder: Recorder,
    tmp_path: Path,
) -> None:
    """A stale ``user.json.account_count`` is corrected by admin reads.

    Simulates an install whose counter was left behind (earlier versions,
    or an out-of-band store write such as the M05 tool host): the account
    store really holds one account while the stored counter says 0. The
    admin JSON detail AND list views must show the real count, and the
    correction must be persisted into ``user.json`` — not just computed
    for the response.
    """
    paths = build_paths(tmp_path)
    ensure_wrap_key(paths)
    record, _ = create_user(paths, "alice")
    aek_hex = users_store.activate_aek(paths, record.id)
    put_account(paths, record.id, encrypt_account_record(_create_account_payload(), aek_hex))
    # Force the stale state: the store holds one account, the counter says 0.
    users_store.update_user(paths, record.id, {"account_count": 0})

    detail = await recorder(
        "stale-detail", admin_client.get(f"/api/admin/users/{record.id}")
    )
    assert _body(detail)["account_count"] == 1

    listing = await recorder("stale-list", admin_client.get("/api/admin/users"))
    listed = {user["id"]: user for user in listing.json()}
    assert listed[record.id]["account_count"] == 1

    # The correction is persisted into user.json, not just computed.
    reloaded = users_store.get_user(paths, record.id)
    assert reloaded is not None and reloaded.account_count == 1
    recorder.assert_no_leaks()


async def test_corrupt_account_store_fails_loud_not_404(
    app: FastAPI, admin_key: str, tmp_path: Path, recorder: Recorder
) -> None:
    """A corrupt ``accounts.json`` is a loud 500 on the reconcile paths.

    The counter reconcile runs AFTER the routers' ValueError→404 mapping,
    so corruption in the account store must surface as a 500 — never be
    masked as ``not_found``. Pins that ordering on the JSON detail AND
    the JSON list (the plural reconcile walks every store).
    """
    paths = build_paths(tmp_path)
    record, _ = create_user(paths, "alice")
    store_dir = paths.user_imap_store_dir(record.id)
    store_dir.mkdir(parents=True)
    (store_dir / "accounts.json").write_bytes(b'{"garbage": true}')

    headers = {"Authorization": f"Bearer {admin_key}"}
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        detail = await recorder(
            "corrupt-store-detail",
            client.get(f"/api/admin/users/{record.id}", headers=headers),
        )
        assert detail.status_code == 500
        assert detail.json() == {"error": "internal_error"}

        listing = await recorder(
            "corrupt-store-list", client.get("/api/admin/users", headers=headers)
        )
        assert listing.status_code == 500
        assert listing.json() == {"error": "internal_error"}
    recorder.assert_no_leaks()
