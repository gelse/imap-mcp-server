"""Scenario 3: user lifecycle via the admin JSON API (M06-T01).

Pins the M03 user-management contract end to end against the real stack:

- the admin creates a user via ``POST /api/admin/users`` and receives the
  one-time ``usr_`` login key in that response body and nowhere else;
- the user logs in with that key (``POST /api/me/login``) and the session
  works (``GET /api/me`` answers 200);
- the admin disables the user (``POST /api/admin/users/{id}/status``) and
  the user's login stops working immediately (the uniform 401) — an
  OUTSTANDING session dies too (``require_user`` re-resolves the store);
- re-enabling restores access with the same key;
- admin rotation (``POST /api/admin/users/{id}/rotate-key``) invalidates
  the old key and issues a new one-time key;
- deletion removes the user: the key stops authenticating, the admin
  listing no longer shows the id, and the user's whole host-side
  directory is gone from ``data/users/``.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from conftest import (
    CLIENT_TIMEOUT,
    GATEWAY_BASE_URL,
    USERS_DIR,
    create_user_via_admin,
)

pytestmark = pytest.mark.e2e


def _user_login_attempt(login_key: str) -> httpx.Response:
    """One ``POST /api/me/login`` attempt with ``login_key`` (fresh client).

    The login route does a full scrypt verify per ACTIVE user, so the
    client carries the suite's generous CLIENT_TIMEOUT rather than the
    httpx default.
    """
    with httpx.Client(base_url=GATEWAY_BASE_URL, timeout=CLIENT_TIMEOUT) as client:
        return client.post("/api/me/login", json={"key": login_key})


def _me(client: httpx.Client) -> httpx.Response:
    """``GET /api/me`` with the session client (metadata-only profile)."""
    return client.get("/api/me")


def test_created_user_receives_one_time_key_and_logs_in(
    admin_auth: httpx.Client,
    user_auth: Any,
) -> None:
    """Create -> one-time key -> user session works."""
    created = create_user_via_admin(admin_auth, "Lifecycle User")
    user_id: str = created["id"]
    login_key: str = created["login_key"]

    session = user_auth(login_key, user_id)
    profile = _me(session.client)
    assert profile.status_code == 200, (
        f"fresh user session failed GET /api/me: {profile.status_code}"
    )
    assert profile.json()["id"] == user_id
    assert profile.json()["key_generation"] == 1


def test_disabled_user_login_fails_and_session_dies(
    admin_auth: httpx.Client,
    user_auth: Any,
) -> None:
    """Disable => the key stops authenticating AND an outstanding session is
    killed immediately (require_user re-resolves the store per request)."""
    created = create_user_via_admin(admin_auth, "Disable Me")
    user_id: str = created["id"]
    login_key: str = created["login_key"]
    session = user_auth(login_key, user_id)
    assert _me(session.client).status_code == 200

    disable = admin_auth.post(f"/api/admin/users/{user_id}/status", json={"status": "disabled"})
    assert disable.status_code == 200, f"disable failed: {disable.status_code} {disable.text}"
    assert disable.json()["status"] == "disabled"

    # New logins with the same key fail (uniform 401).
    attempt = _user_login_attempt(login_key)
    assert attempt.status_code == 401, f"disabled user's key still logs in: {attempt.status_code}"
    # And the outstanding session is dead immediately (uniform 401).
    dead = _me(session.client)
    assert dead.status_code == 401, (
        f"disabled user's live session still serves /api/me: {dead.status_code}"
    )


def test_reenabled_user_access_restored(
    admin_auth: httpx.Client,
    user_auth: Any,
) -> None:
    """Re-enable => the SAME key works again (status flip only)."""
    created = create_user_via_admin(admin_auth, "Reenable Me")
    user_id: str = created["id"]
    login_key: str = created["login_key"]

    admin_auth.post(f"/api/admin/users/{user_id}/status", json={"status": "disabled"})
    assert _user_login_attempt(login_key).status_code == 401

    enable = admin_auth.post(f"/api/admin/users/{user_id}/status", json={"status": "active"})
    assert enable.status_code == 200, f"enable failed: {enable.status_code} {enable.text}"
    session = user_auth(login_key, user_id)
    assert _me(session.client).status_code == 200, "re-enabled user's key must work again"


def test_admin_rotation_invalidates_old_key(
    admin_auth: httpx.Client,
    user_auth: Any,
) -> None:
    """Admin rotate-key: the old one-time key dies, the new one works."""
    created = create_user_via_admin(admin_auth, "Rotate Me")
    user_id: str = created["id"]
    old_key: str = created["login_key"]
    session = user_auth(old_key, user_id)
    assert _me(session.client).status_code == 200

    rotated = admin_auth.post(f"/api/admin/users/{user_id}/rotate-key")
    assert rotated.status_code == 200, (
        f"admin rotation failed: {rotated.status_code} {rotated.text}"
    )
    new_key: str = rotated.json()["login_key"]
    assert new_key != old_key, "rotation minted the same key"
    assert rotated.json()["key_generation"] == 2

    # Old key: dead for new logins (the session cookie itself survives
    # rotation by design — rotation invalidates the KEY, not sessions).
    assert _user_login_attempt(old_key).status_code == 401
    fresh = user_auth(new_key, user_id)
    assert _me(fresh.client).status_code == 200, "new key must authenticate"
    session.client.close()


def test_deleted_user_is_gone(
    admin_auth: httpx.Client,
) -> None:
    """Delete removes the user, their whole directory, and their listing
    entry: the key fails, the id is gone, ``data/users/<id>`` is gone."""
    created = create_user_via_admin(admin_auth, "Delete Me")
    user_id: str = created["id"]
    login_key: str = created["login_key"]

    deleted = admin_auth.delete(f"/api/admin/users/{user_id}")
    assert deleted.status_code == 204, f"delete failed: {deleted.status_code} {deleted.text}"
    assert _user_login_attempt(login_key).status_code == 401
    listing = admin_auth.get("/api/admin/users")
    assert listing.status_code == 200
    listed_ids = [user["id"] for user in listing.json()]
    assert user_id not in listed_ids, "deleted user still listed"
    assert not (USERS_DIR / user_id).exists(), (
        f"user directory survived deletion: {USERS_DIR / user_id}"
    )
