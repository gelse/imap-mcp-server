"""Scenario 4: user self-service — AEK, accounts, key rotation (M06-T01).

Pins the M04 self-service contract against the real stack and the stub
IMAP server:

- a FIRST account add auto-activates the AEK and discloses its plaintext
  hex exactly once (``account_encryption_key``) — later adds and the
  explicit activation route never re-display it (``409 aek_already_active``);
- adding an IMAP account (``POST /api/me/accounts``) against the stub
  (``imap-stub:143``, ``e2euser``/``e2epass``) succeeds, shows up in
  ``GET /api/me`` as metadata only (no credential fields), and can be
  EDITED (``PATCH /api/me/accounts/{id}``);
- self key rotation (``POST /api/me/rotate-key``) invalidates the old
  login key and issues a new one-time key, with accounts intact — the
  rotated key is dead on every surface (the JSON login, MCP header auth).
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from conftest import (
    CLIENT_TIMEOUT,
    MCP_PATH,
    STUB_IMAP_HOST,
    STUB_IMAP_PASSWORD,
    STUB_IMAP_PORT,
    STUB_IMAP_USER,
    STUB_SMTP_PORT,
    create_user_via_admin,
)

pytestmark = pytest.mark.e2e


def _activate_aek(client: httpx.Client) -> httpx.Response:
    """``POST /api/me/accounts/activate`` (the explicit AEK activation)."""
    return client.post("/api/me/accounts/activate")


def _add_stub_account(client: httpx.Client, name: str) -> httpx.Response:
    """Add one IMAP account pointing at the E2E stub."""
    body: dict[str, Any] = {
        "name": name,
        "host": STUB_IMAP_HOST,
        "port": STUB_IMAP_PORT,
        "user": STUB_IMAP_USER,
        "password": STUB_IMAP_PASSWORD,
        "tls": False,
        "smtp": {
            "host": STUB_IMAP_HOST,
            "port": STUB_SMTP_PORT,
            "secure": False,
        },
    }
    return client.post("/api/me/accounts", json=body)


def _list_accounts(client: httpx.Client) -> list[dict[str, Any]]:
    """The profile's account list (metadata only) from ``GET /api/me``."""
    profile = client.get("/api/me")
    assert profile.status_code == 200, f"/api/me failed: {profile.status_code}"
    accounts: list[dict[str, Any]] = profile.json()["accounts"]
    return accounts


def test_first_account_add_activates_aek_and_discloses_it_once(
    admin_auth: httpx.Client,
    user_auth: Any,
) -> None:
    """The lazy path: the FIRST add activates the AEK and returns its hex
    exactly once; the next add carries no key material; the explicit
    activation route then refuses with the fixed 409."""
    created = create_user_via_admin(admin_auth, "Lazy Activate")
    session = user_auth(created["login_key"], created["id"])

    first = _add_stub_account(session.client, "First Account")
    assert first.status_code == 201, f"first account add failed: {first.status_code} {first.text}"
    first_body: dict[str, Any] = first.json()
    aek_hex: str = first_body.get("account_encryption_key", "")
    assert len(aek_hex) == 64 and all(c in "0123456789abcdef" for c in aek_hex), (
        f"first add did not disclose a 32-byte hex AEK once: {aek_hex[:8]}..."
    )
    assert "account" in first_body

    second = _add_stub_account(session.client, "Second Account")
    assert second.status_code == 201, second.text
    assert "account_encryption_key" not in second.json(), (
        "a later add re-disclosed AEK material (one-time contract broken)"
    )

    reactivation = _activate_aek(session.client)
    assert reactivation.status_code == 409, (
        f"re-activation did not 409: {reactivation.status_code} {reactivation.text}"
    )
    assert "account_encryption_key" not in reactivation.json()


def test_explicit_activation_discloses_key_exactly_once(
    admin_auth: httpx.Client,
    user_auth: Any,
) -> None:
    """The explicit path: ``POST /api/me/accounts/activate`` returns the
    AEK hex once; a second activation is the fixed 409 (re-activation must
    never replace the key existing ciphertext depends on)."""
    created = create_user_via_admin(admin_auth, "Explicit Activate")
    session = user_auth(created["login_key"], created["id"])

    first = _activate_aek(session.client)
    assert first.status_code == 200, f"AEK activation failed: {first.status_code} {first.text}"
    aek_hex: str = first.json()["account_encryption_key"]
    assert len(aek_hex) == 64 and all(c in "0123456789abcdef" for c in aek_hex), (
        f"AEK is not 32 bytes of hex: {aek_hex[:8]}..."
    )

    second = _activate_aek(session.client)
    assert second.status_code == 409, (
        f"second activation did not 409: {second.status_code} {second.text}"
    )
    assert "account_encryption_key" not in second.json()


def test_account_lifecycle_against_stub(
    admin_auth: httpx.Client,
    user_auth: Any,
) -> None:
    """Add an IMAP account on the stub; it appears in the listing with
    credential-free metadata only; a PATCH edits it."""
    created = create_user_via_admin(admin_auth, "Account Owner")
    session = user_auth(created["login_key"], created["id"])

    # Activate first, so the add below must carry NO AEK material at all.
    assert _activate_aek(session.client).status_code == 200

    added = _add_stub_account(session.client, "E2E Stub Mailbox")
    assert added.status_code == 201, f"account add failed: {added.status_code} {added.text}"
    body: dict[str, Any] = added.json()
    assert "account_encryption_key" not in body, (
        "account add re-disclosed AEK material (one-time contract broken)"
    )
    account_id: str = body["account"]["id"]
    assert body["account"]["host"] == STUB_IMAP_HOST
    assert body["account"]["user"] == STUB_IMAP_USER

    accounts = _list_accounts(session.client)
    assert len(accounts) == 1, f"expected exactly one account: {accounts}"
    assert accounts[0]["id"] == account_id
    assert accounts[0]["name"] == "E2E Stub Mailbox"
    # Metadata only: no credential fields anywhere in the view.
    assert "password" not in accounts[0]
    assert "smtp" not in accounts[0] or "password" not in accounts[0]["smtp"]

    # The edit path (milestone scenario 4: "edits it").
    edited = session.client.patch(
        f"/api/me/accounts/{account_id}",
        json={"name": "Renamed Mailbox", "port": 10143},
    )
    assert edited.status_code == 200, f"account edit failed: {edited.status_code} {edited.text}"
    assert edited.json()["account"]["name"] == "Renamed Mailbox"
    assert edited.json()["account"]["port"] == 10143
    after = _list_accounts(session.client)
    assert after[0]["name"] == "Renamed Mailbox", after

    # And removal completes the lifecycle.
    removed = session.client.delete(f"/api/me/accounts/{account_id}")
    assert removed.status_code == 204, removed.text
    assert _list_accounts(session.client) == []


def test_self_key_rotation_invalidates_old_key(
    admin_auth: httpx.Client,
    user_auth: Any,
    mcp_client: Any,
) -> None:
    """Rotate-key: new one-time key returned; old key fails everywhere; the
    new key works and the accounts are intact (login key and AEK are
    independent)."""
    created = create_user_via_admin(admin_auth, "Key Rotator")
    user_id: str = created["id"]
    old_key: str = created["login_key"]
    session = user_auth(old_key, user_id)
    assert _activate_aek(session.client).status_code == 200
    assert _add_stub_account(session.client, "Before Rotation").status_code == 201

    rotated = session.client.post("/api/me/rotate-key")
    assert rotated.status_code == 200, f"self rotation failed: {rotated.status_code} {rotated.text}"
    new_key: str = rotated.json()["login_key"]
    assert new_key != old_key

    # A fresh session from the NEW key still sees the accounts.
    fresh = user_auth(new_key, user_id)
    accounts = _list_accounts(fresh.client)
    assert len(accounts) == 1, "rotation must not touch accounts"
    assert accounts[0]["name"] == "Before Rotation"

    # The OLD key no longer authenticates anywhere: /api/me/login (401) and
    # /mcp (401 — the uniform unauthorized on the header-auth surface).
    with httpx.Client(base_url=fresh.client.base_url, timeout=CLIENT_TIMEOUT) as probe:
        assert probe.post("/api/me/login", json={"key": old_key}).status_code == 401
    mcp_old = mcp_client(old_key)
    response = mcp_old.post(
        MCP_PATH,
        content=('{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}'),
    )
    assert response.status_code == 401, f"old key still opens MCP sessions: {response.status_code}"
    mcp_old.close()
    session.client.close()
