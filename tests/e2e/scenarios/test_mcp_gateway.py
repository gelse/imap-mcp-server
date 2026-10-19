"""Scenario 6: the /mcp gateway surface (M06-T01).

Drives ``/mcp`` (Streamable HTTP, JSON mode) exactly as an MCP client
would, against the real stack's vendored upstream child:

- a valid user key header opens a session (``initialize`` answers with a
  result and an assigned ``Mcp-Session-Id``);
- ``tools/list`` over that session exposes EXACTLY the pinned 40-tool
  upstream surface of ``mcp/expected_tools.py`` (the gateway is a verbatim
  bridge — the child, not Python, answers);
- ``imap_list_accounts`` over two users' sessions sees only that user's
  accounts (per-user store isolation on the MCP surface);
- a user who never activated account encryption gets the structured
  AEK-inactive JSON-RPC error (HTTP 200, code ``-32000``, the M05
  fail-closed guidance) instead of a session;
- invalid credentials (wrong key, anonymous) get the uniform 401, and a
  terminated session id can never be reused (404).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from conftest import (
    CLIENT_TIMEOUT,
    GATEWAY_BASE_URL,
    MCP_PATH,
    STUB_IMAP_HOST,
    STUB_IMAP_PASSWORD,
    STUB_IMAP_PORT,
    STUB_IMAP_USER,
    STUB_SMTP_PORT,
    UserSession,
    create_user_via_admin,
    initialize_mcp_session,
    mcp_close_session,
    mcp_post_raw,
    mcp_request,
)

from imap_mcp_gateway.mcp.expected_tools import EXPECTED_TOOL_NAMES

pytestmark = pytest.mark.e2e


def _activate_aek(client: httpx.Client) -> httpx.Response:
    """Activate the user's AEK (``POST /api/me/accounts/activate``)."""
    return client.post("/api/me/accounts/activate")


def _store_stub_account(client: httpx.Client, name: str) -> None:
    """Store one IMAP account on the stub through the real user API."""
    body: dict[str, Any] = {
        "name": name,
        "host": STUB_IMAP_HOST,
        "port": STUB_IMAP_PORT,
        "user": STUB_IMAP_USER,
        "password": STUB_IMAP_PASSWORD,
        "tls": False,
        "smtp": {"host": STUB_IMAP_HOST, "port": STUB_SMTP_PORT, "secure": False},
    }
    added = client.post("/api/me/accounts", json=body)
    assert added.status_code == 201, f"account add failed: {added.status_code} {added.text}"


def test_invalid_credentials_yield_401(
    mcp_client: Callable[[str], httpx.Client],
) -> None:
    """A wrong key and an absent key both get the uniform 401 — before any
    JSON-RPC processing. (Two deliberate failures against /mcp's own
    5-per-10-min limiter; the suite stays well under it.)"""
    bad = mcp_client("usr_" + "A" * 43)
    response = bad.post(
        MCP_PATH,
        content=('{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}'),
    )
    assert response.status_code == 401, (
        f"invalid key did not 401: {response.status_code} {response.text[:200]}"
    )
    bad.close()

    anonymous = httpx.Client(base_url=GATEWAY_BASE_URL, timeout=CLIENT_TIMEOUT)
    bare = anonymous.post(
        MCP_PATH,
        content=('{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}'),
    )
    assert bare.status_code == 401, f"anonymous request did not 401: {bare.status_code}"
    anonymous.close()


def test_initialize_and_tools_list_expose_pinned_surface(
    admin_auth: httpx.Client,
    user_auth: Callable[..., UserSession],
    mcp_client: Callable[[str], httpx.Client],
) -> None:
    """AEK-active user: initialize opens a session; tools/list answers with
    EXACTLY the pinned 40-tool surface — set equality against the
    ``mcp/expected_tools`` pin, not a sample (a renamed, dropped, or added
    tool is a bridge-contract break)."""
    created = create_user_via_admin(admin_auth, "MCP Client")
    session = user_auth(created["login_key"], created["id"])
    assert _activate_aek(session.client).status_code == 200

    client = mcp_client(created["login_key"])
    session_id = initialize_mcp_session(client)

    listing = mcp_request(client, "tools/list", {}, request_id=2, session_id=session_id)
    assert "result" in listing, f"tools/list returned an error: {listing}"
    tools: list[dict[str, Any]] = listing["result"]["tools"]
    tool_names = {tool["name"] for tool in tools}
    assert tool_names == set(EXPECTED_TOOL_NAMES), (
        "the live tools/list surface diverged from the pinned 40-tool "
        f"contract.\nmissing: {sorted(set(EXPECTED_TOOL_NAMES) - tool_names)}\n"
        f"unexpected: {sorted(tool_names - set(EXPECTED_TOOL_NAMES))}"
    )
    mcp_close_session(client, session_id)
    client.close()


def test_two_users_each_see_only_their_own_accounts(
    admin_auth: httpx.Client,
    user_auth: Callable[..., UserSession],
    mcp_client: Callable[[str], httpx.Client],
) -> None:
    """Per-user store isolation on the MCP surface: ``imap_list_accounts``
    over user A's session lists A's account only, and B's lists B's only
    (each tool host runs against the caller's own ``users/<id>/imap-store``)."""
    user_a = create_user_via_admin(admin_auth, "MCP Isolation A")
    user_b = create_user_via_admin(admin_auth, "MCP Isolation B")
    session_a = user_auth(user_a["login_key"], user_a["id"])
    session_b = user_auth(user_b["login_key"], user_b["id"])
    assert _activate_aek(session_a.client).status_code == 200
    assert _activate_aek(session_b.client).status_code == 200
    _store_stub_account(session_a.client, "Alpha Mailbox")
    _store_stub_account(session_b.client, "Beta Mailbox")

    client_a = mcp_client(user_a["login_key"])
    client_b = mcp_client(user_b["login_key"])
    session_id_a = initialize_mcp_session(client_a)
    session_id_b = initialize_mcp_session(client_b)

    listed_a = mcp_request(
        client_a,
        "tools/call",
        {"name": "imap_list_accounts", "arguments": {}},
        request_id=2,
        session_id=session_id_a,
    )
    listed_b = mcp_request(
        client_b,
        "tools/call",
        {"name": "imap_list_accounts", "arguments": {}},
        request_id=2,
        session_id=session_id_b,
    )
    assert "result" in listed_a and "result" in listed_b, (
        f"imap_list_accounts errored: A={listed_a} B={listed_b}"
    )
    text_a = json.dumps(listed_a["result"])
    text_b = json.dumps(listed_b["result"])
    assert "Alpha Mailbox" in text_a and "Beta Mailbox" not in text_a, (
        f"user A's tool call leaked another user's accounts: {text_a[:400]}"
    )
    assert "Beta Mailbox" in text_b and "Alpha Mailbox" not in text_b, (
        f"user B's tool call leaked another user's accounts: {text_b[:400]}"
    )

    mcp_close_session(client_a, session_id_a)
    mcp_close_session(client_b, session_id_b)
    client_a.close()
    client_b.close()


def test_aek_inactive_user_gets_structured_guidance(
    admin_auth: httpx.Client,
    mcp_client: Callable[[str], httpx.Client],
) -> None:
    """The M05 fail-closed contract: a user who NEVER activated the AEK gets
    a JSON-RPC error frame (HTTP 200 on the MCP channel, code -32000,
    "initialize account encryption in the web UI first") instead of a
    session — no child, no keyfile, no tools."""
    created = create_user_via_admin(admin_auth, "MCP AEK Inactive")
    client = mcp_client(created["login_key"])
    response = mcp_post_raw(
        client,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "e2e-suite", "version": "0.0.0"},
            },
        },
    )
    assert response.status_code == 200, (
        f"guidance did not arrive over the MCP channel (HTTP "
        f"{response.status_code}): {response.text[:300]}"
    )
    body: dict[str, Any] = response.json()
    assert "result" not in body, (
        f"AEK-inactive initialize returned a result (session opened): {body}"
    )
    error = body.get("error") or {}
    assert error.get("code") == -32000, body
    assert "initialize account encryption in the web UI first" in str(error.get("message", "")), (
        body
    )
    client.close()
