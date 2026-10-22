"""Scenario 7: reset semantics — disable/enable kills and restores access (M06-T01).

The admin disable lever must take effect IMMEDIATELY on every surface that
authenticates the user:

- ``POST /api/me/login`` with the user's key fails (uniform 401);
- ``/mcp`` with the user's key header fails (uniform 401);
- an outstanding ``/api/me`` session dies on its next request
  (``require_user`` re-resolves the store per request).

Re-enabling restores all of it with the same (unchanged) key. This is the
STATUS lever only — key rotation and the admin-key reset live in
``test_self_service`` and ``test_admin_key_lifecycle`` respectively.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest
from conftest import (
    CLIENT_TIMEOUT,
    GATEWAY_BASE_URL,
    MCP_PATH,
    UserSession,
    create_user_via_admin,
)

pytestmark = pytest.mark.e2e


def _set_status(admin: httpx.Client, user_id: str, status: str) -> httpx.Response:
    """``POST /api/admin/users/{id}/status`` with ``status``."""
    return admin.post(f"/api/admin/users/{user_id}/status", json={"status": status})


def _mcp_attempt(login_key: str) -> httpx.Response:
    """One initialize-shaped ``/mcp`` request with the user key header."""
    with httpx.Client(
        base_url=GATEWAY_BASE_URL,
        headers={
            "Authorization": f"Bearer {login_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        timeout=CLIENT_TIMEOUT,
    ) as client:
        return client.post(
            MCP_PATH,
            content=('{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}'),
        )


def test_disable_blocks_everything_and_enable_restores(
    admin_auth: httpx.Client,
    user_auth: Callable[..., UserSession],
) -> None:
    """The full disable -> block / re-enable -> restore cycle. (The one
    deliberate disabled-key /mcp attempt keeps the suite under that
    surface's 5-failures-per-10-minutes lockout.)"""
    created = create_user_via_admin(admin_auth, "Reset Target")
    user_id: str = created["id"]
    login_key: str = created["login_key"]

    # Baseline: everything works.
    session = user_auth(login_key, user_id)
    assert session.client.get("/api/me").status_code == 200
    assert _mcp_attempt(login_key).status_code == 200, (
        "baseline /mcp access failed before the disable"
    )

    # Disable: every surface 401s immediately.
    disable = _set_status(admin_auth, user_id, "disabled")
    assert disable.status_code == 200, f"disable failed: {disable.status_code} {disable.text}"
    assert session.client.get("/api/me").status_code == 401, (
        "outstanding /api/me session survived the disable"
    )
    mcp_while_disabled = _mcp_attempt(login_key)
    assert mcp_while_disabled.status_code == 401, (
        f"/mcp still serves a disabled user: {mcp_while_disabled.status_code}"
    )
    with httpx.Client(base_url=GATEWAY_BASE_URL, timeout=CLIENT_TIMEOUT) as probe:
        login_while_disabled = probe.post(
            "/api/me/login", json={"key": login_key}
        )
    assert login_while_disabled.status_code == 401, "disabled user's key still logs in"

    # Re-enable: same key, everything back.
    enable = _set_status(admin_auth, user_id, "active")
    assert enable.status_code == 200, f"enable failed: {enable.status_code} {enable.text}"
    restored = user_auth(login_key, user_id)
    assert restored.client.get("/api/me").status_code == 200, (
        "re-enabled user's /api/me access not restored"
    )
    assert _mcp_attempt(login_key).status_code == 200, "re-enabled user's /mcp access not restored"
    session.client.close()
    restored.client.close()
