"""Scenarios 1-2: deployment health/layout and the admin-key lifecycle (M06-T01).

Scenario 1 (Deploy) — the compose stack the suite boots IS the deployment
manifest under test: ``/healthz`` answers, the gateway and stub containers
come up healthy, and the host-side bind mounts carry the documented layout
(``config/admin-key.hash`` + ``config/wrap.key`` after the first boot; the
``users``/``mail`` trees the gateway creates as it goes).

Scenario 2 (Admin key) — the M02-T02 lifecycle end to end against that stack:

- the cold boot of a fresh data dir logs the plaintext ``adm_`` key
  exactly once (the one-time display contract; the ``stack`` fixture
  performs and pins that boot — here we re-check it against the live logs
  and branch on cold vs warm);
- the cookie-session path (``imapgw_admin`` + per-session CSRF token) is
  the browser-facing contract: CSRF-less mutations are 403, CSRF-carrying
  ones work, logout kills the session;
- restarting the container logs ``existing key found`` — never a second
  key — and the SAME key keeps authenticating;
- deleting only ``data/config/admin-key.hash`` and booting again mints a
  NEW key (exactly one ``admin key created`` line), the old key is dead,
  the wrap key and every user survive — the reset must never be a wipe.
"""

from __future__ import annotations

import re
import socket
from typing import Any

import httpx
import pytest
from conftest import (
    ADMIN_KEY_CACHE,
    ADMIN_KEY_HASH,
    ADMIN_KEY_PATTERN,
    CLIENT_TIMEOUT,
    CONFIG_DIR,
    GATEWAY_BASE_URL,
    HEALTHZ_URL,
    MAIL_DIR,
    USERS_DIR,
    WRAP_KEY_FILE,
    create_user_via_admin,
    decode_cookie_payload,
    reboot_after_state_change,
    redact_keys,
    restart_gateway,
    update_admin_key,
    wait_services_healthy,
)

pytestmark = pytest.mark.e2e

_SPA_ASSET_RE = re.compile(r'src="(/assets/[^"]+\.js)"')
"""The hashed bundle reference the built shell carries."""

_KEY_MATERIAL_RE = re.compile(r"\b(?:adm_|usr_)[A-Za-z0-9_-]{20,}")
"""Key MATERIAL (prefix + body) — never allowed in a served shell."""

_EXPECTED_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
    "base-uri 'none'; frame-ancestors 'none'"
)
"""The conservative CSP the gateway pins on every response."""


def _count_boot_lines(logs: str) -> tuple[int, int]:
    """``(created-lines, existing-lines)`` in the given log text."""
    created = sum(1 for line in logs.splitlines() if "admin key created" in line)
    found = sum(1 for line in logs.splitlines() if "existing key found" in line)
    return created, found


def test_deploy_stack_is_healthy_and_lays_out_data(stack: dict[str, Any]) -> None:
    """Scenario 1: the deployment comes up healthy with the documented
    host-side layout, and the stub mailbox is reachable on the test network."""
    health = httpx.get(HEALTHZ_URL, timeout=5.0)
    assert health.status_code == 200, f"/healthz answered {health.status_code}"

    # The bind-mounted layout the deployment docs promise on the host.
    assert ADMIN_KEY_HASH.is_file(), f"missing {ADMIN_KEY_HASH} after boot"
    assert WRAP_KEY_FILE.is_file(), f"missing {WRAP_KEY_FILE} after boot"
    assert CONFIG_DIR.is_dir() and USERS_DIR.is_dir() and MAIL_DIR.is_dir()

    # Compose-level health (the containers' own healthchecks, not just the
    # HTTP probe): both services must report healthy. Their healthchecks flip
    # on their own interval/start-period schedule AFTER the app already serves
    # (the stack fixture's /healthz wait), so poll to convergence instead of
    # racing the first probe.
    entries = wait_services_healthy()
    for service in ("imap-gateway", "imap-stub"):
        assert service in entries, f"service {service} missing from compose ps"
        assert entries[service].get("Health") == "healthy", (
            f"service {service} is not healthy: {entries[service]}"
        )
    # The stub's published port answers with its IMAP greeting (host-side
    # proof that the wire the scenarios configure accounts against exists).
    with socket.create_connection(("127.0.0.1", 1143), timeout=5.0) as probe:
        greeting = probe.recv(256)
    assert b"imap-mcp-e2e-stub ready" in greeting, greeting

    # And the boot log carries the greppable boot marker either way.
    assert "[boot] starting imap-mcp-gateway" in stack["logs"]()

    # The SPA (M07-T05) is served FROM THE IMAGE's built frontend/dist: the
    # shell answers on both surfaces, carries the strict CSP and no-store,
    # references its hashed bundle, and that bundle is served with the
    # immutable cache policy. The shell body carries no key material.
    with httpx.Client(base_url=GATEWAY_BASE_URL, timeout=CLIENT_TIMEOUT) as browser:
        admin_shell = browser.get("/admin")
        user_shell = browser.get("/user")
    assert admin_shell.status_code == 200, (
        f"GET /admin answered {admin_shell.status_code}: {admin_shell.text[:200]}"
    )
    assert "text/html" in admin_shell.headers["content-type"]
    assert admin_shell.headers["cache-control"] == "no-store"
    assert admin_shell.headers["content-security-policy"] == _EXPECTED_CSP
    assert user_shell.status_code == 200, (
        f"GET /user answered {user_shell.status_code}: {user_shell.text[:200]}"
    )
    assert "scrypt$" not in admin_shell.text
    assert _KEY_MATERIAL_RE.search(admin_shell.text) is None

    asset_match = _SPA_ASSET_RE.search(admin_shell.text)
    assert asset_match is not None, "the built shell references no hashed asset"
    asset = httpx.get(
        f"{GATEWAY_BASE_URL}{asset_match.group(1)}", timeout=CLIENT_TIMEOUT
    )
    assert asset.status_code == 200, (
        f"the hashed asset answered {asset.status_code}: {asset.text[:200]}"
    )
    assert asset.headers["cache-control"] == "public, max-age=31536000, immutable"


def test_boot_follows_the_one_time_display_contract(
    stack: dict[str, Any],
) -> None:
    """Cold boot: exactly one ``admin key created`` line (and the plaintext
    matches the key the fixture resolved). Warm boot: ``existing key
    found`` and NO key material at all — the second run of the suite lands
    here and proves the persistence path."""
    logs = stack["logs"]()
    created, found = _count_boot_lines(logs)
    if stack["cold"]:
        assert created == 1 and found == 0, (
            f"cold boot must log the key exactly once (created={created}, found={found}):\n"
            f"{redact_keys(logs)}"
        )
        match = ADMIN_KEY_PATTERN.search(logs)
        assert match is not None and match.group(0) == stack["admin_key"], (
            "the logged admin key is not the key the fixture resolved"
        )
    else:
        assert created == 0 and found >= 1, (
            f"warm boot must log 'existing key found' only (created={created}, "
            f"found={found}):\n{redact_keys(logs)}"
        )
        assert stack["admin_key"] not in logs, (
            "warm-boot logs must never carry the admin key plaintext"
        )


def test_admin_cookie_session_and_csrf_contract(
    stack: dict[str, Any],
    admin_auth: httpx.Client,
) -> None:
    """The browser-facing admin session: login sets the signed cookie; a
    CSRF-less mutation is the fixed 403; the session's CSRF token (inside
    the cookie payload) authorizes the same mutation; logout kills it."""
    with httpx.Client(base_url=GATEWAY_BASE_URL, timeout=CLIENT_TIMEOUT) as browser:
        login = browser.post("/api/admin/login", data={"key": stack["admin_key"]})
        assert login.status_code == 200, (
            f"admin cookie login failed: {login.status_code} {login.text}"
        )
        cookie = browser.cookies.get("imapgw_admin")
        assert cookie, "login did not set the imapgw_admin cookie"
        csrf = decode_cookie_payload(cookie).get("csrf")
        assert csrf, "admin session cookie carries no csrf token"

        # CSRF-less cookie mutation: the fixed 403 (auth succeeded; the
        # token gate is what refused — this is NOT a rate-limit failure).
        no_csrf = browser.post("/api/admin/users", json={"name": "CSRF Probe"})
        assert no_csrf.status_code == 403, (
            f"CSRF-less mutation answered {no_csrf.status_code}: {no_csrf.text}"
        )

        # With the session's token the same mutation works.
        created = browser.post(
            "/api/admin/users",
            json={"name": "Cookie Contract"},
            headers={"X-CSRF-Token": csrf},
        )
        assert created.status_code == 201, (
            f"CSRF-carrying mutation failed: {created.status_code} {created.text}"
        )
        user_id = created.json()["id"]

        # Logout invalidates the cookie session immediately.
        logout = browser.post("/api/admin/logout", headers={"X-CSRF-Token": csrf})
        assert logout.status_code == 200, logout.text
        dead = browser.get("/api/admin/users")
        assert dead.status_code == 401, f"cookie session survived logout: {dead.status_code}"

    # Clean the probe user up over the Bearer surface (CSRF-exempt).
    deleted = admin_auth.delete(f"/api/admin/users/{user_id}")
    assert deleted.status_code == 204, deleted.text


def test_restart_preserves_the_admin_key(stack: dict[str, Any]) -> None:
    """``docker compose restart``: the new boot logs ``existing key found``
    (never a second key), and the SAME key still authenticates — while the
    cookie signer secret (per-boot) is expected to have rotated, which is
    exactly why the suite's admin surface uses Bearer auth."""
    logs = restart_gateway()
    created, found = _count_boot_lines(logs)
    assert created == 0 and found >= 1, (
        f"restart must log 'existing key found' only (created={created}, found={found}):\n"
        f"{redact_keys(logs)}"
    )
    assert not ADMIN_KEY_PATTERN.search(logs), (
        f"a restart re-displayed key material:\n{redact_keys(logs)}"
    )

    with httpx.Client(base_url=GATEWAY_BASE_URL, timeout=CLIENT_TIMEOUT) as client:
        login = client.post("/api/admin/login", data={"key": stack["admin_key"]})
        assert login.status_code == 200, (
            f"admin key stopped authenticating after restart: {login.status_code} {login.text}"
        )

    cached = ADMIN_KEY_CACHE.read_text("ascii").strip()
    assert cached == stack["admin_key"], "the warm-boot key cache drifted from the live admin key"


def test_hash_reset_mints_new_key_and_preserves_users(
    stack: dict[str, Any],
    admin_auth: httpx.Client,
    user_auth: Any,
) -> None:
    """The reset leg (milestone: "delete ``admin-key.hash``, restart → new
    key once, users/accounts intact"): a new key is minted and displayed
    exactly once, the old key is dead — and this is NOT a wipe: the wrap
    key survives (``wrap key found``) and pre-existing users keep working
    with their unchanged keys."""
    survivor = create_user_via_admin(admin_auth, "Reset Survivor")
    session = user_auth(survivor["login_key"], survivor["id"])
    assert session.client.get("/api/me").status_code == 200
    session.client.close()

    old_key: str = stack["admin_key"]
    assert ADMIN_KEY_HASH.is_file(), "admin-key.hash vanished mid-session"
    ADMIN_KEY_HASH.unlink()

    logs = reboot_after_state_change()
    created, found = _count_boot_lines(logs)
    assert created == 1, (
        f"reset boot must log a NEW admin key exactly once "
        f"(created={created}, found={found}):\n{redact_keys(logs)}"
    )
    match = ADMIN_KEY_PATTERN.search(logs)
    assert match is not None, f"no admin key in reset-boot logs:\n{redact_keys(logs)}"
    new_key = match.group(0)
    assert new_key != old_key, "reset boot re-used the old admin key"

    # The wrap key (account-crypto material, NOT an operator credential)
    # must have been found, not recreated: deleting admin-key.hash must
    # never cascade into account-key state.
    assert "[config] wrap key found" in logs, (
        f"reset boot did not keep the existing wrap key:\n{redact_keys(logs)}"
    )

    with httpx.Client(base_url=GATEWAY_BASE_URL, timeout=CLIENT_TIMEOUT) as client:
        old_login = client.post("/api/admin/login", data={"key": old_key})
        assert old_login.status_code == 401, (
            f"old admin key still authenticates after reset: {old_login.status_code}"
        )
        new_login = client.post("/api/admin/login", data={"key": new_key})
        assert new_login.status_code == 200, (
            f"new admin key rejected after reset: {new_login.status_code} {new_login.text}"
        )

    # Users survive the reset untouched: still listed (under the NEW key —
    # note the function-scoped admin_auth client still carries the OLD
    # Bearer header, so a fresh client speaks for the new key) and the
    # user's own LOGIN KEY still authenticates. The pre-restart cookie
    # session does not (the signer secret is per-boot) — that is expected
    # and why this leg re-logs-in instead of reusing the old session.
    update_admin_key(stack, new_key)
    with httpx.Client(
        base_url=GATEWAY_BASE_URL,
        headers={"Authorization": f"Bearer {new_key}"},
        timeout=CLIENT_TIMEOUT,
    ) as new_admin:
        listing = new_admin.get("/api/admin/users")
        assert listing.status_code == 200, listing.text
        assert survivor["id"] in [user["id"] for user in listing.json()]
    survivors_session = user_auth(survivor["login_key"], survivor["id"])
    assert survivors_session.client.get("/api/me").status_code == 200, (
        "user login key broken by the admin-key reset"
    )
    survivors_session.client.close()
