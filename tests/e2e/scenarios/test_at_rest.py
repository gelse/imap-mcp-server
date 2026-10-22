"""Scenario 5: encryption at rest (M06-T01).

Host-side inspection of the bind-mounted ``tests/e2e/data`` — the same tree
the gateway container persists to:

- ``data/users/**`` must contain NO plaintext credential material: neither
  the stub IMAP password the users submitted, nor any ``usr_``/``adm_``
  plaintext key, nor a bare 64-hex AEK blob;
- no session keyfile (``imap-store/.key``) exists while no MCP session is
  running — at rest the AEK exists only in wrapped form;
- every secret-bearing file (``admin-key.hash``, ``wrap.key``, each
  ``user.json``) is mode ``0600`` and every state directory ``0700`` (the
  fs_safe discipline, asserted from outside the process).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path
from stat import S_IMODE
from typing import Any

import httpx
import pytest
from conftest import (
    ADMIN_KEY_HASH,
    STUB_IMAP_HOST,
    STUB_IMAP_PASSWORD,
    STUB_IMAP_PORT,
    STUB_IMAP_USER,
    USERS_DIR,
    WRAP_KEY_FILE,
    UserSession,
    create_user_via_admin,
)

pytestmark = pytest.mark.e2e

_PLAINTEXT_KEY_PATTERN = re.compile(r"\b(?:usr|adm)_[A-Za-z0-9_-]{43}\b")
"""A plaintext login/admin key in a scanned file."""

_AEK_HEX_PATTERN = re.compile(r"\b[0-9a-f]{64}\b")
"""A raw 32-byte hex string (a plaintext AEK would be exactly this)."""


def _user_files() -> list[Path]:
    """Every file under ``data/users/`` (the at-rest scan surface)."""
    if not USERS_DIR.exists():
        return []
    return [path for path in USERS_DIR.rglob("*") if path.is_file()]


def _file_has_bytes(path: Path, needle: bytes) -> bool:
    try:
        return needle in path.read_bytes()
    except OSError:
        return False


def test_no_plaintext_stub_password_at_rest(
    admin_auth: httpx.Client,
    user_auth: Callable[..., UserSession],
) -> None:
    """After a user stored the stub credentials, ``data/users/**`` carries no
    plaintext of the stub password (only ciphertext must exist)."""
    created = create_user_via_admin(admin_auth, "At Rest Probe")
    session = user_auth(created["login_key"], created["id"])
    body: dict[str, Any] = {
        "name": "Stub",
        "host": STUB_IMAP_HOST,
        "port": STUB_IMAP_PORT,
        "user": STUB_IMAP_USER,
        "password": STUB_IMAP_PASSWORD,
        "tls": False,
    }
    added = session.client.post("/api/me/accounts", json=body)
    assert added.status_code == 201, f"account add failed: {added.status_code} {added.text}"

    needle = STUB_IMAP_PASSWORD.encode("utf-8")
    offenders = [path for path in _user_files() if _file_has_bytes(path, needle)]
    assert not offenders, (
        f"plaintext stub password found in {offenders} — the at-rest encryption invariant is broken"
    )


def test_no_plaintext_keys_at_rest() -> None:
    """No file under ``data/users/`` contains a plaintext ``usr_``/``adm_``
    key (hashes are records like ``scrypt$...``; wrapped AEKs are base64)."""
    offenders: list[tuple[Path, str]] = []
    for path in _user_files():
        try:
            text = path.read_text("utf-8", errors="ignore")
        except OSError:
            continue
        match = _PLAINTEXT_KEY_PATTERN.search(text)
        if match is not None:
            offenders.append((path, match.group(0)[:12]))
    assert not offenders, f"plaintext key material found at rest: {offenders}"


def test_no_plaintext_aek_hex_at_rest() -> None:
    """No file under ``data/users/`` carries a bare 64-hex-char blob.

    The AEK is stored wrapped (base64 AES-GCM blob inside ``user.json``'s
    ``aek`` member); a bare hex string of the right length would mean the
    plaintext leaked to disk. The session keyfile (``.key``) is the only
    legitimate hex carrier and must not exist outside a live session.
    """
    offenders: list[tuple[Path, str]] = []
    for path in _user_files():
        try:
            text = path.read_text("utf-8", errors="ignore")
        except OSError:
            continue
        match = _AEK_HEX_PATTERN.search(text)
        if match is not None:
            offenders.append((path, match.group(0)[:12]))
    assert not offenders, f"bare 64-hex blob (possible plaintext AEK) found at rest: {offenders}"


def test_no_session_keyfile_outside_session() -> None:
    """No ``imap-store/.key`` exists while no tool-host session runs.

    The startup sweep removes crash leftovers, so in steady state (this
    test runs before any MCP-session scenario in the same execution —
    alphabetically ``test_at_rest`` < ``test_mcp_gateway``) the keyfile
    must be absent everywhere.
    """
    stray = list(USERS_DIR.glob("*/imap-store/.key")) if USERS_DIR.exists() else []
    assert not stray, f"session keyfile(s) exist outside a session: {stray}"


def test_secret_files_and_directories_are_locked_down(
    admin_auth: httpx.Client,
    user_auth: Callable[..., UserSession],
) -> None:
    """The fs_safe permission discipline, asserted from the host side: the
    admin key hash, the wrap key, and every ``user.json`` are ``0600``;
    the state directories are ``0700``."""
    created = create_user_via_admin(admin_auth, "Mode Probe")
    session = user_auth(created["login_key"], created["id"])
    assert session.client.get("/api/me").status_code == 200
    user_dir = USERS_DIR / created["id"]
    user_json = user_dir / "user.json"
    assert user_json.is_file(), f"missing {user_json}"

    for secret_file in (ADMIN_KEY_HASH, WRAP_KEY_FILE, user_json):
        assert secret_file.is_file(), f"missing {secret_file}"
        mode = S_IMODE(secret_file.stat().st_mode)
        assert mode == 0o600, f"{secret_file} is mode {mode:04o}, expected 0600"

    # The per-user state directory is created by the gateway through the
    # fs_safe discipline (0700). The tree's top-level dirs are prepared by
    # the harness itself (they must be writable for the container to start)
    # and are deliberately not part of the product's mode contract.
    user_dir_mode = S_IMODE(user_dir.stat().st_mode)
    assert user_dir_mode == 0o700, f"{user_dir} is mode {user_dir_mode:04o}, expected 0700"
