"""Session-scoped materialization of the upstream ``.key`` file (M04-T03).

The vendored upstream ``AccountManager`` reads its AES key from
``<HOME>/.imap-mcp/.key`` (a 64-character hex file, mode ``0600``). The
gateway, however, keeps every AEK wrapped at rest (``user.json.aek``, M04-T02)
— so for the lifetime of ONE tool-host session (M05) the user's AEK hex is
materialized at ``DATA_DIR/users/<userId>/imap-store/.key`` (the directory the
M05 session exposes as the child's upstream store), and removed again when the
session ends. At rest the AEK exists only in wrapped form; the plaintext
touches disk only inside this session window.

Crash safety: a gateway kill between materialize and cleanup would leave an
orphaned plaintext key on disk forever — so the startup path runs
:func:`sweep_orphan_key_files`, which deletes every ``imap-store/.key`` found
under ``DATA_DIR/users`` before the HTTP listener starts (a key file has no
legitimate reason to exist while no session is running). Wired in ``app.py``'s
boot lifespan, mirroring the admin/wrap-key ensures.

Writes go through :func:`imap_mcp_gateway.store.fs_safe.write_secret_file`
(temp file + ``os.replace``, mode ``0600`` in a ``0700`` directory); the file
content is exactly the hex spelling with no trailing newline, byte-identical
to what upstream itself writes.
"""

from __future__ import annotations

from pathlib import Path

from imap_mcp_gateway.config.paths import Paths
from imap_mcp_gateway.store.fs_safe import write_secret_file
from imap_mcp_gateway.store.upstream_format import parse_aek_hex

KEY_FILE_NAME = ".key"
"""The upstream key-file name inside the per-user ``imap-store`` directory."""

_IMAP_STORE_DIR_NAME = "imap-store"


def key_file_path(paths: Paths, user_id: str) -> Path:
    """Validated ``DATA_DIR/users/<userId>/imap-store/.key`` (traversal-safe)."""
    return paths.user_imap_store_dir(user_id) / KEY_FILE_NAME


def materialize_key_file(paths: Paths, user_id: str, aek_hex: str) -> Path:
    """Write the user's AEK hex to the session ``.key`` file; return its path.

    The hex is validated (64 lowercase-hex chars = 32 raw bytes) before
    anything touches disk, then written atomically with mode ``0600`` (the
    ``imap-store`` directory is created ``0700`` if missing). Re-materializing
    for a new session overwrites atomically — readers see old or new content,
    never a partial file. Callers hold the returned path only for the session
    and MUST pair it with :func:`cleanup_key_file`.
    """
    parse_aek_hex(aek_hex)  # fail before creating anything on invalid material
    path = key_file_path(paths, user_id)
    write_secret_file(path, aek_hex.encode("ascii"))
    return path


def cleanup_key_file(paths: Paths, user_id: str) -> None:
    """Remove the session ``.key`` file; idempotent, missing-safe.

    Removes exactly the ``.key`` file and nothing else; a missing file or a
    user directory that never had a store is a silent no-op so teardown paths
    can run unconditionally.
    """
    key_file_path(paths, user_id).unlink(missing_ok=True)


def sweep_orphan_key_files(paths: Paths) -> list[str]:
    """Delete every orphaned ``imap-store/.key``; return the swept user ids.

    Startup sweep for crash leftovers: a ``.key`` has no legitimate reason to
    exist while no tool-host session is running, so each one found under
    ``DATA_DIR/users/<userId>/imap-store/`` is deleted (never the rest of the
    store). Users without a key file — and non-directory entries in
    ``users/`` — are left untouched. A missing ``users/`` root sweeps nothing.
    """
    swept: list[str] = []
    users_root = paths.users_dir()
    if not users_root.is_dir():
        return swept
    for entry in sorted(users_root.iterdir()):
        if not entry.is_dir():
            continue
        key_path = entry / _IMAP_STORE_DIR_NAME / KEY_FILE_NAME
        if key_path.is_file():
            key_path.unlink()
            swept.append(entry.name)
    return swept
