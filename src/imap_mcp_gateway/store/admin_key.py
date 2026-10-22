"""Persistence for the root administration key's hash record (M02).

Only the scrypt record produced by :mod:`imap_mcp_gateway.crypto.hash` ever
touches disk — the plaintext admin key exists exactly once in memory between
``crypto.keys.generate_admin_key()`` and the one-time log display (M02-T02)
and is never persisted. Deleting ``admin-key.hash`` is the supported reset
path: the next startup then behaves as first boot.

All file work goes through the fs-safe primitives, so the record is written
atomically with mode ``0600`` inside a ``0700`` config directory.
"""

from __future__ import annotations

import os
import re
from collections import namedtuple
from pathlib import Path

from imap_mcp_gateway.config.paths import Paths
from imap_mcp_gateway.crypto.hash import hash_secret, is_valid_record
from imap_mcp_gateway.crypto.keys import generate_admin_key
from imap_mcp_gateway.store.fs_safe import read_secret_file, write_secret_file

_RECORD_PREFIX_RE = re.compile(r"[a-z0-9]+\$")
"""Records start with a lowercase algorithm identifier, e.g. ``scrypt$...``."""


def load_admin_key_hash(paths: Paths) -> str | None:
    """Return the stored hash record, or ``None`` if no hash file exists.

    Presence is checked with :func:`os.path.lexists`, so a dangling symlink
    or symlink loop at the path is a present (not absent) entry whose read
    then fails with ``OSError`` — never a silent "absent". Surrounding
    whitespace is stripped so an operator edit (e.g. a trailing newline)
    cannot break verification. A file that exists but holds no record reads
    as absent — for this loader only; the startup lifecycle
    (:func:`ensure_admin_key`) gates stricter: any present-but-invalid file
    (empty, garbage, non-ASCII, a structurally invalid record, or a
    broken/unreadable symlink entry) raises
    a fatal :class:`AdminKeyHashCorruptedError` there.
    """
    hash_path = paths.admin_key_hash_path()
    if not os.path.lexists(hash_path):
        return None
    record = read_secret_file(hash_path).decode("ascii").strip()
    return record or None


def save_admin_key_hash(paths: Paths, key_hash: str) -> Path:
    """Persist ``key_hash`` — a ``crypto.hash`` record — to ``admin-key.hash``.

    Raises ``ValueError`` when ``key_hash`` does not look like a serialized
    hash record: records are ASCII and start with a lowercase algorithm
    identifier plus ``$`` (``scrypt$...`` today, ``argon2id$...`` later — the
    store stays format-agnostic), while plaintext ``adm_``/``usr_`` keys and
    other accidental payloads never do. This is the last line of defence
    against persisting plaintext key material.
    """
    if not key_hash.isascii() or _RECORD_PREFIX_RE.match(key_hash) is None:
        raise ValueError("refusing to persist non-hash data: plaintext key material?")
    return write_secret_file(paths.admin_key_hash_path(), key_hash.encode("ascii"))


def admin_key_exists(paths: Paths) -> bool:
    """Return ``True`` iff a path entry exists at ``admin-key.hash``.

    Uses :func:`os.path.lexists` so a dangling symlink or symlink loop at
    the path counts as present — :func:`ensure_admin_key` then fails loud
    on that present-but-invalid entry instead of treating it as absent.
    """
    return os.path.lexists(paths.admin_key_hash_path())


EnsureResult = namedtuple("EnsureResult", "created plaintext")
"""Result of :func:`ensure_admin_key`.

``created`` is ``True`` iff this call performed the first-boot creation;
``plaintext`` carries the freshly minted admin key on that one call and is
``None`` on every other call. Per the single-display invariant (M02-T02) only
the caller's immediate logging site — the startup lifespan in
:mod:`imap_mcp_gateway.app` — may ever format ``plaintext``.
"""


class AdminKeyHashCorruptedError(RuntimeError):
    """``admin-key.hash`` exists but holds no readable valid record.

    Raised by :func:`ensure_admin_key` at startup: the gateway only ever
    writes ASCII scrypt records here, so anything else — corrupted, garbage,
    non-ASCII, or a non-regular/unreadable path — means external corruption
    or tampering. Deleting the file is the supported reset — the next
    startup then behaves as first boot.
    """


def ensure_admin_key(paths: Paths) -> EnsureResult:
    """Idempotent startup gate for the admin key (M02-T02).

    First boot — no ``admin-key.hash`` file on disk: mint a key via
    :func:`imap_mcp_gateway.crypto.keys.generate_admin_key`, persist ONLY its
    scrypt record, and return ``(True, plaintext)``. The plaintext is handed
    to the caller exactly once for the one-time log display; it must never be
    persisted or logged anywhere else. Any later call — a valid record exists
    — returns ``(False, None)`` without touching key material.

    Corrupted hash files fail loud at startup — the deliberate lifecycle
    decision. A present path that holds no readable record (empty or
    whitespace-only, ASCII garbage, bytes that do not decode as ASCII, or a
    non-regular/unreadable file — including a dangling symlink or symlink
    loop at the path) raises :class:`AdminKeyHashCorruptedError`
    naming the file and the reset action, instead of being treated as absent
    or existing. Rationale: the gateway only ever writes ASCII-validated
    records (``save_admin_key_hash``), so such content means external
    corruption or tampering; treating it as absent would silently rotate the
    admin key — a credential replacement whose new plaintext lands in the
    logs while masking the cause — and treating garbage as existing would
    report a healthy boot while admin auth can never succeed again. The
    supported reset stays the operator's explicit deletion of the file. Gate
    boundary (full validation since M02-T03): a present record must fully
    validate via :func:`imap_mcp_gateway.crypto.hash.is_valid_record` — the
    strict structural parse and scrypt parameter bound that
    ``verify_secret`` applies before its KDF — so the startup gate and the
    auth gate are symmetric and an attacker-influenced record with inflated
    parameters can never reach the KDF on either path. Anything invalid is
    external corruption or tampering (the gateway only ever writes fully
    valid records) and fails loud here with the delete-to-reset remediation,
    exactly like the other invalid shapes.

    Deleting ``admin-key.hash`` is the supported reset path: the next call
    then behaves as first boot with a fresh key. All other state under
    ``DATA_DIR`` (user registry, wrap key) is outside this function's write
    scope and is never read or modified here. Single-process assumption: the
    exists→create sequence is not guarded against concurrent boots sharing
    one ``DATA_DIR`` — the gateway is deployed as one process per data dir
    (uvicorn, single worker), the same assumption every other store helper
    makes.
    """
    hash_path = paths.admin_key_hash_path()
    # lexists, not exists: a dangling symlink or symlink loop at the path
    # follows to nothing (Path.exists() is False there) — reading it as
    # absent would silently rotate the key; it must take the present-but-
    # invalid route below instead of the first-boot branch.
    if not os.path.lexists(hash_path):
        plaintext = generate_admin_key()
        save_admin_key_hash(paths, hash_secret(plaintext))
        return EnsureResult(created=True, plaintext=plaintext)
    try:
        stored = load_admin_key_hash(paths)
    except UnicodeDecodeError as exc:
        raise AdminKeyHashCorruptedError(
            f"corrupted admin key hash at {hash_path}: bytes are not ASCII; "
            "delete the file to reset"
        ) from exc
    except OSError as exc:
        # e.g. config/admin-key.hash is a directory (bind-mount/restore
        # mistake), unreadable, or a dangling symlink / symlink loop —
        # same remediation, actionable message.
        raise AdminKeyHashCorruptedError(
            f"corrupted admin key hash at {hash_path}: cannot be read as a "
            "regular file; delete the file to reset"
        ) from exc
    if stored is None or not is_valid_record(stored):
        raise AdminKeyHashCorruptedError(
            f"corrupted admin key hash at {hash_path}: not a valid hash record; "
            "delete the file to reset"
        )
    return EnsureResult(created=False, plaintext=None)
