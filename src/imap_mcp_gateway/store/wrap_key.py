"""Persistence and process bootstrap for the server wrap key (M04-T01).

The server wrap key at ``DATA_DIR/config/wrap.key`` is the AES-256 key every
per-user AEK blob is wrapped under (M04 design): generated on first startup,
persisted through the fs-safe primitives (mode ``0600`` inside the ``0700``
config directory), and installed into
:mod:`imap_mcp_gateway.crypto.wrap`'s single in-memory holder exactly once
per process — after that first install, wrap/unwrap serve from memory and
this store performs no further file reads.

Unlike the admin key, the wrap key is never displayed and never logged: it
is not an operator credential but server-side encryption material. Deleting
the file is therefore a full account-crypto wipe, and the startup gate fails
fast rather than papering over it: with wrapped AEKs on disk (``user.json``
``aek`` blobs), a missing or invalid wrap key aborts startup with a clear
error instead of silently minting a key that cannot open the existing
blobs. Only when no wrapped AEKs exist anywhere is regenerating over
invalid file content safe, and the gate does exactly that.
"""

from __future__ import annotations

import json
import os
import re
from collections import namedtuple

from imap_mcp_gateway.config.paths import Paths
from imap_mcp_gateway.crypto import wrap
from imap_mcp_gateway.crypto.keys import generate_wrap_key
from imap_mcp_gateway.store.fs_safe import read_secret_file, write_secret_file

_WRAP_KEY_RE = re.compile(r"[0-9a-f]{64}")
"""The file holds exactly the generated material: 64 lowercase hex chars."""

EnsureWrapResult = namedtuple("EnsureWrapResult", "created")
"""Result of ``ensure_wrap_key``: ``created`` is True iff this call minted
and persisted a fresh wrap key (first boot, or corruption recovery with no
wrapped AEKs anywhere). No field ever carries key material — unlike the
admin key there is no one-time display, so there is no channel for it."""


class WrapKeyCorruptedError(RuntimeError):
    """``wrap.key`` exists but is unreadable or does not hold a valid key.

    Raised by ``ensure_wrap_key`` at startup. With wrapped AEKs on disk the
    error is terminal: the wrap key is pure encryption material with no
    operator display and no reset that preserves accounts — the only remedy
    is restoring the file from backup. (Without wrapped AEKs, invalid file
    content protects nothing and is regenerated instead — see
    ``ensure_wrap_key``.)
    """


class WrapKeyUnavailableError(RuntimeError):
    """``wrap.key`` is missing while wrapped AEKs exist on disk.

    Deleting the wrap key is a full account-crypto wipe: every persisted
    ``user.json`` ``aek`` blob is undecryptable without it. Startup must not
    pretend all is well by minting a fresh key that cannot open any existing
    blob, so this error names the wipe and the restore-from-backup remedy.
    """


def wrapped_account_keys_exist(paths: Paths) -> bool:
    """Return ``True`` iff any user record carries a wrapped AEK.

    Reads each ``DATA_DIR/users/<userId>/user.json`` at the JSON level and
    treats a present, non-null ``aek`` field as a wrapped AEK (M04-T02
    persists the wrap blob there; M03 records hold ``null`` or absent).
    Fail-closed by design: a user record that exists but cannot be read,
    parsed, or shape-checked as a JSON object (which real records always
    are) counts as MAY-hold-a-wrapped-AEK, so the wipe guard below can
    never be bypassed by a corrupted registry — the safe direction for a
    guard whose false negative would silently destroy account crypto.
    Entries under ``users/`` that are not user-record directories are
    skipped (parity with ``store.users.list_users``).
    """
    users_root = paths.users_dir()
    if not users_root.is_dir():
        return False
    for entry in users_root.iterdir():
        record_path = entry / "user.json"
        if not entry.is_dir() or not os.path.lexists(record_path):
            continue
        try:
            data = json.loads(read_secret_file(record_path))
        except (OSError, ValueError):
            # Unreadable or unparseable record: assume it may hold a wrapped
            # AEK. (UnicodeDecodeError and JSONDecodeError are ValueError
            # subclasses; OSError covers unreadable/non-regular entries.)
            return True
        if not isinstance(data, dict) or data.get("aek") is not None:
            # A JSON non-object is not a shape the gateway ever writes —
            # corruption/tampering, so fail closed like a parse failure.
            return True
    return False


def ensure_wrap_key(paths: Paths) -> EnsureWrapResult:
    """Idempotent startup gate for the server wrap key (M04-T01).

    Wired into the app lifespan immediately after the admin-key ensure.
    Exactly one outcome per call on a fresh process:

    - Holder already loaded (an earlier call in this process): return
      ``(created=False,)`` without touching the filesystem — the
      single-holder invariant means no per-operation file reads after the
      first load, and an operator deleting the file mid-process cannot flip
      live wrapping onto a different key.
    - No ``wrap.key`` on disk: with wrapped AEKs present this is the
      deletion-as-wipe case and raises :class:`WrapKeyUnavailableError`;
      otherwise mint via ``crypto.keys.generate_wrap_key``, persist
      atomically at mode ``0600``, install the holder, return
      ``(created=True,)``.
    - ``wrap.key`` present: read it and install. Content must be exactly 64
      lowercase hex chars (surrounding whitespace tolerated for operator
      edits). Unreadable path entries (a directory, a dangling symlink or
      symlink loop at the path — present-but-invalid per
      ``os.path.lexists``, never absence) always raise
      :class:`WrapKeyCorruptedError`, like the admin-key gate. Invalid
      CONTENT raises too when wrapped AEKs exist — a regenerated key could
      not open those blobs — while with no wrapped AEKs anywhere the content
      protects nothing and is regenerated in place, returning
      ``(created=True,)``.

    The remediation in every error message is restoring the file from
    backup, never deletion: deleting the wrap key wipes all account
    encryption. Known limit (within this task's scope): a restored backup
    with the RIGHT shape but WRONG bytes passes this gate — the mismatch
    only surfaces at the first AEK unwrap, which fails closed with
    ``UnwrapError``; once M04-T02 provides the unwrap API, this gate can
    opportunistically self-check against a persisted blob. Single-process
    assumption, same as every other store helper: one gateway process per
    ``DATA_DIR`` (uvicorn, single worker).
    """
    if wrap.wrap_key_is_loaded():
        return EnsureWrapResult(created=False)
    key_path = paths.wrap_key_path()
    if not os.path.lexists(key_path):
        if wrapped_account_keys_exist(paths):
            raise WrapKeyUnavailableError(
                f"wrap key file {key_path} is missing but wrapped account keys "
                f"exist under {paths.users_dir()}; deleting the wrap key is an "
                "account-crypto wipe — restore the file from backup instead of "
                "booting without it"
            )
        return _create_and_install(paths)
    try:
        raw = read_secret_file(key_path)
    except OSError as exc:
        # A directory / unreadable entry / dangling symlink at the path is
        # present-but-invalid; regeneration cannot cleanly fix the entry
        # (os.replace over a directory fails, over a symlink it would
        # silently clobber the link), so this fails loud regardless of the
        # wrapped-AEK state.
        raise WrapKeyCorruptedError(
            f"unreadable wrap key file at {key_path}: cannot be read as a "
            "regular file; restore it from backup"
        ) from exc
    try:
        key_hex = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        key_hex = ""  # non-ASCII content is corruption like any other invalid content
    if _WRAP_KEY_RE.fullmatch(key_hex) is None:
        if wrapped_account_keys_exist(paths):
            raise WrapKeyCorruptedError(
                f"corrupted wrap key at {key_path}: not a valid 64-hex-character "
                f"key, and wrapped account keys exist under {paths.users_dir()} — "
                "a regenerated key could not open their wrapped AEKs; restore "
                "the file from backup"
            )
        # No wrapped AEKs anywhere: the invalid content protects nothing.
        return _create_and_install(paths)
    wrap.load_wrap_key(key_hex)
    return EnsureWrapResult(created=False)


def _create_and_install(paths: Paths) -> EnsureWrapResult:
    """Mint, persist (atomic, mode ``0600``) and install a fresh wrap key."""
    key_hex = generate_wrap_key()
    write_secret_file(paths.wrap_key_path(), key_hex.encode("ascii"))
    wrap.load_wrap_key(key_hex)
    return EnsureWrapResult(created=True)
