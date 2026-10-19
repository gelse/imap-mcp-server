"""Per-user registry store over ``DATA_DIR/users/<userId>/user.json`` (M03).

Lifecycle mirror of the admin-key store (:mod:`imap_mcp_gateway.store.admin_key`):
a login key is minted by :func:`imap_mcp_gateway.crypto.keys.generate_user_key`
and exists as plaintext exactly once — in the return value of
:func:`create_user` / :func:`rotate_login_key`. Only its scrypt record
(:func:`imap_mcp_gateway.crypto.hash.hash_secret`, fresh per-key salt) is
ever persisted, inside the strict
:class:`imap_mcp_gateway.store.user_schema.UserRecord`. All writes are atomic
and mode ``0600`` via :func:`imap_mcp_gateway.store.fs_safe.write_secret_file`
inside ``0700`` directories.

The AEK (M04-T02) follows the same one-time-disclosure discipline:
:func:`activate_aek` wraps the freshly minted key under the server wrap key
(:mod:`imap_mcp_gateway.crypto.aek`) and returns the plaintext hex exactly
once, for the caller's one-time display to the user — the admin never sees
it. :func:`with_aek` unwraps the persisted blob in memory for a callback and
zeroizes the buffer afterwards. AEK and login key are fully independent:
minting the AEK involves no login-key material, and regenerating the login
key never touches the AEK blob. Rotation (with full re-encryption of the
user's credential stores) lives in
:mod:`imap_mcp_gateway.store.aek_rotation`.

Layout — one directory per user, so M04's encrypted stores later sit next to
the identity state:

::

    DATA_DIR/users/<userId>/user.json

User ids: :func:`create_user` mints one (``uuid4().hex`` — lowercase hex,
always registry-valid, collision-checked against existing directories), and
every other API routes the caller's id through ``Paths.user_record_path``,
which rejects traversal-shaped ids before any path is built.

Listing is credential-free by construction: :func:`list_users` projects each
record to :class:`imap_mcp_gateway.store.user_schema.UserMetadata`, which has
no ``login_key_hash`` field at all, so no hash material can appear in a
listing (M03-T01 acceptance: "``list_users()`` returns metadata only (no
hashes)"). The full record — hash included — stays reachable through
:func:`get_user`, the internal accessor for flows that must touch the stored
scrypt record (M03-T04's ``authenticate_user_key`` walks active users
comparing hashes); M03-T02's response serializer is the HTTP boundary that
projects records to the same metadata shape.

Single-process assumption, same as every other store helper: one gateway
process per ``DATA_DIR`` (uvicorn, single worker); exists→create / load→save
sequences are not guarded against concurrent writers.
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from imap_mcp_gateway.config.paths import Paths
from imap_mcp_gateway.crypto.aek import create_aek, unwrap_aek, wrap_aek, zeroize_aek
from imap_mcp_gateway.crypto.hash import hash_secret, verify_secret
from imap_mcp_gateway.crypto.keys import generate_user_key
from imap_mcp_gateway.store.fs_safe import read_secret_file, write_secret_file
from imap_mcp_gateway.store.user_schema import UserMetadata, UserRecord, WrappedAEK

_ID_MINT_ATTEMPTS = 5
"""Retries for the astronomically unlikely uuid4 directory collision."""

_MUTABLE_FIELDS = frozenset({"name", "status", "account_count"})
"""Fields :func:`update_user` may change. Identity (``id``, ``created_at``)
and credential state (``login_key_hash``, ``key_generation``) change only
through their dedicated flows, and ``aek`` keeps its dedicated M04-T02
flows (:func:`activate_aek` here, rotation in
:mod:`imap_mcp_gateway.store.aek_rotation`)."""


class AEKAlreadyActiveError(RuntimeError):
    """:func:`activate_aek` was called for a user whose AEK is already active.

    Deliberately loud: re-activation must never silently replace the key
    that existing account ciphertext depends on. Replacing an active AEK is
    rotation's job (:func:`imap_mcp_gateway.store.aek_rotation.rotate_aek`),
    which re-encrypts every credential store under the new key.
    """


class AEKNotActiveError(RuntimeError):
    """The user has no activated AEK yet — lazy activation has not happened.

    Raised by :func:`with_aek` and rotation when ``user.json.aek`` is still
    ``None``: activation is lazy (first account-add or an explicit user
    action, wired in M04-T04), so code must not assume a key exists.
    """


def _record_path(paths: Paths, user_id: str) -> Path:
    """Validated ``DATA_DIR/users/<userId>/user.json`` (traversal-safe)."""
    return paths.user_record_path(user_id)


def _load(paths: Paths, user_id: str) -> UserRecord | None:
    """Load and schema-validate a record; ``None`` only when truly absent.

    Presence uses :func:`os.path.lexists` (parity with the admin-key store):
    a dangling symlink or symlink loop at the path is present-but-unreadable
    and fails on the read, never a silent ``None``. A present-but-invalid or
    unreadable file raises (pydantic ``ValidationError`` / ``OSError``) —
    fail loud, like the admin-key store: the gateway only ever writes
    schema-valid records, so anything else is corruption or tampering.
    """
    record_path = _record_path(paths, user_id)
    if not os.path.lexists(record_path):
        return None
    return UserRecord.model_validate_json(read_secret_file(record_path))


def _require(paths: Paths, user_id: str) -> UserRecord:
    """Load a record that MUST exist, or raise ``FileNotFoundError``."""
    record = _load(paths, user_id)
    if record is None:
        raise FileNotFoundError(f"no user record for id {user_id!r}")
    return record


def _save(paths: Paths, record: UserRecord) -> None:
    """Persist ``record`` atomically (mode ``0600``) at its id's path.

    Last line of defence, mirroring ``admin_key.save_admin_key_hash``: the
    schema already rejects plaintext-shaped ``login_key_hash`` values on
    every construction and load; the write refuses to proceed if one appears
    anyway.
    """
    if record.login_key_hash.startswith(("adm_", "usr_")):
        raise ValueError("refusing to persist non-hash data: plaintext key material?")
    write_secret_file(_record_path(paths, record.id), record.model_dump_json().encode("utf-8"))


def _mint_user_id(paths: Paths) -> str:
    """Return a fresh registry-valid id whose user directory does not exist."""
    for _ in range(_ID_MINT_ATTEMPTS):
        candidate = uuid4().hex
        if not paths.user_dir(candidate).exists():
            return candidate
    raise RuntimeError(
        "could not mint a unique user id after repeated collisions; "
        "DATA_DIR/users looks inconsistent"
    )


def create_user(paths: Paths, name: str) -> tuple[UserRecord, str]:
    """Create a registry user; return ``(record, plaintext_login_key)``.

    The plaintext key (``usr_`` + 32 random bytes base64url) exists exactly
    once — in this return value, for the caller's one-time display. Only its
    scrypt record is persisted. Schema defaults apply: ``key_generation``
    1, ``status`` ``"active"``, no AEK, zero accounts. An invalid ``name``
    raises before anything is written.
    """
    plaintext = generate_user_key()
    record = UserRecord(
        id=_mint_user_id(paths),
        name=name,
        created_at=datetime.now(UTC),
        login_key_hash=hash_secret(plaintext),
    )
    _save(paths, record)
    return record, plaintext


def get_user(paths: Paths, user_id: str) -> UserRecord | None:
    """Return the user's full record — credential hash included — or ``None``.

    This is the internal hash-carrying accessor: the only listing surface is
    :func:`list_users` (credential-free), while flows that must touch the
    stored scrypt record load it here — admin detail/management and M03-T04's
    ``authenticate_user_key``, which walks active users comparing hashes.
    HTTP layers must never serialize this record directly (M03-T02's
    serializer projects to the metadata shape instead).
    """
    return _load(paths, user_id)


def list_users(paths: Paths) -> list[UserMetadata]:
    """Return every stored user's metadata, sorted by id — no hashes.

    Metadata only, by construction: each record is loaded through the strict
    schema (fail-loud on invalid record content) and projected to
    :class:`imap_mcp_gateway.store.user_schema.UserMetadata`, which has no
    ``login_key_hash`` field at all — hash material cannot appear in a
    listing (M03-T01 acceptance: "``list_users()`` returns metadata only (no
    hashes)"). Entries under ``DATA_DIR/users`` that are not user-record
    directories (stray files, or directories without a readable
    ``user.json`` — a dangling symlink at that name is skipped too, not
    treated as corruption) are skipped rather than fatal: the directory is a
    collection, and a stray entry must not take the registry listing down.
    Unlike :func:`get_user` (present-but-unreadable is a loud error there),
    listing stays best-effort; it is not an auth gate.
    """
    users_root = paths.users_dir()
    if not users_root.is_dir():
        return []
    users: list[UserMetadata] = []
    for entry in sorted(users_root.iterdir()):
        record_path = entry / "user.json"
        if entry.is_dir() and record_path.is_file():
            record = UserRecord.model_validate_json(read_secret_file(record_path))
            users.append(UserMetadata.from_record(record))
    return users


def update_user(paths: Paths, user_id: str, patch: Mapping[str, Any]) -> UserRecord:
    """Apply a whitelisted metadata patch and persist the result atomically.

    Only ``name``, ``status`` and ``account_count`` are patchable — see
    :data:`_MUTABLE_FIELDS`. Unknown or non-whitelisted keys raise
    ``ValueError`` BEFORE anything is read or written, so a patch can never
    touch identity or credential fields (a plaintext value in
    ``login_key_hash`` is unreachable through this path). The merged record
    is re-validated through the strict schema, so a schema-invalid value
    (e.g. an empty name) also raises without writing.
    """
    unknown = set(patch) - _MUTABLE_FIELDS
    if unknown:
        raise ValueError(f"fields not patchable: {sorted(unknown)}")
    record = _require(paths, user_id)
    data = record.model_dump()
    data.update(patch)
    updated = UserRecord.model_validate(data)
    _save(paths, updated)
    return updated


def delete_user(paths: Paths, user_id: str) -> None:
    """Remove the user's whole directory — recursive and destructive.

    Per the M03 design this also removes anything later kept next to the
    record (M04 encrypted stores); deletion is an explicit admin action with
    no undo. A missing user raises ``FileNotFoundError``.
    """
    user_directory = paths.user_dir(user_id)  # validates the id first
    if not user_directory.exists():
        raise FileNotFoundError(f"no user directory for id {user_id!r}")
    shutil.rmtree(user_directory)


def verify_login_key(paths: Paths, user_id: str, presented: str) -> bool:
    """Constant-time check of ``presented`` against the stored hash.

    Never raises and never leaks existence through an exception: users that
    do not exist, ids that are registry-invalid, users that are ``disabled``,
    and present-but-unreadable record files (a directory or drifted
    permissions at ``user.json``) all fail closed with ``False``.
    Verification itself delegates to
    :func:`imap_mcp_gateway.crypto.hash.verify_secret`.
    """
    try:
        record = _load(paths, user_id)
    except (ValueError, OSError):
        # ValueError: registry-invalid (e.g. traversal-shaped) id — no such
        # user can exist. OSError: a present-but-unreadable record. Either
        # way an auth check fails closed instead of raising.
        return False
    if record is None or record.status != "active":
        return False
    return verify_secret(presented, record.login_key_hash)


def rotate_login_key(paths: Paths, user_id: str) -> tuple[UserRecord, str]:
    """Mint a new login key; return ``(record, plaintext)``.

    Replaces the stored hash, increments ``key_generation``, and returns the
    new plaintext exactly once. The previous key stops authenticating
    immediately — the old hash is atomically replaced. The other fields,
    including ``created_at``, are untouched. A missing user raises
    ``FileNotFoundError``.
    """
    record = _require(paths, user_id)
    plaintext = generate_user_key()
    data = record.model_dump()
    data["login_key_hash"] = hash_secret(plaintext)
    data["key_generation"] = record.key_generation + 1
    updated = UserRecord.model_validate(data)
    _save(paths, updated)
    return updated, plaintext


def activate_aek(paths: Paths, user_id: str) -> str:
    """Mint and persist the user's AEK; return the plaintext hex exactly once.

    Lazy-activation primitive (M04-T02): ``user.json.aek`` stays ``None``
    until this call — the user web UI (M04-T04) invokes it on the first
    account-add or an explicit activation action. The AEK is minted fresh
    from the CSPRNG (:func:`imap_mcp_gateway.crypto.aek.create_aek`, no
    derivation from any stored material — invariant 4) and persisted only
    in wrapped form; the plaintext hex exists exactly once, in this return
    value, for the caller's one-time display. The admin never sees it.

    A user whose AEK is already active raises :class:`AEKAlreadyActiveError`
    — re-activation must never silently replace the key that existing
    account ciphertext depends on (that is rotation's job, with
    re-encryption). A missing user raises ``FileNotFoundError``.
    """
    record = _require(paths, user_id)
    if record.aek is not None:
        raise AEKAlreadyActiveError(
            f"user {user_id!r} already has an activated account-encryption "
            "key; use AEK rotation instead of re-activating"
        )
    aek = bytearray(create_aek())
    plaintext_hex = bytes(aek).hex()
    try:
        data = record.model_dump()
        data["aek"] = WrappedAEK(blob=wrap_aek(bytes(aek)))
        _save(paths, UserRecord.model_validate(data))
    finally:
        zeroize_aek(aek)  # best-effort: see crypto.aek.zeroize_aek
    return plaintext_hex


def with_aek[T](paths: Paths, user_id: str, fn: Callable[[bytearray], T]) -> T:
    """Run ``fn`` with the user's unwrapped AEK; zeroize the buffer afterwards.

    The unwrapped key exists only for the duration of ``fn``: the persisted
    blob is opened under the server wrap key, the raw 32 bytes are handed to
    ``fn`` as a writable ``bytearray``, and the buffer is overwritten with
    zeros in a ``finally`` block — even when ``fn`` raises.

    Zeroization is documented best-effort (Python semantics): the
    ``bytearray`` ``fn`` received is reliably zeroed, but transient
    immutable copies made inside the wrap layer — and any copy ``fn`` itself
    creates (e.g. ``aek.hex()``) — live under the garbage collector's
    control and cannot be scrubbed deterministically. Keep ``fn`` short-lived
    and avoid leaking the buffer into longer-lived objects.

    A user without an activated AEK raises :class:`AEKNotActiveError` (lazy
    activation has not happened yet); a missing user raises
    ``FileNotFoundError``.
    """
    record = _require(paths, user_id)
    if record.aek is None:
        raise AEKNotActiveError(
            f"user {user_id!r} has no activated account-encryption key; "
            "activate it before use"
        )
    aek = bytearray(unwrap_aek(record.aek.blob))
    try:
        return fn(aek)
    finally:
        zeroize_aek(aek)


def disable_user(paths: Paths, user_id: str) -> UserRecord:
    """Set ``status`` to ``disabled``; the key stops authenticating."""
    return update_user(paths, user_id, {"status": "disabled"})


def enable_user(paths: Paths, user_id: str) -> UserRecord:
    """Set ``status`` back to ``active``; the current key works again."""
    return update_user(paths, user_id, {"status": "active"})
