"""AEK rotation with full re-encryption of the user's credential stores (M04-T02).

Rotation mints a fresh AEK, hands the (user, old, new) hex triple to every
registered re-encryption participant, then rewraps the record's ``aek`` blob
and persists — the new plaintext hex is returned exactly once (one-time
display) and the old AEK is destroyed (zeroized, best-effort).

Participants register with :func:`register_reencrypt_hook`. Until M04-T03
the registry is empty and rotation only rewraps the blob — correct, because
no AEK-encrypted credential fields exist yet. M04-T03's encrypted account
store (``store.accounts.reencrypt_all``) becomes the first participant,
making "re-encrypt every credential field of the user's store" concrete
without further changes to :func:`rotate_aek`.

Ordering / failure contract: the new blob is wrapped BEFORE any store is
touched; hooks then re-encrypt their stores under the new key, and the
rewrapped record is persisted LAST. A failing hook therefore aborts
rotation with the persisted blob still under the old AEK; any store
re-encrypted by an earlier participant is left under the new AEK — the
same residual window described below. Each hook must be atomic per
store (temp file + ``os.replace``, the ``fs_safe`` discipline) so a
failure inside one participant cannot half-apply its own store.
Residual window (documented, unavoidable without cross-file
transactions): if the final persist fails AFTER a hook has re-encrypted
its store, that store is under the new AEK while ``user.json`` still
wraps the old one — unrecoverable in-process (the new plaintext was
neither displayed nor persisted). With M04-T03's single per-user store
this window is one atomic replace wide.

This module reuses the user-record I/O primitives of
:mod:`imap_mcp_gateway.store.users` (intra-package imports of ``_require``
and ``_save``): it is the AEK lifecycle sibling of that module, and every
``user.json`` write must stay on the single ``_save`` path (plaintext-
refusal check, atomic replace, mode ``0600``).
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable

from imap_mcp_gateway.config.paths import Paths
from imap_mcp_gateway.crypto.aek import create_aek, unwrap_aek, wrap_aek, zeroize_aek
from imap_mcp_gateway.store.user_schema import UserRecord, WrappedAEK
from imap_mcp_gateway.store.users import AEKNotActiveError, _require, _save

ReencryptHook = Callable[[Paths, str, str, str], None]
"""A rotation participant: ``hook(paths, user_id, old_aek_hex, new_aek_hex)``.

Must re-encrypt every AEK-encrypted credential field of the named user's
store from the old key to the new one, atomically per store, and raise on
any failure (aborting the rotation before the rewrap is persisted).
"""

_REENCRYPT_HOOKS: list[ReencryptHook] = []
"""Ordered re-encryption participants; M04-T03's account store registers here.

Module-global like ``crypto.wrap``'s key holder: populated once at import
time by the stores that own AEK-encrypted fields, read on every rotation.
"""


def register_reencrypt_hook(hook: ReencryptHook) -> Callable[[], None]:
    """Register a credential-store re-encryption participant (M04-T03 wiring).

    Returns an idempotent ``unregister()`` callable, mainly for tests.
    """
    _REENCRYPT_HOOKS.append(hook)

    def unregister() -> None:
        with contextlib.suppress(ValueError):
            _REENCRYPT_HOOKS.remove(hook)

    return unregister


def rotate_aek(paths: Paths, user_id: str) -> str:
    """Rotate the user's AEK; return the new plaintext hex exactly once.

    Mints a fresh AEK (:func:`imap_mcp_gateway.crypto.aek.create_aek`),
    re-encrypts every registered credential store from the old key to the
    new one, rewraps the record's ``aek`` blob under the server wrap key and
    persists atomically. The new plaintext hex exists exactly once — this
    return value, for the caller's one-time display; the old AEK is
    destroyed (zeroized, best-effort) and no longer decrypts anything.

    A user without an activated AEK raises :class:`AEKNotActiveError`
    (activation is lazy and must come first); a missing user raises
    ``FileNotFoundError``. A failing re-encryption hook aborts the rotation
    with the old AEK still authoritative; a persist failure after a hook
    has re-encrypted leaves that store under the new AEK (the documented
    residual window — see the module docstring).
    """
    record = _require(paths, user_id)
    if record.aek is None:
        raise AEKNotActiveError(
            f"user {user_id!r} has no activated account-encryption key; "
            "activate it before rotating"
        )
    old = bytearray(unwrap_aek(record.aek.blob))
    new = bytearray(create_aek())
    old_hex = bytes(old).hex()
    new_hex = bytes(new).hex()
    try:
        new_blob = wrap_aek(bytes(new))  # wrapped before any store is touched
        for hook in tuple(_REENCRYPT_HOOKS):
            hook(paths, user_id, old_hex, new_hex)
        data = record.model_dump()
        data["aek"] = WrappedAEK(blob=new_blob)
        _save(paths, UserRecord.model_validate(data))
    finally:
        zeroize_aek(old)
        zeroize_aek(new)
    return new_hex
