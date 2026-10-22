"""Account-encryption key (AEK) material — mint, wrap, unwrap, zeroize (M04-T02).

Every user owns one dedicated AEK: the key that encrypts their stored
email-account credentials (the encrypted account store itself arrives with
M04-T03). The AEK is deliberately independent of the regenerable user login
key: it is minted here from the CSPRNG directly, and this module imports
nothing from the login-key code paths (``crypto.keys`` / ``crypto.hash``) nor
from any store module. That import discipline is a greppable convention,
enforced by test (M04-T02 invariant 4): the AEK is never derived from, nor
stored in, the persisted credential hash.

Format: 32 random bytes; the lowercase-hex spelling (64 characters) is the
upstream-compatible ``.key`` material the vendored imap-mcp-server expects.
At rest the AEK exists only in wrapped form — an AES-256-GCM blob under the
server wrap key (M04-T01) persisted at ``user.json.aek.blob``. The plaintext
is disclosed exactly once per generation, as the return value of activation
(:func:`imap_mcp_gateway.store.users.activate_aek`) or rotation
(:func:`imap_mcp_gateway.store.aek_rotation.rotate_aek`), and is never
logged, serialized by an API, or persisted.

:func:`zeroize_aek` is the shared best-effort buffer scrub for the AEK
lifecycle: the ``bytearray`` handed to
:func:`imap_mcp_gateway.store.users.with_aek` and the rotation buffers are
overwritten with zeros once no longer needed. Python semantics make this
best-effort only — transient immutable copies (e.g. the ``bytes`` the wrap
layer returns, or the hex strings handed to a caller for one-time display)
live under the garbage collector's control and cannot be scrubbed
deterministically; the M04-T02 contract accepts exactly this caveat.

Pure Python through the pinned ``cryptography`` package only (via the
M04-T01 wrap layer) — nothing here spawns child processes or touches the
environment, so AEK material cannot cross the language boundary into the
vendored npx subprocess. The AEK hex reaches upstream only as the M04-T03
session keyfile content, never through new Node code.
"""

from __future__ import annotations

import secrets

from imap_mcp_gateway.crypto import wrap
from imap_mcp_gateway.crypto.wrap import UnwrapError

_AEK_BYTES = 32
"""AEK size: 256 bits, matching the upstream ``.key`` material (32-byte hex)."""


def create_aek() -> bytes:
    """Return a fresh AEK: 32 CSPRNG bytes.

    The lowercase-hex spelling of the returned bytes (``aek.hex()``, 64
    characters) is the upstream-compatible ``.key`` material. Minted from
    :func:`secrets.token_bytes` directly — no derivation from any stored
    material, which keeps this module import-clean of the login-key code
    paths (M04-T02 invariant 4).
    """
    return secrets.token_bytes(_AEK_BYTES)


def wrap_aek(aek: bytes) -> str:
    """Seal a 32-byte AEK under the server wrap key (M04-T01 AES-256-GCM).

    Returns the ``base64(iv):base64(tag):base64(ciphertext)`` blob persisted
    at ``user.json.aek.blob`` with a fresh random IV per call. A
    wrong-length input raises ``ValueError`` — this is the programming-
    interface check, not a blob-parsing boundary.
    """
    _require_aek_bytes(aek)
    return wrap.wrap_key(aek)


def unwrap_aek(blob: str) -> bytes:
    """Open a :func:`wrap_aek` blob under the installed server wrap key.

    Raises :class:`imap_mcp_gateway.crypto.wrap.UnwrapError` for every
    failure — malformed or non-canonical blob fields, GCM authentication
    failure (any tampered component, or a wrap key restored from the wrong
    backup: the M04-T01 carry-forward — the valid-shape-but-wrong wrap key
    surfaces here as a clear authentication error, never as silently wrong
    bytes), and blobs that authenticate but do not hold exactly 32 bytes.
    """
    aek = wrap.unwrap_key(blob)
    try:
        _require_aek_bytes(aek)
    except ValueError as exc:
        raise UnwrapError(
            f"wrap blob does not hold a {_AEK_BYTES}-byte account-encryption key"
        ) from exc
    return aek


def zeroize_aek(buffer: bytearray) -> None:
    """Best-effort scrub: overwrite ``buffer`` with zeros in place.

    Reliable for the ``bytearray`` itself — the caller's reference observes
    all zeros when this returns. Not extendable to transient immutable
    copies Python created along the way (see the module docstring): that is
    the documented best-effort boundary of the M04-T02 zeroization contract.
    """
    buffer[:] = bytes(len(buffer))


def _require_aek_bytes(aek: bytes) -> None:
    """Raise ``ValueError`` unless ``aek`` is exactly :data:`_AEK_BYTES` long."""
    if len(aek) != _AEK_BYTES:
        raise ValueError(
            f"account-encryption key must be exactly {_AEK_BYTES} bytes, "
            f"got {len(aek)}"
        )
