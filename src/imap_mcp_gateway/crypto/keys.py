"""Key material generation — the single producer of plaintext secrets.

Every plaintext key in the gateway is minted here and nowhere else: callers
receive the value once, hash it (:mod:`imap_mcp_gateway.crypto.hash`) or use
it directly, and must never persist or log it. Key format:

``<prefix> + unpadded urlsafe base64 of 32 random bytes``

- 256 bits of entropy drawn from :func:`secrets.token_bytes` (CSPRNG);
- the ``adm_``/``usr_`` prefix makes keys self-identifying in logs and
  paste-safe (whitespace-free, URL-safe alphabet);
- 43 base64url characters carry the 32 bytes with ``=`` padding stripped.

``random_hex32`` provides non-prefixed raw material (64 hex characters =
32 bytes) for symmetric key generation (M04), exposed as
:func:`generate_wrap_key` for the server wrap key.
"""

from __future__ import annotations

import base64
import secrets

_KEY_BYTES = 32
"""Entropy per key: 256 bits."""

_ADMIN_PREFIX = "adm_"
"""Self-identifying prefix for root administration keys (M02)."""

_USER_PREFIX = "usr_"
"""Self-identifying prefix for user login keys (M03)."""


def _generate_key(prefix: str) -> str:
    """Return ``prefix`` plus unpadded urlsafe base64 of 32 CSPRNG bytes."""
    raw = secrets.token_bytes(_KEY_BYTES)
    encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return prefix + encoded


def generate_admin_key() -> str:
    """Mint a root administration key: ``adm_`` + 32 random bytes base64url."""
    return _generate_key(_ADMIN_PREFIX)


def generate_user_key() -> str:
    """Mint a user login key: ``usr_`` + 32 random bytes base64url (M03)."""
    return _generate_key(_USER_PREFIX)


def generate_wrap_key() -> str:
    """Mint the server wrap key: 32 random bytes as 64 lowercase hex chars (M04).

    Named constructor over :func:`random_hex32` so the minting call site in
    the wrap-key store stays self-describing. The value is the AES-256 key
    material :mod:`imap_mcp_gateway.crypto.wrap` installs; like every key
    minted here it is never persisted as anything but itself at its own
    ``0600`` path and never logged.
    """
    return random_hex32()


def random_hex32() -> str:
    """Return 32 random bytes as 64 lowercase hex chars (AEK/wrap key, M04)."""
    return secrets.token_hex(_KEY_BYTES)
