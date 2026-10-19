"""AES-256-GCM wrapping of key material under the server wrap key (M04-T01).

The wrap primitive seals per-user account-encryption keys (AEKs, M04-T02) so
account credentials never exist as plaintext on disk. The AES-256 key is the
server wrap key — 32 random bytes as 64 hex chars, minted by
:func:`imap_mcp_gateway.crypto.keys.generate_wrap_key` and installed into
this module's single in-memory holder exactly once per process by the
startup gate (``store.wrap_key.ensure_wrap_key``). Blob format:

::

    base64(iv):base64(tag):base64(ciphertext)

- AES-256-GCM via ``cryptography.hazmat.primitives.ciphers.aead.AESGCM``;
- a fresh 12-byte random IV per :func:`wrap_key` call — GCM must never reuse
  a (key, IV) pair, so two calls never produce the same blob;
- the 16-byte GCM tag authenticates ciphertext AND IV together: tampering
  with any blob component, or unwrapping under a different wrap key, raises
  :class:`UnwrapError` instead of returning attacker-chosen bytes.

Pure Python through the pinned ``cryptography`` package only — nothing here
spawns child processes or touches the environment, so wrap key material
cannot cross the language boundary into the vendored Node npx tool host
(M04/M05).
"""

from __future__ import annotations

import base64
import re
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_KEY_BYTES = 32
"""AES-256 wrap key: 32 bytes, persisted and held as 64 hex characters."""

_IV_BYTES = 12
"""GCM standard nonce size; a fresh random IV is drawn per wrap_key call."""

_TAG_BYTES = 16
"""GCM authentication tag length; AESGCM appends it to every ciphertext."""

_KEY_HEX_RE = re.compile(r"[0-9a-f]{64}")
"""The only key spelling accepted at the load boundary: 64 lowercase hex chars."""


class WrapKeyNotLoadedError(RuntimeError):
    """No wrap key is installed in this process.

    :func:`load_wrap_key` is the single installation point, called by the
    startup gate after the key file is created or validated. Wrapping or
    unwrapping before startup completed is a programming error to fix, not a
    runtime condition to recover from.
    """


class WrapKeyAlreadyLoadedError(RuntimeError):
    """A wrap key is already installed; a second ``load_wrap_key`` was refused.

    Deliberately NOT a :class:`WrapKeyNotLoadedError` subclass: the two
    conditions are opposites, and a caller catching "not loaded" to mean
    "not initialized yet" must never misread a refused double install. The
    refusal protects the single-holder invariant — a second load could
    silently switch every future wrap to a different key while blobs
    wrapped under the old one become unopenable.
    """


class UnwrapError(ValueError):
    """A wrap blob is malformed, non-canonical, or fails authentication.

    Raised for every :func:`unwrap_key` failure other than a missing key:
    wrong field count, invalid or non-canonical base64, wrong IV/tag
    lengths, and GCM tag mismatch (wrong key or any tampered component).
    One exception type keeps callers fail-closed without distinguishing
    tamper kinds.
    """


_loaded_wrap_key: str | None = None
"""Single in-memory holder of the server wrap key (hex), installed once.

The startup gate loads the key exactly once per process; wrap/unwrap then
serve from memory and never re-read the file, so an operator deleting or
replacing the file mid-process cannot flip live wrapping onto a different
key. Tests reset this module global to simulate fresh processes.
"""


def wrap_key_is_loaded() -> bool:
    """Return ``True`` once this process has its wrap key installed."""
    return _loaded_wrap_key is not None


def load_wrap_key(key_hex: str) -> None:
    """Install the process-wide wrap key — the single load-once entry point.

    Validates the material shape (exactly 64 lowercase hex chars = 32 bytes)
    and refuses a second installation: a second load could silently switch
    every future wrap to a different key while blobs wrapped under the old
    one become unopenable, so the single-holder invariant is enforced here
    rather than trusted to callers.
    """
    global _loaded_wrap_key
    if _loaded_wrap_key is not None:
        raise WrapKeyAlreadyLoadedError(
            "wrap key already loaded: it is installed exactly once per process"
        )
    if not isinstance(key_hex, str) or _KEY_HEX_RE.fullmatch(key_hex) is None:
        raise ValueError("wrap key must be exactly 64 lowercase hex characters")
    _loaded_wrap_key = key_hex


def wrap_key(plaintext: bytes) -> str:
    """Seal ``plaintext`` under the installed wrap key (AES-256-GCM).

    Returns ``base64(iv):base64(tag):base64(ciphertext)`` with a fresh
    12-byte random IV; the GCM tag authenticates ciphertext and IV.
    """
    key = _installed_key()
    iv = secrets.token_bytes(_IV_BYTES)
    sealed = AESGCM(key).encrypt(iv, plaintext, None)
    ciphertext, tag = sealed[:-_TAG_BYTES], sealed[-_TAG_BYTES:]
    return ":".join(
        base64.b64encode(part).decode("ascii") for part in (iv, tag, ciphertext)
    )


def unwrap_key(blob: str) -> bytes:
    """Open a :func:`wrap_key` blob under the installed wrap key.

    Every structural problem (field count, base64 canonicality, IV/tag
    lengths) and every authentication failure raises :class:`UnwrapError` —
    partially decrypted or attacker-influenced bytes are never returned.
    """
    key = _installed_key()
    iv, tag, ciphertext = _parse_blob(blob)
    try:
        return AESGCM(key).decrypt(iv, ciphertext + tag, None)
    except InvalidTag as exc:
        raise UnwrapError(
            "wrap blob failed authentication: wrong wrap key or tampered blob"
        ) from exc


def _installed_key() -> bytes:
    """The installed wrap key as raw AES bytes; raise when not loaded yet."""
    if _loaded_wrap_key is None:
        raise WrapKeyNotLoadedError(
            "no wrap key loaded: the startup gate must install it before wrapping"
        )
    return bytes.fromhex(_loaded_wrap_key)


def _parse_blob(blob: str) -> tuple[bytes, bytes, bytes]:
    """Strictly parse ``iv:tag:ciphertext``; every deviation is UnwrapError.

    base64 fields use the standard alphabet with padding (blobs live in
    colon-separated strings and JSON, not URLs) and are decoded with the
    same three-layer defence as the hash record fields: ``validate=True``
    rejects characters outside the base64 alphabet (a lenient decoder
    silently DROPS such characters, which could let an edited blob decode
    to its original bytes), the IV/tag length checks reject truncation, and
    the canonical re-encoding check rejects non-canonical spellings.
    """
    try:
        iv_text, tag_text, ciphertext_text = blob.split(":")
        iv = _b64decode_field(iv_text)
        tag = _b64decode_field(tag_text)
        ciphertext = _b64decode_field(ciphertext_text)
    except (AttributeError, TypeError, ValueError) as exc:
        # AttributeError/TypeError: defensive parity for non-str input
        # (typed ``str``); ValueError: field-count mismatch, invalid base64
        # characters/length (binascii.Error subclasses it), and the
        # non-canonical rejection in _b64decode_field.
        raise UnwrapError(
            "malformed wrap blob: expected base64(iv):base64(tag):base64(ciphertext)"
        ) from exc
    if len(iv) != _IV_BYTES or len(tag) != _TAG_BYTES:
        raise UnwrapError(
            f"malformed wrap blob: iv must be {_IV_BYTES} bytes, tag {_TAG_BYTES}"
        )
    return iv, tag, ciphertext


def _b64decode_field(field: str) -> bytes:
    """Strictly decode one canonical standard-base64 blob field."""
    raw = base64.b64decode(field, validate=True)
    if base64.b64encode(raw).decode("ascii") != field:
        raise ValueError("field is not canonical base64")
    return raw
