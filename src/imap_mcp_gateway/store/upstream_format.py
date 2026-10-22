"""Upstream-compatible field encryption for the account store (M04-T03).

Every credential field of a stored email account is sealed exactly the way
upstream ``imap-mcp-server@2.2.0``'s ``AccountManager`` does in
``src/services/account-manager.ts`` (``encrypt``/``decrypt``/``decryptField``),
so the M05 Node tool host consumes ``accounts.json`` unmodified:

- key: the account-encryption key (AEK) as its 64-character lowercase-hex
  spelling, interpreted as raw bytes (``bytes.fromhex`` — exactly upstream's
  ``Buffer.from(key, 'hex')``: 32 bytes for AES-256);
- cipher: AES-256-CBC with PKCS7 padding and a fresh random 16-byte IV per
  field (upstream: ``crypto.randomBytes(16)``, Node's default CBC padding);
- encoding: ``"<iv hex>:<ciphertext hex>"`` — lowercase hex, one colon
  separator (upstream: ``iv.toString('hex') + ':' + encrypted``).

``decrypt_field`` mirrors upstream's ``decryptField`` wrapper semantics: an
empty stored value means "no credential" and decrypts to ``""`` (the upstream
env-override mechanism can fill such a field at runtime); any other value
must carry the ``iv:ciphertext`` shape and decrypt cleanly or the failure is
loud (``ValueError``) — never silently-wrong bytes.

This module is the ONLY place the gateway touches the upstream field-crypto
format. Decrypted secrets exist only in process memory during a call; nothing
here logs, persists, or serializes plaintext.
"""

from __future__ import annotations

import os
import re

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

AEK_HEX_LENGTH = 64
"""Length of the 32-byte AEK's lowercase-hex spelling (the upstream ``.key``)."""

_AEK_BYTES = 32
"""The AEK's raw size in bytes (AES-256)."""

IV_BYTES = 16
"""AES-CBC IV size in bytes (upstream: ``crypto.randomBytes(16)``)."""

CIPHERTEXT_FIELD_RE = re.compile(r"^[0-9a-f]{32}:[0-9a-f]+$")
"""At-rest shape of one encrypted credential field: ``<32 hex iv>:<hex ct>``.

The IV part is always 32 hex characters (16 bytes); the ciphertext part is at
least one AES block (32 hex characters — the PKCS7 padding block of an empty
plaintext). Upstream writes lowercase hex only, so the pattern pins the
canonical form.
"""


def parse_aek_hex(aek_hex: str) -> bytes:
    """Return the raw 32 AES key bytes for a 64-char lowercase-hex AEK.

    ``ValueError`` for anything else — wrong length or non-hex. The decoded
    length is re-checked because ``bytes.fromhex`` silently skips ASCII
    whitespace and could otherwise yield fewer than 32 bytes from a 64-char
    input. This is the exact interpretation upstream applies
    (``Buffer.from(key, 'hex')`` feeding ``aes-256-cbc``), so only this
    spelling ever reaches the cipher.
    """
    if len(aek_hex) != AEK_HEX_LENGTH:
        raise ValueError(
            f"account-encryption key hex must be {AEK_HEX_LENGTH} characters, "
            f"got {len(aek_hex)}"
        )
    try:
        key = bytes.fromhex(aek_hex)
    except ValueError as exc:
        raise ValueError("account-encryption key hex is not valid hexadecimal") from exc
    if len(key) != _AEK_BYTES:
        raise ValueError(
            f"account-encryption key hex must decode to {_AEK_BYTES} raw bytes"
        )
    return key


def is_ciphertext_field(value: str) -> bool:
    """True iff ``value`` has the canonical at-rest ``iv:ciphertext`` shape.

    The schema-level guard against plaintext credentials reaching disk: a
    stored password is either this format or the documented empty value (see
    :func:`decrypt_field`).
    """
    return CIPHERTEXT_FIELD_RE.fullmatch(value) is not None


def encrypt_field(aek_hex: str, plaintext: str) -> str:
    """Encrypt one credential field exactly like upstream ``AccountManager``.

    AES-256-CBC under the raw AEK bytes with PKCS7 padding and a fresh random
    16-byte IV; returns ``"<iv hex>:<ciphertext hex>"`` (lowercase hex). The
    empty string encrypts like any other plaintext (a single padding block) —
    matching upstream, which always encrypts the value it is handed.
    """
    key = parse_aek_hex(aek_hex)
    iv = os.urandom(IV_BYTES)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return f"{iv.hex()}:{ciphertext.hex()}"


def decrypt_field(aek_hex: str, value: str) -> str:
    """Decrypt one stored credential field (upstream ``decryptField`` semantics).

    An empty stored value is "no credential" and yields ``""``. Anything else
    must be ``"<iv hex>:<ciphertext hex>"`` and decrypt cleanly under the AEK:
    a missing separator, non-hex input, a wrong IV length, a wrong key (PKCS7
    padding failure), or tampered ciphertext all raise ``ValueError`` —
    mirroring upstream's fail-loud corrupt-entry behaviour, never silently
    wrong bytes. The plaintext exists only as this call's return value.
    """
    if value == "":
        return ""
    if ":" not in value:
        raise ValueError(
            "cannot decrypt credential field: value is not a valid encrypted string"
        )
    iv_hex, ciphertext_hex = value.split(":", 1)
    try:
        iv = bytes.fromhex(iv_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
    except ValueError as exc:
        raise ValueError("credential field is not valid hexadecimal") from exc
    if len(iv) != IV_BYTES:
        raise ValueError(f"credential field IV must be {IV_BYTES} bytes")
    decryptor = Cipher(algorithms.AES(parse_aek_hex(aek_hex)), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()  # ValueError: wrong key
    return plaintext.decode("utf-8")
