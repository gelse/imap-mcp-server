"""Secret hashing with a self-describing, swappable record format.

The gateway never stores plaintext keys — only records produced here. The
serialized record embeds every parameter needed to verify it later:

::

    scrypt$<N>$<r>$<p>$<salt-b64>$<hash-b64>

- scrypt (N=2^15, r=8, p=1, 16-byte random salt, 32-byte digest) via
  ``cryptography.hazmat.primitives.kdf.scrypt.Scrypt`` — memory-hard, and no
  native dependency beyond the already-pinned ``cryptography`` package;
- base64 fields are unpadded urlsafe base64 (the same paste-safe encoding as
  the keys themselves);
- the leading algorithm name makes the format self-describing: a future
  hasher (e.g. ``argon2id$...``) can coexist without a migration flag,
  because every record carries its own parameters.

Verification validates structure AND the scrypt parameter bound strictly
BEFORE any KDF work (``is_valid_record``): only the milestone parameters
(N=2^15, r=8, p=1) are accepted, so no record can make a verification
allocate beyond the fixed ~32 MiB scrypt cost. Legitimate future parameter
or algorithm changes arrive with a NEW record prefix and extend this
validation at that point (the self-describing-format contract above).
"""

from __future__ import annotations

import base64
import hmac
import secrets
from typing import NamedTuple

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

_ALGORITHM = "scrypt"
"""Record prefix; swapping hashers later means adding a new prefix only."""

_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1

_SALT_BYTES = 16
"""Random salt per record (fresh for every hash_secret call)."""

_DIGEST_BYTES = 32
"""Digest length; also the scrypt output length."""


def hash_secret(plaintext: str) -> str:
    """Hash ``plaintext`` into a self-describing scrypt record.

    The record format is documented in the module docstring. Every call
    draws a fresh random salt, so two records for the same plaintext differ.
    """
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = _derive(plaintext, salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    fields = (
        _ALGORITHM,
        str(_SCRYPT_N),
        str(_SCRYPT_R),
        str(_SCRYPT_P),
        _b64encode(salt),
        _b64encode(digest),
    )
    return "$".join(fields)


class _ParsedRecord(NamedTuple):
    """Fields of a fully validated record, ready for the KDF."""

    n: int
    r: int
    p: int
    salt: bytes
    expected: bytes


def _parse_record(stored: str) -> _ParsedRecord | None:
    """Strictly parse ``stored``; ``None`` unless fully valid and in bounds.

    Structural rules: exactly six ``$``-separated fields; the algorithm
    prefix must be :data:`_ALGORITHM`; the three parameters must be plain
    ASCII digit runs (``int()`` alone would accept ``"+32768"``, whitespace
    and Unicode digits); both base64 fields must be canonical unpadded
    urlsafe base64 of exactly the salt/digest lengths.

    Parameter bound (M02-T03, anti-DoS): the scrypt parameters must equal
    the milestone parameters (N=2^15, r=8, p=1) EXACTLY — checked BEFORE any
    KDF work, so a tampered record can never inflate a verification's cost
    (a hostile ``scrypt$<huge N>$...`` would otherwise request gigabytes of
    scrypt memory per attempt). The gateway writes nothing else, so any
    deviation is corruption or tampering, not a legitimate record; a future
    parameter or algorithm change arrives as a NEW record prefix and extends
    this validation then.
    """
    try:
        algorithm, n_text, r_text, p_text, salt_text, digest_text = stored.split("$")
        if algorithm != _ALGORITHM:
            return None
        if not all(t.isascii() and t.isdigit() for t in (n_text, r_text, p_text)):
            return None
        n, r, p = int(n_text), int(r_text), int(p_text)
        if (n, r, p) != (_SCRYPT_N, _SCRYPT_R, _SCRYPT_P):
            return None
        salt = _b64decode(salt_text, _SALT_BYTES)
        expected = _b64decode(digest_text, _DIGEST_BYTES)
    except (AttributeError, ValueError):
        # AttributeError: defensive parity for non-str input (typed ``str``);
        # ValueError: field-count mismatch (unpack) and base64 failures.
        return None
    return _ParsedRecord(n=n, r=r, p=p, salt=salt, expected=expected)


def is_valid_record(stored: str) -> bool:
    """Return True iff ``stored`` fully parses within bounds — WITHOUT running the KDF.

    This is the validation both gates share: the startup gate in
    ``store.admin_key`` and the auth path (:func:`verify_secret`) call the
    same parser, so a record that boots is
    exactly a record that verifies cheaply — no path can be surprised by an
    attacker-influenced record. Never raises; runs no scrypt work.
    """
    return _parse_record(stored) is not None


def verify_secret(plaintext: str, stored: str) -> bool:
    """Return ``True`` iff ``plaintext`` matches the ``stored`` record.

    Never raises: malformed, truncated, tampered, unsupported or
    out-of-bounds records verify as ``False`` — structural validation and
    the parameter bound run BEFORE the KDF (see :func:`_parse_record`), so
    rejected records cost no scrypt work. The digest comparison itself is
    constant time (:func:`hmac.compare_digest`).
    """
    parsed = _parse_record(stored)
    if parsed is None:
        return False
    try:
        derived = _derive(
            plaintext, salt=parsed.salt, n=parsed.n, r=parsed.r, p=parsed.p
        )
    except Exception:  # noqa: BLE001
        # Broad by design: a KDF failure (e.g. an out-of-memory scrypt
        # request on a constrained host) must fail closed as False instead
        # of raising into callers.
        return False
    # Both buffers are _DIGEST_BYTES long by construction (Scrypt length= and
    # _b64decode's expected_bytes check), so the comparison below is the
    # full constant-time primitive in both the matching and non-matching case.
    return hmac.compare_digest(derived, parsed.expected)


def _b64encode(raw: bytes) -> str:
    """Unpadded urlsafe base64 (the key encoding — keeps records paste-safe)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(field: str, expected_bytes: int) -> bytes:
    """Strictly decode a canonical unpadded urlsafe base64 field.

    Three defenses, so every mutation of a stored record fails:

    - ``validate=True`` rejects any character outside the base64url alphabet
      (a lenient decoder silently DROPS such characters, which could let an
      edited record decode to its original bytes);
    - the length check rejects truncation and oversized fields;
    - the canonical re-encoding check rejects non-canonical spellings —
      without it, flipping the final digest character's ignored trailing
      bits (base64 pads 32 bytes to 258 bits) would decode to the original
      bytes and verify successfully despite a mutated string.
    """
    padded = field + "=" * (-len(field) % 4)
    raw = base64.b64decode(padded.replace("-", "+").replace("_", "/"), validate=True)
    if len(raw) != expected_bytes or _b64encode(raw) != field:
        raise ValueError("field is not canonical base64url of the expected length")
    return raw


def _derive(plaintext: str, *, salt: bytes, n: int, r: int, p: int) -> bytes:
    """Run scrypt over ``plaintext`` with the record's parameters."""
    kdf = Scrypt(salt=salt, length=_DIGEST_BYTES, n=n, r=r, p=p)
    return kdf.derive(plaintext.encode("utf-8"))
