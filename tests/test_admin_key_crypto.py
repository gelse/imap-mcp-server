"""Unit tests for admin-key crypto: key generation, scrypt hashing, hash store.

Coverage per the M02-T01 acceptance criteria:

- generated keys match ``^adm_[A-Za-z0-9_-]{43}$`` and are unique across
  1000 generations (format + entropy);
- ``verify_secret`` accepts only the exact plaintext; any mutation of the
  stored record or the presented key fails, without raising;
- verification routes the digest comparison through
  ``hmac.compare_digest`` (the testable constant-time property);
- ``admin-key.hash`` is created with mode ``0600`` (in a ``0700`` directory)
  and contains only the scrypt record — never plaintext key material.
"""

from __future__ import annotations

import base64
import hmac
import os
import re
from pathlib import Path

import pytest

from imap_mcp_gateway.config.paths import Paths, build_paths
from imap_mcp_gateway.crypto.hash import hash_secret, verify_secret
from imap_mcp_gateway.crypto.keys import (
    generate_admin_key,
    generate_user_key,
    random_hex32,
)
from imap_mcp_gateway.store.admin_key import (
    admin_key_exists,
    load_admin_key_hash,
    save_admin_key_hash,
)

ADMIN_KEY_RE = re.compile(r"^adm_[A-Za-z0-9_-]{43}$")
HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
RECORD_RE = re.compile(r"^scrypt\$32768\$8\$1\$[A-Za-z0-9_-]{22}\$[A-Za-z0-9_-]{43}$")


def _mode(path: Path) -> int:
    """Return the permission bits of ``path`` (``st_mode & 0o777``)."""
    return os.stat(path).st_mode & 0o777


def _mutate_char(text: str, index: int, replacement: str) -> str:
    """Return ``text`` with the character at ``index`` replaced."""
    return text[:index] + replacement + text[index + 1 :]


# --- keys.py: generation format and entropy ----------------------------------


def test_admin_key_format_is_prefix_plus_43_base64url_chars() -> None:
    for _ in range(100):
        assert ADMIN_KEY_RE.fullmatch(generate_admin_key())


def test_admin_keys_are_unique_across_1000_generations() -> None:
    keys = {generate_admin_key() for _ in range(1000)}
    assert len(keys) == 1000


def test_admin_key_payload_decodes_to_32_bytes() -> None:
    key = generate_admin_key()
    payload = key.removeprefix("adm_")
    raw = base64.b64decode(
        payload.replace("-", "+").replace("_", "/") + "=" * (-len(payload) % 4)
    )
    assert len(raw) == 32


def test_user_key_format_uses_distinct_prefix() -> None:
    key = generate_user_key()
    assert key.startswith("usr_")
    assert not key.startswith("adm_")
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", key.removeprefix("usr_"))


def test_user_keys_are_unique_across_1000_generations() -> None:
    keys = {generate_user_key() for _ in range(1000)}
    assert len(keys) == 1000


def test_random_hex32_is_64_lowercase_hex_chars() -> None:
    for _ in range(100):
        assert HEX32_RE.fullmatch(random_hex32())
    assert len({random_hex32() for _ in range(100)}) == 100


# --- hash.py: round-trip, format, salt randomness -----------------------------


def test_hash_round_trip_accepts_exact_plaintext() -> None:
    key = generate_admin_key()
    record = hash_secret(key)
    assert RECORD_RE.fullmatch(record)
    assert verify_secret(key, record)


def test_record_carries_milestone_scrypt_parameters() -> None:
    algorithm, n, r, p, salt_b64, digest_b64 = hash_secret("x").split("$")
    assert algorithm == "scrypt"
    assert (int(n), int(r), int(p)) == (2**15, 8, 1)
    # 16-byte salt / 32-byte digest as unpadded urlsafe base64 (22/43 chars).
    assert len(salt_b64) == 22
    assert len(digest_b64) == 43


def test_two_records_for_same_plaintext_differ_and_both_verify() -> None:
    first = hash_secret("secret")
    second = hash_secret("secret")
    assert first != second  # fresh random salt per record
    assert verify_secret("secret", first)
    assert verify_secret("secret", second)


def test_wrong_plaintext_fails() -> None:
    record = hash_secret("correct-key")
    assert not verify_secret("wrong-key", record)


# --- hash.py: tamper rejection (stored record and presented plaintext) --------
#
# Every case is a record-shaped (or plainly broken) string that must verify
# False without raising. "uniform-fields" is well-formed but carries the wrong
# salt/digest; the whitespace case would decode to the original bytes under a
# lenient base64 decoder (characters silently dropped) and must stay rejected.

_SALT_OK = "A" * 22  # canonical base64url of a 16-byte salt
_DIGEST_OK = "B" * 43  # canonical base64url of a 32-byte digest


def _record(
    salt: str = _SALT_OK,
    digest: str = _DIGEST_OK,
    n: int = 2**15,
    r: int = 8,
    p: int = 1,
) -> str:
    """A scrypt record with the given (possibly tampered) fields."""
    return f"scrypt${n}${r}${p}${salt}${digest}"


TAMPERED_RECORDS: list[tuple[str, str]] = [
    ("empty", ""),
    ("garbage", "not-a-record"),
    ("plaintext-key", "adm_ABcdef123"),
    ("truncated-fields", "scrypt$32768$8$1"),
    ("missing-digest", f"scrypt$32768$8$1${_SALT_OK}"),
    ("extra-field", _record() + "$extra"),
    ("wrong-algorithm", _record().replace("scrypt", "argon2id", 1)),
    ("uniform-fields", _record()),
    ("n-tampered", _record(n=2**15 - 1)),
    ("r-tampered", _record(r=7)),
    ("p-tampered", _record(p=2)),
    ("n-not-power-of-two", _record(n=3)),
    ("r-zero", _record(r=0)),
    ("p-negative", _record(p=-1)),
    ("salt-one-char-short", _record(salt=_SALT_OK[:-1])),
    ("digest-one-char-short", _record(digest=_DIGEST_OK[:-1])),
    ("salt-with-padding-char", _record(salt=_SALT_OK + "=")),
    ("whitespace-injected", _record(salt=_SALT_OK + " ")),
    ("newline-suffix", _record() + "\n"),
    ("space-prefix", " " + _record()),
]


@pytest.mark.parametrize(
    ("name", "stored"), TAMPERED_RECORDS, ids=[name for name, _ in TAMPERED_RECORDS]
)
def test_tampered_or_malformed_records_fail_without_raising(
    name: str, stored: str
) -> None:
    assert verify_secret("any-key", stored) is False


def test_mutations_of_stored_record_at_sampled_positions_fail() -> None:
    key = generate_admin_key()
    record = hash_secret(key)
    digest_start = record.rindex("$") + 1
    assert digest_start == len(record) - 43
    for index in (0, len(record) // 2, len(record) - 1):
        mutated = _mutate_char(record, index, "0" if record[index] != "0" else "1")
        assert verify_secret(key, mutated) is False


def test_trailing_bit_mutation_of_digest_fails() -> None:
    """Flipping only the final digest char's ignored bits must still fail.

    Base64 pads 32 digest bytes to 258 bits, so the last character carries 2
    bits the decoder would ignore; a lenient verifier would accept such a
    mutated record. The canonical re-encoding check in ``_b64decode`` rejects
    it — this test pins that behaviour.
    """
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    key = generate_admin_key()
    record = hash_secret(key)
    sibling = alphabet[alphabet.index(record[-1]) ^ 1]
    assert verify_secret(key, _mutate_char(record, len(record) - 1, sibling)) is False


def test_any_mutated_plaintext_fails() -> None:
    key = generate_admin_key()
    record = hash_secret(key)
    # Mutate the whole prefix plus sampled payload positions (start/middle/end).
    for index in (0, 1, 2, 3, 4, len(key) // 2, len(key) - 1):
        replacement = "B" if key[index] != "B" else "C"
        assert not verify_secret(_mutate_char(key, index, replacement), record)


def test_same_value_parameter_spellings_of_a_real_record_fail() -> None:
    """Non-canonical N spellings fail even when int() would parse them equal.

    ``+32768``, ``" 32768 "`` and Unicode digits all parse to the SAME N via
    ``int()`` — against a record with a real salt/digest they would verify as
    True if the verifier relied on ``int()``'s leniency. The ASCII-digit
    validation must reject them; this pins that guard as a behaviour change,
    not just as reject-without-raise.
    """
    key = generate_admin_key()
    parts = hash_secret(key).split("$")
    for spelling in ("+32768", " 32768 ", "٣٢٧٦٨"):
        mutated = "$".join([parts[0], spelling, *parts[2:]])
        assert not verify_secret(key, mutated)


# --- hash.py: constant-time verification property ------------------------------


def test_verification_compares_through_hmac_compare_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The digest comparison must route through ``hmac.compare_digest``.

    Actual timing behaviour is not assertable in a unit test; proving that the
    comparison goes through the constant-time primitive (with equal-length
    digest buffers) is the testable core of the property.
    """
    calls: list[tuple[bytes, bytes]] = []
    real_compare_digest = hmac.compare_digest

    def spy(a: bytes, b: bytes) -> bool:
        calls.append((a, b))
        return real_compare_digest(a, b)

    monkeypatch.setattr(hmac, "compare_digest", spy)

    record = hash_secret("key")
    assert verify_secret("key", record)
    assert not verify_secret("other", record)

    assert len(calls) == 2  # both verifications compared via compare_digest
    for derived, expected in calls:
        assert len(derived) == len(expected) == 32


# --- store/admin_key.py: hash-only persistence, modes, reset semantics ---------


def test_save_creates_0600_hash_file_in_0700_config_dir(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)
    record = hash_secret(generate_admin_key())

    saved = save_admin_key_hash(paths, record)

    assert saved == paths.admin_key_hash_path()
    assert saved.exists()
    assert _mode(saved) == 0o600
    assert _mode(saved.parent) == 0o700


def test_load_missing_hash_returns_none_and_exists_is_false(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)
    assert load_admin_key_hash(paths) is None
    assert admin_key_exists(paths) is False


def test_store_round_trips_record_exactly(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)
    record = hash_secret(generate_admin_key())

    save_admin_key_hash(paths, record)

    assert admin_key_exists(paths) is True
    assert load_admin_key_hash(paths) == record


def test_overwrite_replaces_record_and_reasserts_0600(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)
    first = hash_secret("first")
    second = hash_secret("second")

    save_admin_key_hash(paths, first)
    os.chmod(paths.admin_key_hash_path(), 0o644)  # simulate permission drift
    save_admin_key_hash(paths, second)

    assert load_admin_key_hash(paths) == second
    assert _mode(paths.admin_key_hash_path()) == 0o600


def test_hash_file_contains_no_plaintext_key_material(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)
    key = generate_admin_key()

    save_admin_key_hash(paths, hash_secret(key))

    raw = paths.admin_key_hash_path().read_bytes()
    assert key.encode("ascii") not in raw
    assert b"adm_" not in raw
    assert raw.decode("ascii").startswith("scrypt$")


def test_save_refuses_plaintext_key_material(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)
    with pytest.raises(ValueError, match="plaintext key material"):
        save_admin_key_hash(paths, generate_admin_key())
    with pytest.raises(ValueError, match="plaintext key material"):
        save_admin_key_hash(paths, generate_user_key())
    # Defence-in-depth variants: plaintext with a stray `$`, and non-ASCII data.
    with pytest.raises(ValueError, match="plaintext key material"):
        save_admin_key_hash(paths, f"{generate_admin_key()}$x")
    with pytest.raises(ValueError, match="plaintext key material"):
        save_admin_key_hash(paths, f"scrypt${generate_admin_key()}é")
    assert not paths.admin_key_hash_path().exists()


def test_load_tolerates_trailing_newline_edit(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)
    record = hash_secret(generate_admin_key())
    save_admin_key_hash(paths, record)
    paths.admin_key_hash_path().write_bytes(record.encode("ascii") + b"\n")

    assert load_admin_key_hash(paths) == record


def test_loaded_record_verifies_the_generating_key(tmp_path: Path) -> None:
    """The end-to-end property the admin auth flow (M02-T03) will rely on."""
    paths = build_paths(tmp_path)
    key = generate_admin_key()
    save_admin_key_hash(paths, hash_secret(key))
    stored = load_admin_key_hash(paths)

    assert stored is not None
    assert verify_secret(key, stored)
    assert not verify_secret(generate_admin_key(), stored)


def test_paths_object_is_the_single_layout_entry_point(tmp_path: Path) -> None:
    """Store functions operate on ``paths.admin_key_hash_path()``."""
    paths = build_paths(tmp_path)
    custom = Paths(data_dir=tmp_path / "elsewhere")
    assert not admin_key_exists(custom)
    save_admin_key_hash(custom, hash_secret("k"))
    assert admin_key_exists(custom)
    assert not admin_key_exists(paths)  # other data_dir is unaffected
