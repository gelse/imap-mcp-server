"""Cross-cutting encryption/isolation invariants (M04-T05).

The permanent regression gate (also cited by the M06 acceptance): five
invariants that must hold across every future change to the M04 crypto and
store layers. Assertions here are deliberately strict — weakening one must
fail review:

1. **Login-key independence.** Regenerating the login key leaves the AEK
   blob byte-identical, the account store byte-identical, and every stored
   credential decryptable (through the persisted blob, not just the cached
   plaintext); the old key stops authenticating, the new one verifies.
2. **AEK wrap integrity.** ``create_aek``/``wrap_aek``/``unwrap_aek``
   round-trip; every tampered blob component (IV, tag, ciphertext) fails
   GCM authentication; a blob under a different wrap key fails; fresh IVs
   make every wrap unique; wrong-length material is refused.
3. **Cross-user isolation at the store layer.** Direct API misuse with
   another user's id cannot see, touch, or decrypt anything: the fixed
   miss/``FileNotFoundError``, the untouched store file, the loud
   ``ValueError`` on decrypting under the wrong AEK, and traversal-shaped
   ids rejected before any path is built.
4. **At-rest hygiene.** After a full activate-and-store flow, ``user.json``
   and ``accounts.json`` contain neither the plaintext credentials nor the
   login key nor the AEK. ``user.json`` holds only base64 blobs and the
   scrypt record, so it must not contain even a bare 64-hex RUN;
   ``accounts.json`` legitimately contains 64-hex runs inside its AES-CBC
   ``iv:ciphertext`` credential fields, so it is checked at the VALUE level:
   no JSON string value anywhere in it is itself exactly 64 hex chars (the
   AEK-as-a-value shape). The stored credential fields are
   ciphertext-shaped (the encryption actually happened) and the record
   really carries a scrypt hash plus a three-field wrapped blob (the checks
   have teeth).
5. **Session keyfile lifecycle.** The upstream ``.key`` file exists ONLY
   between ``materialize_key_file`` and ``cleanup_key_file``: absent before,
   exact-hex 0600 content while materialized, removed (idempotently) by
   cleanup; crash leftovers are removed by the startup sweep; invalid
   material never touches disk.

Store-layer tests throughout (no HTTP): these invariants live below the web
surface, and the web/UI flow is proven separately in
tests/test_user_account_api.py (the user account API),
tests/test_user_session_api.py (the session/CSRF bootstrap the SPA depends
on) and tests/test_spa_shell.py (the SPA shell serving contract), plus the
end-to-end scenarios under tests/e2e/scenarios/.
"""

from __future__ import annotations

import base64
import json
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from imap_mcp_gateway.config.paths import Paths, build_paths
from imap_mcp_gateway.crypto import wrap
from imap_mcp_gateway.crypto.aek import create_aek, unwrap_aek, wrap_aek
from imap_mcp_gateway.crypto.keys import random_hex32
from imap_mcp_gateway.crypto.wrap import UnwrapError
from imap_mcp_gateway.store import accounts as accounts_store
from imap_mcp_gateway.store import session_keyfile
from imap_mcp_gateway.store import users as users_store
from imap_mcp_gateway.store.accounts import encrypt_account_record
from imap_mcp_gateway.store.upstream_format import is_ciphertext_field
from imap_mcp_gateway.store.wrap_key import ensure_wrap_key

HEX64_RUN_RE = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")
"""A bare 64-hex run — the AEK's plaintext spelling (boundary-anchored)."""

HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
"""An entire string that IS 64 hex chars — the AEK-as-a-value shape.

Used on PARSED JSON values: upstream's AES-CBC ciphertext is hex too, so
``accounts.json`` legitimately contains 64-hex RUNS inside its credential
fields — only a value that is exactly 64 hex chars would be key material.
"""

IMAP_PASSWORD = "correct horse battery staple"
SMTP_PASSWORD = "smtp-secret-9"
LOGIN_KEY_RE = re.compile(r"^usr_[A-Za-z0-9_-]{43}$")


def _account_payload(**overrides: Any) -> dict[str, Any]:
    """A plaintext-shaped account record (the store seam's input shape)."""
    payload: dict[str, Any] = {
        "name": "Personal",
        "host": "imap.example.org",
        "port": 993,
        "user": "alice@example.org",
        "password": IMAP_PASSWORD,
        "tls": True,
        "email": "alice@example.org",
        "smtp": {
            "host": "smtp.example.org",
            "port": 465,
            "secure": True,
            "user": "alice@example.org",
            "password": SMTP_PASSWORD,
        },
    }
    payload.update(overrides)
    return payload


@dataclass(frozen=True, slots=True)
class SealedUser:
    """One user with an activated AEK and one stored account."""

    user_id: str
    login_key: str
    aek_hex: str
    account_id: str


@pytest.fixture
def paths(tmp_path: Path) -> Paths:
    """A fresh DATA_DIR with the server wrap key installed (AEK ops need it)."""
    paths = build_paths(tmp_path)
    ensure_wrap_key(paths)
    return paths


def _string_values(node: Any) -> Iterator[str]:
    """Yield every string value anywhere in a decoded JSON structure."""
    if isinstance(node, dict):
        for value in node.values():
            yield from _string_values(value)
    elif isinstance(node, list):
        for value in node:
            yield from _string_values(value)
    elif isinstance(node, str):
        yield node


def _mode(path: Path) -> int:
    """The permission bits of ``path`` (``st_mode & 0o777``)."""
    return os.stat(path).st_mode & 0o777


def _sealed_user(paths: Paths, name: str) -> SealedUser:
    """Create a user, activate the AEK, store one encrypted account."""
    record, login_key = users_store.create_user(paths, name)
    assert LOGIN_KEY_RE.fullmatch(login_key)
    aek_hex = users_store.activate_aek(paths, record.id)
    stored = accounts_store.put_account(
        paths, record.id, encrypt_account_record(_account_payload(), aek_hex)
    )
    return SealedUser(
        user_id=record.id, login_key=login_key, aek_hex=aek_hex, account_id=stored.id
    )


def _stored_account(paths: Paths, user: SealedUser) -> accounts_store.ImapAccount:
    """The user's stored record (ciphertext-carrying)."""
    stored = accounts_store.get_account(paths, user.user_id, user.account_id)
    assert stored is not None
    return stored


# --- invariant 1: login-key regeneration never touches account encryption -------------


def test_login_key_regeneration_leaves_aek_and_accounts_untouched(paths: Paths) -> None:
    user = _sealed_user(paths, "alice")
    record_path = paths.user_record_path(user.user_id)
    store_file = paths.user_imap_store_dir(user.user_id) / "accounts.json"
    record_before = json.loads(record_path.read_bytes())
    store_before = store_file.read_bytes()

    updated, new_key = users_store.rotate_login_key(paths, user.user_id)

    # The rotation happened: new key, bumped generation.
    assert new_key != user.login_key
    assert updated.key_generation == 2
    # ...but the AEK blob is BYTE-IDENTICAL across the rotation.
    record_after = json.loads(record_path.read_bytes())
    assert record_after["aek"] == record_before["aek"]
    # ...and so is the account counter: rotation is crypto-only.
    assert record_after["account_count"] == record_before["account_count"]
    assert record_after["key_generation"] == 2  # the record did change
    # The account store file was not rewritten at all.
    assert store_file.read_bytes() == store_before

    # Every stored credential still decrypts under the disclosed AEK...
    stored = _stored_account(paths, user)
    assert stored.decrypt_password(user.aek_hex) == IMAP_PASSWORD
    assert stored.decrypt_smtp_password(user.aek_hex) == SMTP_PASSWORD
    # ...and through the PERSISTED BLOB (unwrap under the wrap key still
    # yields a working key — the byte-equality above is not vacuous).
    decrypted = users_store.with_aek(
        paths,
        user.user_id,
        lambda aek: _stored_account(paths, user).decrypt_password(bytes(aek).hex()),
    )
    assert decrypted == IMAP_PASSWORD

    # The old key stopped authenticating; the new one verifies.
    assert not users_store.verify_login_key(paths, user.user_id, user.login_key)
    assert users_store.verify_login_key(paths, user.user_id, new_key)


def test_login_key_regeneration_works_before_any_account_exists(paths: Paths) -> None:
    """Rotation is legal pre-activation too: no AEK, no store, no crash."""
    record, first_key = users_store.create_user(paths, "alice")
    _updated, new_key = users_store.rotate_login_key(paths, record.id)
    assert new_key != first_key
    assert not users_store.verify_login_key(paths, record.id, first_key)
    # Still no AEK: rotation must not lazily mint one.
    reloaded = users_store.get_user(paths, record.id)
    assert reloaded is not None and reloaded.aek is None
    assert accounts_store.list_accounts(paths, record.id) == []


# --- invariant 2: AEK wrap/unwrap round trip and GCM tamper rejection -----------------


def _flip_first_byte(field: str) -> str:
    """Flip one bit of a canonical base64 field, staying canonical."""
    raw = bytearray(base64.b64decode(field))
    raw[0] ^= 0x01
    return base64.b64encode(bytes(raw)).decode("ascii")


def test_aek_wrap_unwrap_round_trip() -> None:
    wrap.load_wrap_key(random_hex32())  # fresh-process state (conftest reset)
    aek = create_aek()
    assert len(aek) == 32
    blob = wrap_aek(aek)
    assert unwrap_aek(blob) == aek
    # A fresh random IV per wrap: no two blobs of the same key are equal.
    assert wrap_aek(aek) != blob


def test_aek_tampered_blob_components_fail_authentication() -> None:
    wrap.load_wrap_key(random_hex32())
    aek = create_aek()
    iv, tag, ciphertext = wrap_aek(aek).split(":")
    tampered_blobs = [
        ":".join((_flip_first_byte(iv), tag, ciphertext)),  # tampered IV
        ":".join((iv, _flip_first_byte(tag), ciphertext)),  # tampered tag
        ":".join((iv, tag, _flip_first_byte(ciphertext))),  # tampered ct
    ]
    for blob in tampered_blobs:
        with pytest.raises(UnwrapError):
            unwrap_aek(blob)


def test_aek_blob_is_useless_under_a_different_wrap_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """The M04-T01 carry-forward: a wrong (e.g. restored-backup) wrap key is
    an authentication failure, never silently-wrong bytes."""
    wrap.load_wrap_key(random_hex32())
    blob = wrap_aek(create_aek())
    monkeypatch.setattr(wrap, "_loaded_wrap_key", None)
    wrap.load_wrap_key(random_hex32())  # a DIFFERENT wrap key
    with pytest.raises(UnwrapError):
        unwrap_aek(blob)


def test_aek_wrong_length_material_is_refused() -> None:
    wrap.load_wrap_key(random_hex32())
    with pytest.raises(ValueError):
        wrap_aek(b"short")
    with pytest.raises(ValueError):
        wrap_aek(b"x" * 31)
    with pytest.raises(ValueError):
        wrap_aek(b"x" * 33)
    # A blob that authenticates but does not hold 32 bytes is refused too
    # (built through the RAW wrap layer, which accepts any byte length).
    short_blob = wrap.wrap_key(b"x" * 16)
    with pytest.raises(UnwrapError):
        unwrap_aek(short_blob)


# --- invariant 3: cross-user isolation at the store layer ------------------------------


def test_cross_user_store_access_is_isolated(paths: Paths) -> None:
    alice = _sealed_user(paths, "alice")
    bob = _sealed_user(paths, "bob")
    alice_store_file = paths.user_imap_store_dir(alice.user_id) / "accounts.json"
    alice_store_before = alice_store_file.read_bytes()

    # Bob's API cannot see Alice's account: foreign id == missing id.
    assert accounts_store.get_account(paths, bob.user_id, alice.account_id) is None
    assert [a.id for a in accounts_store.list_accounts(paths, bob.user_id)] == [
        bob.account_id
    ]
    with pytest.raises(FileNotFoundError):
        accounts_store.delete_account(paths, bob.user_id, alice.account_id)

    # Writes under Bob's id resolve under Bob's directory only: Alice's store
    # file is byte-identical afterwards.
    stranger = encrypt_account_record(_account_payload(), bob.aek_hex)
    accounts_store.put_account(paths, bob.user_id, stranger)
    assert alice_store_file.read_bytes() == alice_store_before

    # Bob's AEK cannot decrypt Alice's ciphertext — loud, never silent bytes.
    alice_stored = _stored_account(paths, alice)
    with pytest.raises(ValueError):
        alice_stored.decrypt_password(bob.aek_hex)

    # Credentials do not cross: Alice's key does not verify as Bob (and vice
    # versa), even though both keys are valid for their own owners.
    assert not users_store.verify_login_key(paths, alice.user_id, bob.login_key)
    assert not users_store.verify_login_key(paths, bob.user_id, alice.login_key)
    assert users_store.verify_login_key(paths, alice.user_id, alice.login_key)

    # Traversal-shaped ids are rejected before any path is built.
    for user_id in ("../alice", "..", "a/b", ""):
        with pytest.raises(ValueError):
            accounts_store.list_accounts(paths, user_id)
        with pytest.raises(ValueError):
            users_store.get_user(paths, user_id)
        with pytest.raises(ValueError):
            session_keyfile.key_file_path(paths, user_id)


# --- invariant 4: at-rest inspection of user.json and accounts.json ---------------------


def test_at_rest_files_contain_no_plaintext_credentials_or_aek(paths: Paths) -> None:
    user = _sealed_user(paths, "alice")
    # Teeth: the record really carries a scrypt hash + a three-field blob, and
    # the store really carries ciphertext-shaped credential fields.
    user_json = paths.user_record_path(user.user_id).read_text(encoding="utf-8")
    accounts_json = (
        paths.user_imap_store_dir(user.user_id) / "accounts.json"
    ).read_text(encoding="utf-8")
    record = json.loads(user_json)
    assert record["login_key_hash"].startswith("scrypt$")
    assert len(record["aek"]["blob"].split(":")) == 3
    stored = json.loads(accounts_json)[0]
    assert is_ciphertext_field(stored["password"])
    assert is_ciphertext_field(stored["smtp"]["password"])

    for text in (user_json, accounts_json):
        assert IMAP_PASSWORD not in text  # no plaintext IMAP credential
        assert SMTP_PASSWORD not in text  # no plaintext SMTP credential
        assert user.login_key not in text  # no plaintext login key
        assert "usr_" not in text
        assert user.aek_hex not in text  # no plaintext AEK
    # user.json holds only base64 blobs and the scrypt record — no field (or
    # run inside one) is long enough for a bare 64-hex spelling to be legit.
    assert HEX64_RUN_RE.search(user_json) is None
    # The value-level check is the real gate for the store (its ciphertext
    # fields legitimately contain 64-hex runs): no JSON string value anywhere
    # is itself 64 hex chars — the AEK-as-a-value shape.
    store_values = list(_string_values(json.loads(accounts_json)))
    assert store_values  # teeth: the store is not empty
    assert all(HEX64_RE.fullmatch(value) is None for value in store_values)
    assert '"password"' not in user_json  # the user record has no credential field


def test_at_rest_files_stay_clean_after_a_full_lifecycle(paths: Paths) -> None:
    """Rotation + account churn never introduce plaintext material at rest."""
    user = _sealed_user(paths, "alice")
    _record, new_key = users_store.rotate_login_key(paths, user.user_id)
    accounts_store.delete_account(paths, user.user_id, user.account_id)
    users_store.with_aek(
        paths,
        user.user_id,
        lambda aek: accounts_store.put_account(
            paths,
            user.user_id,
            encrypt_account_record(_account_payload(name="Second"), bytes(aek).hex()),
        ),
    )
    record_text = paths.user_record_path(user.user_id).read_text(encoding="utf-8")
    store_text = (
        paths.user_imap_store_dir(user.user_id) / "accounts.json"
    ).read_text(encoding="utf-8")
    for text in (record_text, store_text):
        assert user.login_key not in text  # the ROTATED key is not stored either
        assert new_key not in text
        assert IMAP_PASSWORD not in text
        assert SMTP_PASSWORD not in text
        assert user.aek_hex not in text
    assert HEX64_RUN_RE.search(record_text) is None
    assert all(
        HEX64_RE.fullmatch(value) is None
        for value in _string_values(json.loads(store_text))
    )


# --- invariant 5: the session .key file exists only while materialized -------------------


def test_key_file_exists_only_while_materialized_and_is_removed_by_cleanup(
    paths: Paths,
) -> None:
    user = _sealed_user(paths, "alice")
    key_path = session_keyfile.key_file_path(paths, user.user_id)
    assert not os.path.lexists(key_path)  # absent at rest

    session_keyfile.materialize_key_file(paths, user.user_id, user.aek_hex)
    assert key_path.is_file()  # exists ONLY inside the session window
    assert key_path.read_text(encoding="ascii") == user.aek_hex  # exact hex
    assert _mode(key_path) == 0o600

    session_keyfile.cleanup_key_file(paths, user.user_id)
    assert not os.path.lexists(key_path)
    session_keyfile.cleanup_key_file(paths, user.user_id)  # idempotent
    assert not os.path.lexists(key_path)


def test_startup_sweep_removes_orphaned_key_files(paths: Paths) -> None:
    user = _sealed_user(paths, "alice")
    other, _other_key = users_store.create_user(paths, "bob")
    key_path = session_keyfile.materialize_key_file(paths, user.user_id, user.aek_hex)
    # Bob (no store yet) must not appear in the sweep result.
    swept = session_keyfile.sweep_orphan_key_files(paths)
    assert swept == [user.user_id]
    assert not os.path.lexists(key_path)
    assert users_store.get_user(paths, other.id) is not None  # untouched
    assert session_keyfile.sweep_orphan_key_files(paths) == []  # nothing left


def test_materialize_refuses_invalid_material_before_touching_disk(
    paths: Paths,
) -> None:
    user = _sealed_user(paths, "alice")
    key_path = session_keyfile.key_file_path(paths, user.user_id)
    for bad in ("", "nothex", "0" * 63, "0" * 65, "Z" * 64):
        with pytest.raises(ValueError):
            session_keyfile.materialize_key_file(paths, user.user_id, bad)
        assert not os.path.lexists(key_path)  # nothing was created
