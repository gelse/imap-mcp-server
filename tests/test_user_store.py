"""User store tests (M03-T01): schema strictness, lifecycle, at-rest invariants.

Coverage per the M03-T01 acceptance criteria:

- ``create_user`` mints a ``usr_`` login key whose plaintext exists exactly
  once (the return value): ``user.json`` carries only the scrypt record —
  no ``usr_`` substring anywhere under ``DATA_DIR``, exactly one ``scrypt$``
  record — and the file is mode ``0600`` inside ``0700`` directories;
- verification succeeds only for the returned key; rotation invalidates the
  old key immediately, bumps ``key_generation``, keeps the file hash-only
  and mode ``0600``; delete removes the whole per-user directory
  recursively and every later lookup/verification fails closed;
- disable/enable flip authentication without destroying data;
- ``update_user`` accepts only whitelisted metadata fields — identity and
  credential fields are unreachable through a patch;
- ``list_users`` returns metadata only, with no hash material in any listed
  entry (no ``login_key_hash`` field exists on the listed ``UserMetadata``
  shape; dumps and JSON round-trips carry no ``scrypt$`` record) — while
  ``get_user`` is the internal hash-carrying accessor that still exposes the
  stored scrypt record (M03-T04's scanner input), verified here with a
  simulated walk-and-compare over active users;
- the schema itself is strict: registry-rule ids, non-empty names,
  ``extra="forbid"``, hash-record-only ``login_key_hash``, and the
  finalized M04 ``aek`` field (absent/``null`` before activation; strict
  ``WrappedAEK`` after — detailed shape coverage in test_aek_lifecycle.py).
"""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from imap_mcp_gateway.config.paths import build_paths
from imap_mcp_gateway.crypto.hash import hash_secret, is_valid_record, verify_secret
from imap_mcp_gateway.store.user_schema import UserMetadata, UserRecord, WrappedAEK
from imap_mcp_gateway.store.users import (
    create_user,
    delete_user,
    disable_user,
    enable_user,
    get_user,
    list_users,
    rotate_login_key,
    update_user,
    verify_login_key,
)

USER_KEY_RE = re.compile(r"^usr_[A-Za-z0-9_-]{43}$")
"""``usr_`` + unpadded urlsafe base64 of 32 bytes (43 characters)."""

USER_ID_RE = re.compile(r"^[a-z0-9-]{1,64}$")

_FIXTURE_HASH = hash_secret("usr_fixture-plaintext")
"""One precomputed valid scrypt record so schema tests skip the KDF cost."""


def _mode(path: Path) -> int:
    """Return the permission bits of ``path`` (``st_mode & 0o777``)."""
    return os.stat(path).st_mode & 0o777


def _valid_record(**overrides: Any) -> dict[str, Any]:
    """A schema-valid ``UserRecord`` payload with optional field overrides."""
    data: dict[str, Any] = {
        "id": "alice",
        "name": "Alice",
        "created_at": datetime.now(UTC),
        "login_key_hash": _FIXTURE_HASH,
    }
    data.update(overrides)
    return data


def _assert_no_hash_material(node: Any) -> None:
    """Recursively assert a dump/JSON payload carries no hash material.

    The M03-T01 listing contract at the value level: no ``login_key_hash``
    key anywhere, and no string anywhere shaped like a serialized hash
    record (``scrypt$...``) or like plaintext key material. Test users have
    display names that never start with a key prefix, so the prefix check
    cannot false-positive here.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            assert key != "login_key_hash"
            assert "scrypt$" not in str(key)
            _assert_no_hash_material(value)
    elif isinstance(node, list):
        for item in node:
            _assert_no_hash_material(item)
    else:
        assert not isinstance(node, str) or (
            "scrypt$" not in node and not node.startswith(("usr_", "adm_"))
        )


# --- create_user: one-time plaintext, hash-only at rest -----------------------


def test_create_user_returns_key_once_and_persists_hash_only(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)

    record, plaintext = create_user(paths, "alice")

    assert USER_KEY_RE.fullmatch(plaintext)
    assert USER_ID_RE.fullmatch(record.id)
    assert is_valid_record(record.login_key_hash)
    assert verify_secret(plaintext, record.login_key_hash)

    record_path = paths.user_record_path(record.id)
    raw = record_path.read_bytes()
    assert plaintext.encode("ascii") not in raw  # hash only, never the plaintext
    assert b"usr_" not in raw  # no user-key material at rest, even as a substring
    assert raw.count(b"scrypt$") == 1  # exactly one scrypt record
    persisted = json.loads(raw)
    assert persisted["login_key_hash"] == record.login_key_hash

    # The plaintext exists nowhere else under DATA_DIR either.
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert plaintext.encode("ascii") not in path.read_bytes(), path

    assert get_user(paths, record.id) == record  # strict JSON round-trip


def test_create_user_layout_defaults_and_modes(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)

    record, _ = create_user(paths, "alice")

    assert record.name == "alice"
    assert record.key_generation == 1
    assert record.status == "active"
    assert record.aek is None  # lazy activation: None until the user opts in
    assert record.account_count == 0
    assert record.created_at.tzinfo is not None
    user_dir = paths.user_dir(record.id)
    assert [path.name for path in user_dir.iterdir()] == ["user.json"]
    assert _mode(paths.users_dir()) == 0o700
    assert _mode(user_dir) == 0o700
    assert _mode(user_dir / "user.json") == 0o600


def test_two_creates_mint_distinct_ids_and_keys(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)

    first, first_key = create_user(paths, "alice")
    second, second_key = create_user(paths, "alice")  # same display name

    assert first.id != second.id
    assert first_key != second_key
    assert {user.id for user in list_users(paths)} == {first.id, second.id}


def test_create_user_rejects_empty_name_without_writing(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)

    with pytest.raises(ValidationError):
        create_user(paths, "")

    assert not paths.users_dir().exists()  # nothing was created


# --- verify_login_key: only the returned key authenticates --------------------


@pytest.mark.parametrize(
    "wrong",
    [
        "",
        "garbage",
        "usr_not-the-key",
        "adm_" + "A" * 43,  # wrong prefix family
        "usr_" + "B" * 43,  # right shape, wrong key
    ],
    ids=["empty", "garbage", "usr-short", "adm-prefix", "usr-other-key"],
)
def test_verify_login_key_rejects_every_other_string(tmp_path: Path, wrong: str) -> None:
    paths = build_paths(tmp_path)
    record, key = create_user(paths, "alice")

    assert verify_login_key(paths, record.id, key)
    assert not verify_login_key(paths, record.id, wrong)


def test_verify_login_key_fails_closed_without_raising(tmp_path: Path) -> None:
    """Missing, invalid-id and disabled users all fail closed."""
    paths = build_paths(tmp_path)
    record, key = create_user(paths, "alice")

    assert not verify_login_key(paths, "no-such-user", key)  # absent
    assert not verify_login_key(paths, "../etc/passwd", key)  # invalid id shape

    disable_user(paths, record.id)
    assert not verify_login_key(paths, record.id, key)  # disabled
    enable_user(paths, record.id)
    assert verify_login_key(paths, record.id, key)  # re-enabled: same key works


def test_verify_login_key_fails_closed_on_unreadable_record(tmp_path: Path) -> None:
    """A present-but-unreadable record is an auth failure, never an exception.

    A directory at ``user.json`` (bind-mount/restore mistake) or unreadable
    bytes must not make the auth primitive — M03-T04's scanner input — raise;
    it fails closed. Admin reads stay fail-loud on the same corruption.
    """
    paths = build_paths(tmp_path)
    record, key = create_user(paths, "alice")
    record_path = paths.user_record_path(record.id)
    record_path.unlink()
    record_path.mkdir()  # a directory where the record file should be

    assert not verify_login_key(paths, record.id, key)  # auth: fail closed
    with pytest.raises(OSError):
        get_user(paths, record.id)  # admin reads: fail loud on corruption


# --- rotate_login_key: one-time replacement ------------------------------------


def test_rotate_login_key_invalidates_old_and_increments_generation(
    tmp_path: Path,
) -> None:
    paths = build_paths(tmp_path)
    record, old_key = create_user(paths, "alice")
    record_path = paths.user_record_path(record.id)
    raw_before = record_path.read_bytes()

    rotated, new_key = rotate_login_key(paths, record.id)

    assert USER_KEY_RE.fullmatch(new_key)
    assert new_key != old_key
    assert rotated.key_generation == record.key_generation + 1 == 2
    assert rotated.created_at == record.created_at  # identity untouched
    assert rotated.name == "alice"
    assert get_user(paths, record.id) == rotated
    assert verify_login_key(paths, record.id, new_key)
    assert not verify_login_key(paths, record.id, old_key)  # old key is dead now

    raw_after = record_path.read_bytes()
    assert raw_after != raw_before  # the hash was replaced
    assert b"usr_" not in raw_after  # still hash-only at rest
    assert raw_after.count(b"scrypt$") == 1
    assert _mode(record_path) == 0o600  # rewrite re-asserts the mode


def test_rotate_missing_user_raises(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)

    with pytest.raises(FileNotFoundError):
        rotate_login_key(paths, "ghost")


# --- disable / enable -----------------------------------------------------------


def test_disable_and_enable_persist_status(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)
    record, key = create_user(paths, "alice")

    disabled = disable_user(paths, record.id)

    assert disabled.status == "disabled"
    assert get_user(paths, record.id) == disabled
    persisted = json.loads(paths.user_record_path(record.id).read_bytes())
    assert persisted["status"] == "disabled"
    assert not verify_login_key(paths, record.id, key)

    enabled = enable_user(paths, record.id)

    assert enabled.status == "active"
    assert get_user(paths, record.id) == enabled
    assert verify_login_key(paths, record.id, key)  # data survived the disable


# --- update_user: whitelisted metadata only ------------------------------------


def test_update_user_applies_whitelisted_patch_and_persists(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)
    record, key = create_user(paths, "alice")

    updated = update_user(paths, record.id, {"name": "alice-co", "account_count": 3})

    assert updated.name == "alice-co"
    assert updated.account_count == 3
    assert updated.id == record.id
    assert updated.login_key_hash == record.login_key_hash  # credential untouched
    assert updated.key_generation == 1
    assert get_user(paths, record.id) == updated
    record_path = paths.user_record_path(record.id)
    assert json.loads(record_path.read_bytes())["name"] == "alice-co"
    assert _mode(record_path) == 0o600
    assert verify_login_key(paths, record.id, key)  # the key still works


@pytest.mark.parametrize(
    "field",
    ["id", "created_at", "login_key_hash", "key_generation", "aek", "bogus_field"],
)
def test_update_user_rejects_non_whitelisted_fields(tmp_path: Path, field: str) -> None:
    paths = build_paths(tmp_path)
    record, key = create_user(paths, "alice")
    record_path = paths.user_record_path(record.id)
    raw_before = record_path.read_bytes()

    with pytest.raises(ValueError, match="not patchable"):
        update_user(paths, record.id, {field: "anything"})

    assert record_path.read_bytes() == raw_before  # nothing was written
    assert verify_login_key(paths, record.id, key)


def test_update_missing_user_raises(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)

    with pytest.raises(FileNotFoundError):
        update_user(paths, "ghost", {"name": "New Name"})


# --- delete_user: recursive directory removal ----------------------------------


def test_delete_user_removes_directory_recursively(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)
    record, key = create_user(paths, "alice")
    user_dir = paths.user_dir(record.id)
    m04_store = user_dir / "imap-store"  # later M04 content must go too
    m04_store.mkdir()
    (m04_store / "accounts.db").write_bytes(b"future encrypted store")
    (user_dir / "notes.txt").write_bytes(b"stray file")

    delete_user(paths, record.id)

    assert not user_dir.exists()
    assert not paths.user_record_path(record.id).exists()
    assert get_user(paths, record.id) is None
    assert not verify_login_key(paths, record.id, key)  # deleted users fail closed
    assert list_users(paths) == []


def test_delete_missing_user_raises(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)

    with pytest.raises(FileNotFoundError):
        delete_user(paths, "ghost")


# --- list_users / get_user: metadata-only listing, hash-carrying accessor -------


def test_list_users_returns_metadata_only_sorted_by_id(tmp_path: Path) -> None:
    """The listing contract: metadata only — no hash material, by construction.

    M03-T01 acceptance: "``list_users()`` returns metadata only (no hashes)".
    The listed ``UserMetadata`` shape has no ``login_key_hash`` field at all,
    and neither the in-memory dump nor the JSON round-trip of any entry
    contains a ``scrypt$`` record or any other hash material.
    """
    paths = build_paths(tmp_path)
    first, _ = create_user(paths, "alice")
    second, _ = create_user(paths, "bob")

    users = list_users(paths)

    assert [user.id for user in users] == sorted([first.id, second.id])
    by_id = {user.id: user for user in users}
    assert by_id[first.id].name == "alice"
    assert by_id[second.id].name == "bob"
    assert all(user.key_generation == 1 and user.status == "active" for user in users)
    assert all(user.account_count == 0 for user in users)
    # No hash-carrying field exists on the metadata shape at all.
    assert set(UserMetadata.model_fields) == {
        "id",
        "name",
        "created_at",
        "key_generation",
        "status",
        "account_count",
    }
    for user in users:
        assert not hasattr(user, "login_key_hash")
        _assert_no_hash_material(user.model_dump())  # in-memory dump
        _assert_no_hash_material(json.loads(user.model_dump_json()))  # wire shape


def test_get_user_is_the_hash_carrying_accessor(tmp_path: Path) -> None:
    """The listing drops hashes; the internal accessor still provides them.

    ``get_user`` — the accessor for flows that must touch the stored scrypt
    record — returns the actual persisted record: its ``login_key_hash``
    equals the stored scrypt record byte-for-byte and verifies against the
    one-time plaintext.
    """
    paths = build_paths(tmp_path)
    record, key = create_user(paths, "alice")

    listed = list_users(paths)
    assert len(listed) == 1
    _assert_no_hash_material(listed[0].model_dump())
    _assert_no_hash_material(json.loads(listed[0].model_dump_json()))

    loaded = get_user(paths, record.id)
    assert loaded is not None
    persisted = json.loads(paths.user_record_path(record.id).read_bytes())
    assert loaded.login_key_hash == persisted["login_key_hash"]
    assert is_valid_record(loaded.login_key_hash)
    assert verify_secret(key, loaded.login_key_hash)


def test_active_user_hash_scan_walk_for_authentication(tmp_path: Path) -> None:
    """M03-T04's scanner path, simulated: metadata walk + hash compare.

    ``authenticate_user_key`` will walk the credential-free listing, load
    each active user's full record through the accessor, and compare the
    presented key against the stored scrypt record. Disabled users are
    skipped and never authenticate; a match names exactly the owning user.
    """
    paths = build_paths(tmp_path)
    alice, alice_key = create_user(paths, "alice")
    bob, bob_key = create_user(paths, "bob")
    carol, _ = create_user(paths, "carol")
    disable_user(paths, bob.id)
    delete_user(paths, carol.id)

    def authenticate(presented: str) -> list[str]:
        matches = []
        for meta in list_users(paths):  # credential-free walk
            assert not hasattr(meta, "login_key_hash")
            if meta.status != "active":
                continue  # disabled users are not authentication candidates
            record = get_user(paths, meta.id)
            assert record is not None
            stored = record.login_key_hash  # the actual stored scrypt record
            assert is_valid_record(stored)
            if verify_secret(presented, stored):
                matches.append(meta.id)
        return matches

    assert authenticate(alice_key) == [alice.id]
    assert authenticate(bob_key) == []  # bob is disabled: skipped entirely
    assert authenticate("usr_" + "C" * 43) == []  # no key matches: no raise


def test_list_users_empty_when_registry_absent(tmp_path: Path) -> None:
    assert list_users(build_paths(tmp_path)) == []


def test_get_user_missing_returns_none(tmp_path: Path) -> None:
    assert get_user(build_paths(tmp_path), "ghost") is None


# --- schema: UserRecord / WrappedAEK strictness ---------------------------------


@pytest.mark.parametrize(
    "bad_id",
    [
        "",
        "Alice",
        "with/slash",
        "with.dot",
        "with space",
        "alién",
        "a" * 65,
        "trailing-newline\n",
    ],
    ids=[
        "empty",
        "uppercase",
        "slash",
        "dot",
        "space",
        "non-ascii",
        "too-long",
        "trailing-newline",
    ],
)
def test_schema_rejects_invalid_user_ids(bad_id: str) -> None:
    with pytest.raises(ValidationError):
        UserRecord.model_validate(_valid_record(id=bad_id))


@pytest.mark.parametrize("good_id", ["a", "a" * 64, "alice-2", "42"])
def test_schema_accepts_registry_rule_boundary_ids(good_id: str) -> None:
    record = UserRecord.model_validate(_valid_record(id=good_id))
    assert record.id == good_id


def test_schema_rejects_empty_name() -> None:
    with pytest.raises(ValidationError):
        UserRecord.model_validate(_valid_record(name=""))


def test_schema_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        UserRecord.model_validate(_valid_record(role="admin"))


def test_schema_rejects_unknown_status() -> None:
    with pytest.raises(ValidationError):
        UserRecord.model_validate(_valid_record(status="paused"))


@pytest.mark.parametrize(
    "plaintext_shaped",
    ["usr_" + "A" * 43, "adm_" + "A" * 43, "deadbeef", ""],
    ids=["usr-key", "adm-key", "raw-hex", "empty"],
)
def test_schema_rejects_plaintext_in_login_key_hash(plaintext_shaped: str) -> None:
    with pytest.raises(ValidationError):
        UserRecord.model_validate(_valid_record(login_key_hash=plaintext_shaped))


def test_schema_aek_finalized_contract() -> None:
    """M04-T02 finalization: absent/``null`` stay tolerated; the M03 empty
    placeholder (``aek: {}``) is now schema-invalid — ``blob`` is required,
    and a full ``WrappedAEK`` round-trips through the record.

    (Detailed ``WrappedAEK`` shape validation lives in test_aek_lifecycle.py.)
    """
    absent = UserRecord.model_validate(_valid_record())
    assert absent.aek is None

    null_aek = UserRecord.model_validate({**_valid_record(), "aek": None})
    assert null_aek.aek is None

    with pytest.raises(ValidationError):
        UserRecord.model_validate({**_valid_record(), "aek": {}})

    wrapped = UserRecord.model_validate(
        {**_valid_record(), "aek": {"blob": "QQ==:Bg==:Cg==", "version": 1}}
    )
    assert wrapped.aek == WrappedAEK(blob="QQ==:Bg==:Cg==", version=1)
