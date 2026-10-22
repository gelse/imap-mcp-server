"""AEK lifecycle tests (M04-T02): activation, use, rotation, invariants.

Coverage per the M04-T02 acceptance criteria and the four test-enforced
invariants:

- invariant 1 — independence from the login key: regenerating the login key
  leaves ``user.json.aek`` byte-identical and accounts decryptable;
- invariant 2 — one-time disclosure: the plaintext hex exists exactly once
  per generation (the activation/rotation return value); no listing,
  serializer, or persisted file exposes it afterwards;
- invariant 3 — the wrapped blob alone is useless: without the server wrap
  key in memory unwrapping cannot even start, a wrong wrap key (the M04-T01
  carry-forward) and every tampered blob fail AES-GCM authentication;
- invariant 4 — no derivation from login-key material: ``crypto.aek``
  imports no login-key code path (greppable AST check), and the AEK
  survives login-key regeneration unchanged;

plus: lazy activation, one-time activation/rotation display, the zeroization
contract of ``with_aek`` (best-effort, bytearray-level), the finalized
``WrappedAEK`` schema, the rotation seam (re-encryption hooks) with full
re-encryption and abort-on-failure semantics, and the "regenerate login key
then decrypt accounts" regression test.
"""

from __future__ import annotations

import ast
import base64
import inspect
import json
import os
import re
import secrets
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import ValidationError

from imap_mcp_gateway.config.paths import Paths, build_paths
from imap_mcp_gateway.crypto import aek as aek_module
from imap_mcp_gateway.crypto import wrap
from imap_mcp_gateway.crypto.aek import (
    create_aek,
    unwrap_aek,
    wrap_aek,
    zeroize_aek,
)
from imap_mcp_gateway.crypto.hash import hash_secret
from imap_mcp_gateway.crypto.keys import generate_wrap_key
from imap_mcp_gateway.crypto.wrap import (
    UnwrapError,
    WrapKeyNotLoadedError,
    load_wrap_key,
)
from imap_mcp_gateway.store import aek_rotation
from imap_mcp_gateway.store.aek_rotation import register_reencrypt_hook, rotate_aek
from imap_mcp_gateway.store.user_schema import UserMetadata, UserRecord, WrappedAEK
from imap_mcp_gateway.store.users import (
    AEKAlreadyActiveError,
    AEKNotActiveError,
    activate_aek,
    create_user,
    get_user,
    list_users,
    rotate_login_key,
    verify_login_key,
    with_aek,
)
from imap_mcp_gateway.store.wrap_key import ensure_wrap_key
from imap_mcp_gateway.web.admin.serializers import to_admin_user_view

HEX32_RE = re.compile(r"^[0-9a-f]{64}$")

_FIXTURE_HASH = hash_secret("usr_fixture-plaintext")
"""One precomputed valid scrypt record so schema tests skip the KDF cost."""


# --- helpers and fixtures -------------------------------------------------------


def _mode(path: Path) -> int:
    """Return the permission bits of ``path`` (``st_mode & 0o777``)."""
    return os.stat(path).st_mode & 0o777


def _hex(aek: bytearray) -> str:
    """``with_aek`` callback: the AEK as its 64-char lowercase hex spelling."""
    return aek.hex()


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


def _flip_first_char(field: str) -> str:
    """Swap the field's first base64 character (A/B are both in the alphabet)."""
    replacement = "A" if field[0] != "A" else "B"
    return replacement + field[1:]


def _tamper(case: str, blob: str) -> str:
    """Return ``blob`` damaged in the way ``case`` names (all must fail)."""
    iv, tag, ciphertext = blob.split(":")
    if case == "iv-flipped":
        return f"{_flip_first_char(iv)}:{tag}:{ciphertext}"
    if case == "tag-flipped":
        return f"{iv}:{_flip_first_char(tag)}:{ciphertext}"
    if case == "ciphertext-flipped":
        return f"{iv}:{tag}:{_flip_first_char(ciphertext)}"
    if case == "garbage":
        return "not-a-blob"
    if case == "empty":
        return ""
    raise AssertionError(f"unknown tamper case {case!r}")


class _FakeCredentialStore:
    """Stand-in for M04-T03's encrypted account store (rotation participant).

    Keeps one AES-256-GCM-encrypted field per fake account id — enough to
    prove the rotation seam contract: after a rotation every field is
    decryptable under the NEW AEK, rejects the OLD one (GCM ``InvalidTag``),
    and the hook saw exactly the (user, old, new) triple rotation handed it.
    """

    def __init__(self) -> None:
        self.fields: dict[str, str] = {}
        self.calls: list[tuple[str, str, str]] = []

    def put(self, account_id: str, aek_hex: str, plaintext: str) -> None:
        iv = secrets.token_bytes(12)
        sealed = AESGCM(bytes.fromhex(aek_hex)).encrypt(iv, plaintext.encode(), None)
        self.fields[account_id] = base64.b64encode(iv + sealed).decode("ascii")

    def read(self, account_id: str, aek_hex: str) -> str:
        raw = base64.b64decode(self.fields[account_id])
        plain = AESGCM(bytes.fromhex(aek_hex)).decrypt(raw[:12], raw[12:], None)
        return plain.decode()

    def reencrypt(
        self, paths: Paths, user_id: str, old_hex: str, new_hex: str
    ) -> None:
        self.calls.append((user_id, old_hex, new_hex))
        for account_id in list(self.fields):
            self.put(account_id, new_hex, self.read(account_id, old_hex))


@pytest.fixture
def paths(tmp_path: Path) -> Paths:
    return build_paths(tmp_path)


@pytest.fixture
def server_wrap_key(paths: Paths) -> None:
    """Bootstrap AND persist this test's server wrap key via the startup gate.

    ``ensure_wrap_key`` (not a bare ``load_wrap_key``) so the key exists on
    disk too: restart-simulation tests reset the in-memory holder and reload
    the SAME key from disk through the same gate, exactly like a real
    process restart. (conftest resets the holder around every test.)
    """
    assert ensure_wrap_key(paths).created is True


@pytest.fixture
def user_id(paths: Paths) -> str:
    record, _ = create_user(paths, "alice")
    return record.id


@pytest.fixture
def reencrypt_registry() -> Iterator[list[aek_rotation.ReencryptHook]]:
    """Fresh rotation-participant registry per test; leftovers restored after."""
    saved = list(aek_rotation._REENCRYPT_HOOKS)
    aek_rotation._REENCRYPT_HOOKS.clear()
    yield aek_rotation._REENCRYPT_HOOKS
    aek_rotation._REENCRYPT_HOOKS[:] = saved


# --- crypto.aek.create_aek: format and entropy ----------------------------------


def test_create_aek_is_32_csprng_bytes_with_upstream_hex_material() -> None:
    aek = create_aek()
    assert len(aek) == 32
    assert HEX32_RE.fullmatch(aek.hex())  # 64 lowercase hex chars: the upstream .key


def test_create_aek_unique_across_generations() -> None:
    keys = {create_aek() for _ in range(1000)}
    assert len(keys) == 1000


# --- crypto.aek: wrap/unwrap round trip and failure modes -----------------------


def test_wrap_unwrap_aek_round_trip(server_wrap_key: None) -> None:
    aek = create_aek()
    blob = wrap_aek(aek)
    assert len(blob.split(":")) == 3  # base64(iv):base64(tag):base64(ciphertext)
    assert unwrap_aek(blob) == aek


@pytest.mark.parametrize(
    "bad_length",
    [0, 1, 31, 33, 64],
    ids=["empty", "one-byte", "short", "long", "double"],
)
def test_wrap_aek_rejects_wrong_length_material(bad_length: int) -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        wrap_aek(bytes(bad_length))


def test_unwrap_aek_rejects_authenticated_non_aek_payload(
    server_wrap_key: None,
) -> None:
    blob = wrap.wrap_key(b"authentic-but-not-an-aek")  # valid blob, wrong payload

    with pytest.raises(UnwrapError, match="32-byte"):
        unwrap_aek(blob)


def test_unwrap_aek_names_wrong_wrap_key_clearly(
    server_wrap_key: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    blob = wrap_aek(create_aek())
    monkeypatch.setattr(wrap, "_loaded_wrap_key", None)
    load_wrap_key(generate_wrap_key())  # a wrap key restored from the wrong backup

    with pytest.raises(UnwrapError, match="wrong wrap key or tampered blob"):
        unwrap_aek(blob)  # M04-T01 carry-forward: clear error, never wrong bytes


@pytest.mark.parametrize(
    "case",
    ["iv-flipped", "tag-flipped", "ciphertext-flipped", "garbage", "empty"],
)
def test_tampered_or_malformed_aek_blob_fails_unwrap(
    paths: Paths, user_id: str, server_wrap_key: None, case: str
) -> None:
    activate_aek(paths, user_id)
    record = get_user(paths, user_id)
    assert record is not None and record.aek is not None

    with pytest.raises(UnwrapError):
        unwrap_aek(_tamper(case, record.aek.blob))


# --- crypto.aek.zeroize_aek: best-effort buffer scrub ---------------------------


def test_zeroize_aek_overwrites_buffer_in_place() -> None:
    buffer = bytearray(range(32))

    zeroize_aek(buffer)

    assert buffer == bytearray(32)


# --- user_schema.WrappedAEK: finalized shape -------------------------------------


def test_wrapped_aek_schema_finalized_shape() -> None:
    wrapped = WrappedAEK(blob="QQ==:Bg==:Cg==")

    assert wrapped.blob == "QQ==:Bg==:Cg=="
    assert wrapped.version == 1  # default wrap-format version
    assert WrappedAEK(blob="QQ==:Bg==:Cg==", version=2).version == 2

    with pytest.raises(ValidationError):
        WrappedAEK.model_validate({})  # blob required — the M03 placeholder is gone
    with pytest.raises(ValidationError):
        # extra="forbid": an unknown field inside the aek record is rejected
        WrappedAEK.model_validate({"blob": "QQ==:Bg==:Cg==", "version": 1, "extra": "no"})


@pytest.mark.parametrize(
    "bad_blob",
    [
        "",
        "QQ==",
        "QQ==:Bg==",
        "QQ==:Bg==:Cg==:Dg==",
        "!!!!:Bg==:Cg==",
        "QQ=:Bg==:Cg==",
        ":Bg==:Cg==",
        "QQ==:Bg==:not base64",
    ],
    ids=[
        "empty",
        "one-field",
        "two-fields",
        "four-fields",
        "non-base64-field",
        "non-canonical-padding",
        "empty-field",
        "space-in-field",
    ],
)
def test_wrapped_aek_schema_rejects_bad_blobs(bad_blob: str) -> None:
    with pytest.raises(ValidationError):
        WrappedAEK(blob=bad_blob)


def test_wrapped_aek_schema_accepts_real_wrap_blob(server_wrap_key: None) -> None:
    blob = wrap_aek(create_aek())

    assert WrappedAEK(blob=blob).blob == blob


def test_user_record_accepts_finalized_wrapped_aek() -> None:
    record = UserRecord.model_validate(
        {**_valid_record(), "aek": {"blob": "QQ==:Bg==:Cg==", "version": 1}}
    )

    assert record.aek == WrappedAEK(blob="QQ==:Bg==:Cg==", version=1)


# --- lazy activation and one-time display (invariant 2) --------------------------


def test_aek_is_lazy_none_until_activation(paths: Paths, user_id: str) -> None:
    record = get_user(paths, user_id)
    assert record is not None
    assert record.aek is None  # lazy: no AEK until the user activates
    persisted = json.loads(paths.user_record_path(user_id).read_bytes())
    assert persisted.get("aek") is None  # null at rest before activation

    with pytest.raises(AEKNotActiveError):
        with_aek(paths, user_id, _hex)
    with pytest.raises(AEKNotActiveError):
        rotate_aek(paths, user_id)


def test_activate_aek_returns_64_hex_once_and_persists_only_wrapped(
    paths: Paths, user_id: str, server_wrap_key: None
) -> None:
    aek_hex = activate_aek(paths, user_id)

    assert HEX32_RE.fullmatch(aek_hex)
    record = get_user(paths, user_id)
    assert record is not None
    assert record.aek is not None
    assert unwrap_aek(record.aek.blob) == bytes.fromhex(aek_hex)
    record_path = paths.user_record_path(user_id)
    persisted = json.loads(record_path.read_bytes())
    assert persisted["aek"] == {"blob": record.aek.blob, "version": 1}
    assert aek_hex not in record_path.read_text(encoding="utf-8")
    assert _mode(record_path) == 0o600


def test_activated_plaintext_never_persisted_anywhere_under_data_dir(
    paths: Paths, tmp_path: Path, user_id: str, server_wrap_key: None
) -> None:
    aek_hex = activate_aek(paths, user_id)

    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert aek_hex.encode("ascii") not in path.read_bytes(), path


def test_double_activation_refused_and_blob_untouched(
    paths: Paths, user_id: str, server_wrap_key: None
) -> None:
    aek_hex = activate_aek(paths, user_id)
    raw_before = paths.user_record_path(user_id).read_bytes()

    with pytest.raises(AEKAlreadyActiveError, match="rotation"):
        activate_aek(paths, user_id)

    assert paths.user_record_path(user_id).read_bytes() == raw_before
    record = get_user(paths, user_id)
    assert record is not None and record.aek is not None
    assert unwrap_aek(record.aek.blob) == bytes.fromhex(aek_hex)  # key not replaced


def test_activate_missing_user_raises(paths: Paths) -> None:
    with pytest.raises(FileNotFoundError):
        activate_aek(paths, "ghost")


def test_no_listing_or_serializer_exposes_aek_material(
    paths: Paths, user_id: str, server_wrap_key: None
) -> None:
    aek_hex = activate_aek(paths, user_id)
    record = get_user(paths, user_id)
    assert record is not None and record.aek is not None

    # Listing: the metadata shape has no aek field at all.
    assert "aek" not in UserMetadata.model_fields
    for user in list_users(paths):
        assert "aek" not in user.model_dump()
        assert "aek" not in json.loads(user.model_dump_json())

    # Admin detail serializer: exactly the six metadata fields — never the
    # wrapped blob, never the one-time plaintext.
    view = to_admin_user_view(record)
    assert set(view) == {
        "id",
        "name",
        "status",
        "key_generation",
        "account_count",
        "created_at",
    }
    assert aek_hex not in json.dumps(view, default=str)  # str(): created_at datetime


# --- with_aek: in-memory use with best-effort zeroization ------------------------


def test_with_aek_hands_unwrapped_key_and_zeroizes_after(
    paths: Paths, user_id: str, server_wrap_key: None
) -> None:
    aek_hex = activate_aek(paths, user_id)
    seen: list[dict[str, object]] = []

    def use(aek: bytearray) -> str:
        seen.append({"hex": aek.hex(), "buffer": aek})
        return aek.hex()

    returned = with_aek(paths, user_id, use)

    assert returned == aek_hex
    assert seen[0]["hex"] == aek_hex  # fn saw the real key...
    buffer = seen[0]["buffer"]
    assert isinstance(buffer, bytearray)
    assert buffer == bytearray(32)  # ...zeroized after fn returned


def test_with_aek_zeroizes_even_when_fn_raises(
    paths: Paths, user_id: str, server_wrap_key: None
) -> None:
    activate_aek(paths, user_id)
    buffers: list[bytearray] = []

    def boom(aek: bytearray) -> str:
        buffers.append(aek)
        raise RuntimeError("callback failed")

    with pytest.raises(RuntimeError, match="callback failed"):
        with_aek(paths, user_id, boom)

    assert buffers == [bytearray(32)]  # zeroized despite the exception


def test_with_aek_survives_process_restart(
    paths: Paths, user_id: str, server_wrap_key: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    aek_hex = activate_aek(paths, user_id)
    monkeypatch.setattr(wrap, "_loaded_wrap_key", None)  # simulate a restart
    assert ensure_wrap_key(paths).created is False  # same key reloaded from disk

    assert with_aek(paths, user_id, _hex) == aek_hex


# --- invariant 1: AEK independent of the login key -------------------------------


def test_login_key_regeneration_leaves_aek_byte_identical(
    paths: Paths, user_id: str, server_wrap_key: None
) -> None:
    aek_hex = activate_aek(paths, user_id)
    record_path = paths.user_record_path(user_id)
    aek_before = json.loads(record_path.read_bytes())["aek"]

    _, new_login_key = rotate_login_key(paths, user_id)

    assert json.loads(record_path.read_bytes())["aek"] == aek_before  # byte-identical
    assert with_aek(paths, user_id, _hex) == aek_hex  # the same AEK bytes
    assert len(new_login_key) != len(aek_hex)  # unrelated key families (43 vs 64)


def test_regenerate_login_key_then_decrypt_accounts_regression(
    paths: Paths, server_wrap_key: None
) -> None:
    record, original_key = create_user(paths, "alice")
    activate_aek(paths, record.id)
    store = _FakeCredentialStore()
    with_aek(paths, record.id, lambda aek: store.put("acct-1", aek.hex(), "s3cret"))
    loaded = get_user(paths, record.id)
    assert loaded is not None and loaded.aek is not None
    blob_before = loaded.aek.blob

    _, new_key = rotate_login_key(paths, record.id)

    assert not verify_login_key(paths, record.id, original_key)  # old key is dead
    assert verify_login_key(paths, record.id, new_key)  # the new key works
    after = get_user(paths, record.id)
    assert after is not None and after.aek is not None
    assert after.aek.blob == blob_before  # AEK untouched by the login-key rotation
    assert (
        with_aek(paths, record.id, lambda aek: store.read("acct-1", aek.hex()))
        == "s3cret"  # accounts still decryptable with the SAME AEK
    )


# --- invariant 4: never derived from login-key material --------------------------


def test_aek_module_imports_no_login_key_code_paths() -> None:
    """Greppable invariant 4: ``crypto.aek`` imports no login-key code path."""
    source = inspect.getsource(aek_module)
    tree = ast.parse(source)
    first_party: list[tuple[str, tuple[str, ...]]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module and node.module.startswith("imap_mcp_gateway"):
                first_party.append(
                    (node.module, tuple(alias.name for alias in node.names))
                )
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("imap_mcp_gateway"):
                    first_party.append((alias.name, ()))
    assert first_party  # the wrap-layer import must be visible to this check
    for module, names in first_party:
        assert module in {
            "imap_mcp_gateway.crypto",
            "imap_mcp_gateway.crypto.wrap",
        }, module
        if module == "imap_mcp_gateway.crypto":
            assert set(names) == {"wrap"}  # the M04-T01 wrap layer only
    # Substring net over identifier-like names (the module-path guard is the
    # AST check above — prose in the docstring legitimately names modules).
    for forbidden in (
        "generate_user_key",
        "hash_secret",
        "login_key_hash",
    ):
        assert forbidden not in source


# --- invariant 3: the wrapped blob alone is useless ------------------------------


def test_wrapped_blob_is_useless_without_the_wrap_key(
    paths: Paths,
    user_id: str,
    server_wrap_key: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    activate_aek(paths, user_id)
    record = get_user(paths, user_id)
    assert record is not None and record.aek is not None
    blob = record.aek.blob

    # No wrap key installed: unwrapping cannot even start.
    monkeypatch.setattr(wrap, "_loaded_wrap_key", None)
    with pytest.raises(WrapKeyNotLoadedError):
        unwrap_aek(blob)

    # A different wrap key (the wrong restored backup): GCM rejects it.
    load_wrap_key(generate_wrap_key())
    with pytest.raises(UnwrapError, match="wrong wrap key or tampered blob"):
        unwrap_aek(blob)

    # Back on the right key, tampering any component still fails.
    monkeypatch.setattr(wrap, "_loaded_wrap_key", None)
    assert ensure_wrap_key(paths).created is False  # the original key, from disk
    iv, tag, ciphertext = blob.split(":")
    with pytest.raises(UnwrapError):
        unwrap_aek(f"{_flip_first_char(iv)}:{tag}:{ciphertext}")


# --- rotation: one-time display, re-encryption seam, abort semantics --------------


def test_rotate_aek_requires_activation(paths: Paths, user_id: str) -> None:
    with pytest.raises(AEKNotActiveError):
        rotate_aek(paths, user_id)


def test_rotate_missing_user_raises(paths: Paths) -> None:
    with pytest.raises(FileNotFoundError):
        rotate_aek(paths, "ghost")


def test_rotate_aek_returns_new_plaintext_once_and_rewraps(
    paths: Paths, user_id: str, server_wrap_key: None
) -> None:
    old_hex = activate_aek(paths, user_id)
    record_path = paths.user_record_path(user_id)
    raw_before = record_path.read_bytes()

    new_hex = rotate_aek(paths, user_id)

    assert HEX32_RE.fullmatch(new_hex)
    assert new_hex != old_hex
    record = get_user(paths, user_id)
    assert record is not None and record.aek is not None
    assert unwrap_aek(record.aek.blob) == bytes.fromhex(new_hex)
    raw_after = record_path.read_bytes()
    assert raw_after != raw_before  # blob rewrapped under the new AEK
    assert old_hex.encode("ascii") not in raw_after
    assert new_hex.encode("ascii") not in raw_after
    for path in paths.data_dir.rglob("*"):
        if path.is_file():
            assert old_hex.encode("ascii") not in path.read_bytes(), path


def test_rotate_aek_reencrypts_registered_store_fields(
    paths: Paths,
    user_id: str,
    server_wrap_key: None,
    reencrypt_registry: list[aek_rotation.ReencryptHook],
) -> None:
    old_hex = activate_aek(paths, user_id)
    store = _FakeCredentialStore()
    with_aek(
        paths, user_id, lambda aek: store.put("acct-1", aek.hex(), "imap-password")
    )

    unregister = register_reencrypt_hook(store.reencrypt)
    try:
        new_hex = rotate_aek(paths, user_id)
    finally:
        unregister()

    assert store.calls == [(user_id, old_hex, new_hex)]  # one (user, old, new) triple
    assert store.read("acct-1", new_hex) == "imap-password"  # decrypts under NEW
    with pytest.raises(InvalidTag):
        store.read("acct-1", old_hex)  # invariant: old AEK no longer decrypts
    assert with_aek(paths, user_id, _hex) == new_hex  # the new key is active


def test_rotate_aek_without_participants_rewraps_blob_only(
    paths: Paths,
    user_id: str,
    server_wrap_key: None,
    reencrypt_registry: list[aek_rotation.ReencryptHook],
) -> None:
    old_hex = activate_aek(paths, user_id)

    new_hex = rotate_aek(paths, user_id)

    assert new_hex != old_hex
    record = get_user(paths, user_id)
    assert record is not None and record.aek is not None
    assert unwrap_aek(record.aek.blob) == bytes.fromhex(new_hex)


def test_rotate_aek_hook_failure_aborts_without_persisting(
    paths: Paths,
    user_id: str,
    server_wrap_key: None,
    reencrypt_registry: list[aek_rotation.ReencryptHook],
) -> None:
    old_hex = activate_aek(paths, user_id)
    raw_before = paths.user_record_path(user_id).read_bytes()

    def failing_hook(paths: Paths, uid: str, old: str, new: str) -> None:
        raise RuntimeError("store re-encryption failed")

    register_reencrypt_hook(failing_hook)

    with pytest.raises(RuntimeError, match="re-encryption failed"):
        rotate_aek(paths, user_id)

    assert paths.user_record_path(user_id).read_bytes() == raw_before
    assert with_aek(paths, user_id, _hex) == old_hex  # old AEK still authoritative


def test_rotate_aek_persist_failure_after_hook_pins_residual_window(
    paths: Paths,
    user_id: str,
    server_wrap_key: None,
    reencrypt_registry: list[aek_rotation.ReencryptHook],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The documented residual rotation window (aek_rotation module docstring).

    Hooks re-encrypt their stores under the new AEK BEFORE the rewrapped
    record is persisted; if that final persist fails, the store is under
    the new AEK while ``user.json`` still wraps the old one — unrecoverable
    in-process (the new plaintext was neither displayed nor persisted).
    This test pins the exact per-artifact outcome so a future hardening
    (M04-T03+) changes it deliberately, not silently.
    """
    old_hex = activate_aek(paths, user_id)
    store = _FakeCredentialStore()
    with_aek(paths, user_id, lambda aek: store.put("acct-1", aek.hex(), "cred"))
    record_path = paths.user_record_path(user_id)
    raw_before = record_path.read_bytes()

    register_reencrypt_hook(store.reencrypt)

    def broken_save(paths: Paths, record: UserRecord) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(aek_rotation, "_save", broken_save)

    with pytest.raises(OSError, match="disk full"):
        rotate_aek(paths, user_id)

    assert record_path.read_bytes() == raw_before  # record: still the old blob
    assert with_aek(paths, user_id, _hex) == old_hex  # old AEK authoritative
    new_hex = store.calls[0][2]  # the (user, old, new) triple the hook received
    assert store.read("acct-1", new_hex) == "cred"  # hook had applied (the window)
