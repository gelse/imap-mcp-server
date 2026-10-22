"""Wrap-key tests (M04-T01): generation, AES-GCM wrap, bootstrap, guards.

Coverage per the M04-T01 acceptance criteria:

- generation format (``crypto.keys.generate_wrap_key``: 64 lowercase hex
  chars = 32 bytes) and entropy;
- bootstrap: a fresh ``DATA_DIR`` creates ``wrap.key`` with mode ``0600`` in
  a ``0700`` config directory, holding exactly 64 hex chars;
- persistence/reuse: a second boot reuses the same key — a value wrapped on
  boot 1 unwraps on boot 2, and the file is byte-identical;
- AES-256-GCM round trip with a fresh random IV per wrap; tampering ANY blob
  component (iv/tag/ciphertext) or any structural damage fails unwrap;
- fail-fast guards: with wrapped AEKs (``user.json`` ``aek`` blobs) on disk,
  a corrupted wrap key file fails startup loudly (never silently
  regenerated), and a MISSING wrap key is refused as the account-crypto
  wipe it is; without wrapped AEKs, corrupt content is regenerated;
- admin-key reset semantics (M02): deleting ``admin-key.hash`` never
  deletes or rotates ``wrap.key``;
- load-once invariant: one in-memory holder per process — after first load,
  wrap/unwrap work without the file, the ensure gate never re-reads or
  re-creates, and a second ``load_wrap_key`` is refused;
- the lifespan log contract (``[config] wrap key created`` / ``[config]
  wrap key found``) with zero key material in any log line;
- the language boundary: the wrap-key modules are pure Python/cryptography —
  no process-spawning or environment machinery that could leak the key into
  the vendored npx subprocess.
"""

from __future__ import annotations

import base64
import importlib
import inspect
import json
import logging
import os
import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from imap_mcp_gateway.app import _boot_lifespan
from imap_mcp_gateway.config.env import Settings
from imap_mcp_gateway.config.paths import Paths, build_paths
from imap_mcp_gateway.crypto import wrap
from imap_mcp_gateway.crypto.keys import generate_wrap_key
from imap_mcp_gateway.crypto.wrap import (
    UnwrapError,
    WrapKeyAlreadyLoadedError,
    WrapKeyNotLoadedError,
    load_wrap_key,
    unwrap_key,
    wrap_key,
)
from imap_mcp_gateway.log import RedactCapableFormatter
from imap_mcp_gateway.store.admin_key import ensure_admin_key
from imap_mcp_gateway.store.wrap_key import (
    WrapKeyCorruptedError,
    WrapKeyUnavailableError,
    ensure_wrap_key,
    wrapped_account_keys_exist,
)
from imap_mcp_gateway.web.server import create_app

HEX32_RE = re.compile(r"^[0-9a-f]{64}$")

_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

_AEK_ABSENT = object()
"""Sentinel: write the user record WITHOUT an ``aek`` field at all."""


class _CaptureLinesHandler(logging.Handler):
    """Test handler recording formatted log lines in memory (pattern of conftest.py)."""

    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.format(record))


@pytest.fixture
def boot_log_lines() -> Iterator[list[str]]:
    """Capture the ``imap_mcp_gateway.app`` logger's formatted lines."""
    handler = _CaptureLinesHandler()
    handler.setFormatter(RedactCapableFormatter())
    logger = logging.getLogger("imap_mcp_gateway.app")
    logger.addHandler(handler)
    try:
        yield handler.lines
    finally:
        logger.removeHandler(handler)


def _boot(paths: Paths) -> None:
    """Run one full lifespan cycle in-process (startup + shutdown)."""
    app = create_app(Settings(data_dir=paths.data_dir), lifespan=_boot_lifespan(paths))
    with TestClient(app):
        pass  # startup logged on __enter__; shutdown logged on __exit__


def _restart(monkeypatch: pytest.MonkeyPatch) -> None:
    """Simulate a process restart: the in-memory wrap key holder is gone."""
    monkeypatch.setattr(wrap, "_loaded_wrap_key", None)


def _mode(path: Path) -> int:
    """Return the permission bits of ``path`` (``st_mode & 0o777``)."""
    return os.stat(path).st_mode & 0o777


def _flip_char(field: str, index: int = 0) -> str:
    """Return ``field`` with one base64 alphabet character swapped (A/B are in it)."""
    replacement = "A" if field[index] != "A" else "B"
    return field[:index] + replacement + field[index + 1 :]


def _non_canonical_sibling(field: str) -> str:
    """Flip the last data char's spare trailing bits: decodes identically, non-canonical.

    In the final base64 group the last data character carries ignored
    trailing bits; mutating only those bits leaves the decoded bytes
    unchanged, so ONLY the canonical re-encoding check can reject the
    spelling (a lenient decoder would silently accept it).
    """
    return field[:-3] + _B64_ALPHABET[_B64_ALPHABET.index(field[-3]) ^ 1] + field[-2:]


def _tamper(case: str, blob: str) -> str:
    """Return ``blob`` damaged in the way ``case`` names (all must fail)."""
    iv, tag, ciphertext = blob.split(":")
    if case == "iv-flipped":
        return f"{_flip_char(iv)}:{tag}:{ciphertext}"
    if case == "tag-flipped":
        return f"{iv}:{_flip_char(tag)}:{ciphertext}"
    if case == "ciphertext-flipped":
        return f"{iv}:{tag}:{_flip_char(ciphertext)}"
    if case == "tag-spare-bits-non-canonical":
        return f"{iv}:{_non_canonical_sibling(tag)}:{ciphertext}"
    if case == "missing-field":
        return f"{iv}:{tag}"
    if case == "extra-field":
        return f"{blob}:{ciphertext}"
    if case == "empty":
        return ""
    if case == "garbage":
        return "not-a-blob"
    if case == "iv-extra-padding":
        return f"{iv}=:{tag}:{ciphertext}"
    if case == "ciphertext-truncated":
        return f"{iv}:{tag}:{ciphertext[:-1]}"
    if case == "whitespace-injected":
        return f"{iv} :{tag}:{ciphertext}"
    raise AssertionError(f"unknown tamper case {case!r}")


def _write_user_record(
    paths: Paths, user_id: str, *, aek: object = _AEK_ABSENT
) -> Path:
    """Write ``users/<id>/user.json`` with an optional ``aek`` field value."""
    record_dir = paths.user_dir(user_id)
    record_dir.mkdir(parents=True, exist_ok=True)
    record_path = record_dir / "user.json"
    record: dict[str, object] = {
        "id": user_id,
        "name": "Alice",
        "created_at": "2026-01-01T00:00:00Z",
        "login_key_hash": (
            "scrypt$32768$8$1$YWFhYWFhYWFhYQ$"
            "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI"
        ),
    }
    if aek is not _AEK_ABSENT:
        record["aek"] = aek
    record_path.write_text(json.dumps(record), encoding="utf-8")
    return record_path


# --- crypto.keys.generate_wrap_key: format and entropy -------------------------


def test_generate_wrap_key_is_64_lowercase_hex_chars() -> None:
    for _ in range(100):
        key = generate_wrap_key()
        assert HEX32_RE.fullmatch(key)
        assert bytes.fromhex(key).hex() == key  # canonical lowercase spelling


def test_generate_wrap_keys_are_unique_across_1000_generations() -> None:
    keys = {generate_wrap_key() for _ in range(1000)}
    assert len(keys) == 1000


# --- crypto.wrap: AES-256-GCM round trip and tamper rejection ------------------


def test_wrap_unwrap_round_trip_with_fresh_iv_per_call() -> None:
    load_wrap_key(generate_wrap_key())
    payload = b"account-encryption-key-\x00\x01\xff"
    first, second = wrap_key(payload), wrap_key(payload)

    assert first != second  # fresh random IV per wrap
    assert unwrap_key(first) == payload
    assert unwrap_key(second) == payload
    assert unwrap_key(wrap_key(b"")) == b""  # degenerate payload still authenticates


def test_blob_format_is_base64_iv_tag_ciphertext() -> None:
    load_wrap_key(generate_wrap_key())
    iv, tag, ciphertext = wrap_key(b"format-check-payload").split(":")

    # base64 of the 12-byte IV (16 chars) and the 16-byte GCM tag (24 chars).
    assert len(base64.b64decode(iv)) == 12
    assert len(base64.b64decode(tag)) == 16
    assert len(ciphertext) % 4 == 0  # standard padded base64 fields


@pytest.mark.parametrize(
    "case",
    [
        "iv-flipped",
        "tag-flipped",
        "ciphertext-flipped",
        "tag-spare-bits-non-canonical",
        "missing-field",
        "extra-field",
        "empty",
        "garbage",
        "iv-extra-padding",
        "ciphertext-truncated",
        "whitespace-injected",
    ],
)
def test_tampered_or_malformed_blob_fails(case: str) -> None:
    load_wrap_key(generate_wrap_key())
    blob = wrap_key(b"tamper-target-payload")

    with pytest.raises(UnwrapError):
        unwrap_key(_tamper(case, blob))


def test_unwrap_under_a_different_wrap_key_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    load_wrap_key(generate_wrap_key())
    blob = wrap_key(b"wrapped-under-the-first-key")

    monkeypatch.setattr(wrap, "_loaded_wrap_key", None)  # fresh process, new key
    load_wrap_key(generate_wrap_key())

    with pytest.raises(UnwrapError, match="failed authentication"):
        unwrap_key(blob)


def test_wrap_and_unwrap_require_the_loaded_key() -> None:
    with pytest.raises(WrapKeyNotLoadedError, match="no wrap key loaded"):
        wrap_key(b"too-early")
    with pytest.raises(WrapKeyNotLoadedError, match="no wrap key loaded"):
        unwrap_key("QQ==:Bg==:Cg==")


def test_load_wrap_key_validates_material_and_refuses_second_install() -> None:
    key = generate_wrap_key()
    load_wrap_key(key)
    with pytest.raises(WrapKeyAlreadyLoadedError):
        load_wrap_key(generate_wrap_key())


@pytest.mark.parametrize(
    "bad_material",
    ["", "zz", "A" * 64, "a" * 63, "a" * 65],
    ids=["empty", "non-hex", "uppercase", "short", "long"],
)
def test_load_wrap_key_rejects_invalid_material(bad_material: str) -> None:
    with pytest.raises(ValueError, match="64 lowercase hex characters"):
        load_wrap_key(bad_material)


# --- store.wrap_key: bootstrap, reuse, modes -----------------------------------


def test_fresh_data_dir_bootstraps_wrap_key_at_0600_with_64_hex_chars(
    tmp_path: Path,
) -> None:
    paths = build_paths(tmp_path)

    result = ensure_wrap_key(paths)

    assert result.created is True
    key_path = paths.wrap_key_path()
    assert key_path.is_file()
    assert _mode(key_path) == 0o600
    assert _mode(key_path.parent) == 0o700
    key_hex = key_path.read_text(encoding="ascii")
    assert HEX32_RE.fullmatch(key_hex)
    # Installed and live: the holder wraps under exactly the persisted key.
    assert unwrap_key(wrap_key(b"live")) == b"live"
    # Single install: the gate's load is the only one for this process.
    with pytest.raises(WrapKeyAlreadyLoadedError):
        load_wrap_key(key_hex)


def test_second_boot_reuses_same_key_and_boot1_wrap_unwraps_on_boot2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = build_paths(tmp_path)
    assert ensure_wrap_key(paths).created is True
    key_hex = paths.wrap_key_path().read_text(encoding="ascii")
    blob = wrap_key(b"wrapped-on-boot-1")

    monkeypatch.setattr(wrap, "_loaded_wrap_key", None)  # simulate process restart
    result = ensure_wrap_key(paths)

    assert result.created is False
    assert paths.wrap_key_path().read_text(encoding="ascii") == key_hex
    assert unwrap_key(blob) == b"wrapped-on-boot-1"


def test_operator_whitespace_edit_tolerated_as_same_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = build_paths(tmp_path)
    assert ensure_wrap_key(paths).created is True
    key_hex = paths.wrap_key_path().read_text(encoding="ascii")
    paths.wrap_key_path().write_text(f"  {key_hex}\n", encoding="ascii")

    monkeypatch.setattr(wrap, "_loaded_wrap_key", None)
    result = ensure_wrap_key(paths)

    assert result.created is False  # same key, not corruption
    assert unwrap_key(wrap_key(b"same-key")) == b"same-key"


# --- store.wrap_key: fail-fast guards (wrapped AEKs on disk) --------------------


def test_corrupt_wrap_key_with_wrapped_aeks_fails_fast_without_regeneration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = build_paths(tmp_path)
    assert ensure_wrap_key(paths).created is True
    _write_user_record(paths, "alice", aek={"blob": "QQ==:Bg==:Cg==", "version": 1})
    paths.wrap_key_path().write_bytes(b"garbage-not-a-key")
    _restart(monkeypatch)  # corruption happened between boots

    with pytest.raises(WrapKeyCorruptedError, match="corrupted wrap key") as excinfo:
        ensure_wrap_key(paths)

    assert "restore the file from backup" in str(excinfo.value)
    assert paths.wrap_key_path().read_bytes() == b"garbage-not-a-key"  # evidence kept


@pytest.mark.parametrize(
    ("payload", "label"),
    [
        (b"", "empty-file"),
        (b"\n", "newline-only"),
        (b"0" * 63, "one-char-short"),
        (b"0" * 65, "one-char-long"),
        (b"\xff\xfe-corrupted", "non-ascii"),
    ],
)
def test_invalid_wrap_key_contents_with_aeks_fail_loudly(
    tmp_path: Path, payload: bytes, label: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = build_paths(tmp_path)
    assert ensure_wrap_key(paths).created is True
    _write_user_record(paths, "alice", aek={"blob": "QQ==:Bg==:Cg==", "version": 1})
    paths.wrap_key_path().write_bytes(payload)
    _restart(monkeypatch)  # corruption happened between boots

    with pytest.raises(WrapKeyCorruptedError, match="corrupted wrap key"):
        ensure_wrap_key(paths)

    assert paths.wrap_key_path().read_bytes() == payload  # nothing rewritten


def test_missing_wrap_key_with_wrapped_aeks_refused_as_crypto_wipe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = build_paths(tmp_path)
    assert ensure_wrap_key(paths).created is True
    _write_user_record(paths, "alice", aek={"blob": "QQ==:Bg==:Cg==", "version": 1})
    paths.wrap_key_path().unlink()  # the deletion == account-crypto wipe
    _restart(monkeypatch)  # the deletion happened between boots

    with pytest.raises(WrapKeyUnavailableError, match="account-crypto") as excinfo:
        ensure_wrap_key(paths)

    assert "restore the file from backup" in str(excinfo.value)
    assert not paths.wrap_key_path().exists()  # NOT silently regenerated


def test_directory_at_wrap_key_path_fails_loudly_without_replacement(
    tmp_path: Path,
) -> None:
    paths = build_paths(tmp_path)
    paths.wrap_key_path().mkdir(parents=True)  # a dir where the key file should be

    with pytest.raises(WrapKeyCorruptedError, match="unreadable wrap key file"):
        ensure_wrap_key(paths)

    assert paths.wrap_key_path().is_dir()  # nothing destroyed or replaced


def test_dangling_symlink_at_wrap_key_path_fails_loudly_without_replacement(
    tmp_path: Path,
) -> None:
    paths = build_paths(tmp_path)
    paths.config_dir().mkdir(parents=True)
    paths.wrap_key_path().symlink_to(tmp_path / "no-such-key")

    with pytest.raises(WrapKeyCorruptedError, match="unreadable wrap key file"):
        ensure_wrap_key(paths)

    assert paths.wrap_key_path().is_symlink()  # evidence preserved


# --- store.wrap_key: recovery without wrapped AEKs ------------------------------


def test_corrupt_wrap_key_without_wrapped_aeks_is_regenerated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = build_paths(tmp_path)
    assert ensure_wrap_key(paths).created is True
    paths.wrap_key_path().write_bytes(b"garbage-not-a-key")
    _restart(monkeypatch)  # corruption happened between boots

    result = ensure_wrap_key(paths)

    assert result.created is True  # recovery reported like a fresh creation
    key_hex = paths.wrap_key_path().read_text(encoding="ascii")
    assert HEX32_RE.fullmatch(key_hex)
    assert _mode(paths.wrap_key_path()) == 0o600
    assert unwrap_key(wrap_key(b"post-recovery")) == b"post-recovery"


def test_missing_wrap_key_without_any_wrapped_aeks_regenerates(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)
    _write_user_record(paths, "alice", aek=None)  # registry exists, no AEK activated

    result = ensure_wrap_key(paths)

    assert result.created is True
    assert HEX32_RE.fullmatch(paths.wrap_key_path().read_text(encoding="ascii"))


# --- store.wrap_key: wrapped-AEK detection --------------------------------------


def test_wrapped_account_keys_exist_scenarios(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)
    assert wrapped_account_keys_exist(paths) is False  # no users dir yet

    _write_user_record(paths, "alice")  # no aek field at all (M03 default)
    assert wrapped_account_keys_exist(paths) is False
    _write_user_record(paths, "bob", aek=None)  # aek reserved, not activated
    assert wrapped_account_keys_exist(paths) is False

    _write_user_record(paths, "carol", aek={"blob": "QQ==:Bg==:Cg==", "version": 1})
    assert wrapped_account_keys_exist(paths) is True


def test_unreadable_user_record_counts_as_wrapped_aek_fail_closed(
    tmp_path: Path,
) -> None:
    paths = build_paths(tmp_path)
    record_dir = paths.user_dir("dave")
    record_dir.mkdir(parents=True)
    (record_dir / "user.json").write_bytes(b"\xff\xfe-not-json")

    assert wrapped_account_keys_exist(paths) is True  # may hold a wrapped AEK


def test_shape_invalid_user_record_counts_as_wrapped_aek_fail_closed(
    tmp_path: Path,
) -> None:
    """A parseable JSON non-object is not a shape the gateway writes: fail closed."""
    paths = build_paths(tmp_path)
    record_dir = paths.user_dir("erin")
    record_dir.mkdir(parents=True)
    (record_dir / "user.json").write_text("[1, 2, 3]", encoding="utf-8")

    assert wrapped_account_keys_exist(paths) is True


def test_non_user_entries_under_users_dir_are_skipped(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)
    paths.users_dir().mkdir(parents=True)
    (paths.users_dir() / "stray.txt").write_text("hello", encoding="utf-8")
    (paths.users_dir() / "ghost").mkdir()  # directory without a record

    assert wrapped_account_keys_exist(paths) is False


# --- admin-key reset invariant (M02 reset semantics) ----------------------------


def test_admin_key_reset_does_not_delete_or_rotate_wrap_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = build_paths(tmp_path)
    assert ensure_admin_key(paths).created is True
    assert ensure_wrap_key(paths).created is True
    blob = wrap_key(b"pre-reset-account-key")
    wrap_bytes = paths.wrap_key_path().read_bytes()

    paths.admin_key_hash_path().unlink()  # the supported admin-key reset action
    assert ensure_admin_key(paths).created is True  # reset boot: new credential

    assert paths.wrap_key_path().read_bytes() == wrap_bytes  # untouched on disk
    # A fresh process still finds the SAME wrap key: boot-1 blob still opens.
    monkeypatch.setattr(wrap, "_loaded_wrap_key", None)
    assert ensure_wrap_key(paths).created is False
    assert unwrap_key(blob) == b"pre-reset-account-key"


# --- load-once invariant (single in-memory holder) ------------------------------


def test_wrap_key_is_loaded_once_and_survives_file_removal(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)
    assert ensure_wrap_key(paths).created is True
    blob = wrap_key(b"in-memory-payload")

    paths.wrap_key_path().unlink()  # operator deletes the file mid-process

    # No per-operation file reads: live wrapping/unwrapping continues.
    assert unwrap_key(blob) == b"in-memory-payload"
    assert unwrap_key(wrap_key(b"second")) == b"second"
    # The ensure gate serves from the holder: no re-read, no re-creation.
    assert ensure_wrap_key(paths).created is False
    assert not paths.wrap_key_path().exists()


# --- lifespan wiring: log contract and fail-fast startup ------------------------


def test_first_boot_logs_created_once_without_key_material(
    boot_log_lines: list[str], tmp_path: Path
) -> None:
    paths = build_paths(tmp_path)

    _boot(paths)

    created = [
        line for line in boot_log_lines if line.endswith("[config] wrap key created")
    ]
    assert len(created) == 1
    key_hex = paths.wrap_key_path().read_text(encoding="ascii")
    assert all(key_hex not in line for line in boot_log_lines)  # never logged
    # Startup ordering: after the [boot] start line, before serving.
    start_index = next(
        index
        for index, line in enumerate(boot_log_lines)
        if "[boot] starting imap-mcp-gateway" in line
    )
    assert boot_log_lines.index(created[0]) > start_index


def test_restart_logs_found_without_created_or_material(
    boot_log_lines: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = build_paths(tmp_path)
    _boot(paths)
    key_hex = paths.wrap_key_path().read_text(encoding="ascii")
    boot_log_lines.clear()
    monkeypatch.setattr(wrap, "_loaded_wrap_key", None)  # simulate process restart

    _boot(paths)

    found = [
        line for line in boot_log_lines if line.endswith("[config] wrap key found")
    ]
    assert len(found) == 1
    assert not any("wrap key created" in line for line in boot_log_lines)
    assert all(key_hex not in line for line in boot_log_lines)  # never logged


def test_corrupt_wrap_key_with_aeks_aborts_startup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = build_paths(tmp_path)
    assert ensure_wrap_key(paths).created is True
    _write_user_record(paths, "alice", aek={"blob": "QQ==:Bg==:Cg==", "version": 1})
    paths.wrap_key_path().write_bytes(b"garbage-not-a-key")
    _restart(monkeypatch)  # corruption happened between boots
    app = create_app(Settings(data_dir=paths.data_dir), lifespan=_boot_lifespan(paths))

    with pytest.raises(WrapKeyCorruptedError):  # startup fails, listener never starts
        with TestClient(app):
            pass

    assert paths.wrap_key_path().read_bytes() == b"garbage-not-a-key"  # rotated nothing


def test_missing_wrap_key_with_aeks_aborts_startup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = build_paths(tmp_path)
    assert ensure_wrap_key(paths).created is True
    _write_user_record(paths, "alice", aek={"blob": "QQ==:Bg==:Cg==", "version": 1})
    paths.wrap_key_path().unlink()
    _restart(monkeypatch)  # the deletion happened between boots
    app = create_app(Settings(data_dir=paths.data_dir), lifespan=_boot_lifespan(paths))

    with pytest.raises(WrapKeyUnavailableError):
        with TestClient(app):
            pass

    assert not paths.wrap_key_path().exists()  # a failed boot regenerates nothing


# --- language boundary: pure Python/crypto, no process or env machinery ---------


def test_wrap_key_modules_never_touch_processes_or_environment() -> None:
    """Greppable boundary check: the wrap key cannot enter a subprocess env.

    The ONLY Node component is the vendored npx subprocess; wrap key material
    must never enter any child's environment or arguments. The wrap/unwrap
    and store modules therefore import no process-spawning or environment
    machinery at all.
    """
    for module_name in (
        "imap_mcp_gateway.crypto.wrap",
        "imap_mcp_gateway.store.wrap_key",
    ):
        module = importlib.import_module(module_name)
        source = inspect.getsource(module)
        assert "subprocess" not in source
        assert "os.environ" not in source
        assert "putenv" not in source
        assert "Popen" not in source
