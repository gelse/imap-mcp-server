"""Admin-key startup lifecycle tests (M02-T02): ensure, ``[auth]`` logs, reset.

Coverage per the M02-T02 acceptance criteria:

- ``ensure_admin_key``'s three lifecycle branches — first boot creates the key
  and persists the hash ONLY, any later boot returns ``(False, None)`` without
  key material, and deleting the hash file rotates the key;
- reset isolation: user registry and ``wrap.key`` survive a reset untouched
  (seeded stand-ins byte-identical; M03/M04 surfaces do not exist yet, so the
  test also asserts non-creation of those paths);
- the lifespan log contract, via captured logger output: exactly one
  ``admin key created`` line carrying the ``adm_`` plaintext and the hash-file
  path on first boot; the literal ``existing key found`` with ZERO ``adm_``
  occurrences on restart; rotation repeats first-boot behaviour with a
  DIFFERENT key whose predecessor no longer verifies;
- the single-display invariant, both behaviourally (one line, one boot) and as
  a greppable source-convention scan (only ``store/admin_key.py`` may name
  ``EnsureResult`` or define ``ensure_admin_key``, only ``app.py`` may access
  ``.plaintext`` or call ``ensure_admin_key``);
 - the corrupted-hash-file lifecycle decision: ANY invalid record in a present
   hash file — non-ASCII bytes, empty/whitespace-only, ASCII garbage, a
   non-regular/unreadable path, or a dangling symlink/symlink loop at the
   path (present-but-invalid, never absence) — fails loud at startup as
   ``AdminKeyHashCorruptedError`` and never rotates the key. Since M02-T03
   the gate fully validates the record (strict structure plus scrypt
   parameter bounds, the same pre-KDF validation the auth path applies —
   symmetric gates), so record-shaped payloads with malformed fields or
   out-of-bounds parameters fail loud like every other invalid shape, while
   a resolvable symlink to a valid record stays on the existing-key path.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import imap_mcp_gateway
from imap_mcp_gateway.app import _boot_lifespan
from imap_mcp_gateway.config.env import Settings
from imap_mcp_gateway.config.paths import Paths, build_paths
from imap_mcp_gateway.crypto.hash import verify_secret
from imap_mcp_gateway.log import RedactCapableFormatter
from imap_mcp_gateway.store.admin_key import (
    AdminKeyHashCorruptedError,
    admin_key_exists,
    ensure_admin_key,
    load_admin_key_hash,
)
from imap_mcp_gateway.web.server import create_app

ADMIN_KEY_RE = re.compile(r"^adm_[A-Za-z0-9_-]{43}$")

CREATED_MESSAGE_PREFIX = (
    "[auth] admin key created — store it now; it will not be shown again: "
)
EXISTING_MESSAGE = "[auth] existing key found"
CORRUPTED_BYTES = b"scrypt$\xff\xfe-corrupted"


class _CaptureLinesHandler(logging.Handler):
    """Test handler recording formatted log lines in memory (pattern of conftest.py)."""

    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.format(record))


@pytest.fixture
def boot_log_lines() -> Iterator[list[str]]:
    """Capture the ``imap_mcp_gateway.app`` logger's formatted lines.

    Gateway loggers do not propagate (so ``caplog`` cannot see them); attach a
    handler to the module logger directly, like tests/test_app_lifecycle.py.
    """
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


def _displayed_created_key(lines: list[str]) -> str:
    """Extract the plaintext key from the single ``admin key created`` line."""
    created = [line for line in lines if CREATED_MESSAGE_PREFIX in line]
    assert len(created) == 1, lines
    return created[0].split(CREATED_MESSAGE_PREFIX, 1)[1]


# --- ensure_admin_key: the three lifecycle branches ----------------------------


def test_first_boot_creates_key_and_persists_hash_only(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)

    result = ensure_admin_key(paths)

    assert result.created is True
    plaintext = result.plaintext
    assert isinstance(plaintext, str)
    assert ADMIN_KEY_RE.fullmatch(plaintext)
    stored = load_admin_key_hash(paths)
    assert stored is not None
    assert verify_secret(plaintext, stored)
    raw = paths.admin_key_hash_path().read_bytes()
    assert plaintext.encode("ascii") not in raw  # hash only, never plaintext
    assert b"adm_" not in raw
    # Non-creation side of reset isolation: only the hash record appears;
    # the M03 registry and M04 wrap key are not created as a side effect.
    assert not paths.wrap_key_path().exists()
    assert not paths.users_dir().exists()
    assert not paths.mail_dir().exists()


def test_second_boot_returns_existing_without_material(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)
    ensure_admin_key(paths)
    record_before = paths.admin_key_hash_path().read_bytes()

    result = ensure_admin_key(paths)

    assert result.created is False
    assert result.plaintext is None  # no key material on the existing path
    assert paths.admin_key_hash_path().read_bytes() == record_before


def test_delete_hash_rotates_key_and_old_key_stops_verifying(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)
    first = ensure_admin_key(paths)
    old_key = first.plaintext
    assert isinstance(old_key, str)

    paths.admin_key_hash_path().unlink()  # the supported reset action

    second = ensure_admin_key(paths)
    assert second.created is True
    new_key = second.plaintext
    assert isinstance(new_key, str)
    assert new_key != old_key
    stored = load_admin_key_hash(paths)
    assert stored is not None
    assert verify_secret(new_key, stored)
    assert not verify_secret(old_key, stored)  # the old key no longer verifies


def test_reset_leaves_user_registry_and_wrap_key_untouched(tmp_path: Path) -> None:
    """A reset must not touch the user registry (M03) or ``wrap.key`` (M04).

    Neither milestone is implemented yet, so the "untouched" contract is
    asserted two ways: byte-identity of seeded stand-ins at the documented
    paths across a full create->reset cycle, and non-creation of anything
    beyond ``admin-key.hash`` in ``config/``.
    """
    paths = build_paths(tmp_path)
    wrap_path = paths.wrap_key_path()
    wrap_path.parent.mkdir(parents=True)
    wrap_bytes = b"wrap-key-sentinel"
    wrap_path.write_bytes(wrap_bytes)
    user_record = paths.user_record_path("alice")
    user_record.parent.mkdir(parents=True)
    user_bytes = b'{"user": "alice"}'
    user_record.write_bytes(user_bytes)

    ensure_admin_key(paths)
    paths.admin_key_hash_path().unlink()
    ensure_admin_key(paths)  # reset boot

    assert wrap_path.read_bytes() == wrap_bytes
    assert user_record.read_bytes() == user_bytes
    assert sorted(path.name for path in paths.config_dir().iterdir()) == [
        "admin-key.hash",
        "wrap.key",
    ]
    assert sorted(path.name for path in paths.users_dir().iterdir()) == ["alice"]


def test_corrupted_hash_file_fails_loudly_without_rotation(tmp_path: Path) -> None:
    """Lifecycle decision: corruption fails loud at startup, never rotates.

    The gateway itself only ever writes ASCII-validated records, so non-ASCII
    content means external corruption or tampering; treating it as absent
    would silently rotate the admin key (a credential replacement whose new
    plaintext lands in the logs) and mask the cause. The supported reset is
    the operator deleting the file — an explicit act — so ``ensure_admin_key``
    raises :class:`AdminKeyHashCorruptedError` (naming the file and the reset
    action, cause chain preserved) instead.
    """
    paths = build_paths(tmp_path)
    hash_path = paths.admin_key_hash_path()
    hash_path.parent.mkdir(parents=True)
    hash_path.write_bytes(CORRUPTED_BYTES)

    with pytest.raises(
        AdminKeyHashCorruptedError, match="corrupted admin key hash"
    ) as excinfo:
        ensure_admin_key(paths)

    assert "delete the file to reset" in str(excinfo.value)  # actionable signal
    assert hash_path.read_bytes() == CORRUPTED_BYTES  # evidence preserved
    assert admin_key_exists(paths)  # not silently treated as absent


@pytest.mark.parametrize(
    "payload",
    [b"", b"\n", b"  \n  ", b"garbage", b"not a record at all"],
    ids=["empty", "newline-only", "whitespace-only", "ascii-garbage", "plain-sentence"],
)
def test_invalid_hash_file_contents_fail_loudly_without_rotation(
    tmp_path: Path, payload: bytes
) -> None:
    """Empty/truncated or ASCII-garbage files are corruption, not absence.

    A zero-length or whitespace-only file (botched restore, truncation) must
    NOT silently rotate the admin key — the same rationale as the non-ASCII
    case, applied consistently to every "present but invalid" shape.
    """
    paths = build_paths(tmp_path)
    hash_path = paths.admin_key_hash_path()
    hash_path.parent.mkdir(parents=True)
    hash_path.write_bytes(payload)

    with pytest.raises(AdminKeyHashCorruptedError, match="corrupted admin key hash"):
        ensure_admin_key(paths)

    assert hash_path.read_bytes() == payload  # nothing rewritten, nothing rotated


def test_non_regular_file_at_hash_path_fails_loudly_with_remediation(
    tmp_path: Path,
) -> None:
    """A directory at the hash path fails loud with the actionable message.

    A bind-mount or restore mistake can leave something that is not a
    regular record file at ``config/admin-key.hash``; that is the same
    fail-loud family (with a raw ``OSError`` traceback, the operator loses
    the "delete the file to reset" remediation), and nothing may be
    destroyed or replaced by the failed boot.
    """
    paths = build_paths(tmp_path)
    hash_path = paths.admin_key_hash_path()
    hash_path.parent.mkdir(parents=True)
    hash_path.mkdir()  # a directory where the record file should be

    with pytest.raises(
        AdminKeyHashCorruptedError, match="corrupted admin key hash"
    ) as excinfo:
        ensure_admin_key(paths)

    assert "delete the file to reset" in str(excinfo.value)
    assert hash_path.is_dir()  # nothing destroyed or replaced


def test_dangling_symlink_at_hash_path_fails_loudly_without_rotation(
    tmp_path: Path,
) -> None:
    """A dangling symlink at the hash path is PRESENT-but-invalid, not absent.

    ``Path.exists()`` follows the link and reports ``False`` for a dangling
    entry; gating on it would take the first-boot branch and silently rotate
    the admin key (with the new plaintext in the logs) while clobbering the
    link — the exact outcome the fail-loud decision exists to prevent. The
    supported reset stays the operator deleting the symlink entry.
    """
    paths = build_paths(tmp_path)
    hash_path = paths.admin_key_hash_path()
    hash_path.parent.mkdir(parents=True)
    hash_path.symlink_to(tmp_path / "no-such-record")  # dangling

    with pytest.raises(
        AdminKeyHashCorruptedError, match="corrupted admin key hash"
    ) as excinfo:
        ensure_admin_key(paths)

    assert "delete the file to reset" in str(excinfo.value)  # actionable signal
    assert hash_path.is_symlink()  # evidence preserved — nothing replaced it
    assert admin_key_exists(paths)  # present, never silently treated as absent


def test_symlink_loop_at_hash_path_fails_loudly_without_rotation(
    tmp_path: Path,
) -> None:
    """A symlink loop at the hash path fails loud exactly like a dangling one.

    ``Path.exists()`` reports ``False`` on ``ELOOP`` too, so a loop must not
    be misread as first boot: the entry is present but unreadable, and the
    rotation with a logged plaintext must not happen.
    """
    paths = build_paths(tmp_path)
    hash_path = paths.admin_key_hash_path()
    hash_path.parent.mkdir(parents=True)
    hash_path.symlink_to(hash_path)  # self-referential loop

    with pytest.raises(
        AdminKeyHashCorruptedError, match="corrupted admin key hash"
    ) as excinfo:
        ensure_admin_key(paths)

    assert "delete the file to reset" in str(excinfo.value)
    assert hash_path.is_symlink()  # nothing replaced
    assert admin_key_exists(paths)  # present, never silently treated as absent


def test_symlink_to_valid_record_stays_on_existing_path(tmp_path: Path) -> None:
    """A resolvable symlink to a valid record is the existing-key path.

    The fail-loud gate must not overreach: a symlink that resolves to a
    readable valid record loads through the link and returns ``(False,
    None)`` — no rotation, no key material — and the link itself is left
    in place.
    """
    paths = build_paths(tmp_path)
    first = ensure_admin_key(paths)
    key = first.plaintext
    assert isinstance(key, str)
    external = tmp_path / "external" / "admin-key.hash"
    external.parent.mkdir()
    external.write_bytes(paths.admin_key_hash_path().read_bytes())
    paths.admin_key_hash_path().unlink()
    paths.admin_key_hash_path().symlink_to(external)

    result = ensure_admin_key(paths)

    assert result.created is False
    assert result.plaintext is None  # no key material on the existing path
    stored = load_admin_key_hash(paths)
    assert stored is not None
    assert verify_secret(key, stored)  # the original key verifies through the link
    assert paths.admin_key_hash_path().is_symlink()  # the link was not replaced


@pytest.mark.parametrize(
    "payload",
    [
        b"scrypt$32768$8$1$short",
        b"scrypt$134217728$8$1$" + b"A" * 22 + b"$" + b"B" * 43,
        b"scrypt$1073741824$8$1$" + b"A" * 22 + b"$" + b"B" * 43,
        b"scrypt$16384$12$1$" + b"A" * 22 + b"$" + b"B" * 43,
        b"scrypt$32768$8$2$" + b"A" * 22 + b"$" + b"B" * 43,
    ],
    ids=[
        "truncated-fields",
        "oversized-n",
        "hugely-oversized-n",
        "out-of-bounds-r",
        "out-of-bounds-p",
    ],
)
def test_record_shaped_but_invalid_fails_loudly_without_rotation(
    tmp_path: Path, payload: bytes
) -> None:
    """Full record validation at the startup gate (M02-T03, symmetric gates).

    Record-SHAPED payloads whose fields or scrypt parameters fail
    ``crypto.hash.is_valid_record`` are corruption like any other invalid
    content: the gateway only ever writes fully valid records, so such a
    file means external tampering — and an oversized ``N`` must never reach
    the KDF on the startup OR the auth path. Fail loud, preserve evidence,
    never rotate; deleting the file stays the supported reset.
    """
    paths = build_paths(tmp_path)
    hash_path = paths.admin_key_hash_path()
    hash_path.parent.mkdir(parents=True)
    hash_path.write_bytes(payload)

    with pytest.raises(AdminKeyHashCorruptedError, match="corrupted admin key hash"):
        ensure_admin_key(paths)

    assert hash_path.read_bytes() == payload  # evidence preserved, nothing rotated


# --- single-display invariant (greppable convention) ---------------------------


def test_single_display_invariant_only_lifespan_site_formats_plaintext() -> None:
    """Only the ensure store and its immediate logging site touch the plaintext.

    ``store/admin_key.py`` may name ``EnsureResult`` and define
    ``ensure_admin_key`` (it produces the values); ``app.py`` may call
    ``ensure_admin_key`` and access ``.plaintext`` (the one-time display). No
    other module in the package may reference any of those — anchoring on the
    call site, not just the attribute name, so tuple-indexing or
    ``getattr`` evasion cannot obtain the key outside the display path. This
    is the greppable convention pinning "no later code path ever logs the
    key".
    """
    src_root = Path(imap_mcp_gateway.__file__).resolve().parent
    offenders: list[str] = []
    for path in sorted(src_root.rglob("*.py")):
        relative = path.relative_to(src_root).as_posix()
        if relative in {"app.py", "store/admin_key.py"}:
            continue
        text = path.read_text(encoding="utf-8")
        if (
            "EnsureResult" in text
            or ".plaintext" in text
            or "ensure_admin_key" in text
        ):
            offenders.append(relative)
    assert offenders == []
    app_text = (src_root / "app.py").read_text(encoding="utf-8")
    assert "ensure_admin_key" in app_text  # the lifespan calls it
    assert "EnsureResult" not in app_text  # app.py logs the display, never the type
    assert app_text.count(".plaintext") == 1  # exactly the display site
    store_text = (src_root / "store" / "admin_key.py").read_text(encoding="utf-8")
    assert ".plaintext" not in store_text  # the store mints values, never formats them


# --- app lifespan: [auth] log contract per boot ---------------------------------


def test_first_boot_logs_created_once_with_hash_file_path(
    boot_log_lines: list[str], tmp_path: Path
) -> None:
    paths = build_paths(tmp_path)

    _boot(paths)

    created = [line for line in boot_log_lines if "admin key created" in line]
    assert len(created) == 1
    key = _displayed_created_key(boot_log_lines)
    assert ADMIN_KEY_RE.fullmatch(key)
    stored = load_admin_key_hash(paths)
    assert stored is not None
    assert verify_secret(key, stored)  # the displayed key is the real one
    assert sum(1 for line in boot_log_lines if key in line) == 1  # displayed once
    hash_lines = [
        line
        for line in boot_log_lines
        if line.endswith(f"[auth] hash file: {paths.admin_key_hash_path()}")
    ]
    assert len(hash_lines) == 1
    # Startup ordering: the ensure runs after the [boot] line, before serving.
    start_index = next(
        index
        for index, line in enumerate(boot_log_lines)
        if "[boot] starting imap-mcp-gateway" in line
    )
    assert start_index < boot_log_lines.index(created[0]) < boot_log_lines.index(
        hash_lines[0]
    )


def test_restart_logs_literal_existing_key_found_and_zero_material(
    boot_log_lines: list[str], tmp_path: Path
) -> None:
    paths = build_paths(tmp_path)
    _boot(paths)  # first boot (created-line assertions live in the test above)
    boot_log_lines.clear()

    _boot(paths)  # restart without changes

    existing = [line for line in boot_log_lines if line.endswith(EXISTING_MESSAGE)]
    assert len(existing) == 1  # the literal wording, as the exact message
    assert not any("adm_" in line for line in boot_log_lines)  # zero key material
    assert not any("admin key created" in line for line in boot_log_lines)


def test_delete_hash_restart_repeats_first_boot_with_different_key(
    boot_log_lines: list[str], tmp_path: Path
) -> None:
    paths = build_paths(tmp_path)
    _boot(paths)
    old_key = _displayed_created_key(boot_log_lines)
    paths.admin_key_hash_path().unlink()
    boot_log_lines.clear()

    _boot(paths)  # restart after deletion == first boot again

    new_key = _displayed_created_key(boot_log_lines)
    assert ADMIN_KEY_RE.fullmatch(new_key)
    assert new_key != old_key
    stored = load_admin_key_hash(paths)
    assert stored is not None
    assert verify_secret(new_key, stored)
    assert not verify_secret(old_key, stored)  # old key dead after reset
    assert sum(1 for line in boot_log_lines if new_key in line) == 1


def test_corrupted_hash_file_aborts_startup_loudly(tmp_path: Path) -> None:
    """The failed-loud decision holds at startup: the lifespan does not serve."""
    paths = build_paths(tmp_path)
    hash_path = paths.admin_key_hash_path()
    hash_path.parent.mkdir(parents=True)
    hash_path.write_bytes(CORRUPTED_BYTES)
    app = create_app(Settings(data_dir=paths.data_dir), lifespan=_boot_lifespan(paths))

    with pytest.raises(
        AdminKeyHashCorruptedError
    ):  # startup fails, listener never starts
        with TestClient(app):
            pass

    assert hash_path.read_bytes() == CORRUPTED_BYTES  # a failed boot rotates nothing
