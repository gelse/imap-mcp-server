"""Unit tests for the fs-safe primitives: private dirs, secret files, atomic writes.

The mid-write failure tests monkeypatch the file-object seam inside
``write_secret_file`` (``os.fdopen``) so the temp file ends up with a partial
payload before the write fails — then assert that no temp/partial file is
left behind and the target's previous content is intact.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from imap_mcp_gateway.store.fs_safe import (
    ensure_dir,
    read_secret_file,
    write_secret_file,
)


def _mode(path: Path) -> int:
    """Return the permission bits of ``path`` (``st_mode & 0o777``)."""
    return os.stat(path).st_mode & 0o777


class _FailPartwayWriter:
    """File-object wrapper that writes half the payload, then fails.

    Simulates a process dying mid-write: the temp file on disk ends up with a
    partial payload while the target is never touched. Everything except
    ``write`` is delegated to a real file object opened on the same fd.
    """

    def __init__(self, fd: int, real_fdopen: Any) -> None:
        self._file = real_fdopen(fd, "wb")

    def write(self, data: bytes) -> int:
        self._file.write(data[: len(data) // 2])
        raise OSError("simulated mid-write failure")

    def flush(self) -> None:
        self._file.flush()

    def fileno(self) -> int:
        return int(self._file.fileno())

    def __enter__(self) -> Any:
        self._file.__enter__()
        return self

    def __exit__(self, *args: Any) -> Any:
        return self._file.__exit__(*args)


def _install_mid_write_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Route the ``os.fdopen`` call inside ``write_secret_file`` through the failing writer."""
    real_fdopen = os.fdopen

    def failing_fdopen(fd: int, mode: str, **kwargs: Any) -> Any:
        return _FailPartwayWriter(fd, real_fdopen)

    monkeypatch.setattr(os, "fdopen", failing_fdopen)


# --- ensure_dir --------------------------------------------------------------


def test_ensure_dir_creates_missing_directories_0700(tmp_path: Path) -> None:
    leaf = ensure_dir(tmp_path / "config" / "nested")
    assert leaf.is_dir()
    assert _mode(tmp_path / "config") == 0o700
    assert _mode(leaf) == 0o700


def test_ensure_dir_reasserts_mode_on_existing_directory(tmp_path: Path) -> None:
    directory = tmp_path / "users"
    directory.mkdir()
    os.chmod(directory, 0o755)
    assert _mode(directory) == 0o755

    ensure_dir(directory)

    assert _mode(directory) == 0o700


def test_ensure_dir_is_idempotent(tmp_path: Path) -> None:
    directory = tmp_path / "mail"
    ensure_dir(directory)
    ensure_dir(directory)
    assert _mode(directory) == 0o700


def test_ensure_dir_leaves_pre_existing_intermediates_untouched(tmp_path: Path) -> None:
    intermediate = tmp_path / "a"
    intermediate.mkdir()
    os.chmod(intermediate, 0o755)
    assert _mode(intermediate) == 0o755

    leaf = ensure_dir(intermediate / "b" / "c")

    # Pre-existing intermediates keep their mode; new levels are 0700.
    assert _mode(intermediate) == 0o755
    assert _mode(intermediate / "b") == 0o700
    assert _mode(leaf) == 0o700


# --- write_secret_file / read_secret_file -----------------------------------


def test_write_secret_file_sets_0600_and_round_trips(tmp_path: Path) -> None:
    target = tmp_path / "config" / "admin-key.hash"

    returned = write_secret_file(target, b"deadbeef")

    assert returned == target
    assert read_secret_file(target) == b"deadbeef"
    assert _mode(target) == 0o600


def test_write_secret_file_creates_missing_parent_0700(tmp_path: Path) -> None:
    target = tmp_path / "users" / "alice" / "user.json"

    write_secret_file(target, b"{}")

    assert _mode(target.parent) == 0o700
    assert _mode(target) == 0o600


def test_write_secret_file_overwrite_reasserts_0600(tmp_path: Path) -> None:
    target = tmp_path / "wrap.key"
    write_secret_file(target, b"old")
    os.chmod(target, 0o644)  # simulate permission drift on the existing file

    write_secret_file(target, b"new-and-longer")

    assert read_secret_file(target) == b"new-and-longer"
    assert _mode(target) == 0o600


def test_mid_write_failure_first_write_leaves_no_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "config" / "admin-key.hash"
    _install_mid_write_failure(monkeypatch)

    with pytest.raises(OSError, match="simulated mid-write failure"):
        write_secret_file(target, b"replacement-secret")

    assert not target.exists()
    # No temp/partial file left behind in the target's directory.
    assert list(target.parent.iterdir()) == []


def test_mid_write_failure_overwrite_keeps_previous_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "wrap.key"
    write_secret_file(target, b"original")
    _install_mid_write_failure(monkeypatch)

    with pytest.raises(OSError, match="simulated mid-write failure"):
        write_secret_file(target, b"replacement-secret-longer")

    assert read_secret_file(target) == b"original"
    assert _mode(target) == 0o600
    # The target is intact and no temp/partial file is left behind.
    assert list(tmp_path.iterdir()) == [target]


def test_failed_replace_leaves_target_and_cleans_temp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "wrap.key"
    write_secret_file(target, b"original")

    def _fail_replace(src: Any, dst: Any, **kwargs: Any) -> None:
        raise OSError("simulated replace failure")

    monkeypatch.setattr(os, "replace", _fail_replace)

    with pytest.raises(OSError, match="simulated replace failure"):
        write_secret_file(target, b"replacement")

    assert read_secret_file(target) == b"original"
    assert list(tmp_path.iterdir()) == [target]


def test_read_secret_file_round_trips_binary_payload(tmp_path: Path) -> None:
    target = tmp_path / "secret.bin"
    payload = bytes(range(256))
    write_secret_file(target, payload)
    assert read_secret_file(target) == payload
