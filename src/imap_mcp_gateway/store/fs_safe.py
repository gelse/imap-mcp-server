"""Crash- and permission-safe filesystem primitives for all gateway state.

Every on-disk write in the gateway goes through this module so the layout
contract holds unconditionally (mirrors upstream's ``enforceStorePermissions``
behaviour):

- directories created here are ``0700`` (:data:`PRIVATE_DIR_MODE`);
- secret-bearing files created here are ``0600`` (:data:`SECRET_FILE_MODE`);
- file contents are replaced atomically: :func:`write_secret_file` writes a
  temp file in the target's directory, fsyncs it, then ``os.replace``s it over
  the target — readers observe either the old or the new content, never a
  partial file. Any catchable failure removes the temp file and keeps the
  previous content intact; only an uncatchable kill (SIGKILL/power loss) can
  leave a hidden ``.name.*.tmp`` file behind — the target itself is never
  partially written;
- modes are re-asserted with ``chmod`` even when the target already exists,
  because ``mkdir``/``open`` creation modes are umask-filtered and existing
  entries may have drifted.

On non-POSIX platforms chmod is best-effort: it is skipped entirely so these
primitives never crash where permission bits do not apply. On POSIX a chmod
failure is a real error and propagates.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path

SECRET_FILE_MODE = 0o600
"""Permission bits for secret-bearing files (admin-key.hash, wrap.key, user.json)."""

PRIVATE_DIR_MODE = 0o700
"""Permission bits for gateway-owned directories (config/, users/, mail/, ...)."""


def _best_effort_chmod(path: Path, mode: int) -> None:
    """``chmod`` on POSIX; a silent no-op on non-POSIX platforms."""
    if os.name == "posix":
        os.chmod(path, mode)


def _fsync_dir_best_effort(path: Path) -> None:
    """Directory fsync so a completed rename survives power loss (POSIX, best-effort)."""
    if os.name != "posix":
        return
    with contextlib.suppress(OSError):
        dir_fd = os.open(path, os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)


def ensure_dir(path: str | Path, mode: int = PRIVATE_DIR_MODE) -> Path:
    """Create ``path`` (and parents) with ``mode``; re-assert ``mode`` if it exists.

    Missing directories are created top-down, each with ``mode`` passed to
    ``mkdir`` AND chmod-re-asserted immediately, so an intermediate is never
    observable with a loose umask-derived mode. The leaf is re-asserted even
    when it pre-existed (drifted permissions are repaired); pre-existing
    intermediates are left untouched.
    """
    directory = Path(path)
    # Record the not-yet-existing chain (leaf first) before creating anything.
    missing: list[Path] = []
    probe = directory
    while not probe.exists():
        missing.append(probe)
        if probe.parent == probe:  # filesystem root reached
            break
        probe = probe.parent
    for missing_dir in reversed(missing):
        missing_dir.mkdir(exist_ok=True, mode=mode)
        _best_effort_chmod(missing_dir, mode)
    # Re-assertion on the leaf even when it pre-existed: creation modes are
    # umask-filtered and existing entries may have drifted. (A newly created
    # leaf was already handled above; this chmod is idempotent.)
    _best_effort_chmod(directory, mode)
    return directory


def write_secret_file(path: str | Path, data: bytes) -> Path:
    """Atomically write ``data`` to ``path`` with mode ``0600``.

    The bytes go to a temp file in the target's directory (``mkstemp`` already
    creates it ``0600``), are fsynced, chmod-asserted, then moved over the
    target with ``os.replace`` (atomic; the parent directory is fsynced
    best-effort afterwards so the rename survives power loss). If anything
    fails before or during the replace, the temp file is removed and the
    target — including any previous content — is left untouched. When the
    target file already exists, its mode is re-asserted to ``0600`` after the
    replace. A missing parent directory is created ``0700``; existing parents
    are left untouched. ``data`` must be ``bytes``; callers encode text
    themselves.
    """
    target = Path(path)
    parent = target.parent
    if not parent.exists():
        ensure_dir(parent)
    fd, temp_name = tempfile.mkstemp(
        dir=parent, prefix=f".{target.name}.", suffix=".tmp"
    )
    temp_path = Path(temp_name)
    try:
        try:
            file_obj = os.fdopen(fd, "wb")
        except BaseException:
            os.close(fd)  # fdopen failed; close the raw descriptor it owned
            raise
        with file_obj:
            file_obj.write(data)
            file_obj.flush()
            os.fsync(file_obj.fileno())
        _best_effort_chmod(temp_path, SECRET_FILE_MODE)
        os.replace(temp_path, target)
    except BaseException:
        # Never leave a temp/partial file behind on a catchable failure — and
        # never mask the original error with a cleanup failure. (An
        # uncatchable kill can leave a hidden temp file; the target is never
        # partially written.)
        with contextlib.suppress(OSError):
            temp_path.unlink(missing_ok=True)
        raise
    _fsync_dir_best_effort(parent)
    # Re-assertion on the final path: os.replace carried the temp file's mode
    # over, but an existing target's drifted permissions end up fixed here too.
    _best_effort_chmod(target, SECRET_FILE_MODE)
    return target


def read_secret_file(path: str | Path) -> bytes:
    """Read a secret file's bytes.

    Read-only by design: permission modes are enforced at write time, so
    reading never mutates the filesystem.
    """
    return Path(path).read_bytes()
