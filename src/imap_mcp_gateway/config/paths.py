"""Typed path helpers for the on-disk data layout under ``DATA_DIR``.

The layout every helper resolves (defaults shown; root comes from
``Settings.data_dir``):

::

    DATA_DIR/
      config/                 # server-level configuration
        admin-key.hash        # hash of the root administration key (M02)
        wrap.key              # server wrap key for per-user AEKs (M04)
      users/                  # per-user state (M03, M04)
        <userId>/
          user.json           # user record: login-key hash, wrapped AEK, metadata
          imap-store/         # upstream-compatible encrypted account store (M04)
      mail/                   # mail artifacts (downloads, upload staging)
        <userId>/             # per-user mail artifacts (user_mail_dir)

Path construction here is pure string work: nothing in this module touches
the filesystem. User ids are validated against ``^[a-z0-9-]{1,64}$`` BEFORE
any path is built, which makes path traversal through a user id impossible
(no ``/``, ``\\``, ``.`` or non-ASCII can survive the check).

There is exactly one :class:`Paths` object per process, built once at startup
from the environment (``app.run`` via :func:`build_paths`) and injected where
needed — this module never reads the environment itself.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_USER_ID_RE = re.compile(r"^[a-z0-9-]{1,64}$")


def validate_user_id(user_id: str) -> str:
    """Return ``user_id`` unchanged if valid, else raise ``ValueError``.

    Valid ids match ``^[a-z0-9-]{1,64}$`` (1-64 chars: lowercase ASCII
    letters, digits, hyphens). The check is a pure string comparison — no
    filesystem access — so traversal-style ids such as ``../etc`` are rejected
    before any path is constructed. ``re.fullmatch`` is used deliberately so a
    trailing newline cannot sneak past the ``$`` anchor.
    """
    if _USER_ID_RE.fullmatch(user_id) is None:
        raise ValueError(
            f"invalid user id {user_id!r}: must match ^[a-z0-9-]{{1,64}}$"
        )
    return user_id


@dataclass(frozen=True, slots=True)
class Paths:
    """Typed helpers resolving the documented layout under one ``data_dir``."""

    data_dir: Path

    def config_dir(self) -> Path:
        """``DATA_DIR/config`` — server-level configuration."""
        return self.data_dir / "config"

    def admin_key_hash_path(self) -> Path:
        """``DATA_DIR/config/admin-key.hash`` (consumed in M02)."""
        return self.config_dir() / "admin-key.hash"

    def wrap_key_path(self) -> Path:
        """``DATA_DIR/config/wrap.key`` (consumed in M04)."""
        return self.config_dir() / "wrap.key"

    def users_dir(self) -> Path:
        """``DATA_DIR/users`` — per-user state root."""
        return self.data_dir / "users"

    def user_dir(self, user_id: str) -> Path:
        """``DATA_DIR/users/<userId>`` (``user_id`` validated first)."""
        return self.users_dir() / validate_user_id(user_id)

    def user_record_path(self, user_id: str) -> Path:
        """``DATA_DIR/users/<userId>/user.json``."""
        return self.user_dir(user_id) / "user.json"

    def user_imap_store_dir(self, user_id: str) -> Path:
        """``DATA_DIR/users/<userId>/imap-store`` (consumed in M04)."""
        return self.user_dir(user_id) / "imap-store"

    def mail_dir(self) -> Path:
        """``DATA_DIR/mail`` — mail artifacts (downloads, upload staging)."""
        return self.data_dir / "mail"

    def user_mail_dir(self, user_id: str) -> Path:
        """``DATA_DIR/mail/<userId>`` — per-user mail artifacts."""
        return self.mail_dir() / validate_user_id(user_id)


def build_paths(data_dir: str | Path) -> Paths:
    """Build the single ``Paths`` object from a resolved ``data_dir`` value.

    This is the wiring point used at startup (``app.run`` passes
    ``Settings().data_dir``) and in tests (a temp ``DATA_DIR``); it never
    reads the environment itself.
    """
    return Paths(data_dir=Path(data_dir))
