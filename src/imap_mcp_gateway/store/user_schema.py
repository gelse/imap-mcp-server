"""Strict pydantic schema for the per-user registry record (M03).

One :class:`UserRecord` serializes to ``DATA_DIR/users/<userId>/user.json``.
The schema is deliberately strict — the record file is security-relevant
state (a credential hash plus the M04 key-material reservation) — so unknown
fields are rejected (``extra="forbid"``) and the identity/credential fields
are validated:

- ``id`` must match ``^[a-z0-9-]{1,64}$`` — the same rule
  :func:`imap_mcp_gateway.config.paths.validate_user_id` enforces before any
  path is built. It is reused here (single source of truth), so a record can
  never name a directory outside ``DATA_DIR/users``;
- ``name`` must be a non-empty string (the admin-facing label);
- ``login_key_hash`` must look like a serialized hash record
  (``scrypt$...`` today): a plaintext ``adm_``/``usr_`` key or any other
  accidental payload is rejected — the schema-level half of the
  no-plaintext-at-rest invariant (the store layer re-checks at write time,
  mirroring ``admin_key.save_admin_key_hash``).

A second model, :class:`UserMetadata`, is the credential-free projection of
:class:`UserRecord`: the shape :func:`imap_mcp_gateway.store.users.list_users`
returns. It has no ``login_key_hash`` field at all, so the listing surface
cannot carry hash material by construction (M03-T01: "``list_users()``
returns metadata only (no hashes)"); the full record stays reachable for
internal flows through ``users.get_user``.

``WrappedAEK`` is the finalized M04 shape (M04-T02): the wrapped
account-encryption key persisted at ``UserRecord.aek`` once the user
activates account encryption — ``None`` before that (lazy activation).
The schema validates the blob's outer shape only; authentication (tamper
and wrap-key checks) is the wrap layer's fail-closed job at unwrap time.
The plaintext AEK is never persisted — the record carries the wrapped
form only.
"""

from __future__ import annotations

import base64
import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

from imap_mcp_gateway.config.paths import validate_user_id

_RECORD_PREFIX_RE = re.compile(r"[a-z0-9]+\$")
"""Hash records start with a lowercase algorithm identifier, e.g. ``scrypt$``."""

_BLOB_FIELD_COUNT = 3
"""A wrap blob is exactly ``iv:tag:ciphertext`` — three colon-separated fields."""


def _is_canonical_base64_field(field: str) -> bool:
    """True iff ``field`` is non-empty canonical standard base64."""
    if not field:
        return False
    try:
        raw = base64.b64decode(field, validate=True)
    except ValueError:
        # binascii.Error subclasses ValueError: invalid characters or padding.
        return False
    return base64.b64encode(raw).decode("ascii") == field


class WrappedAEK(BaseModel):
    """The wrapped account-encryption key persisted at ``UserRecord.aek`` (M04-T02).

    ``blob`` is the AES-256-GCM wrap blob produced by
    :func:`imap_mcp_gateway.crypto.aek.wrap_aek` under the server wrap key
    (``base64(iv):base64(tag):base64(ciphertext)``); ``version`` tags the
    wrap-blob format for future migrations. Strict shape: exactly these two
    fields, and ``blob`` must parse as three non-empty canonical base64
    fields — the schema boundary's coarse at-rest garbage check. Structure
    only: authentication (tamper and wrap-key checks) is the wrap layer's
    fail-closed job in :func:`imap_mcp_gateway.crypto.aek.unwrap_aek`. The
    plaintext AEK is never persisted — the record carries the wrapped form
    only, and ``UserRecord.aek`` stays ``None`` until the user activates
    (lazy activation, M04-T02).
    """

    model_config = ConfigDict(extra="forbid")

    blob: str
    version: int = 1

    @field_validator("blob")
    @classmethod
    def _blob_is_three_canonical_base64_fields(cls, value: str) -> str:
        """Reject anything that is not ``b64:b64:b64`` with canonical fields."""
        fields = value.split(":")
        if len(fields) != _BLOB_FIELD_COUNT or not all(
            _is_canonical_base64_field(field) for field in fields
        ):
            raise ValueError(
                "blob must be base64(iv):base64(tag):base64(ciphertext)"
            )
        return value


class UserRecord(BaseModel):
    """One registry user as persisted at ``DATA_DIR/users/<userId>/user.json``."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    created_at: datetime
    login_key_hash: str
    key_generation: int = 1
    status: Literal["active", "disabled"] = "active"
    aek: WrappedAEK | None = None
    account_count: int = 0

    @field_validator("id")
    @classmethod
    def _id_matches_registry_rule(cls, value: str) -> str:
        """Enforce the user-id rule via the single paths-layer validator."""
        return validate_user_id(value)

    @field_validator("name")
    @classmethod
    def _name_non_empty(cls, value: str) -> str:
        """Reject empty names — the name is the admin-facing label."""
        if not value:
            raise ValueError("name must be a non-empty string")
        return value

    @field_validator("login_key_hash")
    @classmethod
    def _hash_is_record_not_plaintext(cls, value: str) -> str:
        """Reject plaintext key material in the credential field.

        A record value starts with a lowercase algorithm identifier plus
        ``$`` (format-agnostic, like ``admin_key.save_admin_key_hash``);
        plaintext ``adm_``/``usr_`` keys never do.
        """
        if not value.isascii() or _RECORD_PREFIX_RE.match(value) is None:
            raise ValueError("login_key_hash must be a serialized hash record, never plaintext")
        return value


class UserMetadata(BaseModel):
    """Credential-free projection of a :class:`UserRecord` (listings).

    Exactly the fields a listing displays and manages — and deliberately not
    the credential state: there is no ``login_key_hash`` field, so a listing
    built from this shape cannot leak hash material by construction (M03-T01:
    "``list_users()`` returns metadata only (no hashes)"). The reserved M04
    ``aek`` is omitted for the same reason — it is key material, not
    metadata; M04 extends this model when a listing must surface its
    presence.

    Not a persisted shape: instances exist only in memory, projected from an
    already schema-validated record via :meth:`from_record` (so no duplicate
    per-field validators here — the source record is the validation point).
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    created_at: datetime
    key_generation: int
    status: Literal["active", "disabled"]
    account_count: int

    @classmethod
    def from_record(cls, record: UserRecord) -> UserMetadata:
        """Project the non-credential fields of ``record``."""
        return cls(
            id=record.id,
            name=record.name,
            created_at=record.created_at,
            key_generation=record.key_generation,
            status=record.status,
            account_count=record.account_count,
        )
