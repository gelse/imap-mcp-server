"""Per-user upstream-compatible encrypted account store (M04-T03).

One JSON file per user at ``DATA_DIR/users/<userId>/imap-store/accounts.json``,
byte-compatible with upstream ``imap-mcp-server@2.2.0``'s ``AccountManager``
store so the M05 Node tool host consumes it unmodified:

- the file is a JSON array of account records (upstream:
  ``JSON.stringify(accounts, null, 2)``);
- records carry upstream's ``ImapAccount`` shape — Python-side snake_case
  attribute names with the upstream camelCase JSON keys as serialization
  aliases (``allowStartTLS``, ``saveToSent``, ``sentFolder``, ``defaultBcc``,
  ``allowedFrom``), optional fields omitted when unset, and ``id`` a UUID4
  string exactly like upstream's ``crypto.randomUUID()``;
- credential fields (``password``, ``smtp.password``) hold upstream
  AES-256-CBC ciphertext (``iv:ciphertext`` hex, :mod:`upstream_format`) or
  the documented empty "no credential" value — the schema refuses plaintext
  shapes on every construction and load, and :func:`put_account` therefore
  persists records whose credential fields the caller already encrypted
  (web-side CRUD encrypts in process memory, per the M04 design).

API: :func:`list_accounts` (metadata only — no credential fields by
construction, mirroring upstream's own account listing), :func:`get_account`
(internal accessor returning the ciphertext-carrying record),
:func:`put_account` (insert-or-replace, mints the UUID4 id),
:func:`delete_account`, and :func:`reencrypt_all` (atomic per user: one temp
write + ``os.replace`` via :func:`fs_safe.write_secret_file`).

Counter tracking: every successful :func:`put_account` /
:func:`delete_account` also keeps the registry's stored
``user.json.account_count`` in step with the real store (the store file is
the source of truth; the counter is derived metadata — an out-of-band
writer such as the M05 tool host is caught up by the reconcile-on-read
helpers :func:`reconcile_account_count` / :func:`reconcile_account_counts`,
which the admin views call). The sync runs AFTER the real write: a sync
failure surfaces with the mutation already persisted (the counter then
self-heals through reconcile-on-read), and because the reconcile helpers
validate every store they read, one user's corrupt ``accounts.json`` fails
the whole admin listing too — corruption stays loud rather than being
silently served as a wrong count.

AEK rotation: this store is the first M04 rotation participant — it registers
itself with :func:`imap_mcp_gateway.store.aek_rotation.register_reencrypt_hook`
at import time, so :func:`rotate_aek` performs a real
:func:`reencrypt_all` (the rotation residual window narrows to this one
atomic replace). A user without a store file yet is a no-op for the hook:
users activate lazily and may rotate before their first account exists.

Single-process assumption, same as every other store helper: one gateway
process per ``DATA_DIR``; upstream's tool host writes the same file only from
its own (M05) session, and the wrapper re-syncs by re-reading the file on
every call — never caching across calls.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from imap_mcp_gateway.config.paths import Paths
from imap_mcp_gateway.store import aek_rotation, users
from imap_mcp_gateway.store.fs_safe import read_secret_file, write_secret_file
from imap_mcp_gateway.store.upstream_format import (
    decrypt_field,
    encrypt_field,
    is_ciphertext_field,
)
from imap_mcp_gateway.store.user_schema import UserMetadata, UserRecord

_ACCOUNTS_FILE_NAME = "accounts.json"
_NO_CREDENTIAL = ""


class SmtpConfig(BaseModel):
    """The ``smtp`` block of a stored account (upstream ``SmtpConfig`` subset).

    ``password`` carries ciphertext at rest — same schema guard as the IMAP
    password: the upstream ciphertext shape or the empty "no credential"
    value, never plaintext. (Upstream's optional ``authMethod``/``tls`` keys
    are not part of the M04 field set and are rejected by ``extra="forbid"``.)
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    host: str
    port: int
    secure: bool
    user: str | None = None
    password: str = _NO_CREDENTIAL

    @field_validator("password")
    @classmethod
    def _password_is_ciphertext(cls, value: str) -> str:
        """Refuse plaintext credential material in the stored SMTP password."""
        if _NO_CREDENTIAL == value or is_ciphertext_field(value):
            return value
        raise ValueError(
            "smtp.password must be upstream ciphertext 'iv:ciphertext' hex "
            "(or empty for no credential) — encrypt with upstream_format.encrypt_field"
        )


class ImapAccount(BaseModel):
    """One stored account — upstream ``ImapAccount`` shape, ciphertext at rest.

    Python-side snake_case names; ``serialization_alias`` carries the upstream
    camelCase JSON keys and :func:`_dump_record` serializes with
    ``by_alias=True`` so the on-disk file matches upstream byte-for-byte.
    ``populate_by_name=True`` lets callers construct with either spelling.
    Optional fields (upstream: optional tool parameters) are ``None`` and are
    OMITTED from the JSON dump (upstream omits absent optional fields). The
    schema refuses unknown fields — drift between upstream 2.2.0 and this
    model must be a loud event, not silently dropped data. (The gateway's
    deployment surface writes this store only through upstream's MCP account
    tools, which emit exactly the modeled fields; upstream's standalone web
    wizard — not spawned by the gateway — can spread extra request-body keys
    into ``smtp``, and a store carrying one fails loud on load instead of
    silently dropping it.)
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    id: str = _NO_CREDENTIAL
    name: str
    host: str
    port: int
    user: str
    password: str
    tls: bool
    allow_start_tls: bool | None = Field(default=None, alias="allowStartTLS")
    email: str | None = None
    smtp: SmtpConfig | None = None
    save_to_sent: bool | None = Field(default=None, alias="saveToSent")
    sent_folder: str | None = Field(default=None, alias="sentFolder")
    default_bcc: str | list[str] | None = Field(default=None, alias="defaultBcc")
    allowed_from: list[str] | None = Field(default=None, alias="allowedFrom")

    @field_validator("password")
    @classmethod
    def _password_is_ciphertext(cls, value: str) -> str:
        """Refuse plaintext credential material in the stored IMAP password."""
        if _NO_CREDENTIAL == value or is_ciphertext_field(value):
            return value
        raise ValueError(
            "password must be upstream ciphertext 'iv:ciphertext' hex "
            "(or empty for no credential) — encrypt with upstream_format.encrypt_field"
        )

    def decrypt_password(self, aek_hex: str) -> str:
        """Decrypt the IMAP password in memory (never log/serialize the result)."""
        return decrypt_field(aek_hex, self.password)

    def decrypt_smtp_password(self, aek_hex: str) -> str:
        """Decrypt the SMTP password in memory (``""`` when absent)."""
        if self.smtp is None:
            return _NO_CREDENTIAL
        return decrypt_field(aek_hex, self.smtp.password)


def encrypt_account_record(payload: Mapping[str, Any], aek_hex: str) -> ImapAccount:
    """Build a storable record from a plaintext-shaped payload under ``aek_hex``.

    The one seam M04-T04 web flows (and tests) use to turn submitted account
    data into a :class:`ImapAccount` the schema accepts: ``password`` and the
    ``smtp.password`` of the payload are sealed with
    :func:`upstream_format.encrypt_field` BEFORE construction, so the strict
    ciphertext-only credential validators pass by construction. An empty SMTP
    password stays empty (upstream only ever writes ``smtp.password`` when one
    was configured); an empty IMAP password is encrypted like upstream's
    ``addAccount`` does. The plaintext payload exists only in the caller's
    memory; the returned record carries ciphertext only. Payload keys may use
    either the Python-side snake_case names or the upstream camelCase aliases.
    """
    data = dict(payload)
    raw_password = data.get("password", "")
    if not isinstance(raw_password, str):
        raise ValueError("password must be a string")
    data["password"] = encrypt_field(aek_hex, raw_password)
    smtp = data.get("smtp")
    if isinstance(smtp, Mapping):
        smtp_data = dict(smtp)
        smtp_password = smtp_data.get("password", "")
        if smtp_password and not isinstance(smtp_password, str):
            raise ValueError("smtp.password must be a string")
        smtp_data["password"] = (
            encrypt_field(aek_hex, smtp_password) if smtp_password else _NO_CREDENTIAL
        )
        data["smtp"] = smtp_data
    return ImapAccount.model_validate(data)


class SmtpAccountMetadata(BaseModel):
    """Credential-free projection of :class:`SmtpConfig` (listings)."""

    model_config = ConfigDict(extra="forbid")

    host: str
    port: int
    secure: bool


class AccountMetadata(BaseModel):
    """Credential-free projection of :class:`ImapAccount` (listings).

    Exactly what a listing may show — and deliberately NOT the credential
    state: there is no ``password`` field and the ``smtp`` projection carries
    no ``user``/``password``, so neither ciphertext nor plaintext credential
    material can appear in a listing by construction (M04-T03 acceptance:
    "``list_accounts`` output contains no ciphertext-or-plaintext credential
    fields"). Mirrors the spirit of upstream's own account listing, which
    projects ``id``/``name``/``host``/``port``/``user``/``tls`` only.

    The M07-T01 extension adds the four NON-SECRET optional configuration
    fields ``save_to_sent``, ``sent_folder``, ``default_bcc`` and
    ``allowed_from`` (deliberate, documented API extension): the SPA edit
    view must prefill and round-trip them exactly like the old HTML form
    did — without them every edit would silently erase stored values and
    ``save_to_sent`` would become uneditable. They are configuration, never
    credential material (the same class as the already-exposed ``email``),
    so the projection stays credential-free by construction.

    Not a persisted shape: instances exist only in memory, projected from an
    already schema-validated record via :meth:`from_record`.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    host: str
    port: int
    user: str
    tls: bool
    allow_start_tls: bool | None = None
    email: str | None = None
    smtp: SmtpAccountMetadata | None = None
    save_to_sent: bool | None = None
    sent_folder: str | None = None
    default_bcc: str | list[str] | None = None
    allowed_from: list[str] | None = None

    @classmethod
    def from_record(cls, record: ImapAccount) -> AccountMetadata:
        """Project the non-credential fields of ``record``."""
        return cls(
            id=record.id,
            name=record.name,
            host=record.host,
            port=record.port,
            user=record.user,
            tls=record.tls,
            allow_start_tls=record.allow_start_tls,
            email=record.email,
            smtp=(
                SmtpAccountMetadata(
                    host=record.smtp.host,
                    port=record.smtp.port,
                    secure=record.smtp.secure,
                )
                if record.smtp is not None
                else None
            ),
            save_to_sent=record.save_to_sent,
            sent_folder=record.sent_folder,
            default_bcc=record.default_bcc,
            allowed_from=record.allowed_from,
        )


def _store_path(paths: Paths, user_id: str) -> Path:
    """Validated ``DATA_DIR/users/<userId>/imap-store/accounts.json``."""
    return paths.user_imap_store_dir(user_id) / _ACCOUNTS_FILE_NAME


def _dump_record(record: ImapAccount) -> dict[str, object]:
    """Serialize with upstream's camelCase keys, omitting unset optionals.

    ``exclude_none`` drops the unset optional fields exactly like upstream's
    ``JSON.stringify`` drops ``undefined``; ``exclude_defaults`` additionally
    drops the empty "no credential" SMTP password (upstream only ever writes
    ``smtp.password`` when one was configured).
    """
    return dict(record.model_dump(by_alias=True, exclude_none=True, exclude_defaults=True))


def _save_records(paths: Paths, user_id: str, records: list[ImapAccount]) -> None:
    """Persist the store atomically, mode ``0600`` inside the ``0700`` dir.

    ``json.dumps(..., indent=2)`` matches upstream's
    ``JSON.stringify(accounts, null, 2)`` (and, like upstream, no trailing
    newline). ``ensure_ascii=False`` keeps the file valid UTF-8 like
    ``JSON.stringify`` instead of escaping non-ASCII names.
    """
    payload = json.dumps(
        [_dump_record(record) for record in records], indent=2, ensure_ascii=False
    )
    write_secret_file(_store_path(paths, user_id), payload.encode("utf-8"))


def _load_records(paths: Paths, user_id: str) -> list[ImapAccount]:
    """Load and schema-validate the store; ``[]`` only when the file is absent.

    Fail loud on anything present-but-invalid (corrupt JSON, schema drift):
    the gateway and upstream only ever write schema-valid records, so
    anything else is corruption or tampering — never silently an empty list.
    """
    path = _store_path(paths, user_id)
    if not os.path.lexists(path):
        return []
    payload = json.loads(read_secret_file(path).decode("utf-8"))
    if not isinstance(payload, list):
        raise ValueError(f"corrupt account store for {user_id!r}: expected a JSON array")
    records = [ImapAccount.model_validate(item) for item in payload]
    for record in records:
        if not record.id:
            raise ValueError(
                f"corrupt account store for {user_id!r}: record without an id"
            )
    return records


def _sync_account_count(paths: Paths, user_id: str, count: int) -> None:
    """Keep ``user.json.account_count`` in step after a store mutation.

    The account store file has already been saved when this runs; the
    counter is derived metadata, so it is best-effort AFTER the real
    write — a registry-invalid id (impossible through the store's own
    path validation; kept as a defensive guard) is skipped, while a
    present-but-schema-invalid ``user.json`` still fails loud per the
    store contract. The mutation persists even when the sync raises;
    reconcile-on-read repairs the counter on the next admin read.
    ``count`` is ``len(records)`` at every call site — never negative
    by construction.
    """
    try:
        record = users.get_user(paths, user_id)
    except ValidationError:
        raise  # present-but-invalid user.json: fail loud, per the store contract
    except ValueError:
        return  # registry-invalid id: no such user, nothing to sync
    if record is None or record.account_count == count:
        return
    users.update_user(paths, user_id, {"account_count": count})


def reconcile_account_count(paths: Paths, record: UserRecord) -> UserRecord:
    """Repair a stale ``user.json.account_count`` from the real store.

    The store file is the source of truth; the stored counter is derived
    metadata that earlier versions (or an out-of-band writer such as the
    M05 tool host) may have left behind. When the counter already
    matches, the record is returned untouched (no write). Otherwise the
    real number is persisted through the whitelisted ``update_user``
    patch and the corrected record returned. A corrupt account store
    still fails loud — the repair never masks corruption as a count.
    """
    real = len(_load_records(paths, record.id))
    if record.account_count == real:
        return record
    return users.update_user(paths, record.id, {"account_count": real})


def reconcile_account_counts(paths: Paths) -> list[UserMetadata]:
    """Reconcile every user's counter; return the corrected metadata views.

    Walks the registry once (:func:`store.users.list_users`) and repairs
    each user whose stored counter disagrees with the real store,
    returning the credential-free metadata views of the corrected
    records. A corrupt user record still fails loud (the listing
    surfaces deliberately propagate that, unchanged).
    """
    reconciled: list[UserMetadata] = []
    for user in users.list_users(paths):
        record = users.get_user(paths, user.id)
        if record is None:
            continue  # removed between the two reads: nothing left to show
        reconciled.append(
            UserMetadata.from_record(reconcile_account_count(paths, record))
        )
    return reconciled


def list_accounts(paths: Paths, user_id: str) -> list[AccountMetadata]:
    """List the user's accounts — metadata only, no credential fields.

    Re-reads ``accounts.json`` on every call (the re-sync primitive): writes
    from an upstream tool-host session (M05) are visible to the next listing
    without a process restart. A user without a store yet lists as ``[]``.
    """
    return [AccountMetadata.from_record(record) for record in _load_records(paths, user_id)]


def get_account(paths: Paths, user_id: str, account_id: str) -> ImapAccount | None:
    """Return the stored record — ciphertext fields included — or ``None``.

    Internal accessor for flows that must touch the stored ciphertext (the
    M04-T04/M05 decrypt paths wrap it in ``with_aek`` + ``decrypt_field``).
    Never serialize the returned record to an API response: it carries the
    encrypted credentials, and the schema only guarantees they are not
    plaintext.
    """
    for record in _load_records(paths, user_id):
        if record.id == account_id:
            return record
    return None


def put_account(paths: Paths, user_id: str, record: ImapAccount) -> ImapAccount:
    """Insert or replace a record; returns the stored record with its id set.

    A record without an id (the web/form shape) gets a fresh UUID4 string —
    the same spelling upstream's ``crypto.randomUUID()`` writes. Insertion
    keeps file order; replacement keeps the original position. The caller
    must have encrypted the credential fields already (the schema refuses
    plaintext shapes). A successful save also syncs the user's stored
    ``account_count`` to the real store size.
    """
    records = _load_records(paths, user_id)
    account = record if record.id else record.model_copy(update={"id": str(uuid4())})
    for index, existing in enumerate(records):
        if existing.id == account.id:
            records[index] = account
            break
    else:
        records.append(account)
    _save_records(paths, user_id, records)
    _sync_account_count(paths, user_id, len(records))
    return account


def delete_account(paths: Paths, user_id: str, account_id: str) -> None:
    """Remove the account; a missing id (or store) raises ``FileNotFoundError``.

    A successful save also syncs the user's stored ``account_count`` to
    the remaining store size.
    """
    records = _load_records(paths, user_id)
    remaining = [record for record in records if record.id != account_id]
    if len(remaining) == len(records):
        raise FileNotFoundError(
            f"no account {account_id!r} for user {user_id!r}"
        )
    _save_records(paths, user_id, remaining)
    _sync_account_count(paths, user_id, len(remaining))


def _reencrypt_value(old_aek: str, new_aek: str, value: str) -> str:
    """Move one credential field from ``old_aek`` to ``new_aek``.

    The empty "no credential" value stays empty — rotation must not
    manufacture credentials for fields that never had one.
    """
    if value == "":
        return ""
    return encrypt_field(new_aek, decrypt_field(old_aek, value))


def reencrypt_all(paths: Paths, user_id: str, old_aek: str, new_aek: str) -> None:
    """Re-encrypt every credential field from ``old_aek`` to ``new_aek``.

    Decrypts each record's ``password``/``smtp.password`` under the old key
    and re-encrypts under the new one, persisting once (a single atomic
    replace — the narrowed rotation residual window). A user without a store
    file is a no-op (lazy activation: rotation may legitimately run before
    the first account exists). Any decryption failure under the old key is a
    loud ``ValueError``: the store must actually be under ``old_aek`` when
    rotation hands it over.
    """
    records = _load_records(paths, user_id)
    if not records:
        return
    reencrypted: list[ImapAccount] = []
    for record in records:
        data: dict[str, Any] = record.model_dump(by_alias=True, exclude_none=True)
        data["password"] = _reencrypt_value(old_aek, new_aek, record.password)
        if record.smtp is not None:
            smtp_data = dict(data["smtp"])
            smtp_data["password"] = _reencrypt_value(
                old_aek, new_aek, record.smtp.password
            )
            data["smtp"] = smtp_data
        reencrypted.append(ImapAccount.model_validate(data))
    _save_records(paths, user_id, reencrypted)


def _reencrypt_hook(paths: Paths, user_id: str, old_aek: str, new_aek: str) -> None:
    """Adapter signing the store up as an :mod:`aek_rotation` participant."""
    reencrypt_all(paths, user_id, old_aek, new_aek)


unregister_reencrypt_hook: Callable[[], None] = aek_rotation.register_reencrypt_hook(
    _reencrypt_hook
)
"""Import-time registration of this store as the M04-T03 rotation participant.

The registry is module-global by design (:mod:`aek_rotation`): importing
``store.accounts`` wires AEK rotation to a real :func:`reencrypt_all`. The
returned ``unregister`` exists for the rare test that needs the store out of
the registry.
"""
