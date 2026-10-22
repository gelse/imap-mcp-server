"""User self-service serializers and request models (M04-T04).

The HTTP boundary between the credential-carrying store shapes and the
metadata-only ``/api/me`` responses. Two halves:

- **Response projection.** :func:`to_account_view` and
  :func:`to_profile_view` build exactly what a ``/api/me`` response may
  show: the store's own credential-free
  :class:`~imap_mcp_gateway.store.accounts.AccountMetadata` projection (no
  ``password``, no ``smtp.user``/``smtp.password`` — neither ciphertext nor
  plaintext credential material can appear by construction) plus the
  credential-free :class:`~imap_mcp_gateway.store.user_schema.UserMetadata`
  profile. Unset optional fields are omitted (the store's omit-absent
  convention). These functions are the ONLY serializers the user router
  uses; a raw ``ImapAccount`` or ``UserRecord`` (ciphertext / hash
  carrying) must never be serialized to a response.

- **Request models.** :class:`CreateAccountBody`, :class:`UpdateAccountBody`
  and :class:`SmtpBody` mirror the upstream ``imap_add_account`` /
  ``imap_update_account`` field set — exactly the M04-T03 store's fields
  (``name``, ``host``, ``port``, ``user``, ``password``, ``tls``,
  ``allow_start_tls``, ``email``, ``smtp``, ``save_to_sent``,
  ``sent_folder``, ``default_bcc``, ``allowed_from``), with the upstream
  camelCase aliases accepted alongside the snake_case names
  (``populate_by_name``). ``extra="forbid"`` everywhere, like the store
  schema: a drifted field is a loud 400, not silently dropped data.

Credential fields are WRITE-ONLY here: the models accept plaintext
passwords (the web layer encrypts in process memory, per the M04 design)
and no response model ever has one — there is nothing to serialize them
into.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from imap_mcp_gateway.store.accounts import AccountMetadata
from imap_mcp_gateway.store.user_schema import UserMetadata


class SmtpBody(BaseModel):
    """The ``smtp`` block of an account request body.

    ``host``/``port``/``secure`` are required — a stored ``smtp`` block
    always carries them (the store schema requires them), so accepting a
    block without them could only produce a record the store refuses.
    ``user`` is optional (upstream omits it when unset) and ``password`` is
    the write-only plaintext credential: accepted, encrypted server-side,
    never echoed.
    """

    model_config = ConfigDict(extra="forbid")

    host: str
    port: int
    secure: bool
    user: str | None = None
    password: str | None = None


class CreateAccountBody(BaseModel):
    """Body of ``POST /api/me/accounts`` — the full upstream account shape.

    Required fields mirror upstream ``imap_add_account``'s mandatory
    parameters; every optional parameter defaults to unset. ``password`` is
    the write-only IMAP credential (an empty string encrypts like upstream's
    ``addAccount``, which always seals the value it is handed).
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    name: str = Field(min_length=1)
    host: str = Field(min_length=1)
    port: int
    user: str = Field(min_length=1)
    password: str
    tls: bool
    allow_start_tls: bool | None = Field(default=None, alias="allowStartTLS")
    email: str | None = None
    smtp: SmtpBody | None = None
    save_to_sent: bool | None = Field(default=None, alias="saveToSent")
    sent_folder: str | None = Field(default=None, alias="sentFolder")
    default_bcc: str | list[str] | None = Field(default=None, alias="defaultBcc")
    allowed_from: list[str] | None = Field(default=None, alias="allowedFrom")


class UpdateAccountBody(BaseModel):
    """Body of ``PATCH /api/me/accounts/{account_id}`` — a partial update.

    Every field is optional; only the provided (non-``None``) fields are
    applied. The ``smtp`` block, when provided, carries its required
    ``host``/``port``/``secure`` (a stored block always has them) while its
    credentials stay sticky: an omitted ``user`` keeps the stored one and an
    omitted ``password`` keeps the stored ciphertext — write-only blank
    means "unchanged", never "cleared". Clearing the SMTP credential is a
    plain empty string (the store's documented "no credential" value);
    the IMAP ``password`` always encrypts when provided, even when empty,
    exactly like upstream's ``addAccount`` writes it.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    name: str | None = Field(default=None, min_length=1)
    host: str | None = Field(default=None, min_length=1)
    port: int | None = None
    user: str | None = Field(default=None, min_length=1)
    password: str | None = None
    tls: bool | None = None
    allow_start_tls: bool | None = Field(default=None, alias="allowStartTLS")
    email: str | None = None
    smtp: SmtpBody | None = None
    save_to_sent: bool | None = Field(default=None, alias="saveToSent")
    sent_folder: str | None = Field(default=None, alias="sentFolder")
    default_bcc: str | list[str] | None = Field(default=None, alias="defaultBcc")
    allowed_from: list[str] | None = Field(default=None, alias="allowedFrom")


def to_account_view(account: AccountMetadata) -> dict[str, Any]:
    """Project the store's credential-free metadata to the response dict.

    Exactly ``{id, name, host, port, user, tls}`` plus whichever optional
    fields are set (``allow_start_tls``, ``email``, the ``smtp`` projection
    ``{host, port, secure}``, and the M07-T01 extension
    ``save_to_sent``/``sent_folder``/``default_bcc``/``allowed_from``). The
    input is the store's own ``AccountMetadata`` — it has no credential
    fields at all, so the output cannot carry one by construction (the
    M04-T03 listing invariant).

    Deliberate M07 API extension (M07-T01): the four non-secret optional
    configuration fields are now emitted when set, so the SPA edit view can
    prefill and round-trip them exactly like the old HTML form did — without
    them every edit would silently erase stored values and ``save_to_sent``
    would become uneditable. They are configuration, never credential
    material (the same class as the already-exposed ``email``); the pin test
    ``tests/test_user_account_api.py::ACCOUNT_VIEW_FIELDS`` is updated
    accordingly, not weakened — its credential-free and omit-absent
    assertions still hold.
    """
    view: dict[str, Any] = {
        "id": account.id,
        "name": account.name,
        "host": account.host,
        "port": account.port,
        "user": account.user,
        "tls": account.tls,
    }
    if account.allow_start_tls is not None:
        view["allow_start_tls"] = account.allow_start_tls
    if account.email is not None:
        view["email"] = account.email
    if account.smtp is not None:
        view["smtp"] = {
            "host": account.smtp.host,
            "port": account.smtp.port,
            "secure": account.smtp.secure,
        }
    if account.save_to_sent is not None:
        view["save_to_sent"] = account.save_to_sent
    if account.sent_folder is not None:
        view["sent_folder"] = account.sent_folder
    if account.default_bcc is not None:
        view["default_bcc"] = account.default_bcc
    if account.allowed_from is not None:
        view["allowed_from"] = account.allowed_from
    return view


def to_profile_view(
    user: UserMetadata,
    accounts: Sequence[AccountMetadata],
    *,
    aek_active: bool,
) -> dict[str, Any]:
    """Project the authenticated user's profile plus the account listing.

    The profile half is the credential-free ``UserMetadata`` shape (no
    ``login_key_hash``, no ``aek``); ``account_count`` is computed from the
    live listing, never from the stored counter in ``user.json`` (which the
    account store now keeps in step and the admin reads reconcile — this
    view stays live-by-construction regardless). ``key_generation`` is the
    login-key generation — bumping it (self key rotation) never touches the
    AEK or the accounts.

    ``aek_active`` (deliberate M07 API extension, M07-T01, keyword-only so
    no existing positional call can drift): whether the user's
    account-encryption key is activated — a boolean FLAG derived by the
    caller from the full record (``record.aek is not None``), never the
    wrapped blob itself. The SPA needs it to decide between "activate"
    (show the one-time key) and "manage" states without a round-trip;
    nothing key-material crosses this boundary, so the pin test
    ``tests/test_user_account_api.py::PROFILE_FIELDS`` is extended with the
    field, not loosened.
    """
    return {
        "id": user.id,
        "name": user.name,
        "created_at": user.created_at,
        "key_generation": user.key_generation,
        "status": user.status,
        "aek_active": aek_active,
        "account_count": len(accounts),
        "accounts": [to_account_view(account) for account in accounts],
    }
