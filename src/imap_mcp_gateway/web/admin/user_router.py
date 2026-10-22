"""Admin user-management JSON API under ``/api/admin/users`` (M03-T02).

Six routes, every one admin-authenticated (:data:`AdminAuthDep` — the
per-IP lockout gate inside ``require_admin`` is the rate-limiting
mechanism for this whole surface, as in M02-T03) and every mutating one
additionally CSRF-checked for cookie sessions (:data:`CsrfDep`; Bearer is
exempt by convention).

One-time-key contract: ``store.users.create_user`` and
``store.users.rotate_login_key`` return the plaintext ``usr_`` key exactly
once — in that response body and nowhere else — while every other response
is the metadata view built by
:func:`imap_mcp_gateway.web.admin.serializers.to_admin_user_view`, which
cannot carry hash or key material by construction.

Request bodies are parsed and validated manually (small pydantic models)
instead of through FastAPI's automatic body validation: automatic
validation would answer malformed bodies with the framework-default 422,
while this surface pins 400 inside its fixed ``{"error": ...}`` contract —
scoped to these routes only, so no other router's 422 behavior changes.

Store calls run through ``run_in_threadpool`` so the scrypt work inside
``create_user`` / ``rotate_login_key`` never blocks the event loop (the
login route's convention from M02-T03).
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.concurrency import run_in_threadpool

from imap_mcp_gateway.config.paths import Paths
from imap_mcp_gateway.store import accounts as accounts_store
from imap_mcp_gateway.store import users as users_store
from imap_mcp_gateway.web.admin.serializers import to_admin_user_view
from imap_mcp_gateway.web.middleware.admin_auth import AdminAuthDep, AdminHTTPError
from imap_mcp_gateway.web.routers.csrf import CsrfDep

router = APIRouter(tags=["admin"])
"""The ``/users`` sub-router: mounted under the ``/api/admin`` aggregator."""


class CreateUserBody(BaseModel):
    """Body of ``POST /api/admin/users`` — the new user's display name."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)


class SetStatusBody(BaseModel):
    """Body of ``POST /api/admin/users/{user_id}/status`` — the target status."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["active", "disabled"]


def _paths(request: Request) -> Paths:
    """The request's ``Paths`` (the web-layer convention, as in ``admin_auth``)."""
    return Paths(request.app.state.settings.data_dir)


async def _json_body(request: Request) -> Any:
    """Decode the request body as JSON; anything undecodable is a 400.

    Malformed bodies join the fixed admin error contract instead of
    FastAPI's 422 (see the module docstring), so the raw body is decoded
    here and validated against the request models by the caller.
    """
    try:
        return await request.json()
    except Exception:  # a hostile/undecodable body is simply an invalid request
        raise AdminHTTPError(400, "invalid_request") from None


def _validated_body[ModelT: BaseModel](model: type[ModelT], payload: Any) -> ModelT:
    """Validate a decoded JSON body against a request model; 400 on mismatch.

    Missing fields, wrong types, empty strings, values outside the
    ``Literal`` and unknown (``extra="forbid"``) fields all land here.
    """
    try:
        return model.model_validate(payload)
    except ValidationError:
        raise AdminHTTPError(400, "invalid_request") from None


@router.post("", status_code=201)
async def create_user(
    request: Request, _auth: AdminAuthDep, _csrf: CsrfDep
) -> dict[str, Any]:
    """Create a registry user — the ONLY response that ever carries a login key.

    The plaintext ``usr_`` key exists exactly once: in this body, for the
    admin's one-time display; only its scrypt record is persisted.
    """
    body = _validated_body(CreateUserBody, await _json_body(request))
    record, plaintext = await run_in_threadpool(
        users_store.create_user, _paths(request), body.name
    )
    return {
        "id": record.id,
        "name": record.name,
        "key_generation": record.key_generation,
        "login_key": plaintext,
    }


@router.get("")
async def list_users(request: Request, _auth: AdminAuthDep) -> list[dict[str, Any]]:
    """Every registry user as a metadata view, sorted by id — never a key.

    Each user's stored ``account_count`` is reconciled against the real
    account store first, so the listing never forwards a stale counter.
    """
    users = await run_in_threadpool(
        accounts_store.reconcile_account_counts, _paths(request)
    )
    return [to_admin_user_view(user) for user in users]


@router.get("/{user_id}")
async def get_user(request: Request, user_id: str, _auth: AdminAuthDep) -> dict[str, Any]:
    """One user's metadata view; absent (or registry-invalid) ids are 404.

    The ``ValueError`` mapped to 404 is the path layer's registry-id
    validation — an id that can never exist is simply ``not_found``, not a
    server error. A pydantic ``ValidationError`` (a ``ValueError``
    subclass) is deliberately NOT mapped: it can only mean a
    present-but-schema-invalid record file, which the store contract fails
    loud on — so it propagates to the app's 500 handler instead of masking
    corruption as a missing user.
    """
    try:
        record = await run_in_threadpool(users_store.get_user, _paths(request), user_id)
    except ValidationError:
        raise
    except ValueError:
        raise AdminHTTPError(404, "not_found") from None
    if record is None:
        raise AdminHTTPError(404, "not_found")
    record = await run_in_threadpool(
        accounts_store.reconcile_account_count, _paths(request), record
    )
    return to_admin_user_view(record)


@router.post("/{user_id}/rotate-key")
async def rotate_login_key(
    request: Request, user_id: str, _auth: AdminAuthDep, _csrf: CsrfDep
) -> dict[str, Any]:
    """Mint a new login key; the previous one stops authenticating immediately.

    The new plaintext is one-time, like the create key: this body is the
    only place it ever appears. The stored hash is replaced and
    ``key_generation`` bumped atomically by the store.
    """
    try:
        record, plaintext = await run_in_threadpool(
            users_store.rotate_login_key, _paths(request), user_id
        )
    except ValidationError:
        raise  # present-but-invalid record: fail loud, per the store contract
    except (FileNotFoundError, ValueError):
        raise AdminHTTPError(404, "not_found") from None
    return {
        "id": record.id,
        "key_generation": record.key_generation,
        "login_key": plaintext,
    }


@router.post("/{user_id}/status")
async def set_user_status(
    request: Request, user_id: str, _auth: AdminAuthDep, _csrf: CsrfDep
) -> dict[str, Any]:
    """Flip a user between ``active`` and ``disabled``; returns the updated view.

    The response body is the metadata view (the milestone's "every other
    response is metadata-only" rule resolves the open response-body
    question for this route). A disabled user's current login key stops
    authenticating until re-enabled; the key itself is untouched.
    """
    body = _validated_body(SetStatusBody, await _json_body(request))
    flip = (
        users_store.disable_user if body.status == "disabled" else users_store.enable_user
    )
    try:
        record = await run_in_threadpool(flip, _paths(request), user_id)
    except ValidationError:
        raise  # present-but-invalid record: fail loud, per the store contract
    except (FileNotFoundError, ValueError):
        raise AdminHTTPError(404, "not_found") from None
    record = await run_in_threadpool(
        accounts_store.reconcile_account_count, _paths(request), record
    )
    return to_admin_user_view(record)


@router.delete("/{user_id}", status_code=204)
async def delete_user(
    request: Request, user_id: str, _auth: AdminAuthDep, _csrf: CsrfDep
) -> Response:
    """Remove the user and their whole directory (recursive, no undo); 204."""
    try:
        await run_in_threadpool(users_store.delete_user, _paths(request), user_id)
    except (FileNotFoundError, ValueError):
        raise AdminHTTPError(404, "not_found") from None
    return Response(status_code=204)
