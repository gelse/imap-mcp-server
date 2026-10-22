"""Admin response serializers for the user-management API (M03-T02).

The HTTP boundary between the credential-carrying store shapes and the
metadata-only admin responses. Everything this module returns is the
six-field metadata view — ``id``, ``name``, ``status``, ``key_generation``,
``account_count``, ``created_at`` — and never ``login_key_hash``, never
``aek``, and never a ``login_key`` (the one-time plaintext appears only in
the create/rotate response bodies that the router itself builds around a
minted key).
"""

from __future__ import annotations

from typing import Any

from imap_mcp_gateway.store.user_schema import UserMetadata, UserRecord


def to_admin_user_view(user: UserRecord | UserMetadata) -> dict[str, Any]:
    """Project a user record or metadata to the admin metadata view dict.

    The parameter accepts both store shapes — duck-typed over the six
    shared fields. This widens the milestone's original
    ``to_admin_user_view(u: UserRecord)`` signature per the M03-T01
    contract correction: ``store.users.list_users`` already returns
    ``list[UserMetadata]`` (credential-free by construction — the M03-T01
    acceptance criterion "``list_users()`` returns metadata only (no
    hashes)"), so the listing route consumes ``UserMetadata`` directly,
    while the detail and management routes hold the full ``UserRecord``
    from ``store.users.get_user`` / ``disable_user`` / ``enable_user``.

    Hard invariant: the returned dict contains EXACTLY
    ``{id, name, status, key_generation, account_count, created_at}``.
    ``UserMetadata`` lacks ``login_key_hash``/``aek`` fields by type, and
    this projection never reads them off a ``UserRecord`` either — so no
    response built through it can leak hash or key material. HTTP layers
    must never serialize a ``UserRecord`` directly (the ``get_user``
    docstring contract); this serializer is the projection point.
    """
    return {
        "id": user.id,
        "name": user.name,
        "status": user.status,
        "key_generation": user.key_generation,
        "account_count": user.account_count,
        "created_at": user.created_at,
    }
