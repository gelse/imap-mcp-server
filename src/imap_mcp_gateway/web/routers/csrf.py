"""CSRF verification dependency for cookie-authenticated admin POSTs (M02-T03).

Convention (fixed for the admin surface): the per-session CSRF token — a
256-bit random value stored inside the signed ``imapgw_admin`` cookie
payload at login — is REQUIRED for cookie-authenticated state-changing
requests and EXEMPT for Bearer-authenticated API calls. Rationale: browser
sessions are what CSRF attacks impersonate (the cookie rides along
automatically), while Bearer tokens are attached explicitly per request by
non-browser clients, which browsers cannot silently attach cross-site. The
token reaches the client inside the server-rendered forms (hidden
``csrf_token`` field) and returns via that field or the ``X-CSRF-Token``
header.
"""

from __future__ import annotations

import hmac
from typing import Annotated

from fastapi import Depends, Request

from imap_mcp_gateway.web.middleware.admin_auth import (
    AdminAuth,
    AdminHTTPError,
    require_admin,
)


async def verify_csrf(
    request: Request,
    auth: Annotated[AdminAuth, Depends(require_admin)],
) -> None:
    """Reject cookie-authenticated POSTs that omit a valid CSRF token.

    Bearer-authenticated requests pass unconditionally (the exemption
    convention above); for cookie sessions the presented token — the
    ``csrf_token`` form field or the ``X-CSRF-Token`` header — must match
    the session's token, compared in constant time. Anonymous requests
    never get here: the ``require_admin`` sub-dependency has already
    rejected them with the uniform 401.
    """
    if auth.via == "bearer":
        return
    presented = request.headers.get("x-csrf-token")
    if not presented:
        try:
            form = await request.form()
            value = form.get("csrf_token")
        except Exception:  # a hostile/undecodable body simply fails the check
            value = None
        presented = value if isinstance(value, str) else ""
    if not presented or auth.csrf_token is None:
        raise AdminHTTPError(403, "forbidden")
    if not hmac.compare_digest(
        presented.encode("utf-8"), auth.csrf_token.encode("utf-8")
    ):
        raise AdminHTTPError(403, "forbidden")


CsrfDep = Annotated[None, Depends(verify_csrf)]
"""Annotated CSRF dependency (Annotated keeps lint-friendly signatures)."""
