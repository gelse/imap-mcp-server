"""Signed, httpOnly cookie sessions for the gateway's web surface (M02-T03).

A cookie value is ``base64url(json payload) + "." + base64url(HMAC-SHA256)``
where the signing key is a fresh 32-byte CSPRNG secret created with the
:class:`SessionSigner` and kept in memory only — never persisted, never
logged. Sessions therefore die on process restart (operators re-login),
which is the intended lifecycle: no persistent session storage exists.

Cookie naming is a fixed milestone contract (M02):

- :data:`ADMIN_COOKIE_NAME` (``imapgw_admin``) — the admin session cookie,
  active since M02-T03;
- :data:`USER_COOKIE_NAME` (``imapgw_user``) — the user session cookie,
  active since M03-T04: same signer, same scheme, payload ``kind``
  :data:`SESSION_KIND_USER` plus a ``sub`` member carrying the user id.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time

ADMIN_COOKIE_NAME = "imapgw_admin"
"""Active admin session cookie (M02-T03)."""

USER_COOKIE_NAME = "imapgw_user"
"""Active user session cookie (activated in M03-T04; name fixed in M02-T03).

Same signer and signing scheme as the admin cookie; the payload's ``kind``
is :data:`SESSION_KIND_USER` and ``sub`` carries the registry user id.
Reading and enforcing it lives in
:mod:`imap_mcp_gateway.web.middleware.user_auth` (``require_user``).
"""

SESSION_KIND_ADMIN = "admin"
"""``kind`` payload value for admin sessions (the user kind is
:data:`SESSION_KIND_USER`)."""

SESSION_KIND_USER = "user"
"""``kind`` payload value for user sessions (active since M03-T04).

A user-kind payload additionally carries ``sub`` — the authenticated
user's registry id — which
:func:`imap_mcp_gateway.web.middleware.user_auth.require_user` re-resolves
against the store on every request, so deleting or disabling the user
kills an outstanding session immediately.
"""

_SECRET_BYTES = 32
"""Signing-key entropy: 256 bits, drawn once per signer from the CSPRNG."""

_CSRF_TOKEN_BYTES = 32
"""Entropy per CSRF token (256 bits)."""

_SIGNATURE_BYTES = 32
"""HMAC-SHA256 output length."""

_SESSION_TTL_SECONDS = 12 * 3600
"""Server-side session lifetime; also the browser cookie Max-Age."""


class SessionSigner:
    """Signs and verifies session-cookie values with a per-boot random key.

    The secret lives only in this instance's memory: it is drawn fresh from
    :func:`secrets.token_bytes` when the signer is built and dies with the
    process, so every cookie minted before a restart fails signature
    verification afterwards — the re-login-on-restart contract.
    """

    def __init__(
        self,
        *,
        ttl_seconds: int = _SESSION_TTL_SECONDS,
        secret: bytes | None = None,
    ) -> None:
        self._secret = (
            secret if secret is not None else secrets.token_bytes(_SECRET_BYTES)
        )
        self._ttl_seconds = ttl_seconds

    @property
    def ttl_seconds(self) -> int:
        """Session lifetime in seconds (cookie Max-Age and payload ``exp``)."""
        return self._ttl_seconds

    def new_csrf_token(self) -> str:
        """Return a fresh 256-bit CSRF token (unpadded urlsafe base64)."""
        return _b64encode(secrets.token_bytes(_CSRF_TOKEN_BYTES))

    def create_session(self, kind: str, **extra_claims: str) -> tuple[str, str]:
        """Create a new session; return ``(signed cookie value, csrf token)``.

        ``extra_claims`` adds further flat ``str -> str`` payload members —
        e.g. ``sub=<user id>`` for the user-session kind — without forking
        the payload construction. The reserved ``kind``/``csrf``/``exp``
        members always win over same-named extras.
        """
        payload = {
            **extra_claims,
            "kind": kind,
            "csrf": self.new_csrf_token(),
            "exp": str(int(time.time()) + self._ttl_seconds),
        }
        return self.seal(payload), payload["csrf"]

    def seal(self, payload: dict[str, str]) -> str:
        """Serialize ``payload`` deterministically and return the signed value."""
        body = _b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        signature = _b64encode(self._signature(body))
        return f"{body}.{signature}"

    def unseal(self, cookie_value: str) -> dict[str, str] | None:
        """Verify and decode a cookie value; ``None`` unless fully valid.

        The signature is compared in constant time
        (:func:`hmac.compare_digest`). The payload must be a flat
        ``str -> str`` mapping whose ``exp`` is a plain ASCII-digit unix
        timestamp still in the future; anything else — malformed, mutated,
        expired, or replayed from an older process — is ``None``. Never
        raises.
        """
        try:
            body, signature_text = cookie_value.split(".", 1)
            presented = _b64decode(signature_text, _SIGNATURE_BYTES)
            if not hmac.compare_digest(presented, self._signature(body)):
                return None
            payload = json.loads(_b64decode(body).decode("utf-8"))
        except (AttributeError, ValueError):
            # AttributeError: defensive parity for non-str input (typed str);
            # ValueError: unpack mismatch, undecodable base64, or bad JSON
            # (JSONDecodeError subclasses ValueError).
            return None
        if not isinstance(payload, dict):
            return None
        session: dict[str, str] = {}
        for key, value in payload.items():
            if not isinstance(key, str) or not isinstance(value, str):
                return None  # a flat string mapping only — never nested data
            session[key] = value
        exp_text = session.get("exp", "")
        if not (exp_text.isascii() and exp_text.isdigit()):
            return None
        if int(exp_text) <= int(time.time()):
            return None  # expired
        return session

    def _signature(self, body: str) -> bytes:
        """HMAC-SHA256 over the encoded body under the per-boot secret."""
        return hmac.new(self._secret, body.encode("ascii"), hashlib.sha256).digest()


def _b64encode(raw: bytes) -> str:
    """Unpadded urlsafe base64 (the paste-safe encoding used gateway-wide)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(field: str, expected_bytes: int | None = None) -> bytes:
    """Strictly decode a canonical unpadded urlsafe base64 field.

    ``validate=True`` rejects any character outside the base64url alphabet
    (a lenient decoder silently DROPS such characters), and the canonical
    re-encoding check rejects non-canonical spellings — a mutated cookie
    value can never decode to the original bytes. ``expected_bytes``
    additionally pins the decoded length.
    """
    padded = field + "=" * (-len(field) % 4)
    raw = base64.b64decode(padded.replace("-", "+").replace("_", "/"), validate=True)
    if expected_bytes is not None and len(raw) != expected_bytes:
        raise ValueError("field decodes to an unexpected length")
    if _b64encode(raw) != field:
        raise ValueError("field is not canonical base64url")
    return raw
