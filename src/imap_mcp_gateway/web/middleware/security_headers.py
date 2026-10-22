"""Uniform browser-security headers on every application response (M06-T02).

A single pure-ASGI layer, registered outermost in ``web/server.py``, so the
guarantee cannot be forgotten by a future route:

- ``X-Content-Type-Options: nosniff`` — no browser may reinterpre a response
  as another content type (download/HTML sniffing);
- ``X-Frame-Options: DENY`` — no clickjacking frame may embed any page of
  the gateway (login forms included);
- ``Referrer-Policy: no-referrer`` — no response leaks its URL (which may
  carry ids) through the ``Referer`` of a link the user follows next. The
  one-time secret-display pages already pin this per-route (M03-T03/
  M04-T05); this layer makes it the DEFAULT everywhere, and
  :meth:`starlette.datastructures.MutableHeaders.__setitem__` semantics
  (used via ``setdefault`` below) keep any per-route override intact.
- ``Content-Security-Policy`` (M07-T05) — the conservative policy the
  built SPA can actually satisfy: every asset is same-origin (the Vite
  build emits absolute ``/assets/<hash>.js`` references, the build audit
  rejects external URLs and inline script bodies, and the components use
  no inline ``style`` attributes), so the strict policy ships:
  ``default-src 'self'; script-src 'self'; style-src 'self';
  img-src 'self' data:; connect-src 'self'; object-src 'none';
  base-uri 'none'; frame-ancestors 'none'``. ``img-src`` allows ``data:``
  for the inline data-URI favicon; ``object-src 'none'``,
  ``base-uri 'none'`` and ``frame-ancestors 'none'`` deny the plugin,
  base-tag and embedding vectors outright. If a future build ever
  demonstrably needs an inline style, the sanctioned fallback is
  ``style-src 'self' 'unsafe-inline'`` (style-src ONLY), documented in
  ``docs/security.md``.

Deliberately NOT set here: HSTS (meaningful only behind TLS, which the
container itself does not terminate — see ``docs/security.md``), and
``Cache-Control`` (already pinned per-surface: the M02-T03 admin ASGI
middleware plus per-route headers on user secret pages).
"""

from __future__ import annotations

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_DEFAULT_SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    (
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
        "base-uri 'none'; frame-ancestors 'none'",
    ),
)
"""Headers applied to every HTTP response unless already set per-route."""


class SecurityHeadersMiddleware:
    """Pin :data:`_DEFAULT_SECURITY_HEADERS` on every HTTP response.

    ``setdefault`` (not ``__setitem__``) so a route or inner middleware that
    already set a header keeps its value — the secret-display pages'
    existing ``Referrer-Policy: no-referrer`` is identical, and a future
    per-route CSP would not be clobbered. Non-HTTP scopes (websocket) pass
    through untouched.

    One response escapes this layer, matching the ``NoStoreCacheHeadersMiddleware``
    precedent: the fixed ``{"error": "internal_error"}`` 500 that Starlette's
    outermost ``ServerErrorMiddleware`` sends for an unhandled exception goes
    out on the raw channel, below every send-wrapper here, so it carries none
    of these headers. That is acceptable — a fixed JSON body is not a
    sniffing, framing, or link-referrer target — and it is the same response
    the per-surface ``Cache-Control`` pin already cannot reach.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_security_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in _DEFAULT_SECURITY_HEADERS:
                    headers.setdefault(name, value)
            await send(message)

        await self.app(scope, receive, send_with_security_headers)
