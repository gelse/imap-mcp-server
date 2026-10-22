# Changelog

## v0.1.0 - 2026-10-22

First release. A self-hosted FastAPI gateway in front of the upstream
`imap-mcp-server` MCP tool set, with per-user isolation and encrypted account
storage.

- One Docker Compose service serves a Vue 3 single-page web app (admin surface
  at `/admin`, user surface at `/user`), JSON APIs under `/api/*`, and an MCP
  Streamable HTTP endpoint at `/mcp`.
- Three key kinds, each displayed exactly once: admin key (minted and logged on
  first boot), user login key (shown at creation or rotation), and account
  encryption key (AEK, shown at activation) — only hashes and wrapped material
  are ever stored.
- IMAP/SMTP account credentials encrypted at rest; every user sees only their
  own accounts.
- Tool execution via the vendored, pinned `imap-mcp-server@2.2.0` package, one
  child process per MCP session.
- Security posture: strict Content-Security-Policy and security headers on
  every response, CSRF-protected session cookies, rate-limited sign-in, no
  secrets in browser storage.
- Multi-arch container image, `/healthz` probe, and full documentation under
  `docs/`.

Milestone recap: M01 deployment and persistence, M02 admin key and
configuration API, M03 user management, M04 self-service accounts and
encryption, M05 MCP endpoint with authentication and isolation, M06 security
hardening and test gates, M07 Vue 3 single-page app.
