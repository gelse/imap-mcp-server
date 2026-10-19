# Documentation

Operator documentation for the gateway; the guides below take you from
deployment to day-to-day use.

## Guides

- [deployment.md](deployment.md) — compose reference, data layout, first-boot
  admin key capture, restart/reset, backup and restore, upgrade pins
- [keys-and-security.md](keys-and-security.md) — admin key, user login key,
  AEK, and `wrap.key`: formats, lifecycles, regeneration
- [mcp-clients.md](mcp-clients.md) — connect Claude Desktop, Cursor, or any
  MCP client to `/mcp`
- [user-guide.md](user-guide.md) — day-to-day admin and user tasks in the
  web app
- [security.md](security.md) — runtime posture, credentials, log redaction,
  rate limiting, response hardening, the frontend supply chain, the tool-host
  child, residual risks
- [acceptance-checklist.md](acceptance-checklist.md) — requirement checklist
  with the dated gate evidence

The web app is one Vue 3 single-page application with two surfaces,
`/admin` and `/user`; there are no separate server-rendered pages. The
manual UI test script that used to accompany these guides is obsolete — it
described the retired HTML pages — and is not part of the shipped
documentation set.

## E2E release gate (M06-T01)

This suite is the project's release gate — a release does not ship unless
it passes — and if you build and run this repository from source, it is
your end-to-end proof that the stack does what these guides describe.
Docker required. Run it against the real compose stack:

```sh
uv run --extra e2e pytest tests/e2e
# or, equivalently:
uv run pytest -m e2e
```

The suite boots the gateway plus the stub IMAP/SMTP server
(`tests/e2e/docker-compose.e2e.yml` overlaying the root
`docker-compose.yml`), never wipes its data tree, prunes any users leaked
by earlier runs at session start (login latency scales with active-user
count).

Running it twice is required, not optional: invoke the command above two
times in a row against the same data dir. The suite does not enforce this
itself; the second run is what proves the existing-key / persistence path.

The deploy scenario also probes the web app: it asserts that `/admin`
serves the shell with the Content-Security-Policy header and
`Cache-Control: no-store`, that `/user` serves the shell (200), and that
the hashed asset the shell references is served with the immutable cache
policy.

The suite is skipped automatically under a plain `uv run pytest`, so unit
gates stay Docker-free.
