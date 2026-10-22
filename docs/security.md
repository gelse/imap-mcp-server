# Security model and residual risks

This document describes how the gateway protects credentials and
per-account encryption material, and — just as importantly — the risks that
remain after the M06 hardening pass and the M07 replacement of the
server-rendered pages by a single-page web app. It is written for operators
deploying the image with the shipped `docker-compose.yml`. Credential
lifecycles and backup/restore procedures live in the deployment and
key-model guides; this file covers posture.

## Runtime posture

- **Unprivileged container user.** The image runs as `app`, uid `1000`, with
  a `nologin` shell (`Dockerfile`). Nothing in the gateway needs root.
- **Bind mounts.** Compose maps `./data/config`, `./data/users` and
  `./data/mail` into `/data`. The host directories must be writable by uid
  `1000` (`chown 1000:1000` or create them as that user). On-disk state is
  already least-privileged: the gateway writes secret files mode `0600`
  inside directories mode `0700` (the admin-key hash, the wrap key, and every
  `user.json`), so the host-side permissions are the outer layer, not the
  only one.
- **Plain HTTP on the published port (3030 by default).** The container
  terminates no TLS. The compose port mapping publishes
  `${GATEWAY_PORT:-3030}` (default `3030:3030`); treat that as an internal
  listener behind a reverse proxy (below), not as a public endpoint. (The
  bare image's own default is `HTTP_PORT=3000`.)

## Credentials and keys

| Secret | Where it lives | When it is shown |
| --- | --- | --- |
| Admin key (`adm_…`) | scrypt hash at `config/admin-key.hash` | exactly once, on first boot, in the `[auth] admin key created …` log line |
| User login key (`usr_…`) | scrypt hash inside `users/<id>/user.json` | exactly once, in the web app's one-time display panel after the admin creates or rotates the key, or after the user rotates their own |
| Account encryption key (AEK) | wrapped blob inside `users/<id>/user.json` | exactly once, in the web app's one-time display panel after activation or after the first account is added |
| Server wrap key | `config/wrap.key` (64 hex) | never displayed, never logged |

Deleting `admin-key.hash` is the supported admin-key reset (next boot mints a
new one). Deleting `wrap.key` is a full account-crypto wipe: every wrapped
AEK becomes undecryptable, so the gateway refuses to boot without it when
wrapped AEKs exist. Back these files up accordingly.

## Log redaction

A `RedactFilter` (`src/imap_mcp_gateway/log.py`) is attached to every gateway
logger and stdout handler. Before a record is formatted it strips all
key-shaped material — `adm_…`, `usr_…`, 64-lowercase-hex runs (AEKs, the wrap
key, random ids) and `scrypt$…$…$…$…$…` hash records — from the message and
its arguments, and from the `fields`, `tag` and exception/stack text
channels, replacing each span with `[REDACTED]`.

There is exactly **one exemption**: the first-boot `[auth] admin key created
…` line keeps its plaintext, because it is the operator's only delivery
channel for the admin key. The exemption matches a rendered-message *prefix*
only.

Every line relayed from a tool-host child arrives as `[mcp:<userId>]
<text>`, so a hostile child cannot smuggle material past the filter by
imitating that wording. The regression suite pins all of this, including the
forged-relay case.

## Rate limiting and authentication responses

Failed authentication is counted per surface, per socket-peer IP, in a
10-minute sliding window, and locks out with `429` + `Retry-After` (in
memory only — see residual risk 6):

- `POST /api/admin/login` and `Authorization: Bearer` admin checks — 5
  failures;
- `POST /api/me/login` — 8 failures (a separate counter);
- `/mcp` header authentication — 5 failures (a separate counter).

The surfaces never share a counter, so hostile traffic against one form
cannot lock the other out.

Every authentication failure on every surface — wrong key, unknown key,
missing credentials, disabled or deleted user — is the identical body
`{"error": "unauthorized"}` at `401`. The body never echoes key material and
never distinguishes causes, so it cannot serve as an enumeration oracle.

A code-level regression test sweeps the unauthenticated responses (the app
shell, auth failures, health) to confirm no `scrypt$` records, key material,
wrapped-AEK blobs, or 64+-hex secrets are ever
serialized.

## Response hardening

An outermost middleware sets, on every application response:
`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer`, and a `Content-Security-Policy`. Admin
responses additionally carry `Cache-Control: no-store`, and so do the API
responses that may carry a one-time secret and the web app's shell. The one
response that escapes the layer is the fixed `{"error": "internal_error"}`
500 raised inside the middleware chain: Starlette sends it below the header
wrapper, so it carries none of the headers — moot for a fixed JSON body that
is neither sniffed, framed, nor linked from.

Deliberately not set: HSTS (meaningful only behind TLS, which the container
does not terminate), and `Cache-Control` in the shared layer (already pinned
per surface).

### Content-Security-Policy

Every response carries:

```text
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'
```

The policy is strict on purpose: no `'unsafe-inline'`, no `'unsafe-eval'`,
no wildcard, and no external origin anywhere. The web app satisfies it
because every asset it loads is same-origin (the build emits absolute
`/assets/<hash>.js` references), it uses system font stacks and inline SVG
icons instead of remote fonts, and it sets no inline `style` attributes —
the components use CSS classes and custom properties. `img-src` allows
`data:` for the inline data-URI favicon. `object-src 'none'`, `base-uri
'none'` and `frame-ancestors 'none'` deny the plugin, base-tag and embedding
vectors outright.

The middleware uses `setdefault` semantics: a route that sets its own CSP
keeps its value. Should a future build demonstrably need an inline style,
the sanctioned fallback is `style-src 'self' 'unsafe-inline'` for
style-src **only**, with a justification recorded here.

### Caching

The app shell (`index.html`, served at every `/admin` and `/user` path) is
never cached (`Cache-Control: no-store`) — it is small, and a stale shell
would point at stale asset names. The hashed assets under `/assets/` are
cached for a year (`public, max-age=31536000, immutable`): their file names
contain a content hash, so a changed file always gets a new name and a
cached copy can never go stale. A missing asset answers a plain-text `404`
from the static-file mount rather than the JSON `not_found` shape; the
app-level JSON 404 contract is unchanged outside that mount.

## The web app

The admin and user surfaces are one Vue 3 single-page application, built
from TypeScript sources in `frontend/` and served by the gateway. The
previous server-rendered HTML pages — and with them the one-shot form-ticket
machinery — are gone; there is no HTML form login left, and the only login
surfaces are `POST /api/admin/login` and `POST /api/me/login`.

What that changes for a security review:

- **The UI ships JavaScript.** The "server-rendered and JS-free" property
  the pre-M07 documentation claimed is superseded. The bundle is now part
  of the product, and the Content-Security-Policy above is the compensating
  control.
- **The CSRF token reaches the browser.** It arrives in the login response
  (`POST /api/me/login`) or from `GET /api/admin/session` /
  `GET /api/me/session`, and the app holds it in memory only — never in
  `localStorage`, `sessionStorage`, a readable cookie, or a URL. The theme
  preference is the only browser-storage entry, and it is not a secret.
- **Secrets are still shown once.** A login key or an AEK is rendered in a
  one-time display panel, in memory, and is not re-fetchable from any
  endpoint. The API contract for that did not change: only the create and
  rotate responses (admin, including admin-driven rotation), the
  activation, first-add, and rotate-key responses (user), and one
  failure-safe disclosure ever carry such material — if the account store
  cannot be written after the AEK was already activated, the API answers
  `500 {"error":"internal_error","account_encryption_key": …}` that returns
  the key once more, because it is already persisted and refusing to hand
  it over would lock the user out of their own ciphertext
  ([keys-and-security.md](keys-and-security.md#account-encryption-key-aek)).
- **Destructive actions are confirmed in the browser.** The old
  server-side `confirm_name` re-typing check is gone with the HTML pages;
  the web app asks you to type the name before it deletes, and the
  API-level protections (authentication plus CSRF) are unchanged and were
  never part of that confirmation.

## Language boundary

The gateway's server-side code is Python. The web app is TypeScript and
Vue, built into static files at image build time and served as such — no
JavaScript runs in the container on behalf of a request, and the image
carries no frontend sources. The only JavaScript in the runtime image is the
vendored upstream package, which the tool host executes.

This supersedes the earlier project rule that the repository would stay
"Python only, no new Node or JS". The rule existed to keep the runtime
surface small; M07 changed that deliberately, because the admin and user
surfaces needed a real application. What did not change:

- The only Node component that **runs** at runtime is the vendored,
  pinned `imap-mcp-server@2.2.0` child process, with the six-variable
  environment allowlist described below.
- The Node toolchain exists in the image build only, in the `web-build`
  stage, and never in the runtime stage.
- The vendoring policy is the same one the upstream package follows:
  committed lockfile, `npm ci` only, no floating ranges.

## Frontend supply chain

The repository now ships a frontend toolchain, which is a supply-chain
surface of its own:

| Artifact | Where | What it pins |
| --- | --- | --- |
| `frontend/package.json` | committed | exact versions of the build and runtime dependencies (Vue, Vite, TypeScript, vue-tsc, vitest) |
| `frontend/package-lock.json` | committed | the resolved dependency tree — authoritative; `npm ci` installs exactly it and never rewrites it |
| `frontend/dist/` | built at image build | the hashed assets and `index.html` that the runtime image serves |

The rules that keep the surface small:

- **The toolchain runs only in the `web-build` stage.** `npm ci` and
  `npm run build` execute while the image is built. The runtime stage copies
  only `frontend/dist` — no `node_modules`, no frontend sources, no npm
  cache, no dev dependencies.
- **The build ends in an audit.** `frontend/scripts/audit-dist.mjs` is the
  last leg of `npm run build` and fails the build on secret-shaped material
  (key prefixes, 64-hex runs, `scrypt$` markers), on external URLs, and on
  inline scripts or inline event handlers. A violation fails the image
  build, not a deployment.
- **No external requests at runtime.** There is no CDN, no remote font, and
  no telemetry. Everything the app loads is same-origin; the Content
  Security-Policy above enforces it.
- **The frontend dependencies are small and explicit.** Two runtime
  dependencies (Vue, vue-router) and no HTTP client, no CSS framework, and
  no UI kit. The app talks to the gateway with `fetch` only.

The Node binary in the runtime image and `/opt/vendor/npm` are there for the
tool host, not for the web app — see
[The tool-host child](#the-tool-host-child).

## The tool-host child

Each authenticated MCP session gets one fresh `node` child running the
vendored, unmodified `imap-mcp-server@2.2.0`. The child receives **exactly
six** environment variables — `HOME`, `IMAP_DOWNLOAD_DIR`,
`IMAP_UPLOAD_TTL_MS`, `IMAP_MAX_UPLOAD_SIZE`, `PATH`, `LANG` — and nothing
else: no `DATA_DIR`, no wrap-key or admin-hash paths, no parent secrets. Its
stderr is relayed to the gateway log under `[mcp:<userId>]`, sanitized
(control characters flattened, length capped) so it cannot forge log lines,
and scrubbed by the redaction filter like any other line.

## Residual risks and mitigations

1. **A compromised host can decrypt accounts.** Per-account encryption is
   keyed by the AEK, but the AEK is stored *wrapped* under the server wrap
   key, which lives on the same host. Anyone who obtains the host filesystem
   (or root in the container) can recover the wrap key and every AEK, then
   decrypt all account credentials. This is inherent to server-side
   encryption with local key storage, accepted for this design.
   *Mitigations:* keep the host and the `./data` tree least-privileged and
   backed up offline; treat host compromise as full compromise; never expose
   the data directory over the network.

2. **The admin key lives in operator logs.** First boot prints the admin key
   in plaintext once (`[auth] admin key created …`) and the redaction filter
   deliberately leaves that line intact. Those logs are therefore sensitive.
   *Mitigations:* capture the key immediately, then rotate or delete the log
   lines; enable container log rotation and restrict access to `docker logs`;
   the admin key is the only secret that ever appears there, and a grep for
   `adm_|usr_|[0-9a-f]{64,}` over a full scenario run finds nothing outside
   the designated one-time line.

3. **Plain HTTP inside the stack.** The container speaks plain HTTP on the
   published port (3030 by default; `HTTP_PORT` controls it, and the bare
   image default is 3000); session cookies and MCP Bearer keys cross that hop
   in the clear. *Mitigations:* terminate TLS at a reverse proxy in front of
   the gateway and keep the published port bound to the loopback or a private
   network — do not publish it publicly. Session cookies are `HttpOnly` +
   `SameSite=strict`, so HTTPS at the proxy is what keeps them confidential.

4. **The Node runtime ships in the image** (decision (d)). Serving MCP tools
   requires running the upstream Node server, so the image carries Node
   `22.12.x` and the vendored package. *Mitigations:* the package is pinned
   (`imap-mcp-server@2.2.0`), fetched prebuilt, copied to a root-owned
   read-only `/opt/vendor/npm`, and executed unmodified — the vendored code
   is never patched, and the child is confined by the six-variable
   environment allowlist and one-per-session lifetime, and runs as the same
   unprivileged uid.

5. **The image build now runs a JavaScript toolchain** (M07). The web app is
   built from `frontend/` with `npm ci` and Vite, and the build's final leg
   is a secret/external-URL audit. *Mitigations:* the lockfile is committed
   and `npm ci` installs exactly it, so a build resolves the same
   dependencies every time; the toolchain exists only in the build stage, and
   the runtime image receives only the built `frontend/dist`; the audit fails
   the build on secret-shaped material, external URLs, or inline scripts;
   the dependency set is small and explicit (two runtime dependencies, no
   HTTP client, no CSS framework). The residual exposure is the usual one of
   any build-time dependency: a compromised package would run during the
   build, which is why the audit and the lockfile matter, and why the
   runtime image is kept free of the toolchain.

6. **All lockout and session state is in memory.** Rate-limit counters and
   the session-signing secret reset on every restart: outstanding cookies
   become invalid (forcing re-login) and lockout counters clear. *Mitigations:*
   this is a deliberate simplicity/robustness trade-off for a single-process,
   single-`DATA_DIR` deployment; the practical exposure is a brief window
   after a restart in which a brute-force counter is reset, bounded by the
   per-surface limits themselves. Run one gateway process per `DATA_DIR`.

7. **The rate limiter keys on the socket peer, not `X-Forwarded-For`.** No
   trusted-proxy contract is configured, so the forwarded header (which a
   client can set) is ignored. Behind a reverse proxy, every request appears
   to originate from the proxy, so all clients share one lockout bucket.
   *Mitigations:* accept the coarser per-proxy bucket, or terminate and rate
   limit at the proxy; do not "fix" this by trusting `X-Forwarded-For`
   without a trusted-proxy configuration, which would let an attacker evade
   the limit by spoofing the header.
