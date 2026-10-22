# imap-mcp-gateway

A self-hosted HTTP gateway that puts authentication, per-user isolation, and
encrypted account storage in front of the upstream `imap-mcp-server` MCP tool
set. One Docker Compose service (`imap-gateway`) serves a single-page web
application (one Vue 3 app, two role surfaces — `/admin` and `/user`), JSON
APIs, and an MCP Streamable HTTP endpoint at `/mcp`. The gateway is Python
(FastAPI); for tool execution it spawns a child process running the vendored,
pinned `imap-mcp-server@2.2.0` Node package — one child per MCP session.

[![License: MIT](https://img.shields.io/badge/License-GPL-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED.svg?logo=docker)](https://ghcr.io/gelse/ssh-mcp)
[![MCP](https://img.shields.io/badge/MCP-streamable--HTTP-green.svg)](https://modelcontextprotocol.io/)

## One-time secrets — read this first

The single most destructive mistake is losing a key. Three secrets are displayed
**exactly once** — in the browser or in the first-boot container log — and no
endpoint can ever re-display them. Copy each at the moment it appears; reloading
the page or navigating away discards it for good.

| Secret | Format | Shown | Where it lives |
| --- | --- | --- | --- |
| Admin key | `adm_` + 43 characters | once, in the first-boot log line | scrypt hash in `./data/config/admin-key.hash` |
| User login key | `usr_` + 43 characters | once, in the browser, at user creation or rotation | scrypt hash in `./data/users/<id>/user.json` |
| Account encryption key (AEK) | 64 lowercase hex characters | once, in the browser, at activation or first account add | wrapped under `wrap.key` in `user.json.aek` |

Browser storage holds **only** the theme preference under `localStorage` key
`imapgw.theme`. No token or secret is ever stored in the browser; the CSRF token
lives in memory only and is re-fetched after a reload. The theme toggle
(light/dark) in the top bar persists under that key.

Full lifecycles, regeneration, and recovery: [docs/keys-and-security.md](docs/keys-and-security.md).

## Quickstart

```sh
mkdir -p data/config data/users data/mail
docker compose up --build -d
docker compose logs imap-gateway
```

The host directories must be writable by uid 1000 (the container runs as `app`,
uid 1000) — create them as that user or `chown 1000:1000` them.

On the first boot — when `./data/config/admin-key.hash` does not exist — the
gateway mints the admin key and prints it exactly once, on one log line:

```
<timestamp> INFO [auth] admin key created — store it now; it will not be shown again: adm_...
```

Copy the `adm_...` value from that line. It exists nowhere else. The same boot
then logs `[auth] hash file: /data/config/admin-key.hash` and
`[config] wrap key created`. Later boots log `[auth] existing key found` and
never re-display the key. If you miss it, reset it:
[docs/deployment.md](docs/deployment.md#reset-the-admin-key).

Then check the stack is up:

```sh
curl -sS http://localhost:3030/healthz
# {"status":"ok"}
```

The published port defaults to **3030**. Override it for both host and
container with `GATEWAY_PORT=…` (e.g. `GATEWAY_PORT=8080 docker compose up -d`).
The bare image's own default is `HTTP_PORT=3000` — that value only applies when
you run the image directly, outside Compose.

Full procedures (data layout, restart/reset, backup, upgrade):
[docs/deployment.md](docs/deployment.md).

## URLs

The published default port is **3030**. `GET /` is **not** an entry point — it
returns a JSON 404 (`{"error":"not_found","path":"/"}`); the Vue router
redirects `/` to the admin home *inside* the SPA, so your first visit must be
`/admin` or `/user`.

| URL | Purpose |
| --- | --- |
| `http://localhost:3030/admin` | Admin surface — dashboard, users, keys |
| `http://localhost:3030/user` | User surface — accounts, encryption, settings |
| `http://localhost:3030/admin/…`, `/user/…` | Deep links into the SPA (server serves the shell) |
| `http://localhost:3030/api/admin/*` | Admin JSON API — admin key (Bearer or session cookie) |
| `http://localhost:3030/api/me/*` | User JSON API — browser session cookie + CSRF token |
| `http://localhost:3030/mcp` | MCP Streamable HTTP endpoint — user login key |
| `http://localhost:3030/healthz` | Health probe; returns `{"status":"ok"}` |
| `http://localhost:3030/assets/*` | Immutable hashed build assets |

The web app is one Vue 3 single-page application. `/admin` and `/user` are two
entry points into it, and every deep link below them works: the server answers
those paths with the app shell and the app resolves the route in the browser.
The app talks to the JSON APIs above; there are no server-rendered pages.

The stack speaks plain HTTP. For anything beyond localhost, put a
TLS-terminating reverse proxy in front:
[docs/security.md](docs/security.md#runtime-posture).

## Using the web app

### Signing in

- **Admin**: open `/admin`, enter the **Admin key** (password field), click
  **Sign in**. Wrong key → "Sign-in failed. Check the key and try again.";
  repeated failures → "Too many sign-in attempts. Please wait before trying
  again." with a countdown (429).
- **User**: open `/user`, enter the **Login key**, click **Sign in**.

Sessions last 12 hours; a gateway restart ends them. An expired session drops
you to the owning surface's login with the notice
**"Your session has expired. Please sign in again."**; a manual sign-out shows
**"You have been signed out."** A visitor who is already signed in is forwarded
to their home when they open a login page.

### Admin surface

Nav: **Dashboard**, **Users**, **New user**; theme toggle in the top bar;
**Sign out**. Nav is hidden on the login page.

- **Dashboard** (`/admin`): cards **Users** (total, "registered in total"),
  **Active**, **Disabled**, and **API health** (badge OK/Unavailable, caption
  `GET /api/admin/health`); **Create user** CTA; empty state "No users yet".
- **Users** (`/admin/users`): table columns **Name / Status / Key generation /
  Accounts / Created**; status badge "Active" on active users; **Refresh**
  button ("The user list was refreshed."); row link **Manage** → detail.
- **New user** (`/admin/users/new`): field **"Display name"**; submit
  **"Create user"**. Success shows a one-time **"One-time login key"** card
  with KeyDisplay (label "Login key", copy button, confirm **"I have saved
  it"**, warning **"Shown once — it will never be shown again. Copy and store
  it now."**). The value is zeroed on confirm or unmount and is never
  retrievable again.
- **User detail** (`/admin/users/:id`): Details card (Name, Status, Key
  generation, Accounts, Created, plus registry id); **"New login key"** card
  (rotated key shown once, same KeyDisplay/ack); **Actions** card:
  **"Rotate login key"** ("A new login key was minted. The previous key no
  longer works."), **"Disable user"/"Enable user"** (hint: "Disabling a user
  keeps the key but blocks sign-in."), and **"Delete user"** — destructive,
  behind a type-to-confirm dialog titled "Delete user": "This removes the user
  and their whole directory. It cannot be undone. Type the user's exact name to
  confirm." The **Delete** button stays disabled until you type the user's
  exact name.

### User surface

Shell title "My account". Nav: **Accounts** (`/user`), **Add account**
(`/user/accounts/new`), **Settings** (`/user/settings`); theme toggle; **Sign
out**.

- **Accounts** (`/user`): profile header card (Name, Key generation,
  **Account encryption** badge **Active/Not active** from `aek_active`);
  account table columns **Name / Host / User / TLS / SMTP** (Host renders
  `host:port`; TLS badge "TLS"/"Plain"; SMTP = host or "—"); row **Edit** /
  **Delete** (type-to-confirm: "This removes the account and its stored
  credentials. It cannot be undone. Type the account's exact name to
  confirm."); **Refresh** and **Add account** CTA; empty states "No accounts
  yet" / "Add your first mail account. The credentials are stored encrypted
  and are never shown again."
- **Add account** (`/user/accounts/new`): page note "The credentials are
  encrypted before they are stored and are never shown again." Sections
  **IMAP** / **Sending** / **SMTP (optional)** with fields **Account name**,
  **Host**, **Port** (default 993), **User name**, **Password**, **TLS**
  (default on), **Allow STARTTLS**; **E-mail address**, **Save sent messages
  to the Sent folder**, **Sent folder**, **Default BCC** ("One address, or
  several separated by commas."), **Allowed senders** (same hint); **SMTP
  host**, **SMTP port** (default 587), **SMTP over TLS**, **SMTP user name**,
  **SMTP password**. Submit **"Add account"**. A one-time **Account
  encryption key** is shown only when the create response carries it (first
  add activates the AEK; confirm "I have saved it"); a 409 means encryption
  is already active.
- **Edit account** (`/user/accounts/:id`): page note "Credentials are
  write-only: leave them blank to keep the stored values." Non-credential
  fields are prefilled (name, host, port, user, TLS, STARTTLS, email,
  save_to_sent, sent_folder, default_bcc, allowed_from, SMTP host/port/secure);
  credential inputs (Password, SMTP user name, SMTP password) are always blank
  ("Leave blank to keep the stored password." etc.). Switches **"Clear the
  stored IMAP credential"** and **"Clear the stored SMTP credential"** (the
  latter disabled unless an SMTP host is present) send an empty value on
  purpose. Submit **"Save changes"** → "The account was updated."
- **Settings** (`/user/settings`): Profile card (Name, Created, Key
  generation, Account encryption badge). **"Activate account encryption"**
  button shown only when encryption is not yet active — the response AEK is
  displayed once. MCP tool calls require an active AEK (the server answers
  "initialize account encryption in the web UI first"). **"Regenerate login
  key"** → one-time **"New login key"** card, warning "Shown once — it will
  never be shown again. The previous key stops working immediately. Copy and
  store it now." **Sign out**.

### Sessions, theme, and browser storage

- Browser sessions use cookies `imapgw_admin` / `imapgw_user` (HttpOnly, 12 h
  TTL). The user API requires the cookie **plus** an `X-CSRF-Token` header;
  `Authorization: Bearer` on `/api/me/*` gets 401.
- The only browser storage entry is the theme preference under
  `imapgw.theme`; no secret is ever stored. The CSRF token is in memory only.
- Theme: light/dark toggle in the top bar, persisted under `imapgw.theme`.

For the exhaustive task list, see [docs/user-guide.md](docs/user-guide.md).

## Key model

Three kinds of secret, each with a different owner and lifetime. Full detail in
[docs/keys-and-security.md](docs/keys-and-security.md).

**Admin key** (`adm_` + 43 characters) is the operator's root credential. The
first boot prints it to the logs once; only its hash is ever stored. It
authenticates the admin surface (`/admin`, through the admin API) and the
admin API itself, and it never works on `/mcp`.

**User login key** (`usr_` + 43 characters) belongs to one user. The admin
sees it once, at creation or rotation; the user can rotate it themselves. It
logs the user into `/user` and authenticates their MCP sessions at `/mcp`.
Rotating it kills the old key immediately.

**Account encryption key (AEK)** — 64 lowercase hex characters — encrypts a
user's IMAP account records at rest. The user activates it once and stores it;
the admin never sees it. MCP tool calls require an active AEK.

A login key and an AEK are each displayed once, in the browser, and are
never retrievable afterwards. Copy them at the moment they appear; reloading
the page discards them for good.

## Why Node.js ships in the image

The gateway does not re-implement the upstream tools. The image carries a
pinned Node.js 22.12 runtime whose only job is to run the vendored
`imap-mcp-server@2.2.0` package as a child process of the Python gateway
(`node /opt/vendor/npm/node_modules/imap-mcp-server/dist/index.js`, one per
MCP session). This is a deliberate design decision: shipping the upstream
package was chosen over re-implementing its 40 tools in Python. The fuller
language-boundary statement lives in
[docs/security.md](docs/security.md#language-boundary); see also
[docs/mcp-clients.md](docs/mcp-clients.md) for the tool surface clients see.

The web app is built from TypeScript sources in `frontend/`, so the image
build also runs a Node toolchain — at build time only, in the `web-build`
stage: `npm ci` from the committed lockfile, then the bundle build, whose
last step is a secret/external-URL audit that fails the image build on a
violation. The runtime image receives only the built `frontend/dist`
(hashed assets plus `index.html`) — no `node_modules`, no frontend sources.
The Node binary that ships in the runtime image is there for the tool host
above, not for the web app. [docs/security.md](docs/security.md#frontend-supply-chain)
has the supply-chain detail.

## Documentation

- [docs/deployment.md](docs/deployment.md) — compose reference, data layout,
  first-boot key capture, restart/reset, backup and restore, upgrade pins
- [docs/keys-and-security.md](docs/keys-and-security.md) — the three keys,
  `wrap.key`, regeneration semantics
- [docs/mcp-clients.md](docs/mcp-clients.md) — connect Claude Desktop, Cursor,
  or any MCP client
- [docs/user-guide.md](docs/user-guide.md) — day-to-day admin and user tasks
- [docs/security.md](docs/security.md) — runtime posture, redaction, rate
  limits, residual risks
- [docs/acceptance-checklist.md](docs/acceptance-checklist.md) — requirement
  checklist with the dated gate evidence
- [docs/README.md](docs/README.md) — documentation index and the e2e release
  gate
