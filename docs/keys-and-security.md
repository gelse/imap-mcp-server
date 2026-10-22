# Keys and security

The gateway uses three kinds of secret. Each protects different data, lives
in a different place, and recovers differently. Understanding which one you
are holding decides what you can do with it.

| Key | Format | Stored as | Who ever sees the plaintext |
| --- | --- | --- | --- |
| Admin key | `adm_` + 43 characters | scrypt hash in `./data/config/admin-key.hash` | the operator, once, in the first-boot log |
| User login key | `usr_` + 43 characters | scrypt hash in each `user.json` | the admin at creation/rotation, the user at rotation |
| Account encryption key (AEK) | 64 lowercase hex characters | wrapped under `wrap.key` in `user.json.aek` | the user, once, at activation |

## Admin key

The admin key is the operator's root credential. It authenticates the
admin surface of the web app (`/admin`, which calls the admin API) and the
admin API (`/api/admin`), either as `Authorization: Bearer <admin key>` or
through the `imapgw_admin` session cookie. It does not authenticate `/mcp`
— by construction an admin key is rejected there; MCP sessions use a user
login key.

**Format and storage.** `adm_` followed by 43 unpadded urlsafe-base64
characters (32 CSPRNG bytes). The plaintext is minted at first boot, when
`./data/config/admin-key.hash` is absent. Only the scrypt hash of the key is
persisted; the plaintext is printed to the log once and exists nowhere else.

**Reset.** Deleting `./data/config/admin-key.hash` is a supported reset. The
next startup mints and prints a fresh key, exactly like first boot. Users and
`wrap.key` are untouched. If the hash file is present but corrupted, startup
aborts with a fatal error ending `delete the file to reset` — the same reset
applies. Procedures:
[deployment.md](deployment.md#reset-the-admin-key).

**Session lifetime.** Admin web sessions use the `imapgw_admin` cookie:
`HttpOnly`, `SameSite=strict`, 12-hour TTL, signed with a per-boot secret.
Restarting the gateway invalidates every admin session (operators re-login),
while the admin key itself keeps authenticating across restarts.

## User login key

A user login key belongs to one user. It logs that user into the user
surface of the web app (`/user`) and authenticates their MCP sessions at
`/mcp` via `Authorization: Bearer <usr_…>` (or the `X-Api-Key` header).

**Format and storage.** `usr_` plus 43 unpadded urlsafe-base64 characters.
Only its scrypt hash is stored, in `./data/users/<userId>/user.json`.

**One-time display.** The plaintext is shown exactly once — when the admin
creates the user or rotates the key (the admin API's create and rotate
responses are the only admin-API responses that ever carry a login key), or
when the user rotates their own key from the user settings view or
`POST /api/me/rotate-key`. In the web app the key appears in a one-time
display panel with a copy button; the app holds it in memory only and
discards it when you leave the view. It cannot be recovered afterwards, and
no endpoint can return it a second time.

**Rotation.** The admin can rotate a user's key from that user's page in the
admin app, and the user can rotate their own from the user settings view or
`POST /api/me/rotate-key`. Rotation bumps `key_generation` and the old key
stops authenticating immediately. The AEK and all stored accounts are
unaffected.

**Recovery.** There is none. Lost keys are re-rotated — by the admin, or by
the user while still logged in.

**Session lifetime.** User web sessions use the `imapgw_user` cookie:
`HttpOnly`, `SameSite=strict`, 12-hour TTL, signed with the same per-boot
secret as the admin cookie. Restarting the gateway invalidates every user
session (operators and users re-login); the login key itself keeps
authenticating.

## Account encryption key (AEK)

The AEK encrypts one user's IMAP account records at rest. Each user has
their own; account stores (`imap-store/accounts.json`) are ciphertext without
it.

**Format and storage.** 64 lowercase hex characters (32 bytes). Minted
lazily — at the user's first account add, or at explicit activation
(`POST /api/me/accounts/activate`, or the **Activate account encryption**
button in the user settings view). At rest it exists only wrapped under the
server `wrap.key`, as a JSON object in `user.json.aek`:
`{"blob": "base64(iv):base64(tag):base64(ciphertext)", "version": n}`.
During an active MCP session a plaintext copy is materialized at
`imap-store/.key`, removed at session teardown, and any orphan from a crash
is swept at startup.

**One-time display.** The plaintext AEK is disclosed exactly once — to the
user, at activation, whether that happens through the first account add or
the explicit activate action. The web app shows it in a one-time display
panel with a copy button and drops it from memory when you leave the view.
The admin never sees it. Activation is not repeatable: a second activation
answers `409 aek_already_active`.

**One-time disclosure on failure.** If the account store cannot be written
after the AEK was already activated, the API answers
`500 {"error":"internal_error","account_encryption_key": …}` — the AEK
plaintext is returned once more in that body, because the key is already
persisted and refusing to hand it over would lock the user out of their own
ciphertext. It is the only other response that ever carries AEK material.

**Rotation.** Rotating an AEK re-encrypts every account store under the new
key. Login-key rotation does not touch it.

**MCP prerequisite.** Tool calls for a user without an active AEK are
answered with a structured JSON-RPC error directing the client to activate
account encryption in the web UI first.

## wrap.key

`wrap.key` is the server-side AES-256 key that wraps every user's AEK. It is
64 lowercase hex characters at `./data/config/wrap.key`, mode 0600. It is
server material, not a credential: it is never logged and never displayed.

**Deleting it is not a casual reset — neither is finding it corrupted.**
What happens depends on what else is on disk:

| You delete or corrupt | Wrapped AEKs on disk? | Next boot |
| --- | --- | --- |
| `./data/config/admin-key.hash`, deleted | anything | new admin key minted and printed; users and `wrap.key` untouched |
| `./data/config/wrap.key`, deleted | no | silently regenerated; no impact |
| `./data/config/wrap.key`, deleted | yes | startup aborts with `WrapKeyUnavailableError` — the message calls this an account-crypto wipe and advises restoring the file from backup instead |
| `./data/config/wrap.key`, corrupted (present but not valid 64-hex content) | yes | startup aborts with `WrapKeyCorruptedError` — the message says a regenerated key could not open the wrapped AEKs and advises restoring the file from backup |

**Recovery.** The abort repeats: the container crash-loops, `docker compose
ps` reports it restarting with exit code 3, and every attempt logs the same
error. Stop the loop with `docker compose stop imap-gateway`, restore the
file from a backup of `./data` — for example
`tar xzf imap-gateway-data.tgz ./data/config/wrap.key` — then
`docker compose up -d`. The next boot logs `[config] wrap key found`, and
AEK unwrapping works again.

Losing `wrap.key` while wrapped AEKs exist, with no backup, makes every
stored account credential permanently unrecoverable. Back up the whole
`./data` tree, `wrap.key` included:
[deployment.md](deployment.md#back-up-and-restore).

## CSRF token

Browser sessions carry a per-session CSRF token. Every mutating API call
must present it, in the `X-CSRF-Token` header; a missing or wrong token is
answered `403`. On the admin surface, `Authorization: Bearer <admin key>`
calls are exempt — a header-authenticated caller has no cookie to ride on.
The user API surface has no Bearer path at all (it is cookie-only); Bearer
authentication exists only for `/mcp` via `X-Api-Key` or `Authorization`.

The web app obtains the token from the session endpoints and keeps it **in
memory only**:

- `GET /api/admin/session` and `GET /api/me/session` answer
  `{"csrf_token": …}` for a valid session cookie and the uniform
  `401 {"error":"unauthorized"}` otherwise;
- `POST /api/me/login` returns the fresh session's token in its body
  (`{"status":"ok","csrf_token": …}`) so the first call after login needs no
  second round-trip.

The token is never written to `localStorage`, `sessionStorage`, a readable
cookie, or a URL. After a page reload the app re-fetches it from the session
endpoint. The only thing the app stores in the browser is the theme
preference (`localStorage` key `imapgw.theme`) — no secret of any kind.

## Residual risks

The design accepts a defined set of residual risks — a wrapped AEK implies a
compromised host can decrypt accounts, the admin key transiently exists in
operator logs, the stack speaks plain HTTP, the Node runtime ships in the
image by deliberate choice, and the image build now runs a JavaScript
toolchain. Each is enumerated with its mitigation in
[security.md](security.md), starting at
[Residual risks and mitigations](security.md#residual-risks-and-mitigations).

For quick reference, the login and MCP surfaces are rate-limited (admin login
5 failures / 10 minutes / IP; user login 8 / 10 minutes; `/mcp` 5 / 10
minutes, answered `429` with `Retry-After`), and `X-Forwarded-For` is
deliberately not honored — limits key on the socket peer address. The
authoritative detail is in
[security.md](security.md#rate-limiting-and-authentication-responses).
