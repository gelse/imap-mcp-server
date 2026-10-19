# User guide

Start at `/admin` or `/user` — `GET /` is not an entry point and answers
`404 {"error":"not_found","path":"/"}`. Which one is yours depends on your
role: administrators, who mint users and hand out login keys, work at
`/admin`; users, who log in, encrypt their accounts, and connect MCP
clients, work at `/user`. Both live in the same single-page web app, and
every action in it calls the JSON API; the API equivalents are noted where
they matter.

Port note: every `:3030` URL below is only the compose default. If it does
not work, your deployment runs on another port — ask whoever runs the
gateway, and substitute your actual port throughout.

**One-time secrets are shown once.** A login key and an account encryption
key each appear exactly once, in the browser, on the screen that mints
them. Copy them at that moment. Reloading the page or navigating away
loses them permanently — no endpoint can re-display them.

## For administrators

### Log in

Open `http://<host>:3030/admin`. The app sends you to its login view; enter
the admin key. The session cookie lasts 12 hours, but a gateway restart ends
it — log in again after a restart. From the API, authenticate every request
with `Authorization: Bearer <admin key>` instead of a cookie; Bearer requests
are exempt from the CSRF token that browser sessions must carry.

### Create a user

Open `/admin/users` and click **Create user** — it opens `/admin/users/new`
(the same page is reachable via the **New user** nav item). Enter the user's
name in the **Display name** field and submit with **Create user**. The app
shows the user's login key (`usr_` + 43 characters) **once**, with a copy
button. Hand it to the user over a channel you trust; it is never shown
again, and no API endpoint can return it later.

Via the API:

```sh
curl -sS -X POST http://localhost:3030/api/admin/users \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"alice"}'
```

The `201` response carries `id`, `name`, `key_generation`, and `login_key`.
This create response is one of the two admin-API responses that carry a
login key (create and rotate) — the only places the admin API ever reveals
one. Guard it accordingly.

### Rotate a user's key

Open the user (`/admin/users/<id>`) and use **Rotate login key**. Rotation
issues a new login key and bumps the user's `key_generation`. The old key
stops authenticating immediately — every client still using it must be
reconfigured. The user's AEK and stored accounts are unaffected. The new key
is shown once, exactly like a freshly created user's.

Via the API:

```sh
curl -sS -X POST http://localhost:3030/api/admin/users/<id>/rotate-key \
  -H "Authorization: Bearer $ADMIN_KEY"
```

There is no key recovery — a lost key is a lost key; rotate.

### Disable a user

Disabling blocks login and MCP access without deleting anything. On the
user's page, click **Disable user** (the button reads **Enable user** when
the user is already disabled). The change applies immediately, with no
confirmation. Via the API:

```sh
curl -sS -X POST http://localhost:3030/api/admin/users/<id>/status \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"status":"disabled"}'
```

Re-enable with `{"status":"active"}`.

### Delete a user

Deletion is permanent: the user's record and encrypted accounts are removed.
On the user's page, use **Delete user** and type the user's exact name into
the confirmation box. The confirmation is a guard against accidents, not a
server-side check — the API deletes on the request it receives.

Via the API:

```sh
curl -sS -X DELETE http://localhost:3030/api/admin/users/<id> \
  -H "Authorization: Bearer $ADMIN_KEY"
```

The response is `204`. There is no confirmation on the API route — the
request deletes.

### Look up a user

`GET /api/admin/users` lists users; `GET /api/admin/users/<id>` returns one.
Neither ever includes a login key, a hash, or AEK material. The app's table
shows the same fields — Name, Status, Key generation, Accounts, Created.

### Sign out

The **Sign out** button in the top bar of the admin surface ends the admin
session and returns you to the login view; it is present on every
signed-in page. The session cookie is deleted.

## For users

### Log in

Open `http://<host>:3030/user` and enter your login key (`usr_` + 43
characters — the one your administrator handed you, or your latest rotated
key) on the login view. Keep the key — you need it for every sign-in. If
you lose it, you cannot sign in until your administrator rotates your key
(which also invalidates the old one).

Your login key signs you into the web app and authenticates `/mcp`; it
does not work as an API credential against `/api/me`.

### Session expiry

A session lasts 12 hours, and a gateway restart signs everyone out. If
your session expires or becomes invalid mid-task, you are returned to
your surface's login view with `?reason=expired` and the banner "Your
session has expired. Please sign in again." Sign in again; your accounts
are unaffected.

### Activate account encryption

Before adding any account, open `/user/settings` and use **Activate
account encryption**. The app mints your account encryption key (AEK) and
shows its 64 hex characters **once**.

Store the AEK somewhere safe. It is yours alone — the administrator never
sees it, and the server keeps it only in wrapped form. Activation cannot be
repeated: a second attempt is refused (`409 aek_already_active`). Without an
active AEK, MCP tool calls fail with a structured error telling your client
to activate encryption first.

You can also skip this step: adding your first account activates the AEK for
you, and the app shows the key right after the account is created.

### Add an account

Open `/user/accounts/new` and enter the account's **Account name**, IMAP
host and port, user name, and password; the sending and SMTP settings are
optional. The password is stored encrypted under your AEK and is never shown
back to you, the admin, or any API response.

The first account you add also activates account encryption and displays the
AEK once (see above).

### Edit an account

Open the account at `/user/accounts/<id>`. Passwords are write-only: the
edit form never prefills them, and leaving the password field blank keeps
the stored value. Type a new password only to change it. The same holds for
the SMTP user name and password.

Two switches clear a stored credential outright: **Clear the stored IMAP
credential** and **Clear the stored SMTP credential** (the SMTP one is
disabled unless an SMTP host is present). Selecting one sends an empty
value, which removes the stored credential.

The other optional fields — e-mail address, the sent-messages switch,
sent-mail folder, default BCC, allowed senders — round-trip as you left
them. Clearing a text field is deliberate: an emptied field is stored as
empty.

### Delete an account

Open `/user` and use the delete action on the account. Type the account's
exact name into the confirmation box to confirm. The deletion takes effect
immediately and cannot be undone.

### Rotate your login key

On `/user/settings`, use **Regenerate login key** at any time — for example
after sharing a laptop or if you suspect exposure. The new key is shown
once. Your AEK and all accounts are unaffected, but every MCP client using
your old key must be updated with the new one.

### Sign out

Use **Sign out** in the top bar of the user surface — present on every
signed-in page. (The Settings view also has its own copy in its Actions
card.) The app deletes the session cookie and returns you to the login view.

## Connect an MCP client

Once your AEK is active and an account exists, point any MCP client at the
gateway — see [mcp-clients.md](mcp-clients.md).
