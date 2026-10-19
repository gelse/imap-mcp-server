# Deployment

The stack is one Docker Compose service that builds from this repository and
keeps all state in three host directories under `./data`.

## Start the stack

```sh
mkdir -p data/config data/users data/mail
docker compose up --build -d
```

The host directories must be writable by uid 1000 — the container runs the
unprivileged user `app` (uid 1000). Create them as uid 1000 or
`chown 1000:1000` them if your umask made them yours. Then capture the admin
key (next section) before doing anything else.

## Service reference

`docker-compose.yml` defines exactly one service:

| Setting | Value |
| --- | --- |
| Service name | `imap-gateway` (always address it as `docker compose <cmd> imap-gateway`) |
| Build | `.` — the repository's `Dockerfile` |
| Ports | `"${GATEWAY_PORT:-3030}:${GATEWAY_PORT:-3030}"` — host/container port, default 3030 (overridable via `GATEWAY_PORT`) |
| Environment | `DATA_DIR=/data`, `HTTP_PORT=${GATEWAY_PORT:-3030}` (default 3030), `LOG_LEVEL=INFO` |
| Restart | `unless-stopped` |
| Volumes | three bind mounts (below); no named volumes |
| Healthcheck | inherited from the image: `GET /healthz`, interval 5s, timeout 3s, start period 10s, 3 retries |

Recognized environment variables inside the container: `DATA_DIR`,
`HTTP_PORT`, `LOG_LEVEL`, `NODE_BIN` (path to the node binary),
`IMAP_MCP_SERVER_JS` (path to the vendored upstream entrypoint),
`MCP_IDLE_TIMEOUT_SECONDS` (MCP session idle timeout, default `900`), and
`SPA_DIST_DIR` (path to the built web app, default `frontend/dist`; inside
the container that resolves to `/app/frontend/dist`, which is where the
image puts it — you normally do not set it).

The delivered compose file sets only the first three; overriding
`HTTP_PORT` (via `GATEWAY_PORT` in compose, or directly when running the
image) needs no healthcheck change, because the image probe reads
`HTTP_PORT` at runtime (the image's own default is `3000`).

## The web app

The admin surface (`/admin`) and the user surface (`/user`) are two entry
points into one Vue 3 single-page application; `GET /` is not one of them —
it answers `404 {"error":"not_found","path":"/"}`, so an operator opening
the bare host URL must go to `/admin` or `/user` directly. The image ships
it as built files under `/app/frontend/dist`: `index.html` plus
content-hashed assets under `assets/`.
The server answers every `/admin` and `/user` path with the
app shell (`Cache-Control: no-store`) and serves the hashed assets with
`Cache-Control: public, max-age=31536000, immutable`. No CDN and no external
request is involved at runtime — fonts are system fonts, icons are inline
SVG.

`SPA_DIST_DIR` overrides the directory the server reads the shell from. The
default (`frontend/dist`, relative to the working directory `/app`) is where
the image puts the build; you only need to set it when you run the gateway
outside the image.

If the shell is missing, `GET /admin` fails loudly with
`{"error":"internal_error"}` — a deployment fault, not a user error.

## Data directory

All state lives in three host directories bind-mounted into the container.
The layout under `DATA_DIR` (`/data`) is created `0700` at boot.

| Host path | Container path | Contents |
| --- | --- | --- |
| `./data/config/admin-key.hash` | `/data/config/admin-key.hash` | scrypt hash of the admin key, mode 0600; never contains plaintext |
| `./data/config/wrap.key` | `/data/config/wrap.key` | 64 lowercase hex characters of AES-256 key material, mode 0600; wraps every user's account encryption key; never logged |
| `./data/users/<userId>/user.json` | `/data/users/<userId>/user.json` | `login_key_hash` (scrypt), `key_generation`, `aek` (wrapped AEK `{"blob": "base64(iv):base64(tag):base64(ciphertext)", "version": n}`, or null) |
| `./data/users/<userId>/imap-store/accounts.json` | `/data/users/<userId>/imap-store/accounts.json` | encrypted account store (`iv:ciphertext`, lowercase hex) |
| `./data/users/<userId>/imap-store/.key` | `/data/users/<userId>/imap-store/.key` | session-only AEK plaintext; removed at session teardown and swept at startup |
| `./data/users/<userId>/.imap-mcp` | `/data/users/<userId>/.imap-mcp` | symlink to the container path `/data/users/<userId>/imap-store`; resolves only inside the container |
| `./data/mail/<userId>/` | `/data/mail/<userId>/` | download and upload staging; survives user deletion |

What each file means and how to recover it:
[keys-and-security.md](keys-and-security.md).

## Capture the admin key on first boot

The first boot — when `./data/config/admin-key.hash` does not exist — prints
the admin key to the log exactly once:

```sh
docker compose logs imap-gateway
```

Look for this line (during first boot you can follow it with
`docker compose logs -f imap-gateway`):

```
[auth] admin key created — store it now; it will not be shown again: adm_...
```

The key is appended after the colon on that same line. Its shape is `adm_`
followed by 43 characters from `[A-Za-z0-9_-]` — grep it with:

```sh
docker compose logs imap-gateway | grep -oE 'adm_[A-Za-z0-9_-]{43}'
```

The plaintext exists nowhere else: it is not written to any file, and the
only on-disk artifact is the hash in `./data/config/admin-key.hash`.

The same boot then logs `[auth] hash file: /data/config/admin-key.hash` and
`[config] wrap key created`. Later boots log `[auth] existing key found` and
`[config] wrap key found` and never re-display the key.

If you miss it, reset the admin key (below).

## Restart the stack

```sh
docker compose restart imap-gateway
```

A restart preserves the admin key — the new boot logs `[auth] existing key
found` and the same key keeps authenticating.

Admin web sessions do not survive a restart (the session secret is per-boot);
the same holds for user sessions.

After a reload the web app re-fetches its CSRF token from the session
endpoints (`GET /api/admin/session`, `GET /api/me/session`) — the session
cookie outlives the page, the in-memory token does not.

To watch a clean shutdown and boot, note the `[boot] shutdown complete` and
`[boot] starting imap-mcp-gateway data_dir=/data version=0.1.0` lines in
`docker compose logs imap-gateway`.

## Reset the admin key

Deleting the hash file is a supported reset:

```sh
rm ./data/config/admin-key.hash
docker compose restart imap-gateway
```

The next boot behaves as first boot: it mints a fresh admin key and prints
the `[auth] admin key created — …` line again. Users and `wrap.key` are
untouched.

If `admin-key.hash` exists but is corrupted, the gateway refuses to start
with a fatal error whose message ends `delete the file to reset` — apply the
same reset.

## Reset everything

`docker compose down` — even with `-v` — deletes nothing: the stack has no
named volumes, so all state sits in the host `./data` tree. A full reset
requires deleting it:

```sh
docker compose down
rm -rf ./data
mkdir -p data/config data/users data/mail
docker compose up --build -d
```

This is a complete first boot: a new admin key is printed, a new wrap key is
generated, and every user and account is gone.

## Back up and restore

Back up the entire `./data` tree — `config/`, `users/`, and `mail/` together.
`./data/config/wrap.key` is the critical file: losing it while wrapped AEKs
exist on disk makes every stored account credential unrecoverable, with no
exception. If it is deleted while wrapped AEKs exist, the next boot aborts
and the container crash-loops until the file is restored — recovery is
described in [keys-and-security.md](keys-and-security.md#wrapkey).

```sh
docker compose down
tar czf imap-gateway-data.tgz ./data
docker compose up -d
```

To restore, stop the stack, restore the `./data` contents from the archive,
and start the stack again:

```sh
docker compose down
tar xzf imap-gateway-data.tgz
docker compose up -d
```

A restored stack boots against the restored files: the admin key, wrap key,
and user records all keep working.

## Upgrade

The image's supply chain is pinned as follows:

- Upstream MCP package: `imap-mcp-server@2.2.0`, installed by
  `RUN npm install --prefix /opt/vendor/npm imap-mcp-server@2.2.0`; the
  committed `vendor/npm/package-lock.json` resolves exactly `2.2.0`.
- Frontend toolchain: `frontend/package.json` and
  `frontend/package-lock.json` are committed and authoritative. The
  `web-build` stage runs `npm ci --no-audit --no-fund` from that lockfile,
  then `npm run build`, which type-checks, bundles, and finally runs
  `frontend/scripts/audit-dist.mjs`. The audit fails the image build if the
  bundle contains secret-shaped material, an external URL, or an inline
  script. `npm ci` never runs at container start, and it never runs
  outside the image build.
- Base images pinned by digest in the `Dockerfile` `FROM` lines (each digest
  is the tag's multi-arch manifest list):
  - `python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258`
  - `node:22.12-bookworm-slim@sha256:35531c52ce27b6575d69755c73e65d4468dba93a25644eed56dc12879cae9213`

  A digest pin fixes the base content — the tags float when upstream
  rebuilds, the digests do not — and because it pins the image list rather
  than a single platform manifest, the builder selects the host platform's
  variant from it automatically. The `uv` tool is copied from
  `ghcr.io/astral-sh/uv:latest`, a deliberately floating tag.

### What the runtime image contains

The runtime stage copies three things out of the build stages — the Python
environment and app source, the vendored upstream package under
`/opt/vendor/npm`, and the built web app under `/app/frontend/dist` — plus the
`node` binary from the pinned `node` stage. It does **not** contain
`node_modules` (neither the frontend's nor a build toolchain), the frontend
sources, the npm cache, or any development dependency. The `node` binary and
`/opt/vendor/npm` are there because the gateway spawns the upstream tool host
as a child process — not for the web app, which is pre-built static files.

To upgrade in place:

```sh
git pull
docker compose up --build -d
```

Bind-mounted state is untouched by an upgrade: the admin key, wrap key, user
keys, and accounts keep working. Pin changes (a new `imap-mcp-server`
version or base digests) arrive as `Dockerfile` and `vendor/npm/` updates in
the repository, not as in-place edits.
