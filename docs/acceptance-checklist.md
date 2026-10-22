# Acceptance checklist

One row per bullet of the original request, each mapped to its milestone,
task, and a passing test or a documented manual check. Part B is the dated
evidence entry for the final gate (M07-T07); Parts C–E sign off the docs
walkthrough, map the original wording, and record known limitations.

The milestone that closed this checklist is M07 (Vue 3 single-page
application). It replaced both server-rendered web UIs with one SPA, so
every row below is re-pointed at the API or shell surface that replaced the
deleted HTML pages.

## Part A — Checklist

| # | Requirement (original request) | Milestone / task | Evidence (passing test names or documented manual check) |
| --- | --- | --- | --- |
| 1 | Deployable via docker-compose | M01-T03 | e2e scenario 1: `tests/e2e/scenarios/test_admin_key_lifecycle.py::test_deploy_stack_is_healthy_and_lays_out_data` |
| 2 | Persistent config + mails on host via bind mounts | M01-T02 / M01-T03 | e2e scenario 1: `tests/e2e/scenarios/test_admin_key_lifecycle.py::test_deploy_stack_is_healthy_and_lays_out_data` (host-side `config/`, `users/`, `mail/` layout asserted); e2e scenario 5: `tests/e2e/scenarios/test_at_rest.py::test_no_plaintext_stub_password_at_rest`, `tests/e2e/scenarios/test_at_rest.py::test_secret_files_and_directories_are_locked_down` (host-side inspection of the same tree) |
| 3 | Configuration webserver exposed (NOT for emails) | M02-T03 / M03-T03 / M04-T05 / M07-T05 | web-surface behaviour: `tests/test_spa_shell.py` (the SPA shell is served at every admin/user path, the hashed assets are served immutably, the shell carries no secret material, a missing dist fails loud) and `tests/test_admin_auth.py`, `tests/test_user_auth.py` (the JSON surfaces behind the shell keep their auth contracts); SPA probes in e2e scenario 1: `tests/e2e/scenarios/test_admin_key_lifecycle.py::test_deploy_stack_is_healthy_and_lays_out_data`; grep gate (manual check, Part B § Route-surface greps): no mail-reading routes exist — the web surface is `/healthz`, `/api/admin/*`, `/api/me/*`, the SPA shell routes `/admin`, `/admin/{path:path}`, `/user`, `/user/{path:path}`, the `/assets` mount, and the MCP endpoint at `/mcp` only. **Superseded evidence:** the two HTML flow suites this row used to cite (`tests/test_admin_user_ui.py::test_full_acceptance_flow_through_the_ui`, `tests/test_user_ui.py::test_full_acceptance_flow_through_the_user_ui`) were deleted in M07-T05 with the pages they exercised; their replacements are the API suites and `tests/test_spa_shell.py` |
| 4 | Root admin key: generated first startup, hash on disk, shown in docker log | M02-T01 / M02-T02 | e2e scenario 2: `tests/e2e/scenarios/test_admin_key_lifecycle.py::test_boot_follows_the_one_time_display_contract`; unit: `tests/test_admin_key_lifecycle.py::test_first_boot_creates_key_and_persists_hash_only`, `tests/test_admin_key_lifecycle.py::test_first_boot_logs_created_once_with_hash_file_path` |
| 5 | "existing key found" when hash present; hash deletable to reset | M02-T02 | e2e scenario 2: `tests/e2e/scenarios/test_admin_key_lifecycle.py::test_restart_preserves_the_admin_key`, `tests/e2e/scenarios/test_admin_key_lifecycle.py::test_hash_reset_mints_new_key_and_preserves_users`; unit: `tests/test_admin_key_lifecycle.py::test_restart_logs_literal_existing_key_found_and_zero_material`, `tests/test_admin_key_lifecycle.py::test_delete_hash_restart_repeats_first_boot_with_different_key` |
| 6 | Users added via configuration; email accounts not admin-managed | M03-T02 / M07-T05 | e2e scenario 3: `tests/e2e/scenarios/test_user_lifecycle.py::test_created_user_receives_one_time_key_and_logs_in`; admin-surface API contract: `tests/test_admin_user_api.py` (the admin API exposes only user CRUD plus login/logout/session/health, and its user views carry no key material); API surface review (manual check, Part B § Route-surface greps): the admin surface exposes only user CRUD + login/logout/session/health; no email-account routes exist under `/api/admin` or `/admin` — the account routes live only under `/api/me`. **Superseded evidence:** the admin HTML user-management pages this row used to lean on no longer exist; the SPA renders the same fields from the same JSON API |
| 7 | User creation returns a key; not visible afterwards; regenerable | M03-T01 / M03-T02 | e2e scenario 3: `tests/e2e/scenarios/test_user_lifecycle.py::test_created_user_receives_one_time_key_and_logs_in`, `tests/e2e/scenarios/test_user_lifecycle.py::test_admin_rotation_invalidates_old_key`; unit invariants: `tests/test_user_store.py::test_create_user_returns_key_once_and_persists_hash_only`, `tests/test_admin_user_api.py::test_one_time_key_invariant_across_request_sequence`; SPA side: `frontend/tests/admin-views.spec.ts` (the create and rotate views render the one-time key display and never re-request it) |
| 8 | Users log in with their own key | M03-T04 / M04-T05 / M07-T01 | e2e scenario 4: `tests/e2e/scenarios/test_self_service.py::test_account_lifecycle_against_stub`, `tests/e2e/scenarios/test_self_service.py::test_first_account_add_activates_aek_and_discloses_it_once` (each logs in through the user's own one-time key before acting); unit: `tests/test_user_account_api.py` (the JSON login `POST /api/me/login` and its same-origin guard), `tests/test_security_regressions.py` (its rate limiter), `tests/test_user_session_api.py` (the session bootstrap `GET /api/me/session`) |
| 9 | Users regenerate their own key | M04-T04 | e2e scenario 4: `tests/e2e/scenarios/test_self_service.py::test_self_key_rotation_invalidates_old_key`; unit: `tests/test_user_store.py::test_rotate_login_key_invalidates_old_and_increments_generation` |
| 10 | Users add own email accounts, stored encrypted persistent | M04-T02 / M04-T03 | e2e scenario 4: `tests/e2e/scenarios/test_self_service.py::test_account_lifecycle_against_stub`, `tests/e2e/scenarios/test_self_service.py::test_first_account_add_activates_aek_and_discloses_it_once`; e2e scenario 5: `tests/e2e/scenarios/test_at_rest.py::test_no_plaintext_stub_password_at_rest`, `tests/e2e/scenarios/test_at_rest.py::test_no_plaintext_aek_hex_at_rest` |
| 11 | MCP exposed at `<url>/mcp` | M05-T01 | e2e scenario 6: `tests/e2e/scenarios/test_mcp_gateway.py::test_initialize_and_tools_list_expose_pinned_surface`, `tests/e2e/scenarios/test_mcp_gateway.py::test_invalid_credentials_yield_401`; unit: `tests/test_mcp_wiring.py::test_create_app_mounts_mcp_as_exact_path_route` |
| 12 | Key as header value | M05-T01 | e2e scenario 6: `tests/e2e/scenarios/test_mcp_gateway.py::test_invalid_credentials_yield_401` (key presented via request headers); unit: `tests/test_mcp_auth.py::test_bearer_key_performs_initialize_handshake`, `tests/test_mcp_auth.py::test_x_api_key_form_works_identically` |
| 13 | Exactly the same tools as upstream | M05-T03 | parity test: `tests/test_tool_parity.py::test_tools_list_matches_expected_exactly`, `tests/test_tool_parity.py::test_expected_tools_pin_is_self_consistent`; e2e: `tests/e2e/scenarios/test_mcp_gateway.py::test_initialize_and_tools_list_expose_pinned_surface` |
| 14 | Own accounts only; encryption key separate from login key | M04-T02 / M05-T04 | isolation suite: `tests/test_mcp_isolation.py::test_scenario_1_each_user_lists_only_their_own_accounts`, `tests/test_mcp_isolation.py::test_scenario_1_user_a_cannot_address_user_b_account_id`, `tests/test_mcp_isolation.py::test_scenario_5_add_account_writes_only_into_the_calling_users_store`; encryption invariant suite: `tests/test_encryption_invariants.py::test_login_key_regeneration_leaves_aek_and_accounts_untouched`, `tests/test_encryption_invariants.py::test_aek_blob_is_useless_under_a_different_wrap_key`; e2e: `tests/e2e/scenarios/test_mcp_gateway.py::test_two_users_each_see_only_their_own_accounts` |

Scenario numbering follows the e2e scenario suite (M06-T01):
1 Deploy, 2 Admin key, 3 Users, 4 Self-service, 5 At rest, 6 MCP,
7 Reset semantics. (The planning material behind this suite is local,
gitignored working material and is not part of the repository.)

### Web-surface changes in M07 (what rows 3 and 6 had to follow)

- The admin and user UIs are ONE Vue 3 single-page application, served by
  the gateway from the built `frontend/dist`. The server-rendered pages are
  gone — deleted, not deprecated.
- The SPA talks to the unchanged JSON API under `/api/*` with `fetch` only.
  M07 added `GET /api/admin/session`, `GET /api/me/session`,
  `POST /api/me/login`, `POST /api/me/logout`, the `aek_active` profile
  field, and four non-secret optional account fields; it changed no other
  API contract.
- The CSRF token reaches the browser through those session endpoints and
  lives in SPA memory only — never in browser storage, never in a readable
  cookie.
- Every response now carries a strict Content-Security-Policy without
  `'unsafe-inline'`.
- The image build gained a `web-build` stage: `npm ci` and the bundle build
  run at image build time, the build ends in a secret/external-URL audit,
  and the runtime image carries only the built `frontend/dist`.

## Part B — Evidence — 2026-10-22 (M07-T07 final gate)

One-time key values (the admin `adm_…` key, user `usr_…` keys, and AEK hex)
are elided as `adm_<elided>` and similar in this record; each was captured
in full at run time. Everything else is verbatim.

### Gate commands

`uv run ruff check` (2026-10-22):

```text
All checks passed!
```

`uv run mypy` (2026-10-22):

```text
Success: no issues found in 84 source files
```

`uv run pytest` (2026-10-22):

```text
======================= 584 passed, 24 skipped in 55.10s =======================
```

Frontend unit suite — `npm run test -- --run` inside `frontend/`
(Vitest; the component and store specs that cover the SPA itself). On a
fresh clone, run `npm ci` inside `frontend/` first — `frontend/node_modules/`
is gitignored and is installed from the committed `frontend/package-lock.json`.
Re-run on 2026-10-22 (`npm ci` plus the test command above):

```text
 Test Files  14 passed (14)
       Tests  183 passed (183)
```

Focused leak-sweep run —
`uv run pytest tests/test_security_regressions.py -k "authenticated or detector" -v`
(2026-10-22):

```text
============================= test session starts ==============================
platform linux -- Python 3.12.15, pytest-9.1.1, pluggy-1.6.0 -- /home/werner/dev/imap-mcp-server/.venv/bin/python
cachedir: .pytest_cache
rootdir: /home/werner/dev/imap-mcp-server
configfile: pytest.ini
plugins: asyncio-1.4.0, anyio-4.15.1
asyncio: mode=Mode.AUTO, debug=False, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collecting ... collected 20 items / 16 deselected / 4 selected

tests/test_security_regressions.py::test_no_unauthenticated_route_body_emits_secret_material PASSED [ 25%]
tests/test_security_regressions.py::test_no_authenticated_admin_route_body_emits_secret_material PASSED [ 50%]
tests/test_security_regressions.py::test_no_authenticated_user_route_body_emits_secret_material PASSED [ 75%]
tests/test_security_regressions.py::test_leak_sweep_detectors_catch_every_real_secret_artifact PASSED [100%]

======================= 4 passed, 16 deselected in 1.09s =======================
```

Both e2e runs below require Docker: the suite boots the real compose stack
(`tests/e2e/conftest.py` drives `docker compose` with `docker-compose.yml`
plus `tests/e2e/docker-compose.e2e.yml`). Run from the repository root —
the invocation contract (`uv run --extra e2e pytest tests/e2e`, equivalently
`uv run pytest -m e2e`) is documented in
[docs/README.md, § E2E release gate](README.md#e2e-release-gate-m06-t01).

`uv run pytest -m e2e` run 1 (2026-10-22):

```text
================ 24 passed, 584 deselected in 83.15s (0:01:23) =================
```

`uv run pytest -m e2e` run 2 (consecutive, same data tree; 2026-10-22):

```text
================ 24 passed, 584 deselected in 69.65s (0:01:09) =================
```

The e2e suite uses `tests/e2e/data/` (hermetic). Both runs were warm boots
asserting the persistence contract (`existing key found` ≥ 1, zero new
`admin key created` lines).

The deploy scenario additionally probes the web app
(`tests/e2e/scenarios/test_admin_key_lifecycle.py::test_deploy_stack_is_healthy_and_lays_out_data`):
`GET /admin` must answer 200 `text/html` with the strict CSP and
`Cache-Control: no-store`, `GET /user` must answer 200 with the same shell,
the shell's referenced `/assets/*.js` must answer 200 with the immutable
cache policy, and the shell body must carry no key material.

### Route-surface greps (manual checks for rows 3 and 6)

All four greps in this section were re-run on 2026-10-22: every result
reproduced byte-identical, and the mail-verb sweep still finds no matches
(exit 1).

Grep gate — full route inventory of the web surface
(`grep -rn '@router\.\(get\|post\|put\|patch\|delete\)\|add_api_route\|\.mount(\|include_router' src/imap_mcp_gateway/web --include='*.py'`):

```text
src/imap_mcp_gateway/web/routers/health.py:10:@router.get("/healthz")
src/imap_mcp_gateway/web/server.py:131:    application.include_router(health_router)
src/imap_mcp_gateway/web/server.py:132:    application.include_router(admin_api_router)  # /api/admin/* (M02-T03)
src/imap_mcp_gateway/web/server.py:135:    application.include_router(user_api_router)  # /api/me/* (M04-T04)
src/imap_mcp_gateway/web/admin/router.py:17:    router.include_router(users_router, prefix="/users")
src/imap_mcp_gateway/web/admin/router.py:19:(see the real ``include_router`` call below; its routes live in
src/imap_mcp_gateway/web/admin/router.py:50:router.include_router(users_router, prefix="/users")
src/imap_mcp_gateway/web/admin/router.py:68:@router.post("/login")
src/imap_mcp_gateway/web/admin/router.py:108:@router.post("/logout")
src/imap_mcp_gateway/web/admin/router.py:121:@router.get("/session")
src/imap_mcp_gateway/web/admin/router.py:146:@router.get("/health")
src/imap_mcp_gateway/web/admin/user_router.py:92:@router.post("", status_code=201)
src/imap_mcp_gateway/web/admin/user_router.py:113:@router.get("")
src/imap_mcp_gateway/web/admin/user_router.py:126:@router.get("/{user_id}")
src/imap_mcp_gateway/web/admin/user_router.py:152:@router.post("/{user_id}/rotate-key")
src/imap_mcp_gateway/web/admin/user_router.py:177:@router.post("/{user_id}/status")
src/imap_mcp_gateway/web/admin/user_router.py:204:@router.delete("/{user_id}", status_code=204)
src/imap_mcp_gateway/web/user/router.py:331:@router.get("")
src/imap_mcp_gateway/web/user/router.py:352:@router.get("/session")
src/imap_mcp_gateway/web/user/router.py:375:@router.post("/login")
src/imap_mcp_gateway/web/user/router.py:456:@router.post("/logout")
src/imap_mcp_gateway/web/user/router.py:472:@router.post("/accounts", status_code=201)
src/imap_mcp_gateway/web/user/router.py:562:@router.patch("/accounts/{account_id}")
src/imap_mcp_gateway/web/user/router.py:610:@router.delete("/accounts/{account_id}", status_code=204)
src/imap_mcp_gateway/web/user/router.py:625:@router.post("/accounts/activate")
src/imap_mcp_gateway/web/user/router.py:647:@router.post("/rotate-key")
```

The SPA routes and the asset mount are registered directly on the
application (`src/imap_mcp_gateway/web/server.py:140-141`:
`application.router.routes.extend(build_spa_routes())` and
`application.router.routes.append(build_assets_mount(settings))`), so they
do not appear in the decorator grep. The runtime inventory of the built
application is the authoritative list, generated from `create_app(Settings())`
with (regenerated 2026-10-22 on FastAPI 0.143.1, which defers
`include_router` — the snippet resolves the lazily included routers before
walking them, and pins the ordering with an explicit methods tie-break):

```python
from fastapi.routing import _IncludedRouter

from imap_mcp_gateway.config.env import Settings
from imap_mcp_gateway.web.server import create_app

app = create_app(Settings())

def effective_routes(routes):
    """Yield the application's routes with lazy includes resolved."""
    for route in routes:
        if isinstance(route, _IncludedRouter):
            # FastAPI 0.143 defers include_router; yield the resolved contexts
            yield from route.effective_route_contexts()
        else:
            yield route

for route in sorted(
    effective_routes(app.routes),
    key=lambda r: (r.path, ",".join(sorted(getattr(r, "methods", None) or ()))),
):
    methods = ",".join(sorted(getattr(route, "methods", None) or ()))
    if methods:  # skips the /assets Mount and the methods-less /mcp Route
        print(f"{methods:<25}{route.path}")
```

```text
GET,HEAD                 /admin
GET,HEAD                 /admin/{path:path}
GET                      /api/admin/health
POST                     /api/admin/login
POST                     /api/admin/logout
GET                      /api/admin/session
GET                      /api/admin/users
POST                     /api/admin/users
DELETE                   /api/admin/users/{user_id}
GET                      /api/admin/users/{user_id}
POST                     /api/admin/users/{user_id}/rotate-key
POST                     /api/admin/users/{user_id}/status
GET                      /api/me
POST                     /api/me/accounts
POST                     /api/me/accounts/activate
DELETE                   /api/me/accounts/{account_id}
PATCH                    /api/me/accounts/{account_id}
POST                     /api/me/login
POST                     /api/me/logout
POST                     /api/me/rotate-key
GET                      /api/me/session
GET                      /healthz
GET,HEAD                 /user
GET,HEAD                 /user/{path:path}
```

plus the `/assets` mount and the exact-path `/mcp` route
(`src/imap_mcp_gateway/web/server.py:144`). The shell routes accept GET
only; a POST to a shell path answers FastAPI's default 405 JSON.

`src/imap_mcp_gateway/web/server.py:144` attaches the MCP endpoint as an
exact-path route: `application.router.routes.append(Route("/mcp", create_mcp_gateway(factory)))`.

Mail-reading-verb sweep over the same tree
(`grep -rniE 'mailbox|message[s]?/|inbox|fetch_mail|read_mail|send_mail|imap_search|uid_fetch' src/imap_mcp_gateway/web --include='*.py'`)
→ no matches (exit 1). Mail access exists only inside the MCP tool-host
child process, not in any webserver route.

API surface review — admin route decorators only
(`grep -n '@router\.' src/imap_mcp_gateway/web/admin/router.py src/imap_mcp_gateway/web/admin/user_router.py`):

```text
src/imap_mcp_gateway/web/admin/router.py:68:@router.post("/login")
src/imap_mcp_gateway/web/admin/router.py:108:@router.post("/logout")
src/imap_mcp_gateway/web/admin/router.py:121:@router.get("/session")
src/imap_mcp_gateway/web/admin/router.py:146:@router.get("/health")
src/imap_mcp_gateway/web/admin/user_router.py:92:@router.post("", status_code=201)
src/imap_mcp_gateway/web/admin/user_router.py:113:@router.get("")
src/imap_mcp_gateway/web/admin/user_router.py:126:@router.get("/{user_id}")
src/imap_mcp_gateway/web/admin/user_router.py:152:@router.post("/{user_id}/rotate-key")
src/imap_mcp_gateway/web/admin/user_router.py:177:@router.post("/{user_id}/status")
src/imap_mcp_gateway/web/admin/user_router.py:204:@router.delete("/{user_id}", status_code=204)
```

`grep -rn 'account' src/imap_mcp_gateway/web/admin --include='*.py' | grep -iv 'account_count'`
returns only two hits, both about the admin's account_count reconciliation
(`src/imap_mcp_gateway/web/admin/user_router.py:36,118`). Email-account
routes (`.../accounts...`) exist only on the user surface
(`src/imap_mcp_gateway/web/user/router.py`).

### Docs walkthrough — quickstart (SPA probes)

Re-executed 2026-10-22 against a freshly built image. The compose run could
not use the default project name or the published port: this project's own
stack (compose project `imap-mcp-server`, data under `./data`) was already
running on host port 3030 and was left untouched. The walkthrough therefore
ran under a dedicated compose project name (`imapgw-walkthrough`) with a
one-file override that maps the gateway loopback-only on host port 13001 and
remaps the data bind mounts to the scratch tree `.scratch/walkthrough-data/`
— the same `!override` pattern the tracked e2e override uses
(`tests/e2e/docker-compose.e2e.yml`: `ports: !override` →
`"127.0.0.1:${E2E_GATEWAY_PORT:-13000}:${GATEWAY_PORT:-3030}"`). The command
was `docker compose -p imapgw-walkthrough -f docker-compose.yml -f
.scratch/walkthrough/docker-compose.walkthrough.yml up --build -d`; the
fresh scratch tree made this first boot the recorded cold boot (no
`admin-key.hash` deletion needed).

- First-boot log (verbatim, key elided):

```text
imap-gateway-1  | 2026-10-22T12:10:00 INFO [config] data layout resolved data_dir=/data
imap-gateway-1  | 2026-10-22T12:10:00 INFO [boot] starting imap-mcp-gateway data_dir=/data version=0.1.0
imap-gateway-1  | 2026-10-22T12:10:00 INFO [auth] admin key created — store it now; it will not be shown again: adm_<elided>
imap-gateway-1  | 2026-10-22T12:10:00 INFO [auth] hash file: /data/config/admin-key.hash
imap-gateway-1  | 2026-10-22T12:10:00 INFO [config] wrap key created
```

- Key-capture grep —
  `docker compose ... logs imap-gateway | grep -oE 'adm_[A-Za-z0-9_-]{43}' | wc -l`
  → `1` (exactly one match; key elided in this record).
- URL probes on `http://127.0.0.1:13001`:
  - `GET /healthz` → 200 `{"status":"ok"}`, headers
    `x-content-type-options: nosniff`, `x-frame-options: DENY`,
    `referrer-policy: no-referrer`, and the CSP
    `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`;
  - `GET /admin` → 200 `text/html; charset=utf-8` (933 B),
    `cache-control: no-store`, same four security headers;
  - `GET /user` → 200 `text/html; charset=utf-8` (933 B, the same shell);
  - deep links `GET /admin/users` and `GET /user/settings` → 200
    `text/html; charset=utf-8` (933 B — the shell; the SPA resolves the
    route in the browser);
  - the shell body references the hashed bundle
    `<script type="module" crossorigin src="/assets/index-djQKr6mf.js">`
    plus the stylesheet `/assets/index-CnTI0eNI.css`; a secret scan of the
    shell body
    (`scrypt$|adm_[A-Za-z0-9_-]{43}|usr_[A-Za-z0-9_-]{43}|[0-9a-f]{64}`)
    finds 0 hits;
  - `GET /assets/index-djQKr6mf.js` → 200
    `cache-control: public, max-age=31536000, immutable`; a missing asset
    (`GET /assets/index-definitely-missing.js`) → 404;
  - `GET /api/admin/users` unauthenticated → 401 `{"error":"unauthorized"}`;
    `GET /api/admin/session` → 401 `{"error":"unauthorized"}`;
    `POST /mcp` → 401 `{"error":"unauthorized"}`;
  - `GET /definitely-missing` → 404
    `{"error":"not_found","path":"/definitely-missing"}`;
  - `POST /admin/users` (a shell path, non-GET) → 405
    `{"detail":"Method Not Allowed"}` (with `allow: HEAD, GET`).
- SPA's API flows, exercised against the running stack with the same
  requests the app makes:
  - `POST /api/admin/login` (form field `key`) → 200 `{"status":"ok"}` plus
    the `imapgw_admin` cookie; `GET /api/admin/session` → 200
    `{"csrf_token":"…"}`;
  - `POST /api/admin/users {"name":"alice"}` → 201 with the one-time
    `login_key` (`usr_<elided>`) plus `id`, `name`, `key_generation`;
  - `POST /api/me/login {"key":"usr_…"}` → 200
    `{"status":"ok","csrf_token":"…"}` plus the `imapgw_user` cookie;
    `GET /api/me/session` → 200 with the same token (verified equal);
  - `GET /api/me` before the first account → `"aek_active": false`,
    `"account_count": 0`, `"accounts": []`;
  - `POST /api/me/accounts` (first add) → 201 with the account metadata and
    `account_encryption_key` (64 hex, elided) — the one-time AEK
    disclosure; `GET /api/me` afterwards → `"aek_active": true`,
    `"account_count": 1`;
  - `POST /api/me/logout` → 200 `{"status":"ok"}`; `GET /api/me/session`
    afterwards → 401 `{"error":"unauthorized"}`.
- Runtime image contents (checked with `docker run --rm --entrypoint ls`
  against the freshly built `imapgw-walkthrough-imap-gateway` image):
  `/app` holds `.venv`, `src` and `frontend`; `/app/frontend` holds `dist`
  only; `/app/frontend/dist` holds `index.html` and `assets/`
  (`index-djQKr6mf.js`, `index-CnTI0eNI.css`); there is no
  `/app/node_modules`, no `/app/frontend/node_modules` and no
  `/app/frontend/src`; `/usr/local/bin/node` and `/opt/vendor/npm` are
  present for the tool host.

### Serializer leak sweep (mutation verification)

Mutation diff — one-line change in
`src/imap_mcp_gateway/web/admin/serializers.py`, function
`to_admin_user_view`, applied and reverted on 2026-10-22:

```diff
diff --git a/src/imap_mcp_gateway/web/admin/serializers.py b/src/imap_mcp_gateway/web/admin/serializers.py
index d5be98e..db0df97 100644
--- a/src/imap_mcp_gateway/web/admin/serializers.py
+++ b/src/imap_mcp_gateway/web/admin/serializers.py
@@ -44,4 +44,5 @@ def to_admin_user_view(user: UserRecord | UserMetadata) -> dict[str, Any]:
         "key_generation": user.key_generation,
         "account_count": user.account_count,
         "created_at": user.created_at,
+        "aek": getattr(user, "aek", None),  # TEMPORARY MUTATION (M07-T07 verification)
     }
```

Failing run — `uv run pytest tests/test_security_regressions.py -q`
(mutation applied, 2026-10-22). Complete output:

```text
.........F..........                                                     [100%]
=================================== FAILURES ===================================
_________ test_no_authenticated_admin_route_body_emits_secret_material _________

app = <fastapi.applications.FastAPI object at 0x7230e3ade3c0>
admin_key = 'adm_<elided>'
tmp_path = PosixPath('/tmp/pytest-of-werner/pytest-525/test_no_authenticated_admin_ro0')

    async def test_no_authenticated_admin_route_body_emits_secret_material(
        app: FastAPI, admin_key: str, tmp_path: Path
    ) -> None:
        """A sweep of ADMIN-authenticated bodies never carries secret material.
    
        The M06-T04 counterpart of the unauthenticated sweep above: every
        admin surface reached with a REAL admin key — the JSON API by
        ``Authorization: Bearer``, the SPA shell through the session cookie
        that ``POST /api/admin/login`` mints from the same key — must be free
        of ``scrypt$`` records, key material, wrapped-AEK blobs and 64-hex
        secrets. Each response is additionally pinned to its SUCCESS status,
        so an accidental 401/404 can never pass the sweep as a secret-free
        error page. The swept user record has its AEK ACTIVATED, so the detail
        serializer is exercised with the wrapped blob actually present in the
        store shape it must refuse to emit.
        """
        paths = build_paths(tmp_path)
        record, _key = create_user(paths, "admin-sweep-user")
        ensure_wrap_key(paths)
        activate_aek(paths, record.id)  # the record's aek blob exists (mutation target)
    
        async with _client(app) as client:
            login = await client.post("/api/admin/login", data={"key": admin_key})
            shell = await client.get("/admin")
            deep_link = await client.get(f"/admin/users/{record.id}")
            bearer = {"Authorization": f"Bearer {admin_key}"}
            health = await client.get("/api/admin/health", headers=bearer)
            listing = await client.get("/api/admin/users", headers=bearer)
            detail = await client.get(f"/api/admin/users/{record.id}", headers=bearer)
    
        swept = [
            ("POST /api/admin/login", login, 200),
            ("GET /admin", shell, 200),
            ("GET /admin/users/{user_id}", deep_link, 200),
            ("GET /api/admin/health", health, 200),
            ("GET /api/admin/users", listing, 200),
            ("GET /api/admin/users/{user_id}", detail, 200),
        ]
        for label, response, expected in swept:
            assert response.status_code == expected, f"{label}: {response.text}"
>           _assert_no_secret_material(label, response.text)

tests/test_security_regressions.py:397: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 

label = 'GET /api/admin/users/{user_id}'
body = '{"id":"a8ba1d9869e34148946fcd0ffdd125dc","name":"admin-sweep-user","status":"active","key_generation":1,"account_coun...","aek":{"blob":"VeD/2wN/tDmgMm3E:r+eYqc77pvTDtpzfx6hJfQ==:RKCfVbmG9aqNCJKIrf43swFOV8Xmcid/RgXpcIrVnds=","version":1}}'

    def _assert_no_secret_material(label: str, body: str) -> None:
        """Assert one response body carries none of the banned secret shapes.
    
        The M06-T02 leak-scan detectors — ``scrypt$`` records (admin-key and
        login-key hashes), ``adm_``/``usr_`` key material, 64-hex secrets (the
        wrap key, the AEK, the session ``.key`` file) and wrapped-AEK blobs —
        applied to an AUTHENTICATED body (M06-T04). Every failing assert
        carries ``label`` as its message.
        """
        assert "scrypt$" not in body, label
        assert KEY_MATERIAL_RE.search(body) is None, label
        assert HEX64_RE.search(body) is None, label
>       assert WRAPPED_BLOB_RE.search(body) is None, label
E       AssertionError: GET /api/admin/users/{user_id}
E       assert <re.Match object; span=(180, 266), match='VeD/2wN/tDmgMm3E:r+eYqc77pvTDtpzfx6hJfQ==:RKCfVbm> is None
E        +  where <re.Match object; span=(180, 266), match='VeD/2wN/tDmgMm3E:r+eYqc77pvTDtpzfx6hJfQ==:RKCfVbm> = <built-in method search of re.Pattern object at 0x7230e3cc5000>('{"id":"a8ba1d9869e34148946fcd0ffdd125dc","name":"admin-sweep-user","status":"active","key_generation":1,"account_coun...","aek":{"blob":"VeD/2wN/tDmgMm3E:r+eYqc77pvTDtpzfx6hJfQ==:RKCfVbmG9aqNCJKIrf43swFOV8Xmcid/RgXpcIrVnds=","version":1}}')
E        +    where <built-in method search of re.Pattern object at 0x7230e3cc5000> = re.compile('[A-Za-z0-9+/]{16,}={0,2}:[A-Za-z0-9+/]{16,}={0,2}:[A-Za-z0-9+/]{16,}={0,2}').search

tests/test_security_regressions.py:142: AssertionError
=========================== short test summary info ============================
FAILED tests/test_security_regressions.py::test_no_authenticated_admin_route_body_emits_secret_material
1 failed, 19 passed in 1.99s
```

Revert: `git checkout -- src/imap_mcp_gateway/web/admin/serializers.py`.

Reverting-pass run — `uv run pytest tests/test_security_regressions.py -q`
(2026-10-22). Complete output:

```text
....................                                                     [100%]
20 passed in 1.96s
```

Clean-tree proof (2026-10-22): `git status --porcelain src/` → empty output
(no modified files under `src/`); `git diff src/` → empty.

### Link check

`python3 scripts/check-doc-links.py`, run from the repository root: scans
the tracked doc set — `README.md` plus the `docs/*.md` files git lists, so
a fresh clone carries exactly the files scanned — and resolves every
Markdown relative link against the file containing it. Fragments —
`path#fragment` links and fragment-only targets — are resolved against the
target file's headings using GitHub's heading slugs; a fragment-only
target checks against the containing file. Absolute URLs
(http/https/mailto) are skipped.
Additionally, every backticked repository path is checked: a token
qualifies when it has no spaces, is slash-separated or ends in a known
repository extension, and starts with a name tracked at the repository's
top level; it resolves against the containing file's directory first, then
the repository root. `plans/…` paths never qualify (`plans/` is local
working material and is gitignored — see `.gitignore`), and neither do
runtime-only paths such as `data/…`: their first segment is not tracked,
so they cannot be checked against a fresh clone.

Recorded 2026-10-22, re-run after all remaining checklist edits landed:

```text
README.md
  relative link targets checked: 16
  heading anchors checked: 4
  backticked repo paths checked: 1
docs/README.md
  relative link targets checked: 6
  heading anchors checked: 0
  backticked repo paths checked: 2
docs/acceptance-checklist.md
  relative link targets checked: 6
  heading anchors checked: 4
  backticked repo paths checked: 26
docs/deployment.md
  relative link targets checked: 2
  heading anchors checked: 1
  backticked repo paths checked: 7
docs/keys-and-security.md
  relative link targets checked: 5
  heading anchors checked: 4
  backticked repo paths checked: 0
docs/mcp-clients.md
  relative link targets checked: 1
  heading anchors checked: 1
  backticked repo paths checked: 0
docs/security.md
  relative link targets checked: 1
  heading anchors checked: 2
  backticked repo paths checked: 7
docs/user-guide.md
  relative link targets checked: 1
  heading anchors checked: 0
  backticked repo paths checked: 0
files scanned: 8
total relative link targets checked: 38
total heading anchors checked: 16
total backticked repo paths checked: 43
failures: 0
```

`docs/manual-admin-user-ui-test.md` is an untracked, gitignored operator
checklist that described the retired HTML pages. It is obsolete, it is not
rewritten, and no shipped document links to it any more.

### Retained M06 walkthrough evidence (2026-10-20, M06-T04)

The backup/restore round-trip, the `wrap.key`-deletion abort path, and the
exact-log-string table are M06-T04 evidence. Neither M06-T04 nor M07
changed the data layout, the key files, the boot log lines or the
restore procedure, so that evidence still stands. It is summarized here
rather than repeated in full.

- Back-up and restore: the documented procedure
  ([docs/deployment.md](deployment.md#back-up-and-restore)) archived the
  whole `./data` tree, the data was destroyed, the archive was restored, and
  the restored stack booted with `existing key found` / `wrap key found` and
  still authenticated the existing admin and user keys.
- `wrap.key` deletion with a wrapped AEK on disk aborts the boot with
  `WrapKeyUnavailableError` (exit code 3, crash-looping) and is recovered by
  restoring `data/config/wrap.key` from the archive.
- The log strings observed remain the documented ones:
  `[auth] admin key created — store it now; it will not be shown again: …`,
  `[auth] existing key found`, `[config] wrap key created`,
  `[config] wrap key found`.

## Part C — Docs walkthrough sign-off

The M07-T07 walkthrough was executed against the current tree on 2026-10-22
and passed: the quickstart from [README.md](../README.md) (compose up, admin
key capture, URL probes — Part B § Docs walkthrough — quickstart), the
SPA's API flows against the running stack (admin login, user creation, JSON
user login, session bootstrap, first account add with the one-time AEK
disclosure, logout), the runtime-image content check, the focused
leak-sweep run, the mutation verification (Part B § Serializer leak sweep),
and the link check (Part B § Link check).

## Part D — Final review pass against the original request wording

Original request feature list (recorded in the M06 hardening milestone
evidence):
compose deployment; bind-mount persistence; configuration
webserver (not for emails); admin key first-start/hash/log/"existing key
found"/reset-by-delete; users with one-time keys and regeneration; users add
own email accounts stored encrypted; MCP at `<url>/mcp` with key header;
identical tool surface; strict own-account isolation with encryption key
separate from the login key.

Mapping (bullet → checklist rows):

| Bullet | Rows |
| --- | --- |
| compose deployment | 1 |
| bind-mount persistence | 2 |
| configuration webserver (not for emails) | 3 |
| admin key first-start/hash/log | 4 |
| "existing key found"/reset-by-delete | 5 |
| users with one-time keys | 6, 7, 8 |
| and regeneration | 7, 9 |
| users add own email accounts stored encrypted | 10 |
| MCP at `<url>/mcp` with key header | 11, 12 |
| identical tool surface | 13 |
| strict own-account isolation with encryption key separate from the login key | 14 |

Result: every one of the 14 rows corresponds to a bullet of that wording,
and no bullet is unaddressed. The M07 rewrite of rows 3 and 6 changed how
the configuration webserver and the user administration are reached (one SPA
instead of server-rendered pages); it changed no requirement.

## Part E — Known limitations (not waivers)

1. **`user.json.account_count` (resolved after the M06-T04 gate).** The
   original request bullets say nothing about an admin-visible account
   count; the requirement "users add own email accounts" is evidenced
   through the user's own surfaces (`/api/me`, e2e scenarios 4/5). As
   observed at the M06 gate, the stored `account_count` was forwarded
   untouched by the admin serializer, so the admin API's user view could
   report `account_count: 0` for a user who had added accounts via
   `/api/me` (while `GET /api/me` returned the live count correctly).
   Fixed after the gate: every successful account-store mutation
   (`put_account`/`delete_account` in
   `src/imap_mcp_gateway/store/accounts.py`) now syncs the stored
   counter to the real store size, and the admin read surfaces (JSON
   detail, JSON list, status-flip response) also reconcile a stale counter
   against the real store and persist the correction — so an out-of-band
   store write (e.g. the M05 tool host writing `accounts.json` directly)
   is caught up on the next admin read. The user-facing `/api/me` profile
   view is unchanged (it always computed the count live). Covered by
   `tests/test_admin_user_api.py` (HTTP: add/delete tracking and
   stale-counter reconcile) and `tests/test_account_store.py` (store-level
   counter sync and both reconcile helpers). No checklist row is affected.
   (M07 note: the two HTML read surfaces that also reconciled the counter
   are gone; the JSON surfaces above are what remain.)
2. **`.imap-mcp` symlink.** The data-directory table in
   [docs/deployment.md](deployment.md#data-directory) lists
   `./data/users/<userId>/.imap-mcp` as a "symlink to the container path
   `/data/users/<userId>/imap-store`; resolves only inside the container".
   Implemented behaviour: `src/imap_mcp_gateway/mcp/tool_host.py`
   `_ensure_store_link` creates the symlink before each MCP session spawn,
   and the module docstring records that the link "is benign at rest … so
   it is left in place across sessions". A user who has never opened an MCP
   session has no `.imap-mcp` (as in the documented back-up and restore
   procedure, [docs/deployment.md](deployment.md#back-up-and-restore)), and
   once created the link persists. The doc row describes the entry's nature
   and container-only resolution; it asserts neither that the symlink
   exists for every user at boot nor when it is created. No contradiction
   exists between the doc and implemented behaviour; no doc change and no
   waiver.
3. **The browser UI is not covered by a browser-level end-to-end suite.**
   The SPA is covered by Vitest component and store specs (183 tests, Part
   B § Gate commands) and by shell-level HTTP assertions
   (`tests/test_spa_shell.py`, the e2e deploy scenario's SPA probes). What
   is missing is a real browser driver that clicks through the app; the
   e2e suite drives the APIs the app calls, not the app itself. This is a
   coverage statement, not a waiver: the flows the app offers are the API
   flows the e2e suite covers, and the app's own view logic is covered by
   the Vitest specs.
4. **`docs/manual-admin-user-ui-test.md` is obsolete.** The untracked,
   gitignored operator checklist described the retired server-rendered
   pages. It is not rewritten and not referenced from the shipped
   documentation; the shipped replacement for manual walkthroughs is
   [docs/user-guide.md](user-guide.md).
