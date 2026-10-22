"""E2E orchestrator: owns the real docker-compose stack for the M06-T01 suite.

Lifecycle contract (the parent milestone's run-twice requirement):

- The suite NEVER wipes ``tests/e2e/data``. Whether the first boot of a
  session is a genuine cold boot (no ``config/admin-key.hash`` yet — the
  stack fixture scrapes the one-time ``adm_`` plaintext from the
  ``[auth] admin key created`` log line and caches it at
  ``data/.session/admin-key``) or a warm boot over existing state (the
  fixture asserts ``[auth] existing key found`` and reuses the cached key)
  is detected up front and pinned by assertions either way — so running
  the suite twice exercises the persistence path the milestone demands.
- The stack is recreated (``up --force-recreate``) at session start so the
  captured boot logs are always exactly ONE boot's output, and torn down
  with ``down`` (containers/network removed, bind-mount state kept) at
  session end.
- Every user leaked by earlier runs is pruned through the admin API at
  session start (the product's login/auth does a full scrypt verify per
  ACTIVE user, so leaked users ratchet login latency until httpx
  timeouts fail the suite): each run starts from a zero-user baseline
  while the admin-key/wrap-key persistence across runs stays intact.
- Mid-session restarts and the admin-key reset leg go through the helpers
  :func:`restart_gateway` (container restart, logs sliced with
  ``--since``) and :func:`reboot_after_state_change` (recreate → fresh
  boot logs).

Fixture map:

- ``stack`` (session) — boots the compose project (base ``docker-compose.yml``
  + the ``tests/e2e`` override, project name ``imap-mcp-e2e``), waits for
  ``/healthz``, resolves the admin key (cold vs warm), yields runtime state.
  ``stack["admin_key"]`` is MUTABLE: the reset scenario replaces it after
  minting a new one, and every later fixture/test reads the current value.
- ``admin_auth`` (function) — a Bearer-authenticated admin client (the
  admin API's CSRF-exempt convention; freshly bound to the current
  ``stack["admin_key"]`` on every test so a mid-session key reset can never
  strand it, unlike a cookie session which a restart also invalidates).
  The cookie+CSRF path itself is pinned by
  ``test_admin_key_lifecycle.test_admin_cookie_session_and_csrf_contract``.
- ``user_auth`` (session factory) — logs a user in via ``POST
  /api/me/login`` (the JSON login of M07-T01) and returns the cookie-bound
  session plus its CSRF token (read from the ``GET /api/me/session``
  bootstrap endpoint — the same path the SPA uses).
- ``mcp_client`` (session factory) — a Streamable-HTTP JSON-RPC client for
  ``/mcp`` authenticated by ``Authorization: Bearer <usr_ key>``.

Failure discipline: every compose failure, health timeout and boot-contract
violation fails loudly with the offending command output or the captured
gateway logs; the ``pytest_runtest_makereport`` hook below appends a log
tail to EVERY failed test's report. The e2e tests are skipped (not failed)
when the suite was not explicitly selected, so the unit gates of other
milestones stay green on machines without Docker.
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable, Generator, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pluggy import Result

try:  # pragma: no cover - exercised by unit-gate machines without the extra
    import httpx
except ImportError:  # the e2e extra is not installed: skip the whole suite
    httpx = None  # type: ignore[assignment]
    collect_ignore = ["scenarios"]

if httpx is not None:  # pragma: no cover - the None branch is the unit-gate path
    CLIENT_TIMEOUT_SECONDS = 30.0
    """Explicit timeout for every harness HTTP client.

    The product's login and header-auth paths deliberately do a FULL
    scrypt verify per ACTIVE user (no short-circuit — an anti-enumeration
    property, see ``web/middleware/user_auth.py::authenticate_user_key``),
    so those routes' latency grows ~50 ms x active-user-count. The default
    httpx timeout (5 s) is too tight once a data dir has accumulated users;
    30 s covers the within-run worst case (~25 users -> ~1.3 s) with a wide
    margin, and the session-start prune (:func:`_prune_leaked_users`)
    keeps that count bounded across arbitrarily many consecutive runs.
    """
    CLIENT_TIMEOUT = httpx.Timeout(CLIENT_TIMEOUT_SECONDS)
    """The shared :class:`httpx.Timeout` for every harness client."""

E2E_DIR = Path(__file__).resolve().parent
REPO_ROOT = E2E_DIR.parent.parent
BASE_COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"
E2E_COMPOSE_FILE = E2E_DIR / "docker-compose.e2e.yml"
DATA_DIR = E2E_DIR / "data"
CONFIG_DIR = DATA_DIR / "config"
USERS_DIR = DATA_DIR / "users"
MAIL_DIR = DATA_DIR / "mail"
ADMIN_KEY_HASH = CONFIG_DIR / "admin-key.hash"
WRAP_KEY_FILE = CONFIG_DIR / "wrap.key"
SESSION_DIR = DATA_DIR / ".session"
ADMIN_KEY_CACHE = SESSION_DIR / "admin-key"

# The scenario modules live in ``tests/e2e/scenarios/`` while this conftest
# lives one level up; pytest loads the conftest as a plugin but does NOT put
# ``tests/e2e`` on sys.path for the scenario modules' own imports, so they do
# ``from conftest import ...`` by module name. Make that import resolvable.
sys.path.insert(0, os.fspath(E2E_DIR))

COMPOSE_PROJECT = "imap-mcp-e2e"
"""Fixed compose project name: stable identity across runs, isolated from
any production stack at the repository root."""

GATEWAY_HOST_PORT = int(os.environ.get("E2E_GATEWAY_PORT", "13000"))
"""The host port the e2e stack publishes the gateway on.

The base compose publishes ``${GATEWAY_PORT:-3030}:${GATEWAY_PORT:-3030}``;
the e2e override re-publishes it on a fixed loopback-only test port
(``!override``, default 13000, overridable via ``E2E_GATEWAY_PORT``) so the
suite stays hermetic on machines where another service already owns the
published port — and so the HTTP probes below can only ever reach THIS stack,
never that other service. ``docker-compose.e2e.yml`` interpolates the same
host variable with the same default, and takes its container-side target from
``GATEWAY_PORT`` (default 3030), matching the base compose's ``HTTP_PORT``,
so the two sides cannot drift.
"""

GATEWAY_BASE_URL = f"http://127.0.0.1:{GATEWAY_HOST_PORT}"
HEALTHZ_URL = f"{GATEWAY_BASE_URL}/healthz"
# The MCP surface is served on the EXACT path "/mcp" — the mounting contract
# in mcp/gateway.py (an all-methods Starlette Route, never a Mount). Request
# that path from a PATH-LESS base: an httpx ``base_url`` of ".../mcp" gets a
# trailing slash forced onto it, so ``post("/")`` lands on "/mcp/" and
# Starlette's redirect_slashes answers 307 → "/mcp" (httpx does not follow
# redirects by default) — the gateway's own responses would never be seen.
MCP_PATH = "/mcp"
STUB_IMAP_HOST = "imap-stub"
"""The stub's in-network hostname (compose service name)."""
STUB_IMAP_PORT = 143
STUB_SMTP_PORT = 25
STUB_IMAP_USER = "e2euser"
STUB_IMAP_PASSWORD = "e2epass"

HEALTH_TIMEOUT_SECONDS = 120.0
"""Max wait for the gateway's /healthz after any boot/restart."""

COMPOSE_TIMEOUT_SECONDS = 900
"""Per-invocation subprocess timeout (first ``up --build`` builds images)."""

ADMIN_KEY_PATTERN = re.compile(r"adm_[A-Za-z0-9_-]{43}")
"""The one-time ``[auth] admin key created`` line carries the plaintext key."""


def _compose_command(*args: str) -> list[str]:
    """The full ``docker compose`` argv: fixed project name, project
    directory pinned to the repo root, base + override files."""
    return [
        "docker",
        "compose",
        "--project-name",
        COMPOSE_PROJECT,
        "--project-directory",
        os.fspath(REPO_ROOT),
        "-f",
        os.fspath(BASE_COMPOSE_FILE),
        "-f",
        os.fspath(E2E_COMPOSE_FILE),
        *args,
    ]


def _compose_raw(*args: str) -> tuple[int, str]:
    """Run one compose command; never fails the test itself. Returns
    ``(returncode, combined output)``; a missing docker binary degrades to
    returncode 127 with the message (so log-collection hooks stay safe)."""
    command = _compose_command(*args)
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=COMPOSE_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        return 127, "docker is not installed or not on PATH"
    except subprocess.TimeoutExpired:
        return 124, f"docker compose {' '.join(args)} timed out"
    return completed.returncode, completed.stdout + completed.stderr


def compose(*args: str, check: bool = True) -> str:
    """Run one compose command; on failure fail loudly with its output."""
    returncode, output = _compose_raw(*args)
    if check and returncode != 0:
        pytest.fail(f"docker compose {' '.join(args)} failed (exit {returncode}):\n{output}")
    return output


def gateway_logs(since: str | None = None) -> str:
    """The gateway container's combined stdout/stderr logs.

    ``since`` is a docker-log timestamp (RFC3339 UTC, second resolution) —
    used by the restart helper to slice exactly the new boot's lines out of
    a log stream that accumulates across container restarts.
    """
    args = ["logs"]
    if since is not None:
        args += ["--since", since]
    args.append("imap-gateway")
    return compose(*args, check=False)


def _log_since_stamp() -> str:
    """Current UTC time formatted for ``docker compose logs --since``."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ensure_layout() -> None:
    """Create the bind-mount targets (and the host-only key-cache dir).

    The gateway container runs as uid 1000 and writes into these directories
    through the bind mount: chown them to 1000:1000 where possible; when
    that fails (unprivileged host user that is not uid 1000) fall back to
    mode 0777 so the container can still write — a test tree, not a secret
    store (the secrets are the files the gateway creates inside).
    """
    for directory in (CONFIG_DIR, USERS_DIR, MAIL_DIR):
        directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chown(directory, 1000, 1000)
        except OSError:
            os.chmod(directory, 0o777)
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(SESSION_DIR, 0o700)


def _read_key_cache() -> str | None:
    """The cached admin-key plaintext from a previous cold boot, if any."""
    try:
        key = ADMIN_KEY_CACHE.read_text("ascii").strip()
    except OSError:
        return None
    return key if ADMIN_KEY_PATTERN.fullmatch(key) else None


def _write_key_cache(key: str) -> None:
    """Persist the admin-key plaintext for warm boots (host-only, 0600)."""
    ADMIN_KEY_CACHE.write_text(key + "\n", encoding="ascii")
    os.chmod(ADMIN_KEY_CACHE, 0o600)


def update_admin_key(stack: dict[str, Any], key: str) -> None:
    """Install a NEW admin key as the current one (reset scenario) and
    refresh the warm-boot cache so the next session can still log in."""
    assert ADMIN_KEY_PATTERN.fullmatch(key), f"not an admin key: {key!r}"
    stack["admin_key"] = key
    _write_key_cache(key)


def _wait_for_health() -> None:
    """Poll ``/healthz`` until 200, or fail loudly with the boot logs."""
    deadline = time.monotonic() + HEALTH_TIMEOUT_SECONDS
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            response = httpx.get(HEALTHZ_URL, timeout=5.0)
            if response.status_code == 200:
                return
            last_error = RuntimeError(f"/healthz answered {response.status_code}")
        except httpx.HTTPError as error:
            last_error = error
        time.sleep(1.0)
    pytest.fail(
        f"gateway did not become healthy within {HEALTH_TIMEOUT_SECONDS:.0f}s "
        f"(last error: {last_error})\n--- gateway logs ---\n"
        f"{redact_keys(gateway_logs())}"
    )


def _compose_ps_entries(ps_json: str) -> dict[str, dict[str, Any]]:
    """Parse ``docker compose ps --format json`` output.

    The records arrive either as one JSON object per line or as a single
    array, depending on the compose version — normalize both to
    ``{service-name: record}``.
    """
    entries: dict[str, dict[str, Any]] = {}
    for line in ps_json.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            decoded = json.loads(stripped)
        except ValueError:
            continue
        for record in decoded if isinstance(decoded, list) else [decoded]:
            name = str(record.get("Service") or record.get("Name") or "")
            if name:
                entries[name] = record
    return entries


def wait_services_healthy(timeout: float = 60.0) -> dict[str, dict[str, Any]]:
    """Wait until ``docker compose ps`` reports BOTH services docker-healthy.

    The stack fixture's ``/healthz`` wait proves the APP serves; the
    containers' own healthchecks (the image HEALTHCHECK for the gateway, the
    compose healthcheck for the stub) flip on their own interval/start-period
    schedule — a freshly started container reads ``health: starting`` for its
    first seconds even while the app already answers. The deploy scenario
    asserts the docker-level verdict, so it polls to convergence instead of
    racing the first probe. Returns the parsed ``ps`` records
    (``Service -> record``); fails loudly with the last snapshot on timeout.
    """
    services = {"imap-gateway", "imap-stub"}
    deadline = time.monotonic() + timeout
    last_ps = ""
    while True:
        last_ps = compose("ps", "--format", "json")
        entries = _compose_ps_entries(last_ps)
        if services <= entries.keys() and all(
            entries[service].get("Health") == "healthy" for service in services
        ):
            return entries
        if time.monotonic() >= deadline:
            pytest.fail(
                f"services did not report docker-health 'healthy' within "
                f"{timeout:.0f}s (last compose ps):\n{last_ps}"
            )
        time.sleep(2.0)


def reboot_after_state_change() -> str:
    """Recreate the stack and return the (fresh) full boot logs.

    Used by the admin-key reset leg: after host-side state surgery the
    gateway must boot again, and ``--force-recreate`` guarantees the log
    stream contains exactly that one boot — so "exactly one created line"
    assertions stay deterministic.
    """
    compose("up", "-d", "--force-recreate")
    _wait_for_health()
    return gateway_logs()


def restart_gateway() -> str:
    """Restart the gateway container in place; return its post-restart logs.

    A restart keeps the container (and its accumulated log stream), so the
    returned slice starts at the timestamp captured just before the restart
    — the new boot's lines only.
    """
    since = _log_since_stamp()
    compose("restart", "imap-gateway")
    _wait_for_health()
    return gateway_logs(since=since)


def _count(lines: str, needle: str) -> int:
    return sum(1 for line in lines.splitlines() if needle in line)


def redact_keys(text: str) -> str:
    """Scrub admin-key plaintext (``adm_...``) from text destined for a
    failure report, log, or any other artifact that outlives the run.

    The cold-boot log stream carries the one-time
    ``[auth] admin key created`` line, and pytest reports (and CI logs)
    persist — so no failure path may re-print the key (the milestone's
    one-time-display contract extends to our own diagnostics). Scraping
    and comparisons keep using the RAW text; only text that is EMBEDDED
    into a message goes through this helper.
    """
    return ADMIN_KEY_PATTERN.sub("<redacted-admin-key>", text)


def _prune_leaked_users(admin_key: str) -> int:
    """Delete every pre-existing user via the admin API at session start.

    The product's login and header-auth paths deliberately do a FULL scrypt
    verify per ACTIVE user (an anti-enumeration property — see
    ``web/middleware/user_auth.py::authenticate_user_key``), so request
    latency on those routes grows ~50 ms x active-user-count. Users leaked
    by earlier suite runs would therefore ratchet login latency until the
    harness's own httpx timeouts fail tests (observed failure mode: a data
    dir with 88 active users -> ``httpx.ReadTimeout`` on ``/api/me/login``
    and Bearer ``/mcp`` calls). Each session consequently starts from a
    deterministic zero-user baseline, deleting strays through the product's
    OWN deletion path (never a wipe of the data tree — the run-twice
    admin-key persistence contract is untouched; within one run the user
    count stays bounded at ~25, which CLIENT_TIMEOUT covers with margin).
    Returns the number of users removed.
    """
    with httpx.Client(
        base_url=GATEWAY_BASE_URL,
        headers={"Authorization": f"Bearer {admin_key}"},
        timeout=CLIENT_TIMEOUT,
    ) as admin:
        listing = admin.get("/api/admin/users")
        if listing.status_code == 401:
            # A 401 here — BEFORE anything else ran — is almost always the
            # mid-reset desync (admin-key.hash holds the new key while the
            # cache still holds the old one): surface the actionable hint
            # here, since the warm-boot probe below never gets to run.
            pytest.fail(
                f"the admin key cannot list users (401) — on a warm boot "
                f"this means the cached key at {ADMIN_KEY_CACHE} is desynced "
                f"from {ADMIN_KEY_HASH} (likely a previous run aborted "
                f"mid-reset). Fix: delete {ADMIN_KEY_CACHE} and "
                f"{ADMIN_KEY_HASH}, then re-run to re-mint — or restore the "
                f"correct key into the cache.\n"
                f"prune response: {listing.text[:200]}"
            )
        assert listing.status_code == 200, (
            f"cannot list users for the session-start prune: "
            f"{listing.status_code} {listing.text[:200]}"
        )
        users: list[dict[str, Any]] = listing.json()
        for user in users:
            deleted = admin.delete(f"/api/admin/users/{user['id']}")
            assert deleted.status_code == 204, (
                f"session-start prune failed to delete user {user['id']}: "
                f"{deleted.status_code} {deleted.text[:200]}"
            )
        return len(users)


@pytest.fixture(scope="session")
def stack() -> Iterator[dict[str, Any]]:
    """Boot the compose stack once per pytest session; tear it down after.

    Yields a mutable dict: ``admin_key`` (current plaintext admin key),
    ``cold`` (True when the session's boot was a genuine first boot) and
    ``logs`` (callable re-reading the live gateway logs). Before yielding,
    every user leaked by earlier runs is pruned through the admin API (see
    :func:`_prune_leaked_users`) so login latency cannot ratchet across
    consecutive runs on the same data dir.
    """
    _ensure_layout()
    cold = not ADMIN_KEY_HASH.exists()
    compose("up", "-d", "--build", "--force-recreate")
    try:
        _wait_for_health()
        logs = gateway_logs()
        created = _count(logs, "admin key created")
        found = _count(logs, "existing key found")
        key: str
        if cold:
            assert created == 1 and found == 0, (
                "cold-boot log contract broken: expected exactly one "
                f"'[auth] admin key created' line and no 'existing key found' "
                f"(created={created}, found={found}). Logs:\n{redact_keys(logs)}"
            )
            match = ADMIN_KEY_PATTERN.search(logs)
            assert match is not None, f"no admin key found in cold-boot logs:\n{redact_keys(logs)}"
            key = match.group(0)
            _write_key_cache(key)
        else:
            assert created == 0 and found >= 1, (
                "warm-boot log contract broken: expected 'existing key found' "
                f"and no new 'admin key created' line (created={created}, "
                f"found={found}). If a previous run crashed mid-flight, clean "
                f"stragglers first: docker compose --project-name "
                f"{COMPOSE_PROJECT} down. Logs:\n{redact_keys(logs)}"
            )
            cached = _read_key_cache()
            assert cached is not None, (
                f"warm boot (admin-key.hash exists) but the cached key at "
                f"{ADMIN_KEY_CACHE} is missing or unreadable — wipe "
                f"{DATA_DIR} to force a clean cold boot, or restore the "
                f"cached key file"
            )
            key = cached
        # Prune BEFORE the warm-boot probe so the zero-user baseline holds
        # for the probe and every later step — and so a stale-cache desync
        # (see the prune's 401 path) surfaces at the prune rather than as a
        # wall of confusing 401s in the tests themselves.
        _prune_leaked_users(key)
        if not cold:
            # Validate the cached key against the live gate before yielding:
            # a run aborted between the reset leg's unlink and its cache
            # refresh leaves admin-key.hash (new key) desynced from the
            # cache (old key), which would otherwise cascade confusing 401s
            # in every later test. A SUCCESS hands the limiter slot back
            # (see web/admin/router.py), so the healthy path costs nothing.
            probe = httpx.post(
                f"{GATEWAY_BASE_URL}/api/admin/login",
                data={"key": key},
                timeout=CLIENT_TIMEOUT,
            )
            if probe.status_code != 200:
                pytest.fail(
                    f"the cached admin key at {ADMIN_KEY_CACHE} no longer "
                    f"authenticates (HTTP {probe.status_code}): the cache is "
                    f"desynced from {ADMIN_KEY_HASH} (likely a previous run "
                    f"aborted mid-reset). Fix: delete {ADMIN_KEY_CACHE} and "
                    f"{ADMIN_KEY_HASH}, then re-run to re-mint — or restore "
                    f"the correct key into the cache.\n"
                    f"--- gateway logs ---\n{redact_keys(gateway_logs())}"
                )
        yield {"admin_key": key, "cold": cold, "logs": gateway_logs}
    finally:
        compose("down", "--remove-orphans", check=False)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(
    item: pytest.Item, call: pytest.CallInfo[Any]
) -> Generator[None, Result[pytest.TestReport], None]:
    """Append a gateway-log tail to every FAILED test's report (loud failures).

    The tail is redacted BEFORE it is attached: the cold-boot log stream
    carries the one-time admin-key line, and pytest reports persist (in CI
    artifacts) well beyond the key's intended single display.
    """
    outcome = yield
    report = outcome.get_result()
    if report.when == "call" and report.failed:
        report.sections.append(("e2e gateway logs (tail)", redact_keys(gateway_logs())[-8000:]))


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip the suite unless it was explicitly selected.

    The unit gates of the other milestones run plain ``uv run pytest`` over
    ``testpaths = tests``; booting Docker there would be both surprising and
    destructive on developer machines. Selection is explicit by either
    documented spelling: ``-m e2e`` or an argument naming ``tests/e2e``.
    """
    marker_expr = config.getoption("-m", default="") or ""
    args = " ".join(str(arg) for arg in config.args)
    if "e2e" in marker_expr or "e2e" in args:
        return
    skip = pytest.mark.skip(
        reason="e2e suite: select explicitly with `-m e2e` or `pytest tests/e2e`"
    )
    for item in items:
        if str(E2E_DIR) in str(getattr(item, "path", "")):
            item.add_marker(skip)


# --- session/auth helpers -------------------------------------------------------


def decode_cookie_payload(cookie_value: str) -> dict[str, str]:
    """Decode a signed session cookie's payload (``b64url(json).b64url(hmac)``).

    See ``imap_mcp_gateway.web.session``: the payload is a flat ``str -> str``
    mapping carrying the ``csrf`` member. The test harness legitimately holds
    the cookies it was handed (HttpOnly keeps tokens out of ``document.cookie``
    in browsers, not out of an API client that received the Set-Cookie).
    """
    body = cookie_value.split(".", 1)[0]
    padding = "=" * (-len(body) % 4)
    payload = json.loads(base64.urlsafe_b64decode(body + padding))
    return {str(k): str(v) for k, v in payload.items()}


class UserSession:
    """One logged-in user: the cookie-bound client plus its login key."""

    def __init__(self, client: Any, login_key: str, user_id: str) -> None:
        self.client = client
        self.login_key = login_key
        self.user_id = user_id


@pytest.fixture
def admin_auth(stack: dict[str, Any]) -> Iterator[Any]:
    """A Bearer-authenticated admin client for the CURRENT admin key.

    Function-scoped on purpose: the admin-key reset scenario replaces
    ``stack["admin_key"]`` mid-session, and a restart also kills every
    cookie session (the signer secret is per-boot in-memory). Bearer auth
    needs no login round-trip, no CSRF token, and reads the live key on
    every test, so it can never strand later scenarios.
    """
    client = httpx.Client(
        base_url=GATEWAY_BASE_URL,
        headers={"Authorization": f"Bearer {stack['admin_key']}"},
        timeout=CLIENT_TIMEOUT,
    )
    try:
        yield client
    finally:
        client.close()


@pytest.fixture(scope="session")
def user_auth() -> Callable[[str, str], UserSession]:
    """Factory: log a user in via ``POST /api/me/login``; return the session.

    The user surface is cookie-only, so the factory also reads the CSRF
    token from the ``GET /api/me/session`` bootstrap endpoint (the same
    path the SPA uses) and binds it as ``X-CSRF-Token``. M07-T05 removed
    the server-rendered login form — the JSON login is the only login
    surface.
    """

    def _login(login_key: str, user_id: str) -> UserSession:
        client = httpx.Client(base_url=GATEWAY_BASE_URL, timeout=CLIENT_TIMEOUT)
        response = client.post("/api/me/login", json={"key": login_key})
        assert response.status_code == 200, (
            f"user login failed for {user_id}: {response.status_code} {response.text[:200]}"
        )
        session = client.get("/api/me/session")
        assert session.status_code == 200, (
            f"user {user_id} session bootstrap failed: {session.status_code}"
        )
        csrf = session.json()["csrf_token"]
        assert isinstance(csrf, str) and csrf, (
            f"user {user_id} session carries no csrf token"
        )
        client.headers["X-CSRF-Token"] = csrf
        return UserSession(client=client, login_key=login_key, user_id=user_id)

    return _login


@pytest.fixture(scope="session")
def mcp_client() -> Callable[[str], Any]:
    """Factory: a JSON-RPC client for ``/mcp`` (Streamable HTTP, JSON mode)."""

    def _create(login_key: str) -> Any:
        return httpx.Client(
            base_url=GATEWAY_BASE_URL,
            headers={
                "Authorization": f"Bearer {login_key}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            timeout=CLIENT_TIMEOUT,
        )

    return _create


def create_user_via_admin(admin: Any, name: str) -> dict[str, Any]:
    """Admin-creates one user; returns the create response (one-time key)."""
    response = admin.post("/api/admin/users", json={"name": name})
    assert response.status_code == 201, (
        f"admin create user failed: {response.status_code} {response.text}"
    )
    body: dict[str, Any] = response.json()
    assert body.get("login_key", "").startswith("usr_"), (
        f"created-user response carries no one-time usr_ key: {body}"
    )
    return body


# --- MCP (Streamable HTTP, JSON mode) helpers -----------------------------------


def mcp_post_raw(client: Any, frame: dict[str, Any], *, session_id: str | None = None) -> Any:
    """One raw JSON-RPC POST to ``/mcp``; returns the httpx response unasserted."""
    headers = {"Mcp-Session-Id": session_id} if session_id is not None else {}
    return client.post(MCP_PATH, content=json.dumps(frame), headers=headers)


def mcp_request(
    client: Any,
    method: str,
    params: dict[str, Any] | None = None,
    *,
    request_id: int = 1,
    session_id: str | None = None,
) -> dict[str, Any]:
    """One JSON-RPC request frame over an OPEN session; parsed body."""
    frame: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        frame["params"] = params
    response = mcp_post_raw(client, frame, session_id=session_id)
    assert response.status_code == 200, (
        f"MCP {method} failed: {response.status_code} {response.text[:300]}"
    )
    body: dict[str, Any] = response.json()
    return body


def initialize_mcp_session(client: Any) -> str:
    """Open one MCP session (initialize + initialized notification); return
    the ``Mcp-Session-Id`` the gateway assigned (also bound on the client)."""
    frame: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {"roots": {"listChanged": True}},
            "clientInfo": {"name": "e2e-suite", "version": "0.0.0"},
        },
    }
    response = mcp_post_raw(client, frame)
    assert response.status_code == 200, (
        f"MCP initialize failed: {response.status_code} {response.text[:300]}"
    )
    body: dict[str, Any] = response.json()
    assert "result" in body, f"initialize returned an error: {body}"
    session_id: str | None = response.headers.get("Mcp-Session-Id")
    assert isinstance(session_id, str) and session_id, (
        "initialize response carried no Mcp-Session-Id"
    )
    client.headers["Mcp-Session-Id"] = session_id
    # The handshake's client notification (a notification: no reply frame).
    client.post(
        MCP_PATH,
        content=json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    return session_id


def mcp_close_session(client: Any, session_id: str) -> None:
    """DELETE the session (the gateway tears the tool host down) and pin
    that the id can never be reused afterwards (uniform JSON-RPC 404)."""
    closed = client.delete(MCP_PATH, headers={"Mcp-Session-Id": session_id})
    assert closed.status_code in (200, 204), (
        f"session DELETE answered {closed.status_code}: {closed.text[:200]}"
    )
    reuse = mcp_post_raw(
        client,
        {"jsonrpc": "2.0", "id": 99, "method": "tools/list", "params": {}},
        session_id=session_id,
    )
    assert reuse.status_code == 404, f"closed session still routable: HTTP {reuse.status_code}"
