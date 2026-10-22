"""The M05-T04 MCP session-lifecycle suite: keys, status, and process hygiene.

Full-stack scenarios against the production surface — ``create_app`` plus the
real :class:`~imap_mcp_gateway.mcp.tool_host.NodeToolHostFactory` spawning the
Python stub child (no Node, no network IMAP in CI; the language boundary
holds) — asserting MCP/HTTP responses, filesystem artifacts and a
child-process counter, never test-internal state. A regression in any
scenario fails with the scenario name in the test id.

- **Scenario 3 — login-key rotation**: rotating a user's login key invalidates
  the OLD key on the very next MCP request (both addressed at the session it
  opened and as a fresh initialize), while the in-flight session itself
  survives — it is bound to the user, not the key — and the accounts stay
  reachable with the NEW key (the AEK is untouched: the same account still
  decrypts and lists);
- **Scenario 4 — disabled user**: a disabled user's key stops working
  immediately (the in-flight session's next request and a fresh initialize
  both answer the uniform 401); re-enabling restores access;
- **Scenario 6 — process hygiene**: after a session's teardown no child
  process remains (asserted under a ``/proc`` child-process counter), the
  session-scoped ``imap-store/.key`` files are cleaned, and repeated
  sessions never accumulate processes; the container-shutdown drain frees
  every child of every session.

The stub child doubles the vendored upstream ``imap-mcp-server`` (see
:mod:`tests.stub_tool_host` for its wire contract) exactly as the M05-T02
harness does: the spawn contract (``argv = [interpreter, entry_script]``,
stdio pipes, per-user ``HOME``) is identical, and what is under test is the
lifecycle AROUND the process — never the child's internals.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from imap_mcp_gateway.app import _boot_lifespan
from imap_mcp_gateway.config.env import Settings
from imap_mcp_gateway.config.paths import Paths, build_paths
from imap_mcp_gateway.crypto import wrap
from imap_mcp_gateway.mcp.tool_host import NodeToolHostFactory
from imap_mcp_gateway.store.accounts import encrypt_account_record, put_account
from imap_mcp_gateway.store.users import (
    activate_aek,
    create_user,
    disable_user,
    enable_user,
    rotate_login_key,
)
from imap_mcp_gateway.store.wrap_key import ensure_wrap_key
from imap_mcp_gateway.web.server import create_app

_STUB_PATH = Path(__file__).with_name("stub_tool_host.py")

_INITIALIZE_REQUEST: dict[str, Any] = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "lifecycle-probe", "version": "0.0.0"},
    },
}

_LIST_ACCOUNTS_CALL: dict[str, Any] = {
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {"name": "imap_list_accounts", "arguments": {}},
}

_UNAUTHORIZED_BODY = '{"error":"unauthorized"}'
"""The one fixed auth-failure body (the uniform-401 contract)."""


# --- fixtures: seeded store, factory, production app ------------------------------------


@dataclass(slots=True)
class _SeededUser:
    """One seeded registry user: the identifiers the scenarios drive with."""

    user_id: str
    login_key: str
    account_id: str


@dataclass(slots=True)
class _SeededStore:
    """The module store: two users (for the hygiene scenarios), one account each."""

    paths: Paths
    by_name: dict[str, _SeededUser]


def _seed_account(
    paths: Paths, user_id: str, aek_hex: str, *, name: str, host: str
) -> str:
    """Write one account through the M04 store; return its id."""
    stored = put_account(
        paths,
        user_id,
        encrypt_account_record(
            {
                "name": name,
                "host": host,
                "port": 993,
                "user": f"{name}@example.org",
                "password": f"secret-{name}",
                "tls": True,
            },
            aek_hex,
        ),
    )
    return stored.id


@pytest.fixture(scope="module")
def lifecycle_store(tmp_path_factory: pytest.TempPathFactory) -> Iterator[_SeededStore]:
    """Two users (alice, bruno) with activated AEKs and one account each.

    The in-memory wrap-key holder is cleared BEFORE ``ensure_wrap_key`` and
    again at module teardown (the ``test_tool_parity.parity_store``
    precedent): module-scoped fixtures materialize outside the conftest's
    per-test holder reset, so a holder left loaded with an EARLIER module's
    key would make ``ensure_wrap_key`` early-return without ever writing
    this store's ``config/wrap.key`` — and the first per-test reload would
    hit the deliberate wipe guard (wrapped AEKs exist, key file missing).
    Clearing before the mint gives this module fresh-process semantics;
    clearing at teardown hands the next module a virgin holder the same way.
    """
    paths = build_paths(tmp_path_factory.mktemp("mcp-lifecycle"))
    wrap._loaded_wrap_key = None
    ensure_wrap_key(paths)
    store = _SeededStore(paths=paths, by_name={})
    for key, display in (("alice", "alice"), ("bruno", "bruno")):
        record, login_key = create_user(paths, display)
        aek_hex = activate_aek(paths, record.id)
        account_id = _seed_account(
            paths,
            record.id,
            aek_hex,
            name=f"{display}-personal",
            host=f"imap.{display}.example",
        )
        store.by_name[key] = _SeededUser(
            user_id=record.id, login_key=login_key, account_id=account_id
        )
    yield store
    wrap._loaded_wrap_key = None


@pytest.fixture(autouse=True)
def _reload_wrap_key(
    lifecycle_store: _SeededStore, fresh_process_wrap_state: None
) -> None:
    """Re-install the wrap key after conftest's per-test process reset.

    The seeded store is module-scoped, so every test must re-load the wrap
    key from disk (the conftest autouse fixture resets the in-memory holder
    to simulate a fresh process; explicit dependency fixes the ordering).
    """
    ensure_wrap_key(lifecycle_store.paths)


def _mint_active_user(paths: Paths, name: str) -> _SeededUser:
    """A fresh user with an activated AEK and one seeded account (per test)."""
    record, login_key = create_user(paths, name)
    aek_hex = activate_aek(paths, record.id)
    account_id = _seed_account(
        paths,
        record.id,
        aek_hex,
        name=f"{name}-personal",
        host=f"imap.{name}.example",
    )
    return _SeededUser(user_id=record.id, login_key=login_key, account_id=account_id)


def _stub_settings(paths: Paths) -> Settings:
    """Settings spawning the Python stub instead of the vendored Node bundle."""
    return Settings(
        data_dir=paths.data_dir,
        node_bin=Path(sys.executable),
        imap_mcp_server_js=_STUB_PATH,
        # Pinned so an ambient MCP_IDLE_TIMEOUT_SECONDS=0 cannot tear the
        # sessions of these scenarios down mid-test.
        mcp_idle_timeout_seconds=900,
    )


@pytest.fixture
def factory(lifecycle_store: _SeededStore) -> NodeToolHostFactory:
    """A fresh production factory per test (fresh session table)."""
    return NodeToolHostFactory(
        settings=_stub_settings(lifecycle_store.paths),
        paths=lifecycle_store.paths,
    )


@pytest.fixture
def app(lifecycle_store: _SeededStore, factory: NodeToolHostFactory) -> FastAPI:
    """The production app with the stub-spawning factory wired in."""
    return create_app(_stub_settings(lifecycle_store.paths), tool_host_factory=factory)


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http


# --- the child-process counter (the process-leak assertion's instrument) ----------------


def _child_pids() -> Iterator[int]:
    """Pids of this process's direct children, read from ``/proc`` (Linux)."""
    my_pid = os.getpid()
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat_text = (entry / "stat").read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue  # the process vanished mid-scan
        # After the parenthesized comm field: state, ppid, ... (ppid is field 4).
        fields = stat_text.rpartition(")")[2].split()
        try:
            if int(fields[1]) == my_pid:
                yield int(entry.name)
        except (IndexError, ValueError):
            continue


def _child_process_count() -> int:
    """Direct children of this process (zombies count: they are not reaped)."""
    return sum(1 for _ in _child_pids())


def _stub_child_process_count() -> int:
    """Direct children whose cmdline names the stub script (the tool hosts)."""
    count = 0
    for pid in _child_pids():
        try:
            cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
        except OSError:
            continue  # vanished mid-scan
        if b"stub_tool_host.py" in cmdline.replace(b"\x00", b" "):
            count += 1
    return count


def _orphan_key_files(paths: Paths) -> list[Path]:
    """Every ``imap-store/.key`` still on disk (must be none between sessions)."""
    users_root = paths.users_dir()
    if not users_root.is_dir():
        return []
    return sorted(users_root.glob("*/imap-store/.key"))


# --- helpers (the test_tool_host.py HTTP harness patterns) ------------------------------


async def _eventually(condition: Callable[[], bool], *, timeout: float = 5.0) -> None:
    """Poll a condition until met (bridges asynchronous teardown paths)."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not condition():
        if loop.time() > deadline:
            raise AssertionError("condition not met within timeout")
        await asyncio.sleep(0.01)


def _mcp_headers(login_key: str) -> dict[str, str]:
    """The headers one authenticated MCP request carries."""
    return {
        "Authorization": f"Bearer {login_key}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


async def _post_mcp_raw(
    client: httpx.AsyncClient,
    login_key: str,
    payload: dict[str, Any],
    *,
    session_id: str | None = None,
) -> httpx.Response:
    """One authenticated POST to /mcp; the raw response (no status assertion)."""
    headers = _mcp_headers(login_key)
    if session_id is not None:
        headers["mcp-session-id"] = session_id
    return await client.post("/mcp", content=json.dumps(payload), headers=headers)


async def _open_session(client: httpx.AsyncClient, login_key: str) -> str:
    """POST the initialize handshake; return the established session id."""
    response = await _post_mcp_raw(client, login_key, _INITIALIZE_REQUEST)
    assert response.status_code == 200, response.text
    return response.headers["mcp-session-id"]


async def _post_mcp(
    client: httpx.AsyncClient, login_key: str, session_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """One authenticated request on an established session; the JSON body."""
    response = await _post_mcp_raw(client, login_key, payload, session_id=session_id)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


async def _list_account_names(
    client: httpx.AsyncClient, login_key: str, session_id: str
) -> list[str]:
    """``imap_list_accounts`` through the gateway; the listed account names."""
    body = await _post_mcp(client, login_key, session_id, _LIST_ACCOUNTS_CALL)
    payload = json.loads(body["result"]["content"][0]["text"])
    accounts = payload["accounts"]
    return [str(account["name"]) for account in accounts]


async def _close_session(
    client: httpx.AsyncClient, login_key: str, session_id: str
) -> None:
    """DELETE the MCP session (the client-side teardown path)."""
    response = await client.delete(
        "/mcp", headers={**_mcp_headers(login_key), "mcp-session-id": session_id}
    )
    assert response.status_code < 400, response.text


# --- scenario 3: login-key rotation ------------------------------------------------------


async def test_scenario_3_rotation_invalidates_the_old_key_and_the_session_survives(
    lifecycle_store: _SeededStore,
    factory: NodeToolHostFactory,
    client: httpx.AsyncClient,
) -> None:
    """Rotating a login key kills the old key NOW; the session and AEK survive.

    The old key is refused on the very next MCP request — both addressed at
    the session it opened (every request re-authenticates at the auth gate)
    and as a fresh initialize. The in-flight session itself is NOT lost: the
    same session id works with the NEW key and still lists the same account
    (the AEK is untouched by login-key rotation), and fresh sessions open
    with the new key.
    """
    paths = lifecycle_store.paths
    rosa = _mint_active_user(paths, "rosa")
    old_key = rosa.login_key
    session_id = await _open_session(client, old_key)
    new_key = old_key  # the teardown's key; replaced below once rotation lands
    try:
        assert await _list_account_names(client, old_key, session_id) == [
            "rosa-personal"
        ]

        _record, rotated_key = rotate_login_key(paths, rosa.user_id)
        new_key = rotated_key

        # The old key is dead immediately — on the in-flight session...
        refused = await _post_mcp_raw(
            client, old_key, _LIST_ACCOUNTS_CALL, session_id=session_id
        )
        assert refused.status_code == 401, refused.text
        assert refused.text == _UNAUTHORIZED_BODY
        # ...and on a fresh initialize (reconnect with the old key).
        refused_init = await _post_mcp_raw(client, old_key, _INITIALIZE_REQUEST)
        assert refused_init.status_code == 401, refused_init.text
        assert refused_init.text == _UNAUTHORIZED_BODY
        assert "mcp-session-id" not in refused_init.headers

        # The SAME session stays alive under the new key — and the account
        # (encrypted under the untouched AEK) still decrypts and lists.
        assert await _list_account_names(client, new_key, session_id) == [
            "rosa-personal"
        ]

        # Fresh sessions open with the new key exactly as before.
        fresh_session = await _open_session(client, new_key)
        try:
            assert await _list_account_names(client, new_key, fresh_session) == [
                "rosa-personal"
            ]
        finally:
            await _close_session(client, new_key, fresh_session)
    finally:
        await _close_session(client, new_key, session_id)
    assert _orphan_key_files(paths) == []


# --- scenario 4: a disabled user's key stops working immediately --------------------------


async def test_scenario_4_disabled_user_key_stops_working_immediately(
    lifecycle_store: _SeededStore,
    factory: NodeToolHostFactory,
    client: httpx.AsyncClient,
) -> None:
    """``disable_user`` cuts the key off at once — sessions and new logins.

    The in-flight session's next request (its own key, its own session id)
    and a fresh initialize both answer the uniform 401 the moment the status
    flips; re-enabling restores access without any new key.
    """
    paths = lifecycle_store.paths
    dana = _mint_active_user(paths, "dana")
    session_id = await _open_session(client, dana.login_key)
    try:
        assert await _list_account_names(client, dana.login_key, session_id) == [
            "dana-personal"
        ]

        disable_user(paths, dana.user_id)

        # Immediately: the in-flight session refuses its owner's key...
        refused = await _post_mcp_raw(
            client, dana.login_key, _LIST_ACCOUNTS_CALL, session_id=session_id
        )
        assert refused.status_code == 401, refused.text
        assert refused.text == _UNAUTHORIZED_BODY
        # ...and no new session can be opened with the key either.
        refused_init = await _post_mcp_raw(client, dana.login_key, _INITIALIZE_REQUEST)
        assert refused_init.status_code == 401, refused_init.text
        assert refused_init.text == _UNAUTHORIZED_BODY
        assert "mcp-session-id" not in refused_init.headers

        # Control: re-enabling restores access with the SAME key (the key was
        # never the problem — the account status was).
        enable_user(paths, dana.user_id)
        assert await _list_account_names(client, dana.login_key, session_id) == [
            "dana-personal"
        ]
    finally:
        await _close_session(client, dana.login_key, session_id)
    assert _orphan_key_files(paths) == []


# --- scenario 6: process hygiene under the child-process counter --------------------------


async def test_scenario_6_teardown_frees_the_child_and_cleans_the_key_file(
    lifecycle_store: _SeededStore,
    factory: NodeToolHostFactory,
    client: httpx.AsyncClient,
) -> None:
    """After a session's teardown no child process remains; the .key is gone.

    The counter proves the lifecycle end to end: exactly ONE child while the
    session runs (one process per MCP session — never pooled), zero after
    the client's DELETE, and no session ``.key`` file left on disk.
    """
    paths = lifecycle_store.paths
    alice = lifecycle_store.by_name["alice"]
    baseline = _child_process_count()
    assert _stub_child_process_count() == 0  # no tool host before the session

    session_id = await _open_session(client, alice.login_key)
    await _eventually(lambda: _stub_child_process_count() == 1)
    assert _child_process_count() == baseline + 1, (
        "an open MCP session must run exactly one child process"
    )
    assert _orphan_key_files(paths) != []  # the session keyfile is materialized

    await _close_session(client, alice.login_key, session_id)

    await _eventually(lambda: _child_process_count() == baseline)
    assert _stub_child_process_count() == 0
    assert _orphan_key_files(paths) == []  # the .key never outlives the session


async def test_scenario_6_repeated_sessions_do_not_accumulate_processes(
    lifecycle_store: _SeededStore,
    factory: NodeToolHostFactory,
    client: httpx.AsyncClient,
) -> None:
    """Open/close rounds return to the exact baseline every time — no growth."""
    paths = lifecycle_store.paths
    bruno = lifecycle_store.by_name["bruno"]
    baseline = _child_process_count()

    for round_number in (1, 2, 3):
        session_id = await _open_session(client, bruno.login_key)
        await _eventually(lambda: _stub_child_process_count() == 1)
        assert _child_process_count() == baseline + 1, (
            f"round {round_number}: sessions are accumulating child processes"
        )
        await _close_session(client, bruno.login_key, session_id)
        await _eventually(lambda: _child_process_count() == baseline)

    assert _child_process_count() == baseline
    assert _orphan_key_files(paths) == []


async def test_scenario_6_shutdown_drain_frees_every_child_and_key_file(
    lifecycle_store: _SeededStore,
    factory: NodeToolHostFactory,
) -> None:
    """The container shutdown drain frees EVERY session's child and keyfile."""
    paths = lifecycle_store.paths
    alice = lifecycle_store.by_name["alice"]
    bruno = lifecycle_store.by_name["bruno"]
    baseline = _child_process_count()
    app: FastAPI = create_app(
        _stub_settings(paths),
        lifespan=_boot_lifespan(paths, factory),
        tool_host_factory=factory,
    )
    async with _boot_lifespan(paths, factory)(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as http:
            await _open_session(http, alice.login_key)
            await _open_session(http, bruno.login_key)
            await _eventually(lambda: _stub_child_process_count() == 2)
            assert _child_process_count() == baseline + 2
    # The lifespan's shutdown drain ran: every child freed, every keyfile gone.
    await _eventually(lambda: _child_process_count() == baseline)
    assert _stub_child_process_count() == 0
    assert _orphan_key_files(paths) == []
