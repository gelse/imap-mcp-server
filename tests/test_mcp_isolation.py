"""The M05-T04 MCP isolation suite: per-user confinement as observable responses.

Full-stack scenarios against the production surface — ``create_app`` plus the
real :class:`~imap_mcp_gateway.mcp.tool_host.NodeToolHostFactory` spawning the
Python stub child (no Node, no network IMAP in CI; the language boundary
holds) — asserting MCP/HTTP responses, filesystem artifacts and log output,
never test-internal state. A regression in any scenario fails with the
scenario name in the test id.

- **Scenario 1 — user isolation**: user A's session lists only A's accounts
  and user B's only B's (interleaved, two distinct children), and A addressing
  B's ``account_id`` through an account tool gets a TOOL ERROR with no
  cross-read (B's account data appears nowhere in the response) and no
  cross-write (B's store keeps its account; B adding and removing its OWN
  account succeeds — the control that the tool works for the legitimate
  owner);
- **Scenario 2 — auth gate**: MCP requests with no credential or a wrong key
  answer the uniform 401 BEFORE the MCP layer — no JSON-RPC envelope, no
  session id, no session keyfile ever materialized;
- **Scenario 5 — AEK activation gate**: ``imap_add_account`` for a user whose
  account encryption was never activated is refused with the structured
  guidance on the MCP channel (no keyfile, no store write, the session ends
  itself); after activation the same tool writes — and ONLY into the calling
  user's store (the other users' listings and store files stay untouched);
- **Security log assertions**: cross-user attempts — a valid key presenting
  ANOTHER user's session id — produce ``[security]`` log lines naming the
  attempt, and no log line ever carries secret material (neither login key,
  no ``usr_``/``adm_``-prefixed material).

The stub child doubles the vendored upstream ``imap-mcp-server`` (see
:mod:`tests.stub_tool_host` for its wire contract): the ISOLATION properties
under test live in the spawn configuration (per-user ``HOME`` hinge, one
child per session) and the gateway's per-user session table, and those hold
against the real child unchanged — but the tool-result payload SHAPES asserted
here (and the ``debug/*`` methods) are stub-harness specifics; the real
child's tool surface is pinned separately by the M05-T03 parity gate.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from imap_mcp_gateway.config.env import Settings
from imap_mcp_gateway.config.paths import Paths, build_paths
from imap_mcp_gateway.crypto import wrap
from imap_mcp_gateway.log import RedactCapableFormatter
from imap_mcp_gateway.mcp import gateway as gateway_module
from imap_mcp_gateway.mcp.tool_host import (
    AEK_INACTIVE_ERROR_CODE,
    AEK_INACTIVE_GUIDANCE,
    NodeToolHostFactory,
)
from imap_mcp_gateway.store.accounts import encrypt_account_record, put_account
from imap_mcp_gateway.store.session_keyfile import key_file_path
from imap_mcp_gateway.store.users import activate_aek, create_user
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
        "clientInfo": {"name": "isolation-probe", "version": "0.0.0"},
    },
}

_LIST_ACCOUNTS_CALL: dict[str, Any] = {
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {"name": "imap_list_accounts", "arguments": {}},
}


def _tools_call(request_id: int, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """One ``tools/call`` request frame."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


# --- fixtures: seeded store, factory, production app ------------------------------------


@dataclass(slots=True)
class _SeededUser:
    """One seeded registry user: ids/credentials the scenarios drive with."""

    user_id: str
    login_key: str
    account_id: str


@dataclass(slots=True)
class _SeededStore:
    """The module store: two users, each with exactly one seeded account."""

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
def isolation_store(tmp_path_factory: pytest.TempPathFactory) -> Iterator[_SeededStore]:
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
    paths = build_paths(tmp_path_factory.mktemp("mcp-isolation"))
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
    isolation_store: _SeededStore, fresh_process_wrap_state: None
) -> None:
    """Re-install the wrap key after conftest's per-test process reset.

    The seeded store is module-scoped, so every test must re-load the wrap
    key from disk (the conftest autouse fixture resets the in-memory holder
    to simulate a fresh process; explicit dependency fixes the ordering).
    """
    ensure_wrap_key(isolation_store.paths)


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
def factory(isolation_store: _SeededStore) -> NodeToolHostFactory:
    """A fresh production factory per test (fresh session table)."""
    return NodeToolHostFactory(
        settings=_stub_settings(isolation_store.paths),
        paths=isolation_store.paths,
    )


@pytest.fixture
def app(
    isolation_store: _SeededStore, factory: NodeToolHostFactory
) -> FastAPI:
    """The production app with the stub-spawning factory wired in."""
    return create_app(
        _stub_settings(isolation_store.paths), tool_host_factory=factory
    )


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http


class _LineCaptureHandler(logging.Handler):
    """Test handler recording formatted log lines (mirrors conftest's)."""

    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.format(record))


@contextmanager
def _captured_gateway_lines() -> Iterator[list[str]]:
    """Attach a capture handler to the ``/mcp`` gateway's logger."""
    handler = _LineCaptureHandler()
    handler.setFormatter(RedactCapableFormatter())
    logger = gateway_module.log
    logger.addHandler(handler)
    try:
        yield handler.lines
    finally:
        logger.removeHandler(handler)


# --- helpers (the test_tool_host.py HTTP harness patterns) ------------------------------


async def _eventually_async(
    condition: Callable[[], Awaitable[bool]], *, timeout: float = 5.0
) -> None:
    """Poll an async condition until met (bridges asynchronous teardown)."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not await condition():
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


def _tool_result_payload(body: dict[str, Any]) -> dict[str, Any]:
    """The decoded JSON payload of a tool result's text content."""
    payload: dict[str, Any] = json.loads(body["result"]["content"][0]["text"])
    return payload


async def _list_account_names(
    client: httpx.AsyncClient, login_key: str, session_id: str
) -> list[str]:
    """``imap_list_accounts`` through the gateway; the listed account names."""
    body = await _post_mcp(client, login_key, session_id, _LIST_ACCOUNTS_CALL)
    accounts = _tool_result_payload(body)["accounts"]
    return [str(account["name"]) for account in accounts]


async def _child_pid(client: httpx.AsyncClient, login_key: str, session_id: str) -> int:
    """The stub child's pid (proves which process serves a session)."""
    body = await _post_mcp(
        client,
        login_key,
        session_id,
        {"jsonrpc": "2.0", "id": 3, "method": "debug/pid"},
    )
    pid = body["result"]["pid"]
    assert isinstance(pid, int)
    return pid


async def _close_session(
    client: httpx.AsyncClient, login_key: str, session_id: str
) -> None:
    """DELETE the MCP session (the client-side teardown path)."""
    response = await client.delete(
        "/mcp", headers={**_mcp_headers(login_key), "mcp-session-id": session_id}
    )
    assert response.status_code < 400, response.text


def _orphan_key_files(paths: Paths) -> list[Path]:
    """Every ``imap-store/.key`` still on disk (must be none between sessions)."""
    users_root = paths.users_dir()
    if not users_root.is_dir():
        return []
    return sorted(users_root.glob("*/imap-store/.key"))


# --- scenario 1: user isolation ----------------------------------------------------------


async def test_scenario_1_each_user_lists_only_their_own_accounts(
    isolation_store: _SeededStore,
    factory: NodeToolHostFactory,
    client: httpx.AsyncClient,
) -> None:
    """User A lists only A's accounts, user B only B's — in two distinct children.

    Interleaved listings through the production gateway prove the per-user
    ``HOME`` hinge on every call; the distinct child pids prove no process is
    ever shared between users.
    """
    paths = isolation_store.paths
    alice = isolation_store.by_name["alice"]
    bruno = isolation_store.by_name["bruno"]
    alice_session = await _open_session(client, alice.login_key)
    bruno_session = await _open_session(client, bruno.login_key)
    try:
        alice_pid = await _child_pid(client, alice.login_key, alice_session)
        bruno_pid = await _child_pid(client, bruno.login_key, bruno_session)
        assert alice_pid != bruno_pid, "two users must never share a child process"

        for round_number in (1, 2):  # interleaved: isolation holds on every call
            assert await _list_account_names(
                client, alice.login_key, alice_session
            ) == ["alice-personal"], f"round {round_number}: user A saw foreign data"
            assert await _list_account_names(
                client, bruno.login_key, bruno_session
            ) == ["bruno-personal"], f"round {round_number}: user B saw foreign data"
    finally:
        await _close_session(client, alice.login_key, alice_session)
        await _close_session(client, bruno.login_key, bruno_session)
    assert _orphan_key_files(paths) == []


async def test_scenario_1_user_a_cannot_address_user_b_account_id(
    isolation_store: _SeededStore,
    factory: NodeToolHostFactory,
    client: httpx.AsyncClient,
) -> None:
    """A's tool call naming B's ``account_id`` errors out — no cross-read/write.

    The account tool resolves ids strictly within the calling user's own
    store (the child's per-user ``HOME``): B's id is unknown THERE, so the
    response is a tool error that carries none of B's account data, B's
    account survives untouched, and B removing its OWN id succeeds (control).
    """
    paths = isolation_store.paths
    alice = isolation_store.by_name["alice"]
    bruno = isolation_store.by_name["bruno"]
    alice_session = await _open_session(client, alice.login_key)
    bruno_session = await _open_session(client, bruno.login_key)
    try:
        cross = await _post_mcp(
            client,
            alice.login_key,
            alice_session,
            _tools_call(
                4,
                "imap_remove_account",
                {"accountId": bruno.account_id},
            ),
        )
        assert cross["result"]["isError"] is True, cross
        error_text = _tool_result_payload(cross)
        assert "not found" in error_text["error"], cross
        # No cross-read: B's account data appears nowhere in the response.
        assert "bruno-personal" not in json.dumps(cross)
        assert "imap.bruno.example" not in json.dumps(cross)

        # No cross-write either: B's account is still there for B.
        assert await _list_account_names(
            client, bruno.login_key, bruno_session
        ) == ["bruno-personal"]

        # Control: the SAME tool works for the legitimate owner — bruno adds
        # a THROWAWAY account of his own and removes that id successfully,
        # which leaves his seeded store intact for the rest of the module
        # (no test in this module mutates another's seeded state).
        added = await _post_mcp(
            client,
            bruno.login_key,
            bruno_session,
            _tools_call(
                5,
                "imap_add_account",
                {
                    "name": "bruno-throwaway",
                    "host": "imap.bruno.example",
                    "port": 993,
                    "user": "bruno@example.org",
                },
            ),
        )
        assert "isError" not in added["result"], added
        throwaway_id = _tool_result_payload(added)["id"]
        removed = await _post_mcp(
            client,
            bruno.login_key,
            bruno_session,
            _tools_call(
                6,
                "imap_remove_account",
                {"accountId": throwaway_id},
            ),
        )
        assert "isError" not in removed["result"], removed
        assert _tool_result_payload(removed)["removed"] is True
        assert await _list_account_names(
            client, bruno.login_key, bruno_session
        ) == ["bruno-personal"]
        # ...and A's store was never touched by any of it.
        assert await _list_account_names(
            client, alice.login_key, alice_session
        ) == ["alice-personal"]
    finally:
        await _close_session(client, alice.login_key, alice_session)
        await _close_session(client, bruno.login_key, bruno_session)
    assert _orphan_key_files(paths) == []


# --- scenario 2: the auth gate refuses before MCP -----------------------------------------


@pytest.mark.parametrize(
    ("case", "headers"),
    [
        pytest.param("anonymous", None, id="anonymous"),
        pytest.param(
            "wrong-key",
            {"Authorization": "Bearer " + "usr_" + "F" * 43},
            id="wrong-key",
        ),
    ],
)
async def test_scenario_2_wrong_or_missing_key_is_refused_before_mcp(
    isolation_store: _SeededStore,
    factory: NodeToolHostFactory,
    client: httpx.AsyncClient,
    case: str,
    headers: dict[str, str] | None,
) -> None:
    """Anonymous/wrong key → the uniform 401 BEFORE the MCP layer is reached.

    The observable signature of "before MCP": the fixed auth body (not a
    JSON-RPC envelope — every MCP-layer answer carries one), no session id
    issued, and no session keyfile ever materialized for any user (no tool
    host was ever started).
    """
    response = await client.post(
        "/mcp", content=json.dumps(_LIST_ACCOUNTS_CALL), headers=headers
    )

    assert response.status_code == 401, (case, response.text)
    assert response.text == '{"error":"unauthorized"}', case
    assert "jsonrpc" not in response.text, f"{case}: the MCP layer was reached"
    assert "mcp-session-id" not in response.headers, case
    paths = isolation_store.paths
    for seeded in isolation_store.by_name.values():
        assert not key_file_path(paths, seeded.user_id).exists(), (
            f"{case}: a keyfile was materialized for a request that never "
            "authenticated"
        )


# --- the [security] log gate for cross-user attempts ---------------------------------------


async def test_security_cross_user_session_attempts_log_security_without_secrets(
    isolation_store: _SeededStore,
    factory: NodeToolHostFactory,
    client: httpx.AsyncClient,
) -> None:
    """A valid key presenting ANOTHER user's session id logs ``[security]``.

    Every cross-user attempt (POST and DELETE) produces one ``[security]``
    line naming presenter, owner and the targeted session id — and no log
    line anywhere carries secret material. An UNKNOWN session id (junk, not
    a cross-user attempt) logs none: the count pins the distinction.
    """
    alice = isolation_store.by_name["alice"]
    bruno = isolation_store.by_name["bruno"]
    alice_session = await _open_session(client, alice.login_key)
    try:
        with _captured_gateway_lines() as lines:
            hijack_post = await client.post(
                "/mcp",
                content=json.dumps(_LIST_ACCOUNTS_CALL),
                headers={**_mcp_headers(bruno.login_key), "mcp-session-id": alice_session},
            )
            hijack_delete = await client.delete(
                "/mcp",
                headers={
                    **_mcp_headers(bruno.login_key),
                    "mcp-session-id": alice_session,
                },
            )
            # Control: an unknown session id is lifecycle noise, not a
            # cross-user attempt — it must NOT raise a [security] line.
            unknown = await client.post(
                "/mcp",
                content=json.dumps(_LIST_ACCOUNTS_CALL),
                headers={
                    **_mcp_headers(bruno.login_key),
                    "mcp-session-id": "c0ffee00c0ffee00c0ffee00",
                },
            )

        assert hijack_post.status_code == 404
        assert hijack_post.json()["error"]["message"] == "Session not found"
        assert hijack_delete.status_code == 404
        assert unknown.status_code == 404
        # No oracle: the foreign-session answer is byte-identical to the
        # unknown-session one (status, body, content type) — the gateway may
        # log the distinction server-side, never leak it to the client.
        for hijack in (hijack_post, hijack_delete):
            assert hijack.status_code == unknown.status_code
            assert hijack.content == unknown.content
            assert (
                hijack.headers["content-type"] == unknown.headers["content-type"]
            )

        security_lines = [line for line in lines if "[security]" in line]
        assert len(security_lines) == 2, (  # exactly one per cross-user attempt
            f"expected one [security] line per cross-user attempt, got "
            f"{len(security_lines)}: {security_lines}"
        )
        for line in security_lines:
            assert alice.user_id in line  # the owner is named
            assert bruno.user_id in line  # the presenter is named
            assert alice_session in line  # the targeted session is named
        # No secret material in ANY log line: neither login key, no
        # key-shaped (``usr_``/``adm_``) material anywhere.
        for line in lines:
            assert alice.login_key not in line
            assert bruno.login_key not in line
            assert "usr_" not in line
            assert "adm_" not in line

        # The 404 answered the hijacker without disturbing Alice's session.
        assert await _list_account_names(
            client, alice.login_key, alice_session
        ) == ["alice-personal"]
    finally:
        await _close_session(client, alice.login_key, alice_session)


# --- scenario 5: the AEK activation gate ---------------------------------------------------


async def test_scenario_5_aek_gate_blocks_account_tools_until_activation(
    isolation_store: _SeededStore,
    factory: NodeToolHostFactory,
    client: httpx.AsyncClient,
) -> None:
    """``imap_add_account`` is gated: guided error until the AEK is activated.

    Before activation the session's first request answers with the one
    structured JSON-RPC guidance error (never a 500), no keyfile is
    materialized, no store file is written, and the session ends itself —
    a follow-up tool call finds no session (404), so no tool can ever
    execute. After the web-UI activation the SAME tool works.
    """
    paths = isolation_store.paths
    record, login_key = create_user(paths, "cara")  # AEK never activated

    guided = await _post_mcp_raw(client, login_key, _INITIALIZE_REQUEST)
    assert guided.status_code == 200  # guidance, not the generic 500
    body: dict[str, Any] = guided.json()
    assert body["error"]["code"] == AEK_INACTIVE_ERROR_CODE
    assert body["error"]["message"] == AEK_INACTIVE_GUIDANCE
    assert login_key not in guided.text  # no key material echoes
    session_id = guided.headers["mcp-session-id"]
    assert not key_file_path(paths, record.id).exists()
    assert not (paths.user_imap_store_dir(record.id) / "accounts.json").exists()

    async def session_gone() -> bool:
        follow_up = await _post_mcp_raw(
            client,
            login_key,
            _tools_call(
                6,
                "imap_add_account",
                {"name": "must-not-exist", "host": "imap.example", "port": 993},
            ),
            session_id=session_id,
        )
        return follow_up.status_code == 404

    await _eventually_async(session_gone)  # the session ended after the guidance
    assert not (paths.user_imap_store_dir(record.id) / "accounts.json").exists(), (
        "a tool call executed for a user without an activated AEK"
    )

    # The web-UI activation unlocks the tool for the SAME user.
    activate_aek(paths, record.id)
    activated_session = await _open_session(client, login_key)
    try:
        added = await _post_mcp(
            client,
            login_key,
            activated_session,
            _tools_call(
                7,
                "imap_add_account",
                {
                    "name": "cara-added",
                    "host": "imap.cara.example",
                    "port": 993,
                    "user": "cara@example.org",
                },
            ),
        )
        assert "isError" not in added["result"], added
        assert _tool_result_payload(added)["added"] is True
        assert await _list_account_names(
            client, login_key, activated_session
        ) == ["cara-added"]
    finally:
        await _close_session(client, login_key, activated_session)
    assert _orphan_key_files(paths) == []


async def test_scenario_5_add_account_writes_only_into_the_calling_users_store(
    isolation_store: _SeededStore,
    factory: NodeToolHostFactory,
    client: httpx.AsyncClient,
) -> None:
    """A successful ``imap_add_account`` lands ONLY in the calling user's store.

    The add is visible in the caller's next listing and in the caller's own
    ``imap-store/accounts.json``; the other users' listings — and their store
    files, byte-for-byte — are untouched.
    """
    paths = isolation_store.paths
    alice = isolation_store.by_name["alice"]
    bruno = isolation_store.by_name["bruno"]
    record, login_key = create_user(paths, "dave")
    activate_aek(paths, record.id)
    bruno_store_file = paths.user_imap_store_dir(bruno.user_id) / "accounts.json"
    bruno_store_before = bruno_store_file.read_bytes()

    dave_session = await _open_session(client, login_key)
    bruno_session = await _open_session(client, bruno.login_key)
    alice_session = await _open_session(client, alice.login_key)
    try:
        added = await _post_mcp(
            client,
            login_key,
            dave_session,
            _tools_call(
                8,
                "imap_add_account",
                {
                    "name": "dave-added",
                    "host": "imap.dave.example",
                    "port": 993,
                    "user": "dave@example.org",
                },
            ),
        )
        assert "isError" not in added["result"], added
        added_payload = _tool_result_payload(added)
        assert added_payload["added"] is True and added_payload["name"] == "dave-added"

        # The caller's listing shows the new account; nobody else's does.
        assert await _list_account_names(client, login_key, dave_session) == [
            "dave-added"
        ]
        assert await _list_account_names(
            client, bruno.login_key, bruno_session
        ) == ["bruno-personal"]
        assert await _list_account_names(
            client, alice.login_key, alice_session
        ) == ["alice-personal"]

        # The store file evidence: the write landed in dave's store ONLY.
        dave_store = json.loads(
            (paths.user_imap_store_dir(record.id) / "accounts.json").read_text(
                encoding="utf-8"
            )
        )
        assert [str(row["name"]) for row in dave_store] == ["dave-added"]
        assert bruno_store_file.read_bytes() == bruno_store_before
    finally:
        await _close_session(client, login_key, dave_session)
        await _close_session(client, bruno.login_key, bruno_session)
        await _close_session(client, alice.login_key, alice_session)
    assert _orphan_key_files(paths) == []
