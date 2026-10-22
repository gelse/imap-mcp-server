"""Tests for the M05-T02 per-user upstream tool host.

The production child is the vendored ``imap-mcp-server`` Node bundle, which
is NOT installed in the dev environment — so every test points
``Settings.node_bin`` at ``sys.executable`` and ``Settings.imap_mcp_server_js``
at the Python stub in :mod:`tests.stub_tool_host` (no Node here — the
language boundary holds): the spawn contract (``argv = [interpreter,
entry_script]``, stdio pipes, six-variable env allowlist) and everything
around the process are what is under test.

Coverage map (milestone verification criteria):

- **Bridge framing** — ``debug/echo`` round trip is value-for-value verbatim
  (unknown fields and key order survive), notifications cross unchanged, and
  a ``tools/call`` reads only the calling user's store through the
  ``$HOME/.imap-mcp`` hinge;
- **Env allowlist** — the child environment is EXACTLY the six allowlisted
  variables and contains no ``DATA_DIR/config``, ``admin-key.hash`` or
  wrap-key paths, and no caller key material;
- **Two-user isolation (acceptance)** — through the production
  ``create_app`` + real ``NodeToolHostFactory``, users A and B hold
  concurrent sessions with two distinct children and each lists only their
  own account via ``imap_list_accounts``;
- **Teardown** — ``aclose`` SIGTERMs the child (returncode ``-15``), removes
  the session keyfile and empties the registry; it is idempotent;
- **Idle timeout** — an idle session is SIGTERMed and frees the child and
  the registry; a bridge exchange resets the deadline; a NON-ZERO timeout
  takes the watchdog's sleep-then-fire path (child alive before the
  deadline, ``idle timeout (2s)`` logged);
- **Orphan cleanup** — a stale ``imap-store/.key`` (crash leftover) is
  removed by the startup sweep — both the registry unit path and the boot
  lifespan's factory branch (sweep runs exactly once through the factory's
  registry, with the single ``[config] swept`` log line);
- **AEK-null fail-closed** — a user without an activated AEK gets no child,
  no keyfile, and the structured guidance message;
- **stderr relay** — child stderr is logged under the ``[mcp:<userId>]``
  prefix, sanitized so embedded newlines cannot forge log lines;
- **Shutdown drain** — the boot lifespan drains every live session (child
  freed, registry empty).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import signal
import sys
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import httpx
import pytest
from fastapi import FastAPI

from imap_mcp_gateway.app import _boot_lifespan
from imap_mcp_gateway.config.env import Settings
from imap_mcp_gateway.config.paths import Paths, build_paths
from imap_mcp_gateway.log import RedactCapableFormatter
from imap_mcp_gateway.mcp import tool_host as tool_host_module
from imap_mcp_gateway.mcp.gateway import ToolHost
from imap_mcp_gateway.mcp.session_registry import SessionRegistry
from imap_mcp_gateway.mcp.tool_host import (
    AEK_INACTIVE_ERROR_CODE,
    AEK_INACTIVE_GUIDANCE,
    NodeToolHost,
    NodeToolHostFactory,
)
from imap_mcp_gateway.store.accounts import encrypt_account_record, put_account
from imap_mcp_gateway.store.session_keyfile import (
    key_file_path,
    materialize_key_file,
)
from imap_mcp_gateway.store.user_schema import UserMetadata
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
        "clientInfo": {"name": "tool-host-probe", "version": "0.0.0"},
    },
}


# --- fixtures: seeded store, stub settings, factories ---------------------------------


@dataclass(slots=True)
class _SeededUser:
    """One seeded registry user: credential-free metadata + one-time key."""

    metadata: UserMetadata
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
    """Write one account through the M04 store; return its id.

    The AEK hex is used in-process to seal the credential and is never stored
    anywhere (one-time disclosure discipline, as in production).
    """
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
def seeded_store(tmp_path_factory: pytest.TempPathFactory) -> _SeededStore:
    """Two users (alice, bruno) with activated AEKs and one account each."""
    paths = build_paths(tmp_path_factory.mktemp("tool-host"))
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
            metadata=UserMetadata.from_record(record),
            login_key=login_key,
            account_id=account_id,
        )
    return store


@pytest.fixture(autouse=True)
def _reload_wrap_key(
    seeded_store: _SeededStore, fresh_process_wrap_state: None
) -> None:
    """Re-install the wrap key after conftest's per-test process reset.

    The seeded store is module-scoped, so every test must re-load the wrap
    key from disk (the conftest autouse fixture resets the in-memory holder
    to simulate a fresh process; explicit dependency fixes the ordering).
    """
    ensure_wrap_key(seeded_store.paths)


def _stub_settings(paths: Paths, *, idle_timeout_seconds: int = 900) -> Settings:
    """Settings spawning the Python stub instead of the vendored Node bundle."""
    return Settings(
        data_dir=paths.data_dir,
        node_bin=Path(sys.executable),
        imap_mcp_server_js=_STUB_PATH,
        mcp_idle_timeout_seconds=idle_timeout_seconds,
    )


@pytest.fixture
def factory(seeded_store: _SeededStore) -> NodeToolHostFactory:
    """A fresh factory per test (fresh registry, default idle timeout)."""
    return NodeToolHostFactory(
        settings=_stub_settings(seeded_store.paths), paths=seeded_store.paths
    )


class _LineCaptureHandler(logging.Handler):
    """Test handler recording formatted log lines (mirrors conftest's)."""

    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.format(record))


@pytest.fixture
def host_log_lines() -> Iterator[list[str]]:
    """Capture the tool-host module's formatted log lines."""
    handler = _LineCaptureHandler()
    handler.setFormatter(RedactCapableFormatter())
    logger = tool_host_module.log
    logger.addHandler(handler)
    try:
        yield handler.lines
    finally:
        logger.removeHandler(handler)


@pytest.fixture
def boot_log_lines() -> Iterator[list[str]]:
    """Capture the composition-root (``imap_mcp_gateway.app``) log lines."""
    handler = _LineCaptureHandler()
    handler.setFormatter(RedactCapableFormatter())
    logger = logging.getLogger("imap_mcp_gateway.app")
    logger.addHandler(handler)
    try:
        yield handler.lines
    finally:
        logger.removeHandler(handler)


# --- helpers ---------------------------------------------------------------------------


async def _eventually(
    condition: Callable[[], bool], *, timeout: float = 5.0
) -> None:
    """Poll a condition until met (bridges asynchronous teardown paths)."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not condition():
        if loop.time() > deadline:
            raise AssertionError("condition not met within timeout")
        await asyncio.sleep(0.01)


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


async def _call(
    host: ToolHost, method: str, params: dict[str, Any] | None = None
) -> dict[str, Any]:
    """One request/response exchange with a live host; the (echoed) result."""
    request: dict[str, Any] = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        request["params"] = params
    await host.send_frame(json.dumps(request))
    reply = json.loads(await host.receive_frame())
    assert reply.get("id") == 1, reply
    result: dict[str, Any] = reply["result"]
    return result


def _mcp_headers(login_key: str) -> dict[str, str]:
    """The headers one authenticated MCP request carries."""
    return {
        "Authorization": f"Bearer {login_key}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


async def _open_session(http: httpx.AsyncClient, login_key: str) -> str:
    """POST the initialize handshake; return the established session id."""
    response = await http.post(
        "/mcp",
        content=json.dumps(_INITIALIZE_REQUEST),
        headers=_mcp_headers(login_key),
    )
    assert response.status_code == 200, response.text
    return response.headers["mcp-session-id"]


async def _post_mcp(
    http: httpx.AsyncClient, login_key: str, session_id: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """One authenticated request on an established session; the JSON body."""
    response = await http.post(
        "/mcp",
        content=json.dumps(payload),
        headers={**_mcp_headers(login_key), "mcp-session-id": session_id},
    )
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


async def _list_account_names(
    http: httpx.AsyncClient, login_key: str, session_id: str
) -> list[str]:
    """``imap_list_accounts`` through the gateway; the listed account names."""
    body = await _post_mcp(
        http,
        login_key,
        session_id,
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "imap_list_accounts", "arguments": {}},
        },
    )
    accounts = json.loads(body["result"]["content"][0]["text"])["accounts"]
    return [str(account["name"]) for account in accounts]


async def _child_pid(http: httpx.AsyncClient, login_key: str, session_id: str) -> int:
    """The stub child's pid (proves which process serves a session)."""
    body = await _post_mcp(
        http,
        login_key,
        session_id,
        {"jsonrpc": "2.0", "id": 3, "method": "debug/pid"},
    )
    pid = body["result"]["pid"]
    assert isinstance(pid, int)
    return pid


async def _close_session(
    http: httpx.AsyncClient, login_key: str, session_id: str
) -> None:
    """DELETE the MCP session (the client-side teardown path)."""
    response = await http.delete(
        "/mcp",
        headers={**_mcp_headers(login_key), "mcp-session-id": session_id},
    )
    assert response.status_code < 400, response.text


async def _wait_exited(host: NodeToolHost) -> int:
    """Wait until the host's child terminated; return its exit code."""
    await _eventually(lambda: host.child_returncode is not None)
    code = host.child_returncode
    assert code is not None
    return code


# --- bridge framing (verbatim, both ways) -----------------------------------------------


async def test_roundtrip_frame_is_verbatim(
    seeded_store: _SeededStore, factory: NodeToolHostFactory
) -> None:
    """A request crosses to the child and back without reinterpretation.

    Unknown parameter fields and key order survive — a schema-driven bridge
    would drop or re-shape them; this one does not touch payloads.
    """
    alice = seeded_store.by_name["alice"]
    host = await factory.create(alice.metadata, "sess-frame")
    try:
        params: dict[str, Any] = {
            "arguments": {"z": 1, "a": "münchen ✓", "nested": {"k": [1, 2]}},
            "unknown_future_field": {"x": True},
        }
        request = {"jsonrpc": "2.0", "id": 7, "method": "debug/echo", "params": params}
        await host.send_frame(json.dumps(request))
        raw_reply = await host.receive_frame()
        assert "\n" not in raw_reply  # exactly one frame per line, both ways
        reply = json.loads(raw_reply)
        assert reply["id"] == 7
        echo: dict[str, Any] = reply["result"]["echo"]
        assert echo["method"] == "debug/echo"
        echo_params: dict[str, Any] = echo["params"]
        assert echo_params == params  # value-for-value ...
        assert list(echo_params) == list(params)  # ... key order preserved ...
        assert list(echo_params["arguments"]) == list(params["arguments"])  # nested
    finally:
        await host.aclose()


async def test_notification_forwards_both_ways(
    seeded_store: _SeededStore, factory: NodeToolHostFactory
) -> None:
    """A notification (no id) crosses untouched; nothing is synthesized."""
    alice = seeded_store.by_name["alice"]
    host = await factory.create(alice.metadata, "sess-notification")
    try:
        await host.send_frame(
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})
        )
        ack = json.loads(await host.receive_frame())
        assert ack == {
            "jsonrpc": "2.0",
            "method": "notifications/stub-ack",
            "params": {"received": "notifications/initialized"},
        }
        assert "id" not in ack  # an outbound notification, not a fake response
    finally:
        await host.aclose()


async def test_tools_call_reads_only_the_calling_users_store(
    seeded_store: _SeededStore, factory: NodeToolHostFactory
) -> None:
    """``imap_list_accounts`` resolves through the per-user ``$HOME`` hinge.

    The stub reads ``$HOME/.imap-mcp/accounts.json`` exactly as unmodified
    upstream would; the ``.imap-mcp`` symlink is the tool host's hinge onto
    the gateway's per-user ``imap-store`` directory.
    """
    paths = seeded_store.paths
    alice = seeded_store.by_name["alice"]
    host = await factory.create(alice.metadata, "sess-store")
    try:
        link = paths.user_dir(alice.metadata.id) / ".imap-mcp"
        assert link.is_symlink()
        assert link.resolve() == paths.user_imap_store_dir(alice.metadata.id).resolve()
        result = await _call(
            host, "tools/call", {"name": "imap_list_accounts", "arguments": {}}
        )
        payload = json.loads(result["content"][0]["text"])
        assert payload == {
            "accounts": [{"id": alice.account_id, "name": "alice-personal"}]
        }
    finally:
        await host.aclose()


# --- environment allowlist ----------------------------------------------------------------


async def test_child_env_is_the_exact_allowlist(
    seeded_store: _SeededStore, factory: NodeToolHostFactory
) -> None:
    """The child env is EXACTLY the six allowlisted variables — no parent
    secrets, no ``DATA_DIR/config``, no wrap-key/admin-hash paths, no keys."""
    paths = seeded_store.paths
    alice = seeded_store.by_name["alice"]
    host = await factory.create(alice.metadata, "sess-env")
    try:
        env = (await _call(host, "debug/env"))["env"]
        assert set(env) == {
            "HOME",
            "IMAP_DOWNLOAD_DIR",
            "IMAP_UPLOAD_TTL_MS",
            "IMAP_MAX_UPLOAD_SIZE",
            "PATH",
            "LANG",
        }
        assert env["HOME"] == str(paths.user_dir(alice.metadata.id).resolve())
        assert env["IMAP_DOWNLOAD_DIR"] == str(
            paths.user_mail_dir(alice.metadata.id).resolve()
        )
        assert env["IMAP_UPLOAD_TTL_MS"] == "3600000"
        assert env["IMAP_MAX_UPLOAD_SIZE"] == "26214400"
        assert env["LANG"] == "C.UTF-8"
        assert env["PATH"] == os.environ.get("PATH", "")
        dumped = json.dumps(env)
        for forbidden in (
            str(paths.config_dir()),
            "admin-key.hash",
            "wrap.key",
            alice.login_key,
        ):
            assert forbidden not in dumped
    finally:
        await host.aclose()


# --- teardown, idle timeout, orphan cleanup ------------------------------------------------


async def test_aclose_sigterms_child_cleans_keyfile_and_empties_registry(
    seeded_store: _SeededStore,
) -> None:
    """Teardown: SIGTERM (not SIGKILL), keyfile gone, registry empty; idempotent."""
    paths = seeded_store.paths
    alice = seeded_store.by_name["alice"]
    factory = NodeToolHostFactory(settings=_stub_settings(paths), paths=paths)
    host = cast(NodeToolHost, await factory.create(alice.metadata, "sess-teardown"))
    key_path = key_file_path(paths, alice.metadata.id)
    assert key_path.is_file()  # materialized for the session's lifetime
    await _call(host, "debug/echo", {"ping": True})  # the bridge works while alive

    await host.aclose()

    assert host.child_returncode == -signal.SIGTERM
    assert not key_path.exists()
    assert len(factory.registry) == 0
    await host.aclose()  # idempotent: the second close changes nothing
    assert host.child_returncode == -signal.SIGTERM
    assert await host.receive_frame() == ""  # EOF: nothing more is coming


async def test_idle_timeout_sigterms_child_and_empties_registry(
    seeded_store: _SeededStore,
) -> None:
    """An idle session is SIGTERMed; the child is freed and the registry empties."""
    paths = seeded_store.paths
    alice = seeded_store.by_name["alice"]
    factory = NodeToolHostFactory(
        settings=_stub_settings(paths, idle_timeout_seconds=0), paths=paths
    )
    host = cast(NodeToolHost, await factory.create(alice.metadata, "sess-idle"))

    assert await _wait_exited(host) == -signal.SIGTERM
    assert len(factory.registry) == 0
    assert not key_file_path(paths, alice.metadata.id).exists()
    await host.aclose()  # post-mortem close stays a safe no-op
    assert await host.receive_frame() == ""


async def test_bridge_activity_resets_the_idle_deadline(
    seeded_store: _SeededStore,
) -> None:
    """Exchanging frames keeps the session alive past the original deadline."""
    paths = seeded_store.paths
    factory = NodeToolHostFactory(
        settings=_stub_settings(paths, idle_timeout_seconds=1), paths=paths
    )
    host = cast(
        NodeToolHost,
        await factory.create(seeded_store.by_name["alice"].metadata, "sess-activity"),
    )
    try:
        await asyncio.sleep(0.5)
        await _call(host, "debug/echo", {"ping": True})  # activity ≈ t+0.5s
        await asyncio.sleep(0.7)  # t ≈ 1.2s — past the unreset 1.0s deadline
        assert host.child_returncode is None  # alive: the exchange reset it
    finally:
        await host.aclose()


async def test_nonzero_idle_timeout_fires_after_the_elapsed_deadline(
    seeded_store: _SeededStore,
    host_log_lines: list[str],
) -> None:
    """A non-zero idle timeout takes the watchdog's sleep-then-fire path.

    Distinct from the ``idle_timeout_seconds=0`` teardown (which fires on the
    watchdog's very first wake, before it ever sleeps): with a non-zero
    timeout the watchdog sleeps the computed ``remaining``, wakes, recomputes
    the idle span, and only then SIGTERMs — so the child is verifiably alive
    before the deadline, and the log names the non-zero value that fired.
    The 2s deadline keeps a ~1.5s margin around the 0.5s alive-check so a
    loaded runner cannot turn the liveness assertion into a flake.
    """
    paths = seeded_store.paths
    alice = seeded_store.by_name["alice"]
    factory = NodeToolHostFactory(
        settings=_stub_settings(paths, idle_timeout_seconds=2), paths=paths
    )
    host = cast(NodeToolHost, await factory.create(alice.metadata, "sess-idle-nz"))
    try:
        await asyncio.sleep(0.5)
        assert host.child_returncode is None  # alive: the deadline has not elapsed
        assert await _wait_exited(host) == -signal.SIGTERM  # the watchdog fired
    finally:
        await host.aclose()  # post-mortem close stays a safe no-op
    await _eventually(lambda: len(factory.registry) == 0)
    assert len(factory.registry) == 0
    assert not key_file_path(paths, alice.metadata.id).exists()
    assert any("idle timeout (2s)" in line for line in host_log_lines)


async def test_concurrent_same_user_sessions_keep_the_shared_keyfile(
    seeded_store: _SeededStore, factory: NodeToolHostFactory
) -> None:
    """One user's concurrent sessions share ``imap-store/.key`` — refcounted.

    Closing session A must not delete the keyfile session B's child relies
    on; the file goes away exactly when the LAST session of the user ends.
    """
    paths = seeded_store.paths
    alice = seeded_store.by_name["alice"]
    key_path = key_file_path(paths, alice.metadata.id)
    host_a = cast(NodeToolHost, await factory.create(alice.metadata, "sess-a1"))
    host_b = cast(NodeToolHost, await factory.create(alice.metadata, "sess-a2"))
    assert len(factory.registry) == 2
    assert key_path.is_file()

    await host_a.aclose()

    assert host_a.child_returncode == -signal.SIGTERM
    assert key_path.is_file()  # B still runs: the shared keyfile stays
    assert len(factory.registry) == 1
    # B's child keeps serving through its session (the key it boots with is
    # the same AEK hex the shared file holds).
    result = await _call(
        host_b, "tools/call", {"name": "imap_list_accounts", "arguments": {}}
    )
    assert json.loads(result["content"][0]["text"]) == {
        "accounts": [{"id": alice.account_id, "name": "alice-personal"}]
    }

    await host_b.aclose()

    assert host_b.child_returncode == -signal.SIGTERM
    assert not key_path.exists()  # last session out removes it
    assert len(factory.registry) == 0


async def test_teardown_cleanup_runs_even_when_child_termination_fails(
    seeded_store: _SeededStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The terminal cleanup steps are guaranteed even if termination raises.

    Regression pin for the ``finally`` in ``_teardown``: a failing
    ``_terminate_child`` must still remove the keyfile and unregister the
    session — a lingering plaintext ``.key`` or a stuck registry entry would
    be a security/lifecycle regression this pin catches.
    """
    paths = seeded_store.paths
    alice = seeded_store.by_name["alice"]
    factory = NodeToolHostFactory(settings=_stub_settings(paths), paths=paths)
    host = cast(NodeToolHost, await factory.create(alice.metadata, "sess-failclose"))
    key_path = key_file_path(paths, alice.metadata.id)
    assert key_path.is_file()

    real_terminate = NodeToolHost._terminate_child

    async def failing_terminate(self: NodeToolHost) -> None:
        # The child IS reaped, then the step "fails" (e.g. a wait()/kill()
        # error) — exactly the partial-failure shape the finally must survive.
        await real_terminate(self)
        raise ProcessLookupError("bookkeeping failure after the child died")

    monkeypatch.setattr(NodeToolHost, "_terminate_child", failing_terminate)

    await host.aclose()  # best-effort: the failure is logged, not surfaced

    assert host.child_returncode == -signal.SIGTERM  # the child was reaped
    assert not key_path.exists()  # the keyfile never outlives the teardown
    assert len(factory.registry) == 0  # the entry never gets stuck


async def test_last_stderr_line_before_exit_reaches_the_log(
    seeded_store: _SeededStore,
    factory: NodeToolHostFactory,
    host_log_lines: list[str],
) -> None:
    """Stderr written right before the child exits is flushed, not discarded.

    The teardown gives the relay a bounded flush window after the child is
    reaped (boot-failure diagnostics arrive exactly there).
    """
    alice = seeded_store.by_name["alice"]
    prefix = f"[mcp:{alice.metadata.id}]"
    host = cast(NodeToolHost, await factory.create(alice.metadata, "sess-stderr-exit"))
    await host.send_frame(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "debug/stderr",
                "params": {"text": "dying-words", "exit": True},
            }
        )
    )
    assert await host.receive_frame() == ""  # the child exited without replying
    await host.aclose()  # the flush window runs here
    await _eventually(
        lambda: any("dying-words" in line for line in host_log_lines)
    )
    assert any(f"{prefix} dying-words" in line for line in host_log_lines)


async def test_relative_data_dir_still_yields_absolute_home_and_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A relative ``DATA_DIR`` must not break the child's HOME or the hinge.

    The env values and the stored symlink target are resolved to absolute
    paths, so a relative ``DATA_DIR`` cannot make the child (or the link)
    resolve against an arbitrary working directory.
    """
    monkeypatch.chdir(tmp_path)
    paths = build_paths(Path("rel-data"))
    ensure_wrap_key(paths)  # no-op: the module holder is already loaded
    record, _login_key = create_user(paths, "rela")
    activate_aek(paths, record.id)
    factory = NodeToolHostFactory(settings=_stub_settings(paths), paths=paths)
    host = await factory.create(UserMetadata.from_record(record), "sess-rel")
    try:
        env = (await _call(host, "debug/env"))["env"]
        assert env["HOME"] == str(paths.user_dir(record.id).resolve())
        link = paths.user_dir(record.id) / ".imap-mcp"
        assert link.is_symlink()
        stored_target = os.readlink(link)
        assert Path(stored_target).is_absolute()
        assert Path(stored_target) == paths.user_imap_store_dir(record.id).resolve()
    finally:
        await host.aclose()


async def test_guidance_host_notification_and_repeat_frames_are_dropped(
    seeded_store: _SeededStore, factory: NodeToolHostFactory
) -> None:
    """The guidance host's non-answer branches: notifications end the session
    immediately (no synthesized reply); frames after the first answer are
    dropped (exactly one guidance error is ever queued)."""
    paths = seeded_store.paths
    notification_host = await factory.create(
        UserMetadata.from_record(create_user(paths, "erin")[0]), "sess-guidance-n"
    )
    await notification_host.send_frame(
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})
    )
    assert await notification_host.receive_frame() == ""  # prompt EOF, no reply
    await notification_host.aclose()

    answered_host = await factory.create(
        UserMetadata.from_record(create_user(paths, "finn")[0]), "sess-guidance-r"
    )
    await answered_host.send_frame(
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    )
    first = json.loads(await answered_host.receive_frame())
    assert first["id"] == 1 and "error" in first
    await answered_host.send_frame(
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    )
    # The queued EOF marker comes back (after the reply was delivered): no
    # second reply was ever synthesized for the dropped frame.
    assert await answered_host.receive_frame() == ""
    await answered_host.aclose()


async def test_shutdown_drain_racing_start_fails_closed_and_reaps(
    seeded_store: _SeededStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A drain that races the in-flight spawn reaps the fresh child anyway.

    Regression pin: the drain's teardown ran while ``create_subprocess_exec``
    was still in flight (it saw no process yet) — the freshly spawned child
    must never leak: the finishing teardown SIGTERMs it, removes the keyfile,
    and ``create`` fails closed (the gateway answers its 500 shape).
    """
    paths = seeded_store.paths
    alice = seeded_store.by_name["alice"]
    factory = NodeToolHostFactory(settings=_stub_settings(paths), paths=paths)
    spawn_entered = asyncio.Event()
    release_spawn = asyncio.Event()
    real_exec = asyncio.create_subprocess_exec

    async def gated_exec(*args: Any, **kwargs: Any) -> asyncio.subprocess.Process:
        """Park the spawn in flight until the race scenario releases it."""
        spawn_entered.set()
        await release_spawn.wait()
        return await real_exec(*args, **kwargs)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", gated_exec)
    create_task = asyncio.create_task(factory.create(alice.metadata, "sess-race"))
    await _eventually(spawn_entered.is_set)
    entry = factory.registry.get("sess-race")
    assert entry is not None  # self-registered before the first await
    host = cast(NodeToolHost, entry.host)

    await factory.shutdown()  # the drain runs while the spawn is in flight
    assert len(factory.registry) == 0

    release_spawn.set()
    with pytest.raises(RuntimeError, match="tool host torn down while starting"):
        await create_task

    assert host.child_returncode == -signal.SIGTERM  # fresh child reaped
    assert not key_file_path(paths, alice.metadata.id).exists()
    assert len(factory.registry) == 0


async def test_cleanup_orphans_removes_stale_key_files(
    seeded_store: _SeededStore, factory: NodeToolHostFactory
) -> None:
    """The startup sweep deletes crash-leftover ``.key`` files — only those."""
    paths = seeded_store.paths
    alice = seeded_store.by_name["alice"]
    bruno = seeded_store.by_name["bruno"]
    materialize_key_file(paths, alice.metadata.id, "a" * 64)  # crash leftover
    assert key_file_path(paths, alice.metadata.id).is_file()

    swept = factory.registry.cleanup_orphans()

    assert swept == [alice.metadata.id]
    assert not key_file_path(paths, alice.metadata.id).exists()
    # Bruno's store (no stale key) is untouched and unreported.
    assert paths.user_imap_store_dir(bruno.metadata.id).is_dir()
    assert bruno.metadata.id not in swept
    # A data dir without a users root sweeps nothing.
    empty = SessionRegistry(build_paths(Path(paths.data_dir) / "empty-root"))
    assert empty.cleanup_orphans() == []


# --- fail-closed AEK gate ----------------------------------------------------------------


async def test_aek_inactive_user_gets_the_structured_guidance(
    seeded_store: _SeededStore, factory: NodeToolHostFactory
) -> None:
    """No activated AEK → a fail-closed host that ANSWERS with the guidance.

    No child is spawned, no keyfile materialized, nothing registered; the
    host answers the first request with the one structured JSON-RPC error
    (the guidance message) and then signals EOF so the session ends.
    """
    paths = seeded_store.paths
    record, _login_key = create_user(paths, "carol")  # never activated
    host = await factory.create(UserMetadata.from_record(record), "sess-inactive")

    await host.send_frame(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {}},
            }
        )
    )
    reply = json.loads(await host.receive_frame())

    assert reply == {
        "jsonrpc": "2.0",
        "id": 5,
        "error": {
            "code": AEK_INACTIVE_ERROR_CODE,
            "message": "initialize account encryption in the web UI first",
        },
    }
    assert await host.receive_frame() == ""  # EOF: the session ends
    assert len(factory.registry) == 0  # nothing was ever registered
    assert not key_file_path(paths, record.id).exists()
    assert not (paths.user_dir(record.id) / ".imap-mcp").exists()
    await host.aclose()  # teardown stays a safe no-op


async def test_aek_inactive_guidance_via_gateway_is_200_not_500(
    seeded_store: _SeededStore, factory: NodeToolHostFactory
) -> None:
    """Through the production app, the guidance reaches the MCP client.

    The initialize POST answers 200 with the structured JSON-RPC error (the
    guidance message, id echoed) — NOT the generic 500 — and the session is
    gone afterwards (the EOF teardown discarded it).
    """
    paths = seeded_store.paths
    record, login_key = create_user(paths, "dora")  # never activated
    app: FastAPI = create_app(
        Settings(data_dir=paths.data_dir),
        tool_host_factory=factory,
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
        response = await http.post(
            "/mcp",
            content=json.dumps(_INITIALIZE_REQUEST),
            headers=_mcp_headers(login_key),
        )

        assert response.status_code == 200  # guidance, not the generic 500
        body = response.json()
        assert body["jsonrpc"] == "2.0"
        assert body["id"] == 1
        assert body["error"]["code"] == AEK_INACTIVE_ERROR_CODE
        assert body["error"]["message"] == (
            "initialize account encryption in the web UI first"
        )
        assert login_key not in response.text  # no key material echoes
        session_id = response.headers["mcp-session-id"]
        assert len(factory.registry) == 0  # no child ever existed

        # The EOF teardown discarded the session: a stale id answers 404.
        stale = {**_mcp_headers(login_key), "mcp-session-id": session_id}

        async def session_gone() -> bool:
            follow_up = await http.post(
                "/mcp", content=json.dumps(_INITIALIZE_REQUEST), headers=stale
            )
            return follow_up.status_code == 404

        await _eventually_async(session_gone)


# --- stderr relay -------------------------------------------------------------------------


async def test_stderr_relay_prefixes_and_sanitizes(
    seeded_store: _SeededStore,
    factory: NodeToolHostFactory,
    host_log_lines: list[str],
) -> None:
    """Child stderr is logged under ``[mcp:<userId>]``, one line per record.

    An embedded newline must not forge a second log line: every fragment
    rides behind the session's own tag, and no line renders with a
    ``[security]`` TAG slot.
    """
    alice = seeded_store.by_name["alice"]
    prefix = f"[mcp:{alice.metadata.id}]"
    host = await factory.create(alice.metadata, "sess-stderr")
    try:
        await _call(host, "debug/stderr", {"text": "hello-from-stub-child"})
        await _eventually(
            lambda: any("hello-from-stub-child" in line for line in host_log_lines)
        )
        assert any(f"{prefix} hello-from-stub-child" in line for line in host_log_lines)

        await _call(host, "debug/stderr", {"text": "FORGED\n[security] leaked-secret"})
        await _eventually(lambda: any("FORGED" in line for line in host_log_lines))
        await asyncio.sleep(0.05)  # let the second fragment land too
        forged = [
            line
            for line in host_log_lines
            if "FORGED" in line or "leaked-secret" in line
        ]
        assert forged
        for line in forged:
            assert prefix in line  # the tag slot stays mcp:<userId>
        assert not any(re.search(r" INFO \[security\]", line) for line in host_log_lines)

        # Control characters WITHIN one line (no newline) must be flattened —
        # the newline case above would pass even with a plain decode.
        await _call(host, "debug/stderr", {"text": "bad\x1b[31mcolor\rbad"})
        await _eventually(
            lambda: any("bad" in line and "[31mcolor" in line for line in host_log_lines)
        )
        flattened = [
            line for line in host_log_lines if "[31mcolor" in line
        ]
        assert flattened
        for line in flattened:
            assert "\x1b" not in line and "\r" not in line  # controls flattened
            assert prefix in line
    finally:
        await host.aclose()


# --- acceptance: two concurrent users through the production app --------------------------


async def test_two_users_see_only_their_own_accounts_via_gateway(
    seeded_store: _SeededStore, factory: NodeToolHostFactory
) -> None:
    """Users A and B hold concurrent sessions; each lists only their own account.

    Full production surface: ``create_app`` + the real ``NodeToolHostFactory``
    (spawn config pointed at the stub), header auth, two distinct children,
    interleaved tool calls, and per-session teardown emptying the registry.
    """
    paths = seeded_store.paths
    alice = seeded_store.by_name["alice"]
    bruno = seeded_store.by_name["bruno"]
    app: FastAPI = create_app(
        Settings(data_dir=paths.data_dir),
        tool_host_factory=factory,
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
        alice_session = await _open_session(http, alice.login_key)
        bruno_session = await _open_session(http, bruno.login_key)
        assert len(factory.registry) == 2  # two live sessions at once
        alice_pid = await _child_pid(http, alice.login_key, alice_session)
        bruno_pid = await _child_pid(http, bruno.login_key, bruno_session)
        assert alice_pid != bruno_pid  # two distinct children — never shared

        for _ in range(2):  # interleaved: isolation holds on every call
            assert await _list_account_names(http, alice.login_key, alice_session) == [
                "alice-personal"
            ]
            assert await _list_account_names(
                http, bruno.login_key, bruno_session
            ) == ["bruno-personal"]

        await _close_session(http, alice.login_key, alice_session)
        await _close_session(http, bruno.login_key, bruno_session)
    await _eventually(lambda: len(factory.registry) == 0)
    assert len(factory.registry) == 0
    assert not key_file_path(paths, alice.metadata.id).exists()
    assert not key_file_path(paths, bruno.metadata.id).exists()


async def test_boot_lifespan_drains_sessions_on_shutdown(
    seeded_store: _SeededStore, factory: NodeToolHostFactory
) -> None:
    """Container shutdown (the boot lifespan) drains every live session."""
    paths = seeded_store.paths
    alice = seeded_store.by_name["alice"]
    assert factory.registry.cleanup_orphans() == []  # startup sweep: clean here
    app: FastAPI = create_app(
        Settings(data_dir=paths.data_dir),
        lifespan=_boot_lifespan(paths, factory),
        tool_host_factory=factory,
    )
    session_host: NodeToolHost | None = None
    async with _boot_lifespan(paths, factory)(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as http:
            session_id = await _open_session(http, alice.login_key)
            entry = factory.registry.get(session_id)
            assert entry is not None
            session_host = cast(NodeToolHost, entry.host)
            assert len(factory.registry) == 1
    # The lifespan's shutdown drain ran: child freed, registry empty, key gone.
    assert session_host is not None
    assert await _wait_exited(session_host) == -signal.SIGTERM
    assert len(factory.registry) == 0
    assert not key_file_path(paths, alice.metadata.id).exists()


async def test_boot_lifespan_factory_branch_sweeps_orphan_key_files(
    seeded_store: _SeededStore,
    factory: NodeToolHostFactory,
    boot_log_lines: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The boot lifespan's factory branch sweeps orphans THROUGH the registry.

    Regression pin for the folded-in M05-T02 branch (``app._boot_lifespan``'s
    ``tool_host_factory is not None`` path): with the tool-host factory wired
    exactly as production wires it, the startup orphan sweep must run via the
    factory's own session registry (exactly once), delete the stale
    crash-leftover keyfile, and emit the single ``[config] swept ...`` line.
    """
    paths = seeded_store.paths
    alice = seeded_store.by_name["alice"]
    materialize_key_file(paths, alice.metadata.id, "c" * 64)  # crash leftover
    key_path = key_file_path(paths, alice.metadata.id)
    assert key_path.is_file()

    swept_registries: list[SessionRegistry] = []
    real_cleanup = SessionRegistry.cleanup_orphans

    def spy(self: SessionRegistry) -> list[str]:
        swept_registries.append(self)
        return real_cleanup(self)

    monkeypatch.setattr(SessionRegistry, "cleanup_orphans", spy)
    app: FastAPI = create_app(
        Settings(data_dir=paths.data_dir),
        lifespan=_boot_lifespan(paths, factory),
        tool_host_factory=factory,
    )
    async with _boot_lifespan(paths, factory)(app):
        assert not key_path.exists()  # swept during lifespan startup
    assert swept_registries == [factory.registry]  # once, via the registry
    swept_lines = [
        line
        for line in boot_log_lines
        if "swept orphaned session key file(s)" in line
    ]
    assert len(swept_lines) == 1


# --- the registry itself --------------------------------------------------------------------


class _DummyHost:
    """Structural :class:`ToolHost` stand-in for registry unit tests."""

    async def send_frame(self, frame: str) -> None:
        """Unused."""

    async def receive_frame(self) -> str:
        """Unused; ``""`` is the EOF sentinel."""
        return ""

    async def aclose(self) -> None:
        """Unused."""


def test_registry_is_keyed_by_session_and_user(seeded_store: _SeededStore) -> None:
    """Entries are keyed by (session id, user id); wrong-pair removal refuses."""
    registry = SessionRegistry(seeded_store.paths)
    alice_id = seeded_store.by_name["alice"].metadata.id
    bruno_id = seeded_store.by_name["bruno"].metadata.id
    registry.register("sess-1", alice_id, _DummyHost())
    registry.register("sess-2", bruno_id, _DummyHost())
    assert len(registry) == 2
    entry = registry.get("sess-1")
    assert entry is not None and entry.user_id == alice_id

    # Removing with the WRONG user pair is refused and keeps the entry.
    assert registry.remove("sess-1", bruno_id) is False
    assert len(registry) == 2
    assert registry.remove("sess-1", alice_id) is True
    assert registry.remove("sess-1", alice_id) is False  # idempotent
    assert len(registry) == 1

    # A duplicate live registration is a bug and fails loud.
    with pytest.raises(RuntimeError):
        registry.register("sess-2", bruno_id, _DummyHost())


def test_aek_guidance_constant_is_the_milestone_message() -> None:
    """The guidance string and its JSON-RPC error code are pinned."""
    assert AEK_INACTIVE_GUIDANCE == "initialize account encryption in the web UI first"
    assert AEK_INACTIVE_ERROR_CODE == -32000  # implementation-defined range
