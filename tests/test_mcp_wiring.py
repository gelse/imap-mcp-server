"""Production-app wiring tests for the ``/mcp`` gateway (M05-T01 amendment).

``tests/test_mcp_auth.py`` exercises the gateway sub-app on a minimal
mounting app; this module pins the WIRING on the real production app from
:func:`imap_mcp_gateway.web.server.create_app`:

1. **Route shape** — the gateway is attached as exactly ONE exact-path
   ``Route`` (never a ``Mount``: ``Mount`` compiles to ``/mcp/{path}`` and
   would 307-redirect ``/mcp`` to ``/mcp/`` before the auth gate runs);
2. **The gap-closing gate** — an unauthenticated ``POST /mcp`` on the
   production app reaches the gateway's auth gate (401), not the router's
   unmatched-route 404;
3. **Auth matrix against the production app** — every failure identity is
   the identical uniform 401, no key echo, and the factory is never asked
   to create a host;
4. **``X-Api-Key`` handshake** — the alternative header form works against
   the production app; the factory receives exactly one
   ``create(user, session_id)`` with the credential-free ``UserMetadata``;
5. **Placeholder fail-closed** — with no factory supplied, an authenticated
   initialize answers 500 JSON-RPC "Tool host failed to start" (the M05-T02
   drop-in sentinel), never a half-open session;
6. **Verbatim handshake with a real factory** — the production surface
   completes the MCP initialize handshake with verbatim frames both ways
   (the M05-T02 drop-in proof).

Same in-process pattern as tests/test_mcp_auth.py: ``httpx.AsyncClient``
over an ASGI transport; the M05-T02 ``ToolHost``/``ToolHostFactory``
Protocols are doubled in pure Python (no Node here — language boundary).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from mcp_types import INTERNAL_ERROR
from starlette.routing import Mount, Route

from imap_mcp_gateway.config.env import Settings
from imap_mcp_gateway.config.paths import Paths, build_paths
from imap_mcp_gateway.crypto.hash import hash_secret
from imap_mcp_gateway.crypto.keys import generate_admin_key
from imap_mcp_gateway.mcp.gateway import MCPGateway, ToolHost
from imap_mcp_gateway.store.admin_key import save_admin_key_hash
from imap_mcp_gateway.store.user_schema import UserMetadata
from imap_mcp_gateway.store.users import create_user, disable_user
from imap_mcp_gateway.web.server import create_app

# --- the JSON-RPC frames -------------------------------------------------------------


_INITIALIZE_REQUEST: dict[str, Any] = {
    "jsonrpc": "2.0",
    "id": 7,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {"roots": {"listChanged": True}},
        "clientInfo": {"name": "wiring-probe", "version": "0.0.0"},
    },
}


def _host_initialize_reply(request: dict[str, Any]) -> str:
    """The upstream-shaped initialize result a tool host would emit (id echoed)."""
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "imap-mcp-server", "version": "2.2.0"},
            },
        }
    )


# --- the tool host / factory doubles (the M05-T02 seam) ------------------------------


class _HandshakeHost:
    """In-memory :class:`ToolHost` double: records frames, answers initialize."""

    def __init__(self) -> None:
        self.received_frames: list[str] = []
        self.closed = False
        self._outbound: asyncio.Queue[str] = asyncio.Queue()

    async def send_frame(self, frame: str) -> None:
        assert not self.closed, "frame sent to a closed fake host"
        self.received_frames.append(frame)
        request = json.loads(frame)
        if request.get("method") == "initialize":
            self._outbound.put_nowait(_host_initialize_reply(request))

    async def receive_frame(self) -> str:
        return await self._outbound.get()  # "" is the EOF sentinel

    async def aclose(self) -> None:
        if self.closed:
            return
        self.closed = True
        self._outbound.put_nowait("")


class _RecordingToolHostFactory:
    """:class:`ToolHostFactory` double that records every ``create`` call."""

    def __init__(self) -> None:
        self.created: list[tuple[UserMetadata, str]] = []
        self.hosts: list[_HandshakeHost] = []

    @property
    def call_count(self) -> int:
        return len(self.created)

    async def create(self, user: UserMetadata, session_id: str) -> ToolHost:
        self.created.append((user, session_id))
        host = _HandshakeHost()
        self.hosts.append(host)
        return host


# --- fixtures: store, apps, clients ---------------------------------------------------


@pytest.fixture(scope="module")
def wiring_registry(tmp_path_factory: pytest.TempPathFactory) -> tuple[Paths, str, str, str]:
    """A store with one active user, one disabled user, and the admin key.

    Returns ``(paths, alice_key, dana_key, admin_key)``. Module-scoped because
    scrypt runs per user/key; the one mutation (disabling dana) is permanent
    for this module.
    """
    paths = build_paths(tmp_path_factory.mktemp("mcp-wiring"))
    _alice_record, alice_key = create_user(paths, "alice")
    dana_record, dana_key = create_user(paths, "dana")
    disable_user(paths, dana_record.id)
    admin_key = generate_admin_key()
    save_admin_key_hash(paths, hash_secret(admin_key))
    return paths, alice_key, dana_key, admin_key


@pytest.fixture
def factory() -> _RecordingToolHostFactory:
    """A fresh factory (fresh session/host state) per test."""
    return _RecordingToolHostFactory()


@pytest.fixture
def app(
    wiring_registry: tuple[Paths, str, str, str],
    factory: _RecordingToolHostFactory,
) -> FastAPI:
    """The production app with the real (fake-doubled) factory wired in."""
    paths, _alice_key, _dana_key, _admin_key = wiring_registry
    return create_app(
        Settings(data_dir=paths.data_dir), tool_host_factory=factory
    )


@pytest.fixture
def placeholder_app(wiring_registry: tuple[Paths, str, str, str]) -> FastAPI:
    """The production app WITHOUT a factory: the fail-closed placeholder."""
    paths, _alice_key, _dana_key, _admin_key = wiring_registry
    return create_app(Settings(data_dir=paths.data_dir))


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http


@pytest.fixture
async def placeholder_client(
    placeholder_app: FastAPI,
) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=placeholder_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http


# --- helpers ---------------------------------------------------------------------------


async def _post_initialize(
    client: httpx.AsyncClient, headers: dict[str, str] | None = None
) -> httpx.Response:
    """POST one raw initialize frame to /mcp as an MCP client would."""
    request_headers: dict[str, str] = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if headers:
        request_headers.update(headers)
    return await client.post(
        "/mcp", content=json.dumps(_INITIALIZE_REQUEST), headers=request_headers
    )


async def _eventually(condition: Callable[[], bool], *, timeout: float = 2.0) -> None:
    """Poll a condition — bridges the gateway's asynchronous bridge pumping."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not condition():
        if loop.time() > deadline:
            raise AssertionError("condition not met within timeout")
        await asyncio.sleep(0.01)


# --- 1. route shape: one exact-path Route, never a Mount --------------------------------


def test_create_app_mounts_mcp_as_exact_path_route(app: FastAPI) -> None:
    """The gateway is ONE exact-path ``Route`` — no ``Mount`` for ``/mcp``.

    ``Mount("/mcp", ...)`` compiles to ``/mcp/{path}``: a request to exactly
    ``/mcp`` would be answered ``307 -> /mcp/`` by the router BEFORE the
    gateway (and its auth gate) ever ran.
    """
    mcp_routes = [r for r in app.router.routes if isinstance(r, Route) and r.path == "/mcp"]

    assert len(mcp_routes) == 1
    assert isinstance(mcp_routes[0].app, MCPGateway)  # the route serves the gateway
    assert mcp_routes[0].methods is None  # every method reaches the gateway's own 405
    assert not [
        r for r in app.router.routes if isinstance(r, Mount) and r.path == "/mcp"
    ]


# --- 2. the gap-closing gate: 401, not the router's 404 ----------------------------------


async def test_create_app_unauthenticated_post_to_mcp_returns_401_not_404(
    client: httpx.AsyncClient,
) -> None:
    """On the production app, a keyless POST /mcp hits the gateway's auth gate."""
    response = await _post_initialize(client)

    assert response.status_code == 401
    assert response.json() == {"error": "unauthorized"}


# --- 3. the auth matrix against the production app ----------------------------------------

_FAILURE_CASES = (
    "missing-key",
    "wrong-user-key",
    "admin-key-bearer",
    "admin-key-x-api-key",
    "disabled-user-key",
    "malformed-bearer-double-space",
    "non-bearer-scheme",
    "empty-api-key",
)


def _failure_headers(
    case: str, wiring_registry: tuple[Paths, str, str, str]
) -> dict[str, str] | None:
    """The presented credentials for one auth-matrix failure case."""
    _paths, alice_key, dana_key, admin_key = wiring_registry
    return {
        "missing-key": None,
        "wrong-user-key": {"Authorization": "Bearer " + "usr_" + "F" * 43},
        "admin-key-bearer": {"Authorization": f"Bearer {admin_key}"},
        "admin-key-x-api-key": {"X-Api-Key": admin_key},
        "disabled-user-key": {"X-Api-Key": dana_key},
        # A valid key inside a malformed Bearer shape must still fail closed.
        "malformed-bearer-double-space": {"Authorization": f"Bearer  {alice_key}"},
        "non-bearer-scheme": {"Authorization": "Basic dXNlcjpwYXNz"},
        "empty-api-key": {"X-Api-Key": "   "},
    }[case]


@pytest.mark.parametrize("case", _FAILURE_CASES)
async def test_create_app_auth_matrix_against_production_app(
    client: httpx.AsyncClient,
    factory: _RecordingToolHostFactory,
    wiring_registry: tuple[Paths, str, str, str],
    case: str,
) -> None:
    """Every failure identity → the identical uniform 401; no host is created."""
    _paths, alice_key, dana_key, admin_key = wiring_registry

    response = await _post_initialize(client, _failure_headers(case, wiring_registry))

    assert response.status_code == 401, (case, response.text)
    assert response.json() == {"error": "unauthorized"}, case
    assert response.text == '{"error":"unauthorized"}', case  # one fixed body
    assert factory.call_count == 0, case  # nothing under /mcp reached the transport
    # No key material ever echoes back — not even a valid key in a bad shape.
    for secret in (alice_key, dana_key, admin_key):
        assert secret not in response.text, case


# --- 4. the X-Api-Key form against the production app -------------------------------------


async def test_create_app_x_api_key_form_works_against_production_app(
    client: httpx.AsyncClient,
    factory: _RecordingToolHostFactory,
    wiring_registry: tuple[Paths, str, str, str],
) -> None:
    """``X-Api-Key`` opens a real session on the production app; the factory
    receives exactly one credential-free ``create(user, session_id)``."""
    _paths, alice_key, _dana_key, _admin_key = wiring_registry

    response = await _post_initialize(client, {"X-Api-Key": alice_key})

    assert response.status_code == 200
    session_id = response.headers["mcp-session-id"]
    assert session_id
    assert response.json() == json.loads(_host_initialize_reply(_INITIALIZE_REQUEST))
    assert json.loads(factory.hosts[0].received_frames[0]) == _INITIALIZE_REQUEST
    assert factory.call_count == 1
    user, created_session_id = factory.created[0]
    assert user.name == "alice" and user.status == "active"
    assert not hasattr(user, "login_key_hash") and not hasattr(user, "aek")
    assert "usr_" not in user.model_dump_json()
    assert created_session_id == session_id

    await client.delete(
        "/mcp",
        headers={"X-Api-Key": alice_key, "mcp-session-id": session_id},
    )
    await _eventually(lambda: factory.hosts[0].closed)


async def test_create_app_with_placeholder_factory_returns_500_on_authenticated_initialize(
    placeholder_client: httpx.AsyncClient,
    wiring_registry: tuple[Paths, str, str, str],
) -> None:
    """With no factory supplied, an authenticated initialize fails closed."""
    _paths, alice_key, _dana_key, _admin_key = wiring_registry

    response = await _post_initialize(
        placeholder_client, {"Authorization": f"Bearer {alice_key}"}
    )

    assert response.status_code == 500
    body = response.json()
    assert body["jsonrpc"] == "2.0"
    assert body["id"] is None
    assert body["error"]["code"] == INTERNAL_ERROR
    assert body["error"]["message"] == "Tool host failed to start"
    assert alice_key not in response.text  # no key material echoes


async def test_create_app_with_real_factory_completes_handshake_verbatim(
    client: httpx.AsyncClient,
    factory: _RecordingToolHostFactory,
    wiring_registry: tuple[Paths, str, str, str],
) -> None:
    """The M05-T02 drop-in proof: with a factory plugged into ``create_app``,
    the production ``/mcp`` surface completes the initialize handshake with
    verbatim frames both ways."""
    _paths, alice_key, _dana_key, _admin_key = wiring_registry

    response = await _post_initialize(client, {"Authorization": f"Bearer {alice_key}"})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    session_id = response.headers["mcp-session-id"]
    assert session_id  # a server-side session exists
    # The response body is exactly the frame the host emitted (id echoed,
    # result verbatim) — value-for-value, nothing added or re-shaped.
    assert response.json() == json.loads(_host_initialize_reply(_INITIALIZE_REQUEST))
    assert alice_key not in response.text  # no key material echoes
    # The host received the client's frame untouched.
    assert factory.call_count == 1
    assert json.loads(factory.hosts[0].received_frames[0]) == _INITIALIZE_REQUEST
    # The factory saw exactly the calling user's credential-free identity.
    user, created_session_id = factory.created[0]
    assert user.name == "alice" and user.status == "active"
    assert not hasattr(user, "login_key_hash") and not hasattr(user, "aek")
    assert "usr_" not in user.model_dump_json()
    assert created_session_id == session_id

    await client.delete(
        "/mcp",
        headers={"Authorization": f"Bearer {alice_key}", "mcp-session-id": session_id},
    )
    await _eventually(lambda: factory.hosts[0].closed)
