"""``/mcp`` gateway tests: the header-auth matrix and verbatim JSON-RPC pass-through (M05-T01).

Coverage per the M05-T01 acceptance criteria:

1. **Auth matrix against a fake ``ToolHostFactory``** — every unauthenticated
   or non-user identity is refused before the transport: missing key, unknown
   key, the stored ADMIN key (Bearer and ``X-Api-Key`` — explicitly rejected
   on ``/mcp``), a disabled user's key, and malformed header shapes — each the
   identical uniform ``401 {"error": "unauthorized"}`` with no key echo, and
   the fake factory is never asked to create a host;
2. **Rate limiting** — presented-but-invalid attempts count; after
   ``FAILURE_LIMIT`` of them even a VALID key gets ``429`` (self-healing after
   the window), while absent credentials never consume budget;
3. **Routing before the transport** — unknown session id → 404 JSON-RPC error
   (byte-identical to a foreign session's answer: no oracle); methods outside
   GET/POST/DELETE → 405 (401 first when unauthenticated); the host-cost gate
   refuses sessionless GET/DELETE and non-initialize/malformed/oversized
   POSTs BEFORE a tool host is created;
4. **Initialize handshake as raw JSON-RPC** — Bearer and ``X-Api-Key`` forms
   complete a real MCP initialize handshake through the mounted gateway; the
   frames captured by the fake host and the response bodies are compared
   value-for-value against what the client sent / the host emitted, pinning
   verbatim pass-through (no re-serialization of ``tools/list`` payloads,
   notifications forwarded untouched);
5. **Isolation seam** — each session's host is created with exactly its
   calling user's credential-free metadata (no hash, no key material), the
   same principal is attached at ``scope["state"]["user"]``, and another
   user's valid key cannot steer (or delete) an existing session — foreign
   session ids answer the same 404 as unknown ones;
6. **Lifecycle** — DELETE closes the session and the host; a failed host
   start fails closed (500 JSON-RPC error) without poisoning the gateway;
7. **Dependency form** — ``Depends(require_user_key_header)`` over
   ``app.state.mcp_rate_limiter`` works and refuses the keyless uniformly.

The fake host/factory double the M05-T02 ``ToolHost``/``ToolHostFactory``
Protocols in pure Python (no Node here — language boundary). All HTTP tests
run in-process via ``httpx.AsyncClient`` over an ASGI transport (the pattern
of tests/test_user_auth.py).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from mcp_types import INVALID_REQUEST
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from imap_mcp_gateway.config.env import Settings
from imap_mcp_gateway.config.paths import Paths, build_paths
from imap_mcp_gateway.crypto.hash import hash_secret
from imap_mcp_gateway.crypto.keys import generate_admin_key
from imap_mcp_gateway.mcp.gateway import ToolHost, ToolHostFactory, create_mcp_gateway
from imap_mcp_gateway.store.admin_key import save_admin_key_hash
from imap_mcp_gateway.store.user_schema import UserMetadata
from imap_mcp_gateway.store.users import create_user, disable_user
from imap_mcp_gateway.web.middleware.admin_auth import (
    FAILURE_LIMIT,
    AdminHTTPError,
    AdminRateLimiter,
    admin_http_error_handler,
)
from imap_mcp_gateway.web.middleware.user_auth import (
    UserKeyHeaderDep,
    authenticate_user_key,
)

# --- the fake tool host / factory (the M05-T02 seam) -------------------------------


_INITIALIZE_REQUEST: dict[str, Any] = {
    "jsonrpc": "2.0",
    "id": 7,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {"roots": {"listChanged": True}},
        "clientInfo": {"name": "verbatim-probe", "version": "0.0.0"},
    },
}

_TOOLS_LIST_REQUEST: dict[str, Any] = {
    "jsonrpc": "2.0",
    "id": 11,
    "method": "tools/list",
    "params": {},
}

_INITIALIZED_NOTIFICATION: dict[str, Any] = {
    "jsonrpc": "2.0",
    "method": "notifications/initialized",
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


_TOOLS_LIST_REPLY = json.dumps(
    {
        "jsonrpc": "2.0",
        "id": 11,
        "result": {
            "tools": [
                {
                    "name": "imap_list_accounts",
                    "description": "Liste des comptes — ✓ unicode passes through",
                    "inputSchema": {
                        "type": "object",
                        "properties": {},
                        "additionalProperties": False,
                    },
                }
            ]
        },
    }
)


class FakeToolHost:
    """In-memory :class:`ToolHost` double: records inbound frames, answers from a script.

    ``initialize`` and ``tools/list`` get canned replies (the former echoes the
    request id); every frame is recorded. ``aclose`` enqueues an EOF sentinel
    so a pending :meth:`receive_frame` returns ``""`` — the host-died shape.
    """

    def __init__(self) -> None:
        self.received_frames: list[str] = []
        self.closed = False
        self.closed_event = asyncio.Event()
        self._outbound: asyncio.Queue[str] = asyncio.Queue()

    async def send_frame(self, frame: str) -> None:
        assert not self.closed, "frame sent to a closed fake host"
        self.received_frames.append(frame)
        request = json.loads(frame)
        if request.get("method") == "initialize":
            self._outbound.put_nowait(_host_initialize_reply(request))
        elif request.get("method") == "tools/list":
            self._outbound.put_nowait(_TOOLS_LIST_REPLY)

    async def receive_frame(self) -> str:
        return await self._outbound.get()  # "" is the EOF sentinel

    async def aclose(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.closed_event.set()
        self._outbound.put_nowait("")


class FakeToolHostFactory:
    """:class:`ToolHostFactory` double that records every ``create`` call."""

    def __init__(self) -> None:
        self.created: list[tuple[UserMetadata, str]] = []
        self.hosts: list[FakeToolHost] = []
        self.fail_next: Exception | None = None

    @property
    def call_count(self) -> int:
        return len(self.created)

    async def create(self, user: UserMetadata, session_id: str) -> ToolHost:
        if self.fail_next is not None:
            failure, self.fail_next = self.fail_next, None  # fails exactly once
            raise failure
        self.created.append((user, session_id))
        host = FakeToolHost()
        self.hosts.append(host)
        return host


class _StateCapture:
    """ASGI wrapper recording the ``scope["state"]["user"]`` principal.

    Wraps the gateway exactly as a curious downstream consumer (the M05-T02
    factory seam is the intended one) would observe the isolation binding.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self.captured: list[UserMetadata] = []

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self.app(scope, receive, send)
        # Observed AFTER the wrapped gateway ran: the binding happens inside
        # its ``__call__`` (auth gate → ``scope["state"]["user"]``), so reading
        # beforehand would never see it.
        principal = scope.get("state", {}).get("user")
        if principal is not None:
            self.captured.append(principal)


# --- fixtures: store, app, client ----------------------------------------------------


class _Clock:
    """Controllable monotonic clock for rate-limiter window tests."""

    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture(scope="module")
def mcp_registry(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Paths, str, str, str, str]:
    """A store with two active users, one disabled user, and the admin key.

    Returns ``(paths, alice_key, bob_key, dana_key, admin_key)``. Module-scoped
    because scrypt runs per user/key; the one mutation (disabling dana) is
    permanent for this module.
    """
    paths = build_paths(tmp_path_factory.mktemp("mcp-auth"))
    _alice_record, alice_key = create_user(paths, "alice")
    _bob_record, bob_key = create_user(paths, "bob")
    dana_record, dana_key = create_user(paths, "dana")
    disable_user(paths, dana_record.id)
    admin_key = generate_admin_key()
    save_admin_key_hash(paths, hash_secret(admin_key))
    return paths, alice_key, bob_key, dana_key, admin_key


def _gateway_app(
    paths: Paths,
    factory: FakeToolHostFactory,
    *,
    rate_limiter: AdminRateLimiter | None = None,
) -> FastAPI:
    """A minimal mounting app: settings + error handler + the gateway at /mcp.

    The gateway is attached as an EXACT-path ``Route`` (the SDK's own mounting
    shape) — ``app.mount("/mcp", ...)`` compiles to ``/mcp/{path}`` and
    Starlette would answer a request to exactly ``/mcp`` with a 307 redirect
    before the gateway (and its auth gate) ever runs.
    """
    app = FastAPI()
    app.state.settings = Settings(data_dir=paths.data_dir)
    app.add_exception_handler(AdminHTTPError, admin_http_error_handler)
    gateway = create_mcp_gateway(factory, rate_limiter=rate_limiter)
    app.router.routes.append(Route("/mcp", gateway))
    return app


@pytest.fixture
def factory() -> FakeToolHostFactory:
    """A fresh factory (fresh session/host state) per test."""
    return FakeToolHostFactory()


@pytest.fixture
def app(
    mcp_registry: tuple[Paths, str, str, str, str], factory: FakeToolHostFactory
) -> FastAPI:
    paths, _alice_key, _bob_key, _dana_key, _admin_key = mcp_registry
    return _gateway_app(paths, factory)


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http


# --- helpers ---------------------------------------------------------------------------


def _auth_header(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def _post_json(
    client: httpx.AsyncClient,
    body: dict[str, Any],
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """POST one raw JSON-RPC frame to /mcp as an MCP client would."""
    request_headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if headers:
        request_headers.update(headers)
    return await client.post("/mcp", content=json.dumps(body), headers=request_headers)


async def _post_initialize(
    client: httpx.AsyncClient, headers: dict[str, str] | None = None
) -> httpx.Response:
    return await _post_json(client, _INITIALIZE_REQUEST, headers)


async def _eventually(condition: Callable[[], bool], *, timeout: float = 2.0) -> None:
    """Poll a condition — bridges the gateway's asynchronous bridge pumping."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not condition():
        if loop.time() > deadline:
            raise AssertionError("condition not met within timeout")
        await asyncio.sleep(0.01)


@asynccontextmanager
async def _mcp_session(
    client: httpx.AsyncClient, factory: FakeToolHostFactory, key: str
) -> AsyncIterator[tuple[str, FakeToolHost]]:
    """Open a session via the initialize handshake; DELETE it on exit."""
    response = await _post_initialize(client, _auth_header(key))
    assert response.status_code == 200, response.text
    session_id = response.headers["mcp-session-id"]
    host = factory.hosts[-1]
    try:
        yield session_id, host
    finally:
        await client.delete("/mcp", headers=_auth_header(key) | {"mcp-session-id": session_id})


# --- 1. structural: the doubles satisfy the M05-T02 Protocols ----------------------------


def test_doubles_satisfy_the_tool_host_protocols() -> None:
    """The fakes are contract-conformant stand-ins for M05-T02's NodeToolHost."""
    assert isinstance(FakeToolHostFactory(), ToolHostFactory)
    assert isinstance(FakeToolHost(), ToolHost)


# --- 2. the initialize handshake as raw JSON-RPC (verbatim pass-through) ------------------


async def test_bearer_key_performs_initialize_handshake(
    client: httpx.AsyncClient,
    factory: FakeToolHostFactory,
    mcp_registry: tuple[Paths, str, str, str, str],
) -> None:
    """The canonical form: ``Authorization: Bearer usr_...`` performs the handshake."""
    _paths, alice_key, _bob_key, _dana_key, _admin_key = mcp_registry

    response = await _post_initialize(client, _auth_header(alice_key))

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    session_id = response.headers["mcp-session-id"]  # a server-side session exists
    assert session_id
    # The response body is exactly the frame the host emitted (id echoed,
    # result verbatim) — value-for-value, nothing added or re-shaped.
    assert json.loads(response.text) == json.loads(_host_initialize_reply(_INITIALIZE_REQUEST))
    assert alice_key not in response.text  # no key material echoes
    # The host received the client's frame untouched (framing is not our job).
    assert factory.call_count == 1
    assert json.loads(factory.hosts[0].received_frames[0]) == _INITIALIZE_REQUEST
    # The resolved user reached the factory credential-free (the isolation seam).
    user, created_session_id = factory.created[0]
    assert set(UserMetadata.model_fields) == {
        "id",
        "name",
        "created_at",
        "key_generation",
        "status",
        "account_count",
    }
    assert not hasattr(user, "login_key_hash") and not hasattr(user, "aek")
    assert "usr_" not in user.model_dump_json()
    assert user.name == "alice" and user.status == "active"
    assert created_session_id == session_id

    await client.delete("/mcp", headers=_auth_header(alice_key) | {"mcp-session-id": session_id})


async def test_x_api_key_form_works_identically(
    client: httpx.AsyncClient,
    factory: FakeToolHostFactory,
    mcp_registry: tuple[Paths, str, str, str, str],
) -> None:
    """``X-Api-Key: <key>`` authenticates exactly like the Bearer form."""
    _paths, alice_key, _bob_key, _dana_key, _admin_key = mcp_registry

    response = await _post_initialize(client, {"X-Api-Key": alice_key})

    assert response.status_code == 200
    session_id = response.headers["mcp-session-id"]
    assert response.json() == json.loads(_host_initialize_reply(_INITIALIZE_REQUEST))
    assert json.loads(factory.hosts[0].received_frames[0]) == _INITIALIZE_REQUEST
    assert factory.created[0][0].name == "alice"

    await client.delete(
        "/mcp",
        headers={"X-Api-Key": alice_key, "mcp-session-id": session_id},
    )


async def test_tools_list_payload_passes_through_unmodified(
    client: httpx.AsyncClient,
    factory: FakeToolHostFactory,
    mcp_registry: tuple[Paths, str, str, str, str],
) -> None:
    """``tools/list``: the tool surface crosses as-is — schemas are never re-shaped."""
    _paths, alice_key, _bob_key, _dana_key, _admin_key = mcp_registry
    async with _mcp_session(client, factory, alice_key) as (session_id, host):
        response = await _post_json(
            client,
            _TOOLS_LIST_REQUEST,
            _auth_header(alice_key) | {"mcp-session-id": session_id},
        )

    assert response.status_code == 200
    assert json.loads(response.text) == json.loads(_TOOLS_LIST_REPLY)
    assert json.loads(host.received_frames[-1]) == _TOOLS_LIST_REQUEST


async def test_notifications_pass_through_with_202(
    client: httpx.AsyncClient,
    factory: FakeToolHostFactory,
    mcp_registry: tuple[Paths, str, str, str, str],
) -> None:
    """Notifications are acknowledged (202) and forwarded to the host untouched."""
    _paths, alice_key, _bob_key, _dana_key, _admin_key = mcp_registry
    async with _mcp_session(client, factory, alice_key) as (session_id, host):
        response = await _post_json(
            client,
            _INITIALIZED_NOTIFICATION,
            _auth_header(alice_key) | {"mcp-session-id": session_id},
        )

    assert response.status_code == 202
    assert response.text == ""  # acknowledged, no JSON-RPC body
    await _eventually(lambda: len(host.received_frames) >= 2)
    assert json.loads(host.received_frames[-1]) == _INITIALIZED_NOTIFICATION


# --- 3. the auth matrix: every failure is the uniform 401, transport never reached ---------

_FAILURE_CASES = (
    "missing-key",
    "wrong-user-key",
    "admin-key-bearer",
    "admin-key-x-api-key",
    "disabled-user-key",
    "malformed-bearer-double-space",
    "non-bearer-scheme",
    "authorization-wins-over-x-api-key",
    "empty-api-key",
)


def _failure_headers(
    case: str, mcp_registry: tuple[Paths, str, str, str, str]
) -> dict[str, str] | None:
    """The presented credentials for one auth-matrix failure case."""
    _paths, alice_key, _bob_key, dana_key, admin_key = mcp_registry
    return {
        "missing-key": None,
        "wrong-user-key": {"Authorization": "Bearer " + "usr_" + "F" * 43},
        "admin-key-bearer": {"Authorization": f"Bearer {admin_key}"},
        "admin-key-x-api-key": {"X-Api-Key": admin_key},
        "disabled-user-key": {"X-Api-Key": dana_key},
        # A valid key inside a malformed Bearer shape must still fail closed.
        "malformed-bearer-double-space": {"Authorization": f"Bearer  {alice_key}"},
        "non-bearer-scheme": {"Authorization": "Basic dXNlcjpwYXNz"},
        # A present Authorization header decides, always: a valid key in
        # X-Api-Key cannot rescue an invalid Bearer (user_from_bearer rules).
        "authorization-wins-over-x-api-key": {
            "Authorization": "Bearer nope",
            "X-Api-Key": alice_key,
        },
        "empty-api-key": {"X-Api-Key": "   "},
    }[case]


@pytest.mark.parametrize("case", _FAILURE_CASES)
async def test_auth_failures_never_reach_the_transport(
    client: httpx.AsyncClient,
    factory: FakeToolHostFactory,
    mcp_registry: tuple[Paths, str, str, str, str],
    case: str,
) -> None:
    """Missing/wrong/admin/disabled keys → the identical 401; no host is created."""
    _paths, alice_key, _bob_key, dana_key, admin_key = mcp_registry

    response = await _post_initialize(client, _failure_headers(case, mcp_registry))

    assert response.status_code == 401, (case, response.text)
    assert response.json() == {"error": "unauthorized"}, case
    assert factory.call_count == 0, case  # nothing under /mcp reached the transport
    # No key material ever echoes back — not even a valid key in a bad shape.
    for secret in (alice_key, dana_key, admin_key):
        assert secret not in response.text, case


async def test_every_auth_failure_body_is_byte_identical(
    client: httpx.AsyncClient, factory: FakeToolHostFactory
) -> None:
    """One fixed body across all failure kinds — no enumeration oracle."""
    bodies: set[str] = set()
    for headers in (None, {"Authorization": "Bearer nope"}, {"X-Api-Key": "usr_wrong"}):
        response = await _post_initialize(client, headers)
        assert response.status_code == 401
        bodies.add(response.text)
    assert bodies == {'{"error":"unauthorized"}'}


# --- 4. rate limiting ------------------------------------------------------------------------


@pytest.fixture
def clock() -> _Clock:
    return _Clock()


@pytest.fixture
def limited_app(
    mcp_registry: tuple[Paths, str, str, str, str],
    factory: FakeToolHostFactory,
    clock: _Clock,
) -> FastAPI:
    paths, _alice_key, _bob_key, _dana_key, _admin_key = mcp_registry
    return _gateway_app(
        paths, factory, rate_limiter=AdminRateLimiter(clock=clock, window_seconds=600.0)
    )


@pytest.fixture
async def limited_client(limited_app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=limited_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http


async def test_failed_attempts_lock_out_even_valid_keys(
    limited_client: httpx.AsyncClient,
    factory: FakeToolHostFactory,
    mcp_registry: tuple[Paths, str, str, str, str],
    clock: _Clock,
) -> None:
    """5 wrong-key attempts → the 6th (with a VALID key) answers 429 + Retry-After."""
    _paths, alice_key, _bob_key, _dana_key, _admin_key = mcp_registry
    for _ in range(FAILURE_LIMIT):
        denied = await _post_initialize(limited_client, {"X-Api-Key": "usr_" + "F" * 43})
        assert denied.status_code == 401
    assert factory.call_count == 0

    locked = await _post_initialize(limited_client, _auth_header(alice_key))
    assert locked.status_code == 429
    assert locked.json() == {"error": "rate_limited"}
    assert int(locked.headers["Retry-After"]) >= 1
    assert factory.call_count == 0  # the lockout gate sits before any host start

    clock.now += 601  # every failure ages out of the window: self-healing
    healed = await _post_initialize(limited_client, _auth_header(alice_key))
    assert healed.status_code == 200
    assert healed.json()["result"]["serverInfo"]["name"] == "imap-mcp-server"


async def test_absent_credentials_do_not_consume_rate_limit_budget(
    limited_client: httpx.AsyncClient,
    factory: FakeToolHostFactory,
    mcp_registry: tuple[Paths, str, str, str, str],
) -> None:
    """Keyless requests fail closed without counting (require_admin's doctrine)."""
    _paths, alice_key, _bob_key, _dana_key, _admin_key = mcp_registry
    for _ in range(FAILURE_LIMIT * 2):
        denied = await _post_initialize(limited_client, None)
        assert denied.status_code == 401
    assert factory.call_count == 0

    response = await _post_initialize(limited_client, _auth_header(alice_key))
    assert response.status_code == 200  # never locked out


# --- 5. routing before the transport ------------------------------------------------------------

@pytest.mark.parametrize("method", ["GET", "DELETE"])
async def test_session_methods_require_auth_too(
    client: httpx.AsyncClient,
    factory: FakeToolHostFactory,
    method: str,
) -> None:
    """GET/DELETE with no key → 401 before any transport/session handling."""
    response = await client.request(
        method, "/mcp", headers={"Accept": "text/event-stream, application/json"}
    )
    assert response.status_code == 401
    assert response.json() == {"error": "unauthorized"}
    assert factory.call_count == 0


async def test_unknown_session_id_with_valid_key_is_a_jsonrpc_404(
    client: httpx.AsyncClient,
    factory: FakeToolHostFactory,
    mcp_registry: tuple[Paths, str, str, str, str],
) -> None:
    """A valid key but an unknown/expired session id → 404 JSON-RPC error."""
    _paths, alice_key, _bob_key, _dana_key, _admin_key = mcp_registry
    response = await _post_json(
        client,
        _TOOLS_LIST_REQUEST,
        _auth_header(alice_key) | {"mcp-session-id": "baddadsession"},
    )
    assert response.status_code == 404
    body = response.json()
    assert body["jsonrpc"] == "2.0"
    assert body["id"] is None
    assert body["error"]["code"] == INVALID_REQUEST
    assert factory.call_count == 0  # no host for a session that does not exist


async def test_another_users_valid_key_cannot_hijack_a_session(
    client: httpx.AsyncClient,
    factory: FakeToolHostFactory,
    mcp_registry: tuple[Paths, str, str, str, str],
) -> None:
    """Isolation: Bob's valid key + Alice's session id → 404, and it stays hers.

    Foreign and unknown sessions answer identically (no oracle), and the
    foreign request never reaches Alice's tool host — not for tools/list,
    not for DELETE.
    """
    _paths, alice_key, bob_key, _dana_key, _admin_key = mcp_registry
    async with _mcp_session(client, factory, alice_key) as (alice_session, alice_host):
        frames_before = len(alice_host.received_frames)

        hijack = await _post_json(
            client,
            _TOOLS_LIST_REQUEST,
            _auth_header(bob_key) | {"mcp-session-id": alice_session},
        )
        assert hijack.status_code == 404
        assert hijack.json() == json.loads(
            '{"jsonrpc":"2.0","id":null,'
            '"error":{"code":-32600,"message":"Session not found"}}'
        )

        hijacked_delete = await client.delete(
            "/mcp", headers=_auth_header(bob_key) | {"mcp-session-id": alice_session}
        )
        assert hijacked_delete.status_code == 404
        assert hijacked_delete.json() == hijack.json()

        hijacked_get = await client.get(
            "/mcp", headers=_auth_header(bob_key) | {"mcp-session-id": alice_session}
        )
        assert hijacked_get.status_code == 404
        assert hijacked_get.json() == hijack.json()  # foreign == unknown, every verb

        # ...and byte-identical to the UNKNOWN-session answer (no oracle):
        # a foreign session is indistinguishable from a nonexistent one.
        unknown = await _post_json(
            client,
            _TOOLS_LIST_REQUEST,
            _auth_header(bob_key) | {"mcp-session-id": "c0c0c0c0c0c0"},
        )
        assert unknown.status_code == 404
        assert unknown.text == hijack.text

        # Nothing reached Alice's host, and the session still works for Alice.
        assert len(alice_host.received_frames) == frames_before
        own = await _post_json(
            client,
            _TOOLS_LIST_REQUEST,
            _auth_header(alice_key) | {"mcp-session-id": alice_session},
        )
        assert own.status_code == 200


async def test_get_with_valid_session_reaches_the_transport(
    client: httpx.AsyncClient,
    factory: FakeToolHostFactory,
    mcp_registry: tuple[Paths, str, str, str, str],
) -> None:
    """Authenticated GET session semantics: the transport answers (406: JSON-only Accept).

    Proves the routed GET carries the session id all the way to the session's
    own transport (an unknown/foreign id would answer the gateway's 404
    instead). A real SSE stream is not opened here — that is M05-T04's
    lifecycle territory.
    """
    _paths, alice_key, _bob_key, _dana_key, _admin_key = mcp_registry
    async with _mcp_session(client, factory, alice_key) as (session_id, _host):
        response = await client.get(
            "/mcp",
            headers=_auth_header(alice_key)
            | {"Accept": "application/json", "mcp-session-id": session_id},
        )
    assert response.status_code == 406  # the transport's own Accept rejection


async def test_methods_outside_get_post_delete_are_405_after_auth(
    client: httpx.AsyncClient,
    factory: FakeToolHostFactory,
    mcp_registry: tuple[Paths, str, str, str, str],
) -> None:
    _paths, alice_key, _bob_key, _dana_key, _admin_key = mcp_registry
    denied = await client.request("PUT", "/mcp", headers={"Authorization": "Bearer nope"})
    assert denied.status_code == 401  # auth still runs first

    response = await client.request("PUT", "/mcp", headers=_auth_header(alice_key))
    assert response.status_code == 405
    assert response.headers["allow"] == "GET, POST, DELETE"
    assert response.json()["error"]["code"] == INVALID_REQUEST
    assert factory.call_count == 0


# --- 6. lifecycle: DELETE teardown and failed host starts ----------------------------------------


async def test_delete_ends_the_session_and_the_host(
    client: httpx.AsyncClient,
    factory: FakeToolHostFactory,
    mcp_registry: tuple[Paths, str, str, str, str],
) -> None:
    _paths, alice_key, _bob_key, _dana_key, _admin_key = mcp_registry
    async with _mcp_session(client, factory, alice_key) as (session_id, host):
        response = await client.delete(
            "/mcp", headers=_auth_header(alice_key) | {"mcp-session-id": session_id}
        )
        assert response.status_code == 200
        await _eventually(lambda: host.closed)

        # The session id is dead: further requests answer 404.
        after = await _post_json(
            client,
            _TOOLS_LIST_REQUEST,
            _auth_header(alice_key) | {"mcp-session-id": session_id},
        )
        assert after.status_code == 404


async def test_tool_host_start_failure_fails_closed(
    client: httpx.AsyncClient,
    factory: FakeToolHostFactory,
    mcp_registry: tuple[Paths, str, str, str, str],
) -> None:
    """A factory crash on session open → JSON-RPC 500, nothing leaks into the next try."""
    _paths, alice_key, _bob_key, _dana_key, _admin_key = mcp_registry
    factory.fail_next = RuntimeError("spawn failed")

    failed = await _post_initialize(client, _auth_header(alice_key))

    assert failed.status_code == 500
    body = failed.json()
    assert body["jsonrpc"] == "2.0" and body["id"] is None
    assert body["error"]["message"] == "Tool host failed to start"
    assert factory.hosts == []  # nothing half-started

    # The gateway is not poisoned: the next initialize succeeds.
    async with _mcp_session(client, factory, alice_key) as (_session_id, host):
        assert json.loads(host.received_frames[0]) == _INITIALIZE_REQUEST


# --- 7. the isolation seam: per-user host binding -------------------------------------------------


async def test_each_session_is_bound_to_its_calling_user(
    client: httpx.AsyncClient,
    factory: FakeToolHostFactory,
    mcp_registry: tuple[Paths, str, str, str, str],
) -> None:
    """Alice's and Bob's sessions each get their own host with their own identity."""
    _paths, alice_key, bob_key, _dana_key, _admin_key = mcp_registry
    async with _mcp_session(client, factory, alice_key) as (alice_session, _alice_host):
        async with _mcp_session(client, factory, bob_key) as (bob_session, _bob_host):
            assert alice_session != bob_session  # never share a session
            (alice_user, _alice_sid), (bob_user, _bob_sid) = factory.created
            assert alice_user.id != bob_user.id
            assert alice_user.name == "alice" and bob_user.name == "bob"
            for user in (alice_user, bob_user):
                # Credential-free by construction: the isolation principal.
                assert not hasattr(user, "login_key_hash") and not hasattr(user, "aek")


async def test_scope_state_carries_the_isolation_principal(
    mcp_registry: tuple[Paths, str, str, str, str],
    factory: FakeToolHostFactory,
) -> None:
    """The resolved user is attached at scope["state"]["user"] (the isolation binding)."""
    paths, alice_key, _bob_key, _dana_key, _admin_key = mcp_registry
    app = FastAPI()
    app.state.settings = Settings(data_dir=paths.data_dir)
    app.add_exception_handler(AdminHTTPError, admin_http_error_handler)
    capture = _StateCapture(create_mcp_gateway(factory))
    app.router.routes.append(Route("/mcp", capture))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await _post_initialize(client, _auth_header(alice_key))
        assert response.status_code == 200
        session_id = response.headers["mcp-session-id"]
        await client.delete(
            "/mcp", headers=_auth_header(alice_key) | {"mcp-session-id": session_id}
        )

    assert capture.captured, "the gateway never attached the isolation principal"
    for principal in capture.captured:
        assert isinstance(principal, UserMetadata)
        assert principal.name == "alice"
        assert not hasattr(principal, "login_key_hash") and not hasattr(principal, "aek")
        assert "usr_" not in principal.model_dump_json()
    # The factory saw exactly the same credential-free identity.
    assert capture.captured[0].model_dump() == factory.created[0][0].model_dump()


async def test_require_user_key_header_dependency_form(
    mcp_registry: tuple[Paths, str, str, str, str],
) -> None:
    """The ``Depends(require_user_key_header)`` wiring shape (app.state.mcp_rate_limiter)."""
    paths, alice_key, _bob_key, _dana_key, _admin_key = mcp_registry
    app = FastAPI()
    app.state.settings = Settings(data_dir=paths.data_dir)
    app.state.mcp_rate_limiter = AdminRateLimiter()  # the mounting app's contract
    app.add_exception_handler(AdminHTTPError, admin_http_error_handler)

    @app.get("/mcp-principal")
    async def principal(user: UserKeyHeaderDep) -> dict[str, str]:
        return {"id": user.id, "name": user.name}

    expected = authenticate_user_key(paths, alice_key)
    assert expected is not None
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        ok = await client.get("/mcp-principal", headers=_auth_header(alice_key))
        denied = await client.get("/mcp-principal")

    assert ok.status_code == 200
    assert ok.json() == {"id": expected.id, "name": "alice"}
    assert denied.status_code == 401
    assert denied.json() == {"error": "unauthorized"}


# --- 8. the host-cost gate: only a valid initialize can spawn a host -------------------------


async def test_sessionless_get_and_delete_spawn_no_host(
    client: httpx.AsyncClient,
    factory: FakeToolHostFactory,
    mcp_registry: tuple[Paths, str, str, str, str],
) -> None:
    """Authenticated sessionless GET/DELETE cannot open — or cost — a session.

    The transport would reject these anyway; the gateway refuses them BEFORE
    the tool host is created (a valid key must not spawn subprocesses with
    junk requests).
    """
    _paths, alice_key, _bob_key, _dana_key, _admin_key = mcp_registry
    for method in ("GET", "DELETE"):
        response = await client.request(method, "/mcp", headers=_auth_header(alice_key))
        assert response.status_code == 400, method
        assert response.json()["error"]["message"] == "Bad Request: Missing session ID"
    assert factory.call_count == 0


async def test_non_initialize_and_malformed_posts_spawn_no_host(
    client: httpx.AsyncClient,
    factory: FakeToolHostFactory,
    mcp_registry: tuple[Paths, str, str, str, str],
) -> None:
    """Sessionless POSTs that cannot establish a session cost no tool host."""
    _paths, alice_key, _bob_key, _dana_key, _admin_key = mcp_registry
    headers = _auth_header(alice_key) | {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    tools_list = await client.post(
        "/mcp", content=json.dumps(_TOOLS_LIST_REQUEST), headers=headers
    )
    assert tools_list.status_code == 400
    malformed = await client.post("/mcp", content=b"{not json", headers=headers)
    assert malformed.status_code == 400
    # initialize-SHAPED but transport-invalid: a notification has no usable id.
    idless = await client.post(
        "/mcp",
        content=b'{"jsonrpc":"2.0","id":null,"method":"initialize","params":{}}',
        headers=headers,
    )
    assert idless.status_code == 400
    # ids the JSON-RPC request envelope can never carry (bool / float).
    for bad_id in (b"true", b"1.5"):
        body = b'{"jsonrpc":"2.0","id":' + bad_id + b',"method":"initialize","params":{}}'
        rejected = await client.post("/mcp", content=body, headers=headers)
        assert rejected.status_code == 400, body
    # Nesting depth beyond the json decoder (well within the 4 MiB cap) must
    # fail closed to the same 400 — never escape as a 500.
    deep = b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":' + b"[" * 20_000
    deep_response = await client.post("/mcp", content=deep, headers=headers)
    assert deep_response.status_code == 400
    assert factory.call_count == 0

    # The gateway is not poisoned: a REAL initialize still opens a session.
    handshake = await _post_initialize(client, _auth_header(alice_key))
    assert handshake.status_code == 200
    await client.delete(
        "/mcp",
        headers=_auth_header(alice_key) | {"mcp-session-id": handshake.headers["mcp-session-id"]},
    )


async def test_oversized_body_is_rejected_without_a_host(
    client: httpx.AsyncClient,
    factory: FakeToolHostFactory,
    mcp_registry: tuple[Paths, str, str, str, str],
) -> None:
    """The body cap (4 MiB, the SDK manager's own middleware) sits before host creation."""
    _paths, alice_key, _bob_key, _dana_key, _admin_key = mcp_registry
    response = await client.post(
        "/mcp",
        content=b"x" * (4 * 1024 * 1024 + 1),
        headers=_auth_header(alice_key)
        | {"Accept": "application/json", "Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert factory.call_count == 0


async def test_transport_rejected_opening_still_tears_down_the_host(
    client: httpx.AsyncClient,
    factory: FakeToolHostFactory,
    mcp_registry: tuple[Paths, str, str, str, str],
) -> None:
    """A pre-filter-passing body the transport refuses must not leak its host.

    The opening window's ``finally`` discard: the host was created (the body
    looked like an initialize), the transport then rejects the request, and
    the session plus host must be gone before the next handshake — with the
    gateway unpoisoned.
    """
    _paths, alice_key, _bob_key, _dana_key, _admin_key = mcp_registry
    headers = _auth_header(alice_key) | {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    # Wrong protocol version: passes the cheap pre-filter, fails the schema.
    rejected = await client.post(
        "/mcp",
        content=b'{"jsonrpc":"1.0","id":1,"method":"initialize","params":{}}',
        headers=headers,
    )
    assert rejected.status_code == 400
    assert factory.call_count == 1  # the host WAS created for this attempt…
    await _eventually(lambda: factory.hosts[-1].closed)  # …and torn down again

    # The gateway is not poisoned: a REAL initialize still opens a session.
    handshake = await _post_initialize(client, _auth_header(alice_key))
    assert handshake.status_code == 200
    await client.delete(
        "/mcp",
        headers=_auth_header(alice_key) | {"mcp-session-id": handshake.headers["mcp-session-id"]},
    )


async def test_string_request_ids_complete_the_handshake(
    client: httpx.AsyncClient,
    factory: FakeToolHostFactory,
    mcp_registry: tuple[Paths, str, str, str, str],
) -> None:
    """String request ids (``mcp_types.RequestId``) cross the bridge untouched."""
    _paths, alice_key, _bob_key, _dana_key, _admin_key = mcp_registry
    request = {**_INITIALIZE_REQUEST, "id": "init-1"}

    response = await _post_json(client, request, _auth_header(alice_key))

    assert response.status_code == 200
    assert response.json()["id"] == "init-1"
    assert json.loads(response.text)["id"] == "init-1"
    assert json.loads(factory.hosts[0].received_frames[0]) == request
    await client.delete(
        "/mcp",
        headers=_auth_header(alice_key) | {"mcp-session-id": response.headers["mcp-session-id"]},
    )
