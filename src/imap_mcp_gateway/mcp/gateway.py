"""The ``/mcp`` Streamable HTTP endpoint: header auth, per-user isolation seam,
and verbatim JSON-RPC bridging to a per-session tool host (M05-T01).

``create_mcp_gateway(tool_host_factory)`` builds the ASGI 3.0 sub-app the app
factory mounts at ``/mcp``. Every request crosses four stages, in order:

1. **Auth gate** (:func:`imap_mcp_gateway.web.middleware.user_auth.
   authenticate_key_header`) — Bearer (canonical) or ``X-Api-Key`` login-key
   header, rate-limited like the other auth surfaces. Admin keys are rejected
   by construction (the user scan never consults admin credentials). Every
   failure is the uniform ``401 {"error": "unauthorized"}`` raised as
   :class:`~imap_mcp_gateway.web.middleware.admin_auth.AdminHTTPError` — the
   mounting app's registered handler renders it, so no unauthenticated request
   ever reaches the transport and no failure echoes key material.
2. **Isolation binding** — the resolved credential-free
   :class:`~imap_mcp_gateway.store.user_schema.UserMetadata` is attached at
   ``scope["state"]["user"]`` (request-local ASGI state) and handed to the
   factory. This is the boundary that keeps the gateway free of global
   account state: a tool host can only ever be born with one user's identity,
   and no code path can reach another user's data through the gateway — a
   request for a session id bound to another user answers the same 404 as an
   unknown one, and the foreign-session attempt is logged under the reserved
   ``[security]`` tag (server-side only — identifiers, never key material).
3. **Host-cost gate** — POST bodies are capped (the SDK's
   ``RequestBodyLimitMiddleware``, 4 MiB like the session manager applies),
   and a sessionless request only reaches the tool-host factory when it is a
   POST whose body parses as a JSON-RPC ``initialize`` request — the one
   shape that can establish a session — so a valid key cannot spawn hosts
   with junk requests. The buffered body is replayed to the transport
   untouched.
4. **Transport** — one :class:`mcp.server.streamable_http.StreamableHTTPServerTransport`
   per MCP session (POST opens, ``Mcp-Session-Id`` routes, DELETE closes, GET
   carries the server-initiated stream). The gateway pumps
   :class:`~mcp.shared.message.SessionMessage` objects unmodified between the
   transport's memory streams and the session's
   :class:`ToolHost` — the transport does the only parse/serialize, exactly
   as it would for a native server, so ``initialize``/``tools/list``/
   ``tools/call`` payloads cross this seam without reinterpretation and tool
   parity stays "by construction" (the child, not Python, answers).

Deliberate, documented deviations from the milestone's literal text:

- **No ``StreamableHTTPSessionManager``.** The milestone said to track
  sessions "via the SDK's session manager", but that manager is hard-wired to
  drive a low-level ``mcp.server.Server`` message loop: Python would answer
  ``initialize`` itself (its own ``serverInfo``/capabilities) and re-serialize
  every result through typed handlers — exactly the lossy reimplementation
  the same milestone forbids ("no re-serialization of ``tools/list`` /
  ``tools/call`` payloads"; parity "by construction"). The gateway therefore
  builds on the milestone's first-named primitive,
  ``StreamableHTTPServerTransport``, and keeps a minimal per-process session
  table with the manager's own semantics (opening request establishes or is
  discarded; unknown/expired id answers 404; DELETE terminates).

- **JSON-mode responses.** ``is_json_response_enabled=True``: each POST is
  answered with a single ``application/json`` JSON-RPC frame rather than an
  SSE stream — the simplest lossless wire for the request/response bridge
  this milestone tests. The GET server-initiated stream (SSE) stays
  available; session idle timeouts arrive with the real tool host (M05-T02).

- **Protocol first, host later.** :class:`ToolHostFactory` and
  :class:`ToolHost` are declared here as Protocols — the contract M05-T02's
  ``NodeToolHost`` implements (one pinned Node subprocess per session). This
  task ships no host implementation; tests double it in Python.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import Awaitable, Callable
from typing import Protocol, runtime_checkable

import anyio
from mcp.server.streamable_http import (
    MCP_SESSION_ID_HEADER,
    StreamableHTTPServerTransport,
)
from mcp.server.transport_security import (
    DEFAULT_MAX_REQUEST_BODY_SIZE,
    RequestBodyLimitMiddleware,
)
from mcp.shared._stream_protocols import ReadStream, WriteStream
from mcp.shared.message import SessionMessage
from mcp_types import (
    INTERNAL_ERROR,
    INVALID_REQUEST,
    ErrorData,
    JSONRPCError,
    JSONRPCMessage,
    jsonrpc_message_adapter,
)
from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from imap_mcp_gateway.log import get_logger
from imap_mcp_gateway.store.user_schema import UserMetadata
from imap_mcp_gateway.web.middleware.admin_auth import AdminRateLimiter
from imap_mcp_gateway.web.middleware.user_auth import authenticate_key_header

log = get_logger(__name__)


def _wire_dump(message: JSONRPCMessage) -> str:
    """Serialize one JSON-RPC message exactly as the SDK writes its responses.

    Single choke point so a future flag change cannot desynchronize the two
    directions of the bridge.
    """
    return message.model_dump_json(by_alias=True, exclude_unset=True)


def _is_initialize_request(body: bytes) -> bool:
    """True iff ``body`` parses as a JSON-RPC ``initialize`` request.

    Cheap pre-filter for the session-opening path (the transport re-validates
    the body fully): a JSON object with ``method == "initialize"`` and an
    ``id`` member the transport could accept (int or str — JSON-RPC requests,
    unlike notifications, carry a non-null id; pydantic's strict int rejects
    bools). Anything unparseable, truncated, or not-initialize-shaped returns
    ``False`` and is refused before a tool host exists.
    """
    try:
        decoded = json.loads(body)
    except (ValueError, RecursionError):
        # ValueError: malformed JSON. RecursionError: nesting depth beyond the
        # json decoder — reachable well within the 4 MiB cap, so it must fail
        # closed to the same 400 instead of escaping as a 500.
        return False
    if not isinstance(decoded, dict) or decoded.get("method") != "initialize":
        return False
    request_id = decoded.get("id")
    return isinstance(request_id, (int, str)) and not isinstance(request_id, bool)


@runtime_checkable
class ToolHost(Protocol):
    """One session's tool-host handle: newline-delimited JSON-RPC over stdio.

    M05-T02 implements this against the pinned Node subprocess (one child per
    MCP session, never shared between users). Frames are whole JSON-RPC
    messages without the trailing newline; the implementer owns the wire
    framing on its side.
    """

    async def send_frame(self, frame: str) -> None:
        """Write one JSON-RPC message (a line; the host adds the newline) to the child's stdin."""
        ...

    async def receive_frame(self) -> str:
        """Read one JSON-RPC message line from the child's stdout; ``""`` on EOF."""
        ...

    async def aclose(self) -> None:
        """Tear the host down (SIGTERM + wait for M05-T02); idempotent."""
        ...


@runtime_checkable
class ToolHostFactory(Protocol):
    """The per-session tool-host seam M05-T02's ``NodeToolHost`` plugs into.

    ``create`` must bind the host to exactly the given user — the factory is
    the isolation boundary, so it receives the credential-free
    :class:`UserMetadata` (never key material) and the MCP session id, and
    must never return a host already bound to another user or session.
    """

    async def create(self, user: UserMetadata, session_id: str) -> ToolHost:
        """Materialize one fresh tool host for this user and session."""
        ...


class _Session:
    """One MCP session: its transport, its tool host and its bridge task."""

    __slots__ = ("host", "ready", "session_id", "task", "transport", "user")

    def __init__(
        self,
        session_id: str,
        transport: StreamableHTTPServerTransport,
        user: UserMetadata,
    ) -> None:
        self.session_id = session_id
        self.transport = transport
        self.user = user
        self.host: ToolHost | None = None
        self.ready = asyncio.Event()
        self.task: asyncio.Task[None] | None = None


class MCPGateway:
    """The raw-ASGI ``/mcp`` sub-app (see the module docstring for the design)."""

    def __init__(
        self,
        tool_host_factory: ToolHostFactory,
        *,
        rate_limiter: AdminRateLimiter | None = None,
    ) -> None:
        self._factory = tool_host_factory
        # Per-surface lockout (M02 semantics: 5 failures / 10 min, socket-peer
        # IP). Own instance: /mcp failures must not lock out /admin logins.
        self._rate_limiter = rate_limiter if rate_limiter is not None else AdminRateLimiter()
        self._sessions: dict[str, _Session] = {}
        # Body cap on every dispatched request (the SDK session manager applies
        # this same middleware to its transport): the transport buffers POST
        # bodies whole, so an uncapped body means memory exhaustion for anyone
        # holding a valid key. The middleware also buffers-and-replays the
        # body, which the opening path needs for its initialize pre-check.
        self._body_limited = RequestBodyLimitMiddleware(
            self._dispatch, DEFAULT_MAX_REQUEST_BODY_SIZE
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """ASGI 3.0 entry: auth gate first, then (body-capped) dispatch."""
        if scope["type"] != "http":  # websocket/lifespan never reach a mount
            return
        request = Request(scope, receive)
        # Stage 1+2 — the auth gate raises the uniform 401/429 through the
        # mounting app's handler; nothing below runs unauthenticated.
        user = await authenticate_key_header(request, self._rate_limiter)
        scope.setdefault("state", {})["user"] = user
        await self._body_limited(scope, receive, send)

    async def _dispatch(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Post-auth routing: method filter, session table, opening path."""
        request = Request(scope, receive)
        user: UserMetadata = scope["state"]["user"]

        if request.method not in ("GET", "POST", "DELETE"):
            await self._method_not_allowed(request, scope, receive, send)
            return
        session_id = request.headers.get(MCP_SESSION_ID_HEADER)
        if session_id is not None:
            session = self._sessions.get(session_id)
            if session is None or session.user.id != user.id:
                # Unknown AND foreign sessions answer identically — a valid
                # key can never steer another user's session (no oracle). A
                # FOREIGN one (the session exists, bound to another user) is
                # additionally logged under the reserved [security] tag: the
                # cross-user attempt the M05 isolation gate requires on
                # record. The log is server-side only — the response below
                # stays the same 404 an unknown session gets, so the logging
                # cannot become an oracle. Fields are identifiers only
                # (registry-validated user ids, the server-generated session
                # id); no key material is ever in scope on this path.
                if session is not None:
                    log.warning(
                        "[security] MCP session id belongs to another user",
                        extra={
                            "fields": {
                                "user_id": user.id,
                                "owner_user_id": session.user.id,
                                "session_id": session_id,
                            }
                        },
                    )
                await self._jsonrpc_error(404, "Session not found", INVALID_REQUEST)(
                    scope, receive, send
                )
                return
            await session.transport.handle_request(scope, receive, send)
            if session.transport.is_terminated:  # client DELETE: forget it now
                await self._discard(session_id)
            return
        await self._handle_opening(user, request, scope, receive, send)

    # --- session lifecycle ---------------------------------------------------

    async def _handle_opening(
        self,
        user: UserMetadata,
        request: Request,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """Serve the session-opening request (Streamable HTTP: no session id yet).

        Mirrors the SDK session manager's dance: admit the session, start its
        bridge task, serve the request, and DISCARD the session again when the
        opening request was not established (the ``finally`` — including on
        cancellation, so a half-open session can never leak its tool host).

        Host-cost gate: only a POST whose body parses as a JSON-RPC
        ``initialize`` request reaches the factory. Everything else sessionless
        is refused by the transport anyway — creating a tool host before that
        check would let any valid key spawn subprocesses with junk requests
        (sessionless GET/DELETE are always invalid; a sessionless POST that is
        not a valid initialize cannot establish a session). Rejections use the
        transport's own shape (``400 Bad Request: Missing session ID``). The
        buffered body is replayed to the transport byte-for-byte untouched.
        """
        if request.method != "POST":
            await self._jsonrpc_error(
                400, "Bad Request: Missing session ID", INVALID_REQUEST
            )(scope, receive, send)
            return
        body = await request.body()
        if not _is_initialize_request(body):
            await self._jsonrpc_error(
                400, "Bad Request: Missing session ID", INVALID_REQUEST
            )(scope, receive, send)
            return
        body_replayed = False

        async def replay_body() -> Message:
            nonlocal body_replayed
            if not body_replayed:
                body_replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        session_id = uuid.uuid4().hex
        transport = StreamableHTTPServerTransport(
            mcp_session_id=session_id,
            is_json_response_enabled=True,
        )
        session = _Session(session_id, transport, user)
        try:
            session.host = await self._factory.create(user, session_id)
        except Exception:
            # Fails closed before anything is registered or served; the exact
            # reason stays server-side (the AEK-inactive guidance is a tool
            # error surfaced by M05-T02, not a gateway HTTP body).
            log.exception("[mcp:%s] tool host failed to start", user.id)
            await self._jsonrpc_error(500, "Tool host failed to start", INTERNAL_ERROR)(
                scope, receive, send
            )
            return
        self._sessions[session_id] = session
        # Hosted on the event loop (not a gateway-owned task group): a mounted
        # ASGI sub-app never runs a lifespan of its own, so there is no outer
        # task group to host session tasks. Anyio primitives run fine inside
        # this plain asyncio task.
        session.task = asyncio.create_task(
            self._run_session(session), name=f"mcp-session:{session_id}"
        )
        established = False
        try:
            await session.ready.wait()  # servable only once the transport connected
            status = await _serve_and_report(
                session.transport.handle_request, scope, replay_body, send
            )
            established = status is not None and status < 400
        finally:
            if not established:
                await self._discard(session_id)

    async def _run_session(self, session: _Session) -> None:
        """Bridge one session's transport streams to its tool host until it ends."""
        host = session.host
        if host is None:  # pragma: no cover - _handle_opening always sets it
            session.ready.set()
            return
        try:
            async with session.transport.connect() as streams:
                read_stream, write_stream = streams
                session.ready.set()
                async with anyio.create_task_group() as tg:
                    tg.start_soon(self._pump_client_to_host, read_stream, host)
                    tg.start_soon(self._pump_host_to_client, host, write_stream, session)
        except Exception:
            log.exception("[mcp:%s] session crashed", session.user.id)
        finally:
            # Set even on the failure paths: the opening request waits on this
            # event and must never hang because the bridge died before it.
            session.ready.set()
            await self._discard(session.session_id)

    async def _discard(self, session_id: str) -> None:
        """Forget the session and tear down transport + host exactly once.

        Idempotent (first pop wins, so the host closes exactly once) and
        shielded: teardown must complete even while the surrounding task is
        being cancelled (server shutdown mid-session). Each teardown step is
        guarded individually — a failing step (e.g. a host already dead)
        neither skips the other step nor escapes after the response is sent.
        """
        session = self._sessions.pop(session_id, None)
        if session is None:
            return
        with anyio.CancelScope(shield=True):
            try:
                if not session.transport.is_terminated:
                    await session.transport.terminate()
            except Exception:
                log.exception("[mcp:%s] transport teardown failed", session.user.id)
            try:
                if session.host is not None:
                    await session.host.aclose()
            except Exception:
                log.exception("[mcp:%s] tool host teardown failed", session.user.id)
            log.info("[mcp:%s] session closed", session.user.id)

    # --- the verbatim bridge ---------------------------------------------------

    async def _pump_client_to_host(
        self, read_stream: ReadStream[SessionMessage | Exception], host: ToolHost
    ) -> None:
        """Transport → host: one wire frame per inbound message, unmodified.

        The ``SessionMessage`` is never inspected beyond serializing it with
        the SDK's own flags — no method dispatch, no envelope edits.
        """
        try:
            async for session_message in read_stream:
                if isinstance(session_message, BaseException):
                    continue  # transport-internal errors are logged there
                await host.send_frame(_wire_dump(session_message.message))
        except (anyio.EndOfStream, anyio.ClosedResourceError, anyio.BrokenResourceError):
            pass  # session ended (DELETE, host death, termination)

    async def _pump_host_to_client(
        self,
        host: ToolHost,
        write_stream: WriteStream[SessionMessage],
        session: _Session,
    ) -> None:
        """Host → transport: one ``SessionMessage`` per frame, unmodified.

        On host EOF the transport is terminated so in-flight requests fail
        closed and the session ends (the task group's other pump sees the
        closed streams and unwinds).
        """
        try:
            while True:
                frame = await host.receive_frame()
                if not frame:  # EOF: the tool host is gone
                    log.info("[mcp:%s] tool host exited", session.user.id)
                    await session.transport.terminate()
                    return
                try:
                    message: JSONRPCMessage = jsonrpc_message_adapter.validate_json(frame)
                except ValidationError:
                    # Never reinterpret: a frame the schema rejects is dropped
                    # server-side. Only the size reaches the log — never the
                    # (untrusted) frame content.
                    log.warning(
                        "[mcp:%s] dropped a malformed JSON-RPC frame (%d bytes)",
                        session.user.id,
                        len(frame),
                    )
                    continue
                await write_stream.send(SessionMessage(message))
        except (anyio.ClosedResourceError, anyio.BrokenResourceError):
            pass  # transport terminated concurrently (DELETE / host-EOF race)

    # --- fixed wire shapes -------------------------------------------------------

    def _jsonrpc_error(self, status_code: int, message: str, error_code: int) -> Response:
        """A JSON-RPC error body like the SDK session manager's own rejections."""
        body = JSONRPCError(
            jsonrpc="2.0",
            id=None,
            error=ErrorData(code=error_code, message=message),
        )
        return Response(
            body.model_dump_json(by_alias=True, exclude_unset=True),
            status_code=status_code,
            media_type="application/json",
        )

    async def _method_not_allowed(
        self, request: Request, scope: Scope, receive: Receive, send: Send
    ) -> None:
        """Mirror the transport's 405 shape (Allow header + JSON-RPC error)."""
        response = self._jsonrpc_error(405, "Method Not Allowed", INVALID_REQUEST)
        response.headers["Allow"] = "GET, POST, DELETE"
        session_id = request.headers.get(MCP_SESSION_ID_HEADER)
        if session_id is not None:
            response.headers[MCP_SESSION_ID_HEADER] = session_id
        await response(scope, receive, send)


def create_mcp_gateway(
    tool_host_factory: ToolHostFactory,
    *,
    rate_limiter: AdminRateLimiter | None = None,
) -> ASGIApp:
    """Build the ``/mcp`` sub-app: auth gate + per-user isolation + verbatim bridge.

    ``tool_host_factory`` is the M05-T02 seam (Protocols above); ``rate_limiter``
    defaults to a fresh per-gateway :class:`AdminRateLimiter` and is injectable
    for clock-controlled tests. The returned app depends on the mounting app
    for ``app.state.settings.data_dir`` (the store the auth gate scans) and for
    the registered :class:`~imap_mcp_gateway.web.middleware.admin_auth.AdminHTTPError`
    handler that renders its uniform 401/429 bodies.

    Mounting contract (how the app factory must attach this — this is the
    reserved M05-T01 startup hook, wired once M05-T02 supplies the real
    factory): attach the gateway as an EXACT-path route, the way the SDK's own
    ``streamable_http_app`` does::

        app.router.routes.append(starlette.routing.Route("/mcp", gateway))

    A Starlette ``app.mount("/mcp", gateway)`` does NOT satisfy the endpoint
    contract: ``Mount`` compiles to ``/mcp/{path}``, so a request to exactly
    ``/mcp`` never reaches the gateway — the router answers ``307 → /mcp/``
    before auth, and MCP clients that do not follow redirects (and the plain
    ``curl`` acceptance) fail. ``Route`` matches the exact path for every
    HTTP method and lets the gateway own its own 405 shape.
    """
    return MCPGateway(tool_host_factory, rate_limiter=rate_limiter)


async def _serve_and_report(
    handle: Callable[[Scope, Receive, Send], Awaitable[None]],
    scope: Scope,
    receive: Receive,
    send: Send,
) -> int | None:
    """Run one ASGI request and return the answered status (the SDK manager's helper).

    ``None`` means the handler sent no ``http.response.start`` at all —
    treated as not-established like any >= 400 answer.
    """
    status: int | None = None

    async def watch_status(message: Message) -> None:
        nonlocal status
        if message["type"] == "http.response.start":
            status = message["status"]
        await send(message)

    await handle(scope, receive, watch_status)
    return status
