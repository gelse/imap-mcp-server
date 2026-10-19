"""The per-session tool host: one pinned upstream Node subprocess (M05-T02).

``NodeToolHostFactory`` is the production :class:`imap_mcp_gateway.mcp.
gateway.ToolHostFactory` behind the M05-T01 seam: every authenticated
``initialize`` gets a FRESH ``node <imap_mcp_server_js>`` child — one per
MCP session, never shared between users, never pooled, never reused across
authenticated keys. The factory receives the credential-free
:class:`~imap_mcp_gateway.store.user_schema.UserMetadata` and the MCP session
id and returns a host bound to exactly that pair.

Per-user isolation, in the order ``NodeToolHost.start`` applies it:

1. **AEK check (fail closed, with the structured guidance).** The user's
   record is loaded before any host is built. A user who has not activated
   account encryption yet gets NO child process and NO keyfile; the factory
   serves :class:`AEKInactiveGuidanceHost` instead, which answers the
   session's first request with the one structured JSON-RPC error carrying
   ``"initialize account encryption in the web UI first"`` and then ends the
   session — the client SEES the guidance on the MCP channel (never a
   gateway HTTP body, per the M05-T01 contract), no tool ever executes, and
   no key material exists. Deliberate deviation from the milestone's
   parenthetical "(surfaced when tools that need accounts are called)": the
   session cannot half-open with a keyless child, because the unmodified
   upstream ``AccountManager`` reads ``$HOME/.imap-mcp/.key`` at boot — a
   keyless child cannot serve tool calls, and answering tool calls from
   Python would break the verbatim pass-through contract (no wrapper-side
   tool logic). Other start failures (missing record, spawn failure) still
   raise into the gateway's generic 500 — those are server-side faults, not
   user guidance.

2. **Session keyfile.** The unwrapped AEK hex is materialized at
   ``DATA_DIR/users/<userId>/imap-store/.key`` via the M04-T03 store API
   (:func:`imap_mcp_gateway.store.session_keyfile.materialize_key_file`) and
   removed again on teardown (:func:`...cleanup_key_file`). The plaintext key
   touches disk only while a session of the user runs: concurrent sessions of
   the SAME user share the one keyfile path, so a teardown removes it only
   when it is the last live session of that user (the registry's
   ``has_live_sessions`` refcount; sessions self-register at the very start
   of ``start()``, before their first await, so the refcount cannot miss one).

3. **The HOME hinge + store link.** The child gets
   ``HOME=DATA_DIR/users/<userId>``, but unmodified upstream resolves its
   store at ``$HOME/.imap-mcp`` — so before spawn, ``$HOME/.imap-mcp`` is
   pointed (idempotently, a symlink) at the gateway's per-user ``imap-store``
   directory: the exact indirection the M04-T03 interop harness proved
   byte-compatible. The link itself is benign at rest (it names no secret
   and the store holds ciphertext only), so it is left in place across
   sessions; crash leftovers that matter are ``.key`` files, which teardown
   and the startup sweep remove.

4. **Explicit environment allowlist.** The child env is EXACTLY six
   variables — ``HOME``, ``IMAP_DOWNLOAD_DIR`` (per-user mail artifacts),
   ``IMAP_UPLOAD_TTL_MS`` / ``IMAP_MAX_UPLOAD_SIZE`` (upstream defaults),
   ``PATH`` (inherited) and ``LANG=C.UTF-8`` — and nothing else: no
   ``DATA_DIR``, no wrap-key or admin-hash paths, no parent secrets. The only
   user-specific values are the calling user's own directory names. Before
   the spawn, the per-user mail directory (``DATA_DIR/mail/<userId>``) is
   ensured to exist at ``0700`` (M05-T03): upstream resolves
   ``$IMAP_DOWNLOAD_DIR`` lazily per tool call, so without this guarantee the
   first ``imap_download_attachment``/``imap_upload_file`` call of a fresh
   data layout would race its own ``mkdir -p`` against an unwritable or
   absent parent; the directory is never removed at teardown — downloads and
   upload staging persist on the ``mail`` bind mount beyond the session.

Bridge: :meth:`NodeToolHost.send_frame` / :meth:`NodeToolHost.receive_frame`
move whole JSON-RPC lines over the child's stdin/stdout (newline-delimited —
the framing upstream's ``StdioServerTransport`` speaks). Frames are forwarded
without reinterpretation: no method dispatch, no envelope edits, no
re-serialization — the child does the only JSON-RPC semantics, so
``initialize``/``tools/list``/``tools/call`` and notifications cross this
seam unchanged and the tool surface is upstream's by construction. A stdout
line that exceeds the stream limit cannot be framed reliably, so the session
ends (fail closed) instead of forwarding a truncated frame.

Lifecycle: the child's stderr is drained on a dedicated task and logged
line-by-line under the ``[mcp:<userId>]`` tag, sanitized first (control
characters flattened, length capped) so the child cannot forge log lines
(the log module's stated requirement) — stdout is never read for logging; it
is the JSON-RPC channel only. An idle watchdog terminates a session that
exchanged no frames for ``settings.mcp_idle_timeout_seconds`` (default
15 min) with SIGTERM. :meth:`NodeToolHost.aclose` is the single idempotent
teardown funnel: SIGTERM, then SIGKILL after a grace period, tasks joined,
keyfile removed, session unregistered. Container shutdown drains every live
session (:meth:`NodeToolHostFactory.shutdown`, wired into ``app.run``'s boot
lifespan). One task group per MCP session spans the child's stdio pipes and
the Streamable HTTP transport — that group is the gateway's bridge task
(M05-T01); this host contributes its two named tasks (stderr relay, idle
watchdog), which teardown joins.

Language boundary: everything here is Python asyncio subprocess
orchestration. The ONLY Node component remains the vendored upstream package
consumed exactly as shipped — the child argv is ``[node, imap_mcp_server_js]``
with no wrapper script, no extra arguments, no upstream patching.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from typing import TYPE_CHECKING

from imap_mcp_gateway.config.paths import Paths
from imap_mcp_gateway.log import get_logger
from imap_mcp_gateway.mcp.session_registry import SessionRegistry
from imap_mcp_gateway.store.fs_safe import ensure_dir
from imap_mcp_gateway.store.session_keyfile import (
    cleanup_key_file,
    materialize_key_file,
)
from imap_mcp_gateway.store.users import get_user, with_aek

if TYPE_CHECKING:
    from imap_mcp_gateway.config.env import Settings
    from imap_mcp_gateway.mcp.gateway import ToolHost
    from imap_mcp_gateway.store.user_schema import UserMetadata

log = get_logger(__name__)

AEK_INACTIVE_GUIDANCE = "initialize account encryption in the web UI first"
"""The structured fail-closed guidance for users without an activated AEK."""

_UPLOAD_TTL_MS = "3600000"
"""Upstream ``IMAP_UPLOAD_TTL_MS`` default: upload staging lives one hour."""

_MAX_UPLOAD_SIZE = "26214400"
"""Upstream ``IMAP_MAX_UPLOAD_SIZE`` default: 25 MiB."""

_STORE_LINK_NAME = ".imap-mcp"
"""Where upstream resolves its store, relative to ``$HOME`` (hardcoded there)."""

_CHILD_STREAM_LIMIT = 4 * 1024 * 1024
"""Per-line StreamReader cap on the child's pipes (the gateway's body cap)."""

_TERM_GRACE_SECONDS = 5.0
"""SIGTERM → SIGKILL grace for a child that ignores termination."""

_STDERR_DRAIN_SECONDS = 1.0
"""Grace for the stderr relay to flush after the child exits (then cancel)."""

_MAX_STDERR_LOG_CHARS = 2000
"""Sanitized stderr lines are truncated to this length before logging."""


class AEKInactiveError(RuntimeError):
    """A tool-host start was attempted for a user without an activated AEK.

    Defensive guard inside :meth:`NodeToolHost.start`; the factory routes the
    AEK-inactive case to :class:`AEKInactiveGuidanceHost` BEFORE a host is
    ever constructed, so through the factory this is unreachable.
    """


AEK_INACTIVE_ERROR_CODE = -32000
"""JSON-RPC error code on the guidance response (implementation-defined range)."""

_GUIDANCE_EOF_GRACE_SECONDS = 0.05
"""In-process grace before the guidance host's intentional EOF: the
transport's internal router must deliver the error response into the parked
request handler before the EOF terminates the session, or the transport
answers its own 500 ("terminated before the request completed") instead of
the guidance."""

_EOF_AFTER_REPLY = object()
"""Queue sentinel: end the session only after the queued reply was delivered."""


class AEKInactiveGuidanceHost:
    """The fail-closed host for a user without an activated AEK (no child).

    The user's account encryption has never been activated, so there is no
    AEK to materialize and no child to spawn — but the user still deserves
    the structured guidance instead of an opaque failure: every request this
    host receives is answered with the ONE JSON-RPC error carrying
    :data:`AEK_INACTIVE_GUIDANCE` ("initialize account encryption in the web
    UI first"), after which the host signals EOF so the transport ends the
    session and the gateway tears the empty host down. The client therefore
    SEES the structured error the M04/M05 design promises (a JSON-RPC error
    frame on the MCP channel — never a gateway HTTP body), no tool ever
    executes, no child exists, and no key material ever touches disk.

    Not registered in the session registry (there is no child to track) and
    exempt from the idle watchdog (the session ends by itself after the first
    answered request).
    """

    def __init__(self, user_id: str) -> None:
        self._user_id = user_id
        self._outbound: asyncio.Queue[object] = asyncio.Queue()
        self._answered = False

    async def send_frame(self, frame: str) -> None:
        """Answer the first request with the guidance error, then end the session.

        Notifications (no ``id``) and any frames after the first answer are
        dropped: the session is already ending.
        """
        if self._answered:
            return
        self._answered = True
        request_id = None
        try:
            request = json.loads(frame)
        except ValueError:
            request = None
        if isinstance(request, dict):
            request_id = request.get("id")
        if request_id is None:  # a notification: no response is in flight
            self._outbound.put_nowait("")  # EOF: end the session immediately
            return
        self._outbound.put_nowait(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {
                        "code": AEK_INACTIVE_ERROR_CODE,
                        "message": AEK_INACTIVE_GUIDANCE,
                    },
                }
            )
        )
        self._outbound.put_nowait(_EOF_AFTER_REPLY)

    async def receive_frame(self) -> str:
        """The queued answer (or EOF); ``""`` again after EOF, per the Protocol."""
        frame = await self._outbound.get()
        if frame is _EOF_AFTER_REPLY:
            # The guidance response was handed to the transport's write
            # stream; give its in-process router the scheduling window to
            # deliver it into the parked request handler BEFORE the EOF —
            # an immediate EOF would terminate the session under the response
            # and the transport would answer its own 500 instead.
            await asyncio.sleep(_GUIDANCE_EOF_GRACE_SECONDS)
            return ""  # EOF: the session ends after the answer
        return str(frame)

    async def aclose(self) -> None:
        """Nothing to kill; unblock a pending ``receive_frame`` with EOF."""
        self._outbound.put_nowait("")


def _sanitize_log_text(raw: bytes) -> str:
    """Decode one child-stderr line for logging; forge-proof and length-capped.

    Control characters (newlines among them — ``str.isprintable`` is False for
    every C0/Cf code point) become spaces, so one stderr write can never
    split into a second forged log line, and the result is capped so a
    hostile child cannot flood the log with one line.
    """
    text = raw.decode("utf-8", errors="replace")
    flattened = "".join(char if char.isprintable() else " " for char in text)
    return flattened.strip()[:_MAX_STDERR_LOG_CHARS]


class NodeToolHost:
    """One pinned upstream Node subprocess bound to one user and MCP session.

    Implements the gateway's :class:`~imap_mcp_gateway.mcp.gateway.ToolHost`
    Protocol (newline-delimited JSON-RPC frames; ``""`` as the EOF sentinel
    from :meth:`receive_frame`). Constructed only by :class:`NodeToolHostFactory`,
    which pairs it with the session registry whose teardown bookkeeping it
    completes in :meth:`aclose`.
    """

    __slots__ = (
        "_closed",
        "_idle_task",
        "_idle_timeout_seconds",
        "_last_activity",
        "_paths",
        "_process",
        "_registry",
        "_session_id",
        "_settings",
        "_stderr_task",
        "_user_id",
    )

    def __init__(
        self,
        *,
        settings: Settings,
        paths: Paths,
        user_id: str,
        session_id: str,
        registry: SessionRegistry,
    ) -> None:
        self._settings = settings
        self._paths = paths
        self._user_id = user_id
        self._session_id = session_id
        self._registry = registry
        self._process: asyncio.subprocess.Process | None = None
        self._stderr_task: asyncio.Task[None] | None = None
        self._idle_task: asyncio.Task[None] | None = None
        self._idle_timeout_seconds = int(settings.mcp_idle_timeout_seconds)
        self._last_activity = time.monotonic()
        self._closed = False

    # --- lifecycle ------------------------------------------------------------

    @property
    def child_returncode(self) -> int | None:
        """The child's exit code once terminated (``None`` while it runs).

        The lifecycle-test/operations surface for the "the child is freed"
        invariant: ``-signal.SIGTERM`` after a normal teardown, ``-signal.SIGKILL``
        after the grace-period escalation, ``None`` before any spawn.
        """
        process = self._process
        return None if process is None else process.returncode

    async def start(self) -> None:
        """Register → AEK check → keyfile → store link → spawn → tasks.

        Registration happens FIRST (before any await — the factory's caller
        cannot observe an unregistered starting host) so a concurrent session
        of the same user always sees this one in the shared-keyfile refcount;
        any failure path tears the host down, which unregisters it again, so
        the registry only ever holds live-or-starting sessions.

        Fails closed BEFORE a child exists for every precondition: unknown
        user record, inactive AEK (:class:`AEKInactiveError`), unusable store
        link, or a spawn failure — in the failure cases any keyfile already
        written is removed again before the error propagates. A teardown that
        raced the in-flight spawn (shutdown drain) is finished over the
        freshly spawned child instead, and this start fails.
        """
        self._registry.register(self._session_id, self._user_id, self)
        try:
            record = get_user(self._paths, self._user_id)
            if record is None:
                raise RuntimeError(f"no user record for id {self._user_id!r}")
            if record.aek is None:
                raise AEKInactiveError(AEK_INACTIVE_GUIDANCE)
            # The unwrapped AEK exists only inside the callback;
            # materialize_key_file validates the hex and writes the
            # store-side .key atomically (0600).
            with_aek(
                self._paths,
                self._user_id,
                lambda aek: materialize_key_file(
                    self._paths, self._user_id, bytes(aek).hex()
                ),
            )
            self._ensure_store_link()
            self._ensure_mail_dir()
            self._process = await asyncio.create_subprocess_exec(
                str(self._settings.node_bin),
                str(self._settings.imap_mcp_server_js),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._child_env(),
                limit=_CHILD_STREAM_LIMIT,
            )
            self._last_activity = time.monotonic()
            self._stderr_task = asyncio.create_task(
                self._drain_stderr(), name=f"mcp-stderr:{self._session_id}"
            )
            self._idle_task = asyncio.create_task(
                self._watch_idle(), name=f"mcp-idle:{self._session_id}"
            )
        except BaseException:
            await self.aclose()  # failure cleanup; never leaks a spawned child
            raise
        if self._closed:
            # A concurrent teardown (the shutdown drain) ran while the spawn
            # was in flight and saw no process yet: the freshly spawned child
            # must not outlive the session it lost — finish the teardown over
            # it and fail this start (the gateway answers its 500 shape).
            await self._teardown()
            raise RuntimeError("tool host torn down while starting")
        log.info(
            "[mcp:%s] tool host started",
            self._user_id,
            extra={"fields": {"session_id": self._session_id}},
        )

    async def aclose(self) -> None:
        """Tear the host down exactly once (idempotent): SIGTERM → cleanup.

        Delegates the steps to :meth:`_teardown` under the once-only guard;
        :meth:`start` calls :meth:`_teardown` directly to finish a teardown
        that raced its in-flight spawn (see there). Best-effort by contract:
        the terminal steps already ran in :meth:`_teardown`'s ``finally``, so
        a failing child teardown is logged, never surfaced — callers include
        the unguarded idle watchdog, and a teardown error must neither mask
        the session's own unwind nor kill the watchdog.
        """
        if self._closed:
            return
        self._closed = True
        try:
            await self._teardown()
        except Exception:
            log.exception("[mcp:%s] tool host teardown error", self._user_id)

    async def _teardown(self) -> None:
        """The teardown steps; individually idempotent (safe to re-run).

        Also the idle watchdog's own exit path, so cancelling that task is
        skipped when the teardown runs from inside it. A child that already
        died, a keyfile already gone, or an entry already removed never
        prevents the remaining steps. The TERMINAL steps (keyfile removal and
        registry unregistration) are sync-only and guaranteed by the
        ``finally``: they run even when the child teardown above raises or
        this task is being cancelled — the plaintext key must never outlive
        the teardown and the registry entry must never get stuck.
        """
        try:
            current = asyncio.current_task()
            idle_task = self._idle_task
            self._idle_task = None
            if idle_task is not None and idle_task is not current:
                idle_task.cancel()
                try:
                    await idle_task
                except asyncio.CancelledError:
                    pass
            await self._terminate_child()
            stderr_task = self._stderr_task
            self._stderr_task = None
            if stderr_task is not None and stderr_task is not current:
                # Let the relay flush what the child wrote before it exited —
                # exactly the boot-failure/crash diagnostics — then cancel.
                try:
                    await asyncio.wait_for(
                        asyncio.shield(stderr_task), _STDERR_DRAIN_SECONDS
                    )
                except TimeoutError:
                    stderr_task.cancel()
                try:
                    await stderr_task
                except asyncio.CancelledError:
                    pass
        finally:
            try:
                if self._registry.has_live_sessions(
                    self._user_id, excluding=self._session_id
                ):
                    # A concurrent session of the same user still runs and
                    # shares the single users/<userId>/imap-store/.key path —
                    # it must find its materialized key. The last session out
                    # removes the file.
                    log.info(
                        "[mcp:%s] key file kept for concurrent session(s)",
                        self._user_id,
                    )
                else:
                    cleanup_key_file(self._paths, self._user_id)
            except OSError:
                log.exception("[mcp:%s] key file cleanup failed", self._user_id)
            self._registry.remove(self._session_id, self._user_id)
            log.info("[mcp:%s] tool host torn down", self._user_id)

    async def _terminate_child(self) -> None:
        """SIGTERM the child; SIGKILL after the grace period; await exit."""
        process = self._process
        if process is None:
            return
        if process.returncode is None:
            process.terminate()  # SIGTERM — the milestone-mandated teardown signal
            try:
                await asyncio.wait_for(process.wait(), _TERM_GRACE_SECONDS)
            except TimeoutError:
                process.kill()
                await process.wait()
        stdin = process.stdin
        if stdin is not None:
            stdin.close()  # the reader side sees EOF with (or before) exit

    # --- the ToolHost Protocol (verbatim frame bridge) --------------------------

    async def send_frame(self, frame: str) -> None:
        """Write one JSON-RPC message line to the child's stdin (newline added).

        Any failure (child gone → ``BrokenPipeError``/``ConnectionResetError``)
        propagates: the gateway's bridge unwinds and tears the session down.
        """
        self._touch_activity()
        stdin = self._stdin()
        stdin.write(frame.encode("utf-8") + b"\n")
        await stdin.drain()

    async def receive_frame(self) -> str:
        """Read one JSON-RPC message line from the child's stdout; ``""`` on EOF.

        Blank separator lines are skipped (they are neither frames nor EOF).
        A line beyond the stream limit is unframeable — the session is torn
        down and EOF reported rather than forwarding a truncated frame.
        """
        self._touch_activity()
        stdout = self._stdout()
        while True:
            try:
                raw = await stdout.readline()
            except ValueError:
                log.warning(
                    "[mcp:%s] stdout frame exceeded the stream limit; "
                    "ending the session",
                    self._user_id,
                )
                await self.aclose()
                return ""
            if not raw:
                return ""  # EOF sentinel per the ToolHost Protocol
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if line.strip():
                return line

    # --- housekeeping tasks ------------------------------------------------------

    async def _drain_stderr(self) -> None:
        """Relay the child's stderr to the log under ``[mcp:<userId>]``.

        Never touches stdout (the JSON-RPC channel). Ends on stderr EOF —
        i.e. when the child exits.
        """
        assert self._process is not None and self._process.stderr is not None
        stderr = self._process.stderr
        while True:
            try:
                raw = await stderr.readline()
            except ValueError:  # single line beyond the stream limit
                log.warning(
                    "[mcp:%s] dropped an over-long stderr line", self._user_id
                )
                continue
            if not raw:
                return
            text = _sanitize_log_text(raw)
            if text:
                log.info("[mcp:%s] %s", self._user_id, text)

    async def _watch_idle(self) -> None:
        """SIGTERM the host after ``mcp_idle_timeout_seconds`` without frames.

        Wakes at each computed deadline and recomputes: activity that happened
        during the sleep shrinks the idle span, so an active session is never
        torn down — it only costs one extra wakeup at the old deadline. A
        timeout of ``0`` (or less) tears down immediately (the test knob).
        """
        while True:
            idle_for = time.monotonic() - self._last_activity
            remaining = self._idle_timeout_seconds - idle_for
            if remaining <= 0:
                log.info(
                    "[mcp:%s] idle timeout (%ds) — terminating tool host",
                    self._user_id,
                    self._idle_timeout_seconds,
                )
                await self.aclose()
                return
            await asyncio.sleep(remaining)

    def _touch_activity(self) -> None:
        """Record a bridge exchange for the idle watchdog."""
        self._last_activity = time.monotonic()

    # --- spawn-time setup ----------------------------------------------------------

    def _child_env(self) -> dict[str, str]:
        """The explicit environment allowlist — exactly six variables.

        No parent environment is inherited beyond ``PATH``: no ``DATA_DIR``,
        no wrap-key/admin-hash paths, no credentials or tokens. The
        user-specific values are the calling user's own directories only.
        """
        return {
            # Absolute spellings: a relative DATA_DIR must not make the child's
            # HOME resolve against an arbitrary working directory.
            "HOME": str(self._paths.user_dir(self._user_id).resolve()),
            "IMAP_DOWNLOAD_DIR": str(
                self._paths.user_mail_dir(self._user_id).resolve()
            ),
            "IMAP_UPLOAD_TTL_MS": _UPLOAD_TTL_MS,
            "IMAP_MAX_UPLOAD_SIZE": _MAX_UPLOAD_SIZE,
            "PATH": os.environ.get("PATH", ""),
            "LANG": "C.UTF-8",
        }

    def _ensure_store_link(self) -> None:
        """Point ``$HOME/.imap-mcp`` at the per-user ``imap-store`` directory.

        Upstream hardcodes ``$HOME/.imap-mcp``; the gateway keeps the store at
        ``users/<userId>/imap-store`` — the symlink is the hinge (the same
        indirection the M04-T03 interop harness proved byte-compatible with
        upstream's ``AccountManager``). Idempotent: a correct link is left
        alone, a stale one is re-pointed via a temp symlink + ``os.replace``
        (atomic), and a REAL file/directory at the name is refused rather
        than clobbered (unknown state must fail loud).
        """
        home = self._paths.user_dir(self._user_id)
        # The stored link target must be ABSOLUTE: with a relative DATA_DIR the
        # raw path would resolve against the link's own directory.
        store = self._paths.user_imap_store_dir(self._user_id).resolve()
        link = home / _STORE_LINK_NAME
        if link.is_symlink():
            if os.path.realpath(link) == os.path.realpath(store):
                return
            temp = home / f".{_STORE_LINK_NAME}.{self._session_id[:8]}.tmp"
            temp.symlink_to(store, target_is_directory=True)
            os.replace(temp, link)
            return
        if link.exists():
            raise RuntimeError(
                f"refusing to replace non-symlink {_STORE_LINK_NAME!r} in "
                f"user directory {home}"
            )
        link.symlink_to(store, target_is_directory=True)

    def _ensure_mail_dir(self) -> None:
        """Ensure ``DATA_DIR/mail/<userId>`` exists (``0700``) before the spawn.

        M05-T03: the child's ``IMAP_DOWNLOAD_DIR`` — where unmodified upstream
        saves ``imap_download_attachment`` files and stages ``imap_upload_file``
        uploads — must exist and be private BEFORE the child runs, so downloads
        and upload staging persist on the ``mail`` bind mount, per-user
        subdirectory. :func:`imap_mcp_gateway.store.fs_safe.ensure_dir` creates
        missing parents with ``0700`` and re-asserts the mode on an existing
        leaf (umask-filtered or drifted permissions are repaired). Deliberately
        never undone by teardown: the artifacts are the user's mail downloads,
        which must outlive the session.
        """
        ensure_dir(self._paths.user_mail_dir(self._user_id))

    def _stdin(self) -> asyncio.StreamWriter:
        """The child's stdin writer; loud failure before ``start``/after death."""
        process = self._process
        if process is None or process.stdin is None:
            raise RuntimeError("tool host is not started")
        return process.stdin

    def _stdout(self) -> asyncio.StreamReader:
        """The child's stdout reader; loud failure before ``start``."""
        process = self._process
        if process is None or process.stdout is None:
            raise RuntimeError("tool host is not started")
        return process.stdout


class NodeToolHostFactory:
    """The production :class:`imap_mcp_gateway.mcp.gateway.ToolHostFactory`.

    One instance per gateway process (built once in ``app.run`` and handed to
    :func:`imap_mcp_gateway.web.server.create_app`). :meth:`create` spawns a
    fresh child per call — the isolation boundary: no code path can return a
    host bound to another user or session, because a host is born with its
    user id and never re-bound.
    """

    def __init__(self, *, settings: Settings, paths: Paths) -> None:
        self._settings = settings
        self._paths = paths
        self._registry = SessionRegistry(paths)

    @property
    def registry(self) -> SessionRegistry:
        """The live-session registry (startup sweep + shutdown drain entry)."""
        return self._registry

    async def create(self, user: UserMetadata, session_id: str) -> ToolHost:
        """Start one fresh tool host for ``user`` (the host self-registers).

        AEK-inactive users get :class:`AEKInactiveGuidanceHost` — the
        structured fail-closed guidance as a JSON-RPC error on the MCP
        channel, no child, no keyfile. Other failures raise (the gateway
        answers its generic 500): a missing user record, or a spawn/start
        failure — every start failure path unregisters the session again
        (:meth:`NodeToolHost.start` registers up front, before its first
        await, so the shared-keyfile refcount in :meth:`NodeToolHost.aclose`
        always sees concurrent same-user sessions).
        """
        record = get_user(self._paths, user.id)
        if record is None:
            raise RuntimeError(f"no user record for id {user.id!r}")
        if record.aek is None:
            log.info("[mcp:%s] account encryption not activated — fail-closed host", user.id)
            return AEKInactiveGuidanceHost(user.id)
        host = NodeToolHost(
            settings=self._settings,
            paths=self._paths,
            user_id=user.id,
            session_id=session_id,
            registry=self._registry,
        )
        await host.start()
        return host

    async def shutdown(self) -> None:
        """Drain every live session (container shutdown); the registry empties."""
        await self._registry.drain()
