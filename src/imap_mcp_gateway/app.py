"""Composition root for the gateway process.

``run()`` is the console-script / ``python -m`` entry point (M01-T01) and the
only place the environment is read (M01-T02): it resolves ``Settings``, builds
the one ``Paths`` object from ``DATA_DIR`` and passes both on. M01-T04
completes the HTTP bootstrap: the data-dir layout is created, the app comes
from ``web.server.create_app`` with the ``[boot]`` lifespan below, and
uvicorn serves it — uvicorn owns SIGTERM/SIGINT during serve and runs the
lifespan shutdown on the way out; the pre-installed clean-exit handlers
(``_terminate_cleanly``) absorb the signal uvicorn re-raises afterwards, so a
graceful SIGTERM/SIGINT stop exits 0. The lifespan also runs the admin-key
lifecycle (M02-T02): the first boot prints the plaintext key exactly once,
every later boot only ``[auth] existing key found`` — never key material —
and then the wrap-key lifecycle (M04-T01): ``[config] wrap key created`` on
first boot, ``[config] wrap key found`` afterwards. Unlike the admin key,
the wrap key is never displayed or logged: it is not an operator credential.
M05-T02 drops the real tool-host factory in: ``run`` builds the one
``NodeToolHostFactory`` (per-session upstream Node children) and hands it to
``create_app``; the lifespan uses its registry for the startup orphan sweep
and drains every live tool-host session on shutdown.
"""

from __future__ import annotations

import argparse
import signal
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from types import FrameType
from typing import NoReturn

import uvicorn
from fastapi import FastAPI
from starlette.types import Lifespan

from imap_mcp_gateway import __version__
from imap_mcp_gateway.config.env import Settings
from imap_mcp_gateway.config.paths import Paths, build_paths
from imap_mcp_gateway.log import get_logger
from imap_mcp_gateway.mcp.tool_host import NodeToolHostFactory
from imap_mcp_gateway.store.admin_key import ensure_admin_key
from imap_mcp_gateway.store.fs_safe import ensure_dir
from imap_mcp_gateway.store.session_keyfile import sweep_orphan_key_files
from imap_mcp_gateway.store.wrap_key import ensure_wrap_key
from imap_mcp_gateway.web.server import create_app

log = get_logger(__name__)


def _terminate_cleanly(signum: int, frame: FrameType | None) -> NoReturn:
    """Convert a termination signal into a clean ``SystemExit(0)``.

    Installed for SIGTERM/SIGINT before ``uvicorn.run``. During serve uvicorn
    swaps these handlers for its own graceful-stop handler, so the graceful
    path is untouched. But uvicorn 0.32's ``Server.capture_signals`` restores
    the pre-serve handlers once shutdown has run and then RE-RAISES the
    captured signal; with the default disposition that re-raise would kill the
    process after its clean shutdown (exit 128+15 = 143 under ``kill -TERM``).
    Landing the re-raise here instead exits 0. The same handler also covers
    the pre-serve window: a signal arriving before uvicorn's handlers are up
    exits cleanly now instead of taking the default disposition.
    """
    raise SystemExit(0)


def run(argv: Sequence[str] | None = None) -> int:
    """Console-script / ``python -m`` entry point; returns the exit code.

    ``--help`` and ``--version`` print their output and exit 0 (argparse raises
    ``SystemExit`` internally). Any other invocation resolves the environment
    once (``Settings``), builds the single ``paths`` object from ``DATA_DIR``,
    creates the data layout, and serves the app until uvicorn exits. A
    SIGTERM/SIGINT stops uvicorn gracefully (lifespan shutdown included) and
    then exits 0 via the pre-installed handlers — see ``_terminate_cleanly``.
    """
    parser = argparse.ArgumentParser(
        prog="imap-mcp-gateway",
        description=(
            "Self-hosted FastAPI gateway in front of the upstream "
            "imap-mcp-server. Serves /healthz with JSON error handling; "
            "the full HTTP surface grows in later milestones."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.parse_args(argv)

    # The single startup environment read: Settings resolves the process env
    # and the one Paths object is built from DATA_DIR here at the composition
    # root. Consumers receive these values; nothing else re-reads the env.
    # (LOG_LEVEL is resolved into Settings but deliberately NOT applied to the
    # loggers yet — every gateway logger stays at its get_logger default; wire
    # a global level here only when a milestone first needs it.)
    settings = Settings()
    paths = build_paths(settings.data_dir)
    log.info(
        "[config] data layout resolved",
        extra={"fields": {"data_dir": str(paths.data_dir)}},
    )

    _ensure_data_dirs(paths)
    # M05-T02: the real tool-host factory — one NodeToolHost per authenticated
    # MCP session. Built once here (the composition root) and shared by the
    # app (the /mcp gateway's factory seam) and the boot lifespan (startup
    # orphan sweep + shutdown drain), so the registry has exactly one owner.
    tool_host_factory = NodeToolHostFactory(settings=settings, paths=paths)
    application = create_app(
        settings,
        lifespan=_boot_lifespan(paths, tool_host_factory),
        tool_host_factory=tool_host_factory,
    )
    # Signal-exit normalization (see _terminate_cleanly): uvicorn replaces
    # these handlers for the whole serve — so the graceful SIGTERM/SIGINT path
    # (and the lifespan shutdown behind it) is untouched — and restores them
    # before re-raising the captured signal, making THAT the exit-0 path.
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, _terminate_cleanly)
    uvicorn.run(
        application,
        host="0.0.0.0",
        port=settings.http_port,
        log_config=None,
    )
    return 0


def _ensure_data_dirs(paths: Paths) -> None:
    """Create the top-level data layout (``config/``, ``users/``, ``mail/``) at 0700."""
    for directory in (paths.config_dir(), paths.users_dir(), paths.mail_dir()):
        ensure_dir(directory)  # PRIVATE_DIR_MODE (0700) is ensure_dir's default


def _boot_lifespan(
    paths: Paths, tool_host_factory: NodeToolHostFactory | None = None
) -> Lifespan[FastAPI]:
    """Return the FastAPI lifespan emitting the greppable ``[boot]`` lines.

    ``tool_host_factory`` (M05-T02) is supplied by ``run``: its registry then
    owns the startup orphan sweep and the shutdown drain of live tool-host
    sessions. ``None`` keeps the pre-M05 behavior (the direct
    :func:`imap_mcp_gateway.store.session_keyfile.sweep_orphan_key_files`
    sweep, no drain) for tests that boot the app without the MCP surface.
    """

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        log.info(
            "[boot] starting imap-mcp-gateway",
            extra={
                "fields": {
                    "data_dir": str(paths.data_dir),
                    "version": __version__,
                },
            },
        )
        # M02-T02: admin-key ensure, before the HTTP listener starts. First
        # boot displays the plaintext exactly once — the operator's only
        # delivery channel; every later boot reports "existing key found".
        # Single-display invariant: the created-branch log line below is the
        # ONLY code path that ever formats the ensure result's plaintext; no
        # later code may log it (pinned by tests/test_admin_key_lifecycle.py).
        ensure_result = ensure_admin_key(paths)
        if ensure_result.created:
            log.info(
                "[auth] admin key created — store it now; "
                f"it will not be shown again: {ensure_result.plaintext}"
            )
            log.info(f"[auth] hash file: {paths.admin_key_hash_path()}")
        else:
            log.info("[auth] existing key found")
        # M04-T01: wrap-key ensure, immediately after the admin-key ensure.
        # The wrap key is server-side encryption material, not an operator
        # credential: unlike the admin key it is never displayed, so only the
        # created/found fact is logged — never key material. A missing or
        # corrupted wrap key with wrapped AEKs on disk raises out of the
        # ensure and aborts startup (fail fast, never silently rewrap).
        wrap_result = ensure_wrap_key(paths)
        if wrap_result.created:
            log.info("[config] wrap key created")
        else:
            log.info("[config] wrap key found")
        # M04-T03: session-key-file orphan sweep. A materialized imap-store/.key
        # must exist only for the lifetime of a tool-host session; a crash
        # between materialize and cleanup leaves one behind — delete every
        # orphan before serving (at rest the AEK exists only in wrapped form).
        # Only the count is logged — the ids/paths stay out of the log. With
        # the M05-T02 factory this runs through the session registry's
        # cleanup_orphans (the same store API underneath).
        if tool_host_factory is not None:
            swept_users = tool_host_factory.registry.cleanup_orphans()
        else:
            swept_users = sweep_orphan_key_files(paths)
        if swept_users:
            log.info(
                "[config] swept orphaned session key file(s)",
                extra={"fields": {"count": len(swept_users)}},
            )
        # Remaining reserved startup hooks — comment-only until their
        # milestones land:
        # - M05-T01: MCP gateway mount (mount the /mcp ASGI app).
        try:
            yield
        finally:
            # M05-T02: drain every live tool-host session (SIGTERM the
            # children, remove their session keyfiles, empty the registry)
            # before uvicorn's shutdown completes.
            if tool_host_factory is not None:
                await tool_host_factory.shutdown()
            log.info("[boot] shutdown complete")

    return lifespan
