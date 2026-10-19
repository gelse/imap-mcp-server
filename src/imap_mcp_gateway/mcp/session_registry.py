"""Registry of live per-user tool-host sessions (M05-T02).

One :class:`SessionRegistry` belongs to the production
:class:`imap_mcp_gateway.mcp.tool_host.NodeToolHostFactory` and answers two
questions the gateway deliberately does not: which MCP sessions currently
have a tool-host child running, and whose they are. The map is keyed by the
pair ``(MCP session id, user id)`` — never the session id alone — so a
session can never be looked up, drained, or accounted for without naming its
user too (mirrors the gateway's isolation binding: a session id bound to
another user is, for every purpose here, an unknown session).

Entries live exactly as long as their host's start-to-teardown window: the
host self-registers at the very beginning of :meth:`NodeToolHost.start`
(before its first await, so concurrent same-user sessions and a shutdown
drain always see it), and :meth:`NodeToolHost.aclose` — the single teardown
funnel (client DELETE, host death, idle timeout, shutdown drain, or a failed
start) — removes the entry again. A registry that is empty after teardown is
the "processes are freed" invariant the lifecycle tests pin; nothing here
pools or reuses children across users (M05 non-goal: no process pool).

Startup / shutdown duties:

- :meth:`SessionRegistry.cleanup_orphans` is the startup walk over
  ``DATA_DIR/users/*/imap-store/.key``: a materialized session keyfile has no
  legitimate reason to exist while no tool-host session is running, so every
  file found is deleted. It delegates to the M04-T03 store API
  (:func:`imap_mcp_gateway.store.session_keyfile.sweep_orphan_key_files`) —
  the same primitive the boot lifespan has run since M04 — so the sweep has
  one implementation and the registry adds only the session-aware entry
  point (no new store file). The registry itself does not log the sweep: the
  boot lifespan owns that ``[config]`` line, so a boot can never emit it
  twice.
- :meth:`SessionRegistry.drain` is the container-shutdown path: every live
  host is closed (SIGTERM + wait) and the registry ends empty. Wired in
  ``app.run``'s boot lifespan alongside the startup sweep.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import anyio

from imap_mcp_gateway.config.paths import Paths
from imap_mcp_gateway.log import get_logger
from imap_mcp_gateway.store.session_keyfile import sweep_orphan_key_files

if TYPE_CHECKING:
    from imap_mcp_gateway.mcp.gateway import ToolHost

log = get_logger(__name__)


@dataclass(slots=True)
class SessionEntry:
    """One live tool-host session: its ids and its host handle."""

    session_id: str
    user_id: str
    host: ToolHost


class SessionRegistry:
    """Session map keyed by ``(MCP session id, user id)`` (see module docstring)."""

    def __init__(self, paths: Paths) -> None:
        self._paths = paths
        self._sessions: dict[tuple[str, str], SessionEntry] = {}

    def register(self, session_id: str, user_id: str, host: ToolHost) -> SessionEntry:
        """Add one live session; a duplicate id for the same user is a bug."""
        key = (session_id, user_id)
        if key in self._sessions:
            raise RuntimeError(
                f"session {session_id!r} already registered for user {user_id!r}"
            )
        entry = SessionEntry(session_id=session_id, user_id=user_id, host=host)
        self._sessions[key] = entry
        return entry

    def remove(self, session_id: str, user_id: str) -> bool:
        """Forget one session; idempotent (``False`` when it was not live)."""
        return self._sessions.pop((session_id, user_id), None) is not None

    def get(self, session_id: str) -> SessionEntry | None:
        """The live entry for ``session_id``, whatever user owns it, or ``None``."""
        for key, entry in self._sessions.items():
            if key[0] == session_id:
                return entry
        return None

    def entries(self) -> list[SessionEntry]:
        """Snapshot of the live entries (drain/inspection iterate over a copy)."""
        return list(self._sessions.values())

    def has_live_sessions(self, user_id: str, *, excluding: str | None = None) -> bool:
        """``True`` iff ``user_id`` has a live session other than ``excluding``.

        The shared-keyfile refcount: concurrent sessions of one user share the
        single ``users/<userId>/imap-store/.key`` path, so a teardown may only
        remove it when the LAST session of that user ends. ``excluding`` names
        the tearing-down session id.
        """
        return any(
            key[0] != excluding and key[1] == user_id for key in self._sessions
        )

    def __len__(self) -> int:
        return len(self._sessions)

    def cleanup_orphans(self) -> list[str]:
        """Delete every stale ``imap-store/.key``; return the swept user ids.

        The startup walk (crash leftovers): delegates to
        :func:`imap_mcp_gateway.store.session_keyfile.sweep_orphan_key_files`,
        which touches only ``users/<userId>/imap-store/.key`` files and never
        the rest of a store. No logging here — the boot lifespan owns the
        ``[config]`` sweep line (one log site, never doubled).
        """
        return sweep_orphan_key_files(self._paths)

    async def drain(self) -> None:
        """Close every live host (container shutdown); the registry ends empty.

        Each host's :meth:`~imap_mcp_gateway.mcp.gateway.ToolHost.aclose` is
        awaited exactly once and independently — one failing teardown must
        not skip the others — and unregisters itself, so ``len()`` is 0 when
        this returns. The loop is shielded (the gateway's own ``_discard``
        pattern): once shutdown drain begins, an outer cancellation cannot
        leave the remaining hosts un-drained.
        """
        with anyio.CancelScope(shield=True):
            for entry in self.entries():
                try:
                    await entry.host.aclose()
                except Exception:
                    log.exception(
                        "[mcp:%s] tool host teardown failed during drain",
                        entry.user_id,
                    )
