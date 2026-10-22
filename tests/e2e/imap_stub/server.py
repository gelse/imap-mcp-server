"""Minimal asyncio IMAP4rev1 + SMTP stub for the E2E suite (M06-T01).

IMAP: a hand-rolled line protocol server speaking just enough of RFC 3501
for the upstream ``imap-mcp-server`` child to open a session and list/
fetch mail — ``LOGIN``, ``SELECT``, ``LIST``, ``FETCH``, ``NOOP``, plus
``CAPABILITY`` and ``LOGOUT`` for well-behaved clients. Every other
command is answered ``NO`` (fail closed) without disconnecting. Only
``e2euser``/``e2epass`` authenticates; wrong credentials get ``NO`` —
that negative case is a scenario assertion (login with bad credentials
must not magically succeed).

The mailbox state is hardcoded: one message in ``INBOX`` and the two
folders ``INBOX``/``Sent`` listed. No persistence, no real mail.

SMTP: ``aiosmtpd`` in non-authenticating relay-less mode, accepting mail
into memory (this suite never reads it back — the stub only has to accept
deliveries so upstream SMTP tooling can complete).

Both servers listen on 0.0.0.0 inside the container; the compose manifest
publishes them only on 127.0.0.1 on the host.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

from aiosmtpd.controller import Controller

# --- fixed mailbox state ---------------------------------------------------------

VALID_USER = "e2euser"
VALID_PASSWORD = "e2epass"
"""The single credential the stub accepts (M06-T01 fixture constant)."""

_CAPABILITIES = "* CAPABILITY IMAP4rev1 AUTH=PLAIN"
"""The greeting/POSTAUTH capability line (IMAP4rev1 is all upstream needs)."""

_FETCH_RESPONSE = (
    '* 1 FETCH (UID 1 FLAGS (\\Seen) '
    'INTERNALDATE "01-Jan-2026 00:00:00 +0000" '
    'RFC822.SIZE 48 '
    'BODY[] {48}\r\n'
    "From: sender@example.com\r\n"
    "To: e2euser@example.com\r\n"
    "Subject: e2e\r\n\r\nstub body\r\n)"
)
"""One hardcoded FETCH answer: a single tiny literal-carrying message."""

_LIST_RESPONSE = ('* LIST (\\HasNoChildren) "/" "INBOX"\r\n'
                  '* LIST (\\HasNoChildren) "/" "Sent"')
"""The hardcoded LIST answer: exactly two mailboxes."""

_MAILBOX_EXISTS = "* 1 EXISTS\r\n* 1 RECENT"
"""The SELECT untitled responses: INBOX holds exactly one message."""


def _imap_response(tag: str, text: str) -> bytes:
    """One tagged IMAP response line."""
    return f"{tag} {text}\r\n".encode("ascii")


class _IMAPClientSession:
    """Line protocol state for one connected IMAP client."""

    def __init__(self) -> None:
        self.authenticated = False
        self.selected = False

    async def handle_line(self, line: str, writer: asyncio.StreamWriter) -> None:
        """Answer one client command line; ``tag`` is the client's first token."""
        tag, _, rest = line.partition(" ")
        if not tag:  # a blank/garbage line: nothing to answer
            return
        command = rest.split(" ", 1)[0].upper() if rest else ""

        if command == "CAPABILITY":
            writer.write(_imap_response(tag, f"{_CAPABILITIES}"))
            await writer.drain()
            return
        if command == "NOOP":
            writer.write(_imap_response(tag, "OK NOOP completed"))
            await writer.drain()
            return
        if command == "LOGOUT":
            writer.write(b"* BYE stub logging out\r\n")
            await writer.drain()
            writer.write(_imap_response(tag, "OK LOGOUT completed"))
            await writer.drain()
            writer.close()
            return
        if command == "LOGIN":
            # LOGIN <user> <pass> — either quoting style (bare/quoted) works;
            # the stub only has one valid pair, so the parse can be coarse.
            args = rest[len("LOGIN"):].strip()
            parts: list[str] = []
            token = ""
            in_quotes = False
            for char in args:
                if char == '"':
                    in_quotes = not in_quotes
                elif char == " " and not in_quotes:
                    parts.append(token)
                    token = ""
                else:
                    token += char
            if token:
                parts.append(token)
            ok = len(parts) == 2 and parts[0] == VALID_USER and parts[1] == VALID_PASSWORD
            self.authenticated = ok
            writer.write(_imap_response(tag, "OK LOGIN completed" if ok else
                                        "NO LOGIN failed"))
            await writer.drain()
            return
        if not self.authenticated:
            # Every mailbox command before a successful LOGIN fails closed.
            writer.write(_imap_response(tag, "NO Please authenticate first"))
            await writer.drain()
            return
        if command == "SELECT":
            self.selected = True
            writer.write(f"{_MAILBOX_EXISTS}\r\n".encode("ascii"))
            await writer.drain()
            writer.write(_imap_response(tag, "OK [READ-WRITE] SELECT completed"))
            await writer.drain()
            return
        if command == "LIST":
            writer.write(f"{_LIST_RESPONSE}\r\n".encode("ascii"))
            await writer.drain()
            writer.write(_imap_response(tag, "OK LIST completed"))
            await writer.drain()
            return
        if command == "FETCH":
            writer.write(f"{_FETCH_RESPONSE}\r\n".encode("ascii"))
            await writer.drain()
            writer.write(_imap_response(tag, "OK FETCH completed"))
            await writer.drain()
            return
        # Unknown/authenticated-but-unsupported: NO, connection stays up.
        writer.write(_imap_response(tag, "NO unsupported command"))
        await writer.drain()


async def _handle_imap_client(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    """Serve one IMAP client until EOF/disconnect."""
    session = _IMAPClientSession()
    writer.write(f"{_CAPABILITIES} imap-mcp-e2e-stub ready\r\n".encode("ascii"))
    await writer.drain()
    try:
        while True:
            raw = await reader.readline()
            if not raw:
                return
            await session.handle_line(raw.decode("ascii", "replace").rstrip("\r\n"),
                                      writer)
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()


def _smtp_handler() -> Any:
    """An aiosmtpd handler that accepts (and discards) every message."""
    try:
        from aiosmtpd.handlers import Message as MessageHandler  # noqa: PLC0415
    except ImportError:  # pragma: no cover - aiosmtpd is a pinned build dep

        class _AcceptAllPlain:
            async def handle_DATA(self, *args: Any) -> tuple[int, bytes]:
                return 250, b"OK"

        return _AcceptAllPlain()

    # aiosmtpd is a build-time dependency of the stub IMAGE only — it is
    # never installed in the dev/e2e venv where mypy runs, so with
    # ``ignore_missing_imports`` its names are Any and strict's
    # disallow_subclassing_any must be silenced on exactly this line.
    class _AcceptAll(MessageHandler):  # type: ignore[misc]
        def handle_message(self, message: Any) -> None:  # noqa: ARG002
            return  # accepted into memory; nothing is persisted

    return _AcceptAll()


def main() -> None:
    """Start both servers and run until cancelled."""
    logging.basicConfig(level=logging.INFO)
    imap_port = int(os.environ.get("IMAP_PORT", "143"))
    smtp_port = int(os.environ.get("SMTP_PORT", "25"))

    smtp = Controller(_smtp_handler(), hostname="0.0.0.0", port=smtp_port)
    smtp.start()

    async def serve() -> None:
        imap_server = await asyncio.start_server(_handle_imap_client, "0.0.0.0",
                                                 imap_port)
        async with imap_server:
            await imap_server.serve_forever()

    try:
        asyncio.run(serve())
    finally:
        smtp.stop()


if __name__ == "__main__":
    main()
