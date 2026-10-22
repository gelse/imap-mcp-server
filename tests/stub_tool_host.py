"""A stub upstream tool host for the M05-T02 tests (Python; NOT Node code).

The production child is the vendored ``imap-mcp-server`` Node bundle; these
tests cannot assume Node is installed, so they point ``Settings.node_bin`` at
``sys.executable`` and ``Settings.imap_mcp_server_js`` at this file — the
spawn contract (``argv = [interpreter, entry_script]``, stdio pipes, the
six-variable env allowlist) is identical, and everything around the process
is what is under test.

Wire protocol: newline-delimited JSON-RPC over stdin/stdout, exactly what the
real child speaks. Behavior:

- ``initialize`` / ``tools/list`` — canned upstream-shaped replies (id echoed);
- ``tools/call`` ``imap_list_accounts`` — reads ``$HOME/.imap-mcp/accounts.json``
  (the path unmodified upstream resolves through its per-user ``HOME`` hinge)
  and answers the ``{id, name}`` pairs as a tool-result text payload;
- ``tools/call`` ``imap_add_account`` — appends one record to
  ``$HOME/.imap-mcp/accounts.json`` (upstream ``JSON.stringify(accounts,
  null, 2)`` shape, written 0600), the file-system effect upstream's
  ``addAccount`` has — the M05-T04 store-isolation scenarios assert where
  the write landed through the NEXT ``imap_list_accounts`` of each user;
- ``tools/call`` ``imap_remove_account`` — resolves ``accountId`` against
  the SAME caller-local store (upstream's ``resolveAccountId`` contract):
  unknown ids raise the upstream-shaped "Account <id> not found" tool error
  (an ``isError`` result), known ids are removed from the file. This is the
  account-id-addressing tool the cross-user scenario aims at another user's
  id with — the caller's own store is the only one the child can ever see;
- ``tools/call`` ``imap_download_attachment`` — writes fixed bytes into
  ``$IMAP_DOWNLOAD_DIR/<basename(filename)>`` (mkdir -p first), exactly the
  file-system effect unmodified upstream's non-image save path has (M05-T03:
  the attachment lands in the per-user mail directory via the child env);
- ``tools/call`` anything else — ``{"ok": <name>}``;
- ``debug/env`` — the child's exact environment (the allowlist assertions);
- ``debug/pid`` — the child's pid (the "two sessions, two children" proof);
- ``debug/stderr`` — writes ``params.text`` to stderr verbatim (the relay and
  log-forging tests);
- any other method with an id — echoes ``{method, params}`` back (the
  verbatim-framing proof: extra fields and key order must survive);
- notifications (no ``id``) — never answered; acknowledged out-of-band with
  the ``notifications/stub-ack`` notification carrying the received method.

Exits 0 on stdin EOF.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any


class _StubToolError(Exception):
    """A tool-level failure the stub reports as an MCP ``isError`` result.

    Mirrors how the MCP SDK surfaces a tool handler that raises: the request
    is answered with a result carrying ``isError: true`` and the message as
    text content — never a transport-level JSON-RPC error.
    """


def _emit(frame: dict[str, Any]) -> None:
    """Write one JSON-RPC line to stdout; the channel must stay flushed."""
    sys.stdout.write(json.dumps(frame) + "\n")
    sys.stdout.flush()


def _store_file() -> Path:
    """The upstream store path exactly as unmodified upstream resolves it."""
    home = os.environ.get("HOME", "")
    return Path(home) / ".imap-mcp" / "accounts.json"


def _read_raw_records(store: Path) -> list[dict[str, Any]]:
    """The raw record list of one store; ``[]`` when the file is absent."""
    if not store.is_file():
        return []
    payload = json.loads(store.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise SystemExit(f"stub: corrupt store at {store}")
    return [row for row in payload if isinstance(row, dict)]


def _write_raw_records(store: Path, records: list[dict[str, Any]]) -> None:
    """Persist the record list in upstream's ``JSON.stringify(.., null, 2)`` shape.

    Written 0600 like every secret-bearing store file (the plaintext password
    the stub records stay test-local dummies, but the file lives in the same
    directory the gateway treats as a store).
    """
    store.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(records, indent=2, ensure_ascii=False)
    descriptor = os.open(store, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(payload)


def _read_store_accounts() -> list[dict[str, Any]]:
    """The account list exactly as upstream would see it via ``$HOME``."""
    return [
        {"id": row.get("id"), "name": row.get("name")}
        for row in _read_raw_records(_store_file())
    ]


def _add_account(arguments: dict[str, Any]) -> dict[str, Any]:
    """Append one account record to the CALLER's store (upstream addAccount).

    The record lands in ``$HOME/.imap-mcp/accounts.json`` — the only store
    this child can ever see — in upstream's on-disk shape (camelCase keys,
    UUID4 id, ``JSON.stringify(accounts, null, 2)``). The ``password`` is the
    documented empty "no credential" value: the stub does not encrypt (it
    holds no ``.key``-reading logic), and the empty value is exactly what the
    gateway's strict store schema accepts for a credential-less record.
    """
    record: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "name": str(arguments.get("name") or "unnamed"),
        "host": str(arguments.get("host") or ""),
        "port": int(arguments.get("port") or 993),
        "user": str(arguments.get("user") or ""),
        "password": "",
        "tls": True,
    }
    store = _store_file()
    records = _read_raw_records(store)
    records.append(record)
    _write_raw_records(store, records)
    return {"added": True, "id": record["id"], "name": record["name"]}


def _remove_account(arguments: dict[str, Any]) -> dict[str, Any]:
    """Resolve ``accountId`` in the caller's store; unknown ids are tool errors.

    Upstream's ``resolveAccountId`` contract: an id that does not exist in
    the (caller-local) store raises "Account <id> not found. Use
    imap_list_accounts to see available accounts." — the tool error the
    cross-user isolation scenario asserts. A known id is removed from the
    file (the caller's own store — and only that one).
    """
    account_id = str(arguments.get("accountId") or "")
    store = _store_file()
    records = _read_raw_records(store)
    remaining = [row for row in records if row.get("id") != account_id]
    if len(remaining) == len(records):
        raise _StubToolError(
            f"Account {account_id} not found. "
            "Use imap_list_accounts to see available accounts."
        )
    _write_raw_records(store, remaining)
    return {"removed": True, "id": account_id}


def _tool_payload(params: dict[str, Any]) -> dict[str, Any]:
    """The payload for one ``tools/call``."""
    name = params.get("name")
    if name == "imap_list_accounts":
        return {"accounts": _read_store_accounts()}
    if name == "imap_add_account":
        return _add_account(params.get("arguments") or {})
    if name == "imap_remove_account":
        return _remove_account(params.get("arguments") or {})
    if name == "imap_download_attachment":
        return _save_download_attachment(params.get("arguments") or {})
    return {"ok": name}


_ATTACHMENT_BYTES = b"stub-attachment-bytes"
"""The fixed content the stub saves for ``imap_download_attachment`` calls."""


def _save_download_attachment(arguments: dict[str, Any]) -> dict[str, Any]:
    """Save an attachment into ``$IMAP_DOWNLOAD_DIR`` like upstream does.

    Unmodified upstream resolves ``DOWNLOAD_DIR = $IMAP_DOWNLOAD_DIR``,
    ``mkdirSync(downloadDir, {recursive: true})``s it, and writes the file at
    ``join(DOWNLOAD_DIR, basename(filename))``. The stub reproduces exactly
    that effect (with fixed bytes) so tests can assert where the child wrote.
    """
    filename = str(arguments.get("filename") or "attachment.bin")
    download_dir = Path(os.environ["IMAP_DOWNLOAD_DIR"])
    download_dir.mkdir(parents=True, exist_ok=True)
    target = download_dir / Path(filename).name
    target.write_bytes(_ATTACHMENT_BYTES)
    return {
        "saved": True,
        "path": str(target),
        "filename": target.name,
        "contentType": "application/octet-stream",
        "size": len(_ATTACHMENT_BYTES),
    }


def _handle(frame: dict[str, Any]) -> None:
    """Answer one inbound frame per the contract in the module docstring."""
    method = str(frame.get("method", ""))
    params = frame.get("params")
    params_dict: dict[str, Any] = params if isinstance(params, dict) else {}
    request_id = frame.get("id")
    if request_id is None:  # notification: never answered on the request lane
        _emit(
            {
                "jsonrpc": "2.0",
                "method": "notifications/stub-ack",
                "params": {"received": method},
            }
        )
        return
    result: dict[str, Any]
    if method == "initialize":
        result = {
            "protocolVersion": params_dict.get("protocolVersion"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "stub imap-mcp-server", "version": "2.2.0"},
        }
    elif method == "tools/list":
        result = {
            "tools": [
                {
                    "name": "stub_tool",
                    "description": "stub tool",
                    "inputSchema": {"type": "object"},
                }
            ]
        }
    elif method == "tools/call":
        try:
            payload: dict[str, Any] = _tool_payload(params_dict)
        except _StubToolError as exc:
            result = {
                "content": [{"type": "text", "text": json.dumps({"error": str(exc)})}],
                "isError": True,
            }
        else:
            result = {"content": [{"type": "text", "text": json.dumps(payload)}]}
    elif method == "debug/env":
        result = {"env": dict(os.environ)}
    elif method == "debug/pid":
        result = {"pid": os.getpid()}
    elif method == "debug/stderr":
        sys.stderr.write(f"{params_dict.get('text', 'stub stderr line')}\n")
        sys.stderr.flush()
        if params_dict.get("exit"):
            sys.exit(0)  # die immediately: the last stderr line races the relay
        result = {"ok": True}
    else:
        result = {"echo": {"method": method, "params": params}}
    _emit({"jsonrpc": "2.0", "id": request_id, "result": result})


def main() -> None:
    """Read-request/reply loop; exits 0 on stdin EOF."""
    while True:
        line = sys.stdin.readline()
        if not line:
            return
        line = line.strip()
        if not line:
            continue
        _handle(json.loads(line))


if __name__ == "__main__":
    main()
