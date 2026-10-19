# Connect an MCP client

An MCP client connects to the gateway's Streamable HTTP endpoint at
`http://<host>:3030/mcp` with a **user login key** in a header. Admin keys do
not work here — the endpoint rejects them by construction.

Port note: every `:3030` URL below is only the compose default. If it does
not work, your deployment runs on another port — ask whoever runs the
gateway, and substitute your actual port throughout.

## What you need

1. The gateway URL — `http://<host>:3030/mcp` (exact path, no trailing
   slash; it is a single route, not a mount).
2. A user's login key — `usr_` plus 43 characters, handed over by the admin
   at creation or rotation, or rotated by the user themselves.
3. That user's account encryption key activated — see
   [Activate account encryption first](#activate-account-encryption-first).

## Authenticate

Present the login key in one of two headers:

```http
Authorization: Bearer usr_...
```

or

```http
X-Api-Key: usr_...
```

`Authorization` is canonical. If both are present, `Authorization` wins.
Any other authorization scheme (`Basic`, …) is rejected outright, even when
`X-Api-Key` is also set.

## Claude Desktop

Add the gateway to Claude Desktop's `mcpServers` configuration:

```json
{
  "mcpServers": {
    "imap": {
      "type": "http",
      "url": "http://localhost:3030/mcp",
      "headers": {
        "Authorization": "Bearer usr_REPLACE_ME"
      }
    }
  }
}
```

Replace `localhost` with the gateway host and `usr_REPLACE_ME` with the
user's login key.

## Cursor and other clients

Any client that speaks MCP over Streamable HTTP needs the same three things —
URL, auth header, and the exact path `/mcp`. For example, in Cursor's
`~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "imap": {
      "url": "http://localhost:3030/mcp",
      "headers": {
        "Authorization": "Bearer usr_REPLACE_ME"
      }
    }
  }
}
```

## Smoke-test with curl

Initialize a session:

```sh
curl -sS -D - -X POST http://localhost:3030/mcp \
  -H "Authorization: Bearer usr_REPLACE_ME" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"curl","version":"0.1"}}}'
```

The response carries an `Mcp-Session-Id` header. Send it on every subsequent
request; `POST initialize` opens the session, the header routes frames to it,
and `DELETE /mcp` closes it. A request carrying an unknown, expired, or
foreign session id answers `404`.

Two limits apply: request bodies are capped at 4 MiB, and an idle session is
reaped after 900 seconds (the `MCP_IDLE_TIMEOUT_SECONDS` setting).

## Tool surface

Clients see **40 upstream tools, verbatim** — the vendored
`imap-mcp-server@2.2.0` package's full surface, bridged without filtering:
7 Account, 21 Email, 4 Folder, and 8 Spam tools. The gateway does not rename,
wrap, or add tools; `tools/list` is whatever upstream answers.

Mailbox work — connect, list folders, read mail — needs a reachable IMAP
server with the account's credentials. Without one, the accounts-surface
calls still succeed: on a user who has activated account encryption but
added no IMAP account yet, `imap_list_accounts` answers
`{"accounts": []}`.

## Activate account encryption first

A user with no active account encryption key cannot use the tools. The
gateway answers with a structured JSON-RPC error directing you to
initialize account encryption in the web UI first. Until the user completes
activation in the web app — open `http://<host>:3030/user`, go to
**Settings**, and use **Activate account encryption** (one-time display of
the AEK — see [user-guide.md](user-guide.md)) — tool calls will not run.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `401` on `/mcp` | missing, malformed, or wrong key header — must be `Bearer usr_…` or `X-Api-Key: usr_…` |
| Immediate rejection with an admin key (`adm_…`) | admin keys are not valid on `/mcp`; use a user login key |
| JSON-RPC error about activating account encryption | the user has not activated their AEK yet |
| `404` after initialize | the `Mcp-Session-Id` header is stale or belongs to another user |
| `429` with `Retry-After` | `/mcp` login rate limit (5 failures / 10 minutes) tripped; wait and retry |
