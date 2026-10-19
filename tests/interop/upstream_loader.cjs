// upstream_loader.cjs — the ONE approved Node artifact of M04-T03 (interop).
//
// Spawned as a child process by tests/interop/test_upstream_account_manager.py
// to prove byte-format compatibility with the vendored, unmodified
// imap-mcp-server@2.2.0 package. The published bundle exports a single class:
// WebUIServer (dist/web/server.js), whose constructor instantiates upstream's
// AccountManager from $HOME/.imap-mcp — the harness uses that instance
// exactly as shipped (the express app is built but NEVER started; the
// module's self-start block is argv-guarded and does not trigger on import).
//
// Usage:
//   node upstream_loader.cjs <packageRoot> read <accountId>
//       Print one JSON line: {"found":true,"account":{...decrypted...}} or
//       {"found":false}.
//   node upstream_loader.cjs <packageRoot> add
//       Read the account payload (JSON, no id, plaintext credentials) from
//       stdin; add it via upstream addAccount; print {"added":true,"id":"..."}.
//
// The package root must be the npm `--prefix` layout (package at
// <root>/../.. style sibling deps) so the bundle's imports resolve — e.g.
// /opt/vendor/npm/node_modules/imap-mcp-server in the deployment image, or
// any dev directory with `npm install --prefix <dir> imap-mcp-server@2.2.0`.
//
// Protocol: exactly one JSON line on stdout; diagnostics go to stderr; exit 0
// on success, 1 on any failure. Key material never arrives via env or argv —
// the parent only sets HOME/PATH, and the AEK reaches this process solely
// through the .key file inside the store directory HOME points at.
'use strict';

const path = require('path');
const fs = require('fs');
const { pathToFileURL } = require('url');

async function main() {
  const [packageRoot, mode, accountId] = process.argv.slice(2);
  if (!packageRoot || !mode) {
    throw new Error('usage: upstream_loader.cjs <packageRoot> <read|add> [accountId]');
  }

  // Import the unmodified upstream bundle (module specifiers resolve against
  // the package's own context and its sibling node_modules). Never
  // dist/index.js: that is the stdio MCP server entry and would self-start.
  const serverJs = path.join(packageRoot, 'dist', 'web', 'server.js');
  const { WebUIServer } = await import(pathToFileURL(serverJs).href);

  // Constructor side effects: builds the express app and upstream's
  // AccountManager (reads $HOME/.imap-mcp/.key and accounts.json). Port 0 is
  // never bound — .start() is not called; nothing listens.
  const ui = new WebUIServer(0);
  const manager = ui.accountManager;
  if (!manager) throw new Error('upstream WebUIServer exposed no accountManager');

  if (mode === 'read') {
    if (!accountId) throw new Error('read mode requires an accountId');
    const account = manager.getAccount(accountId);
    process.stdout.write(
      `${JSON.stringify({ found: account !== undefined, account })}\n`
    );
    return;
  }

  if (mode === 'add') {
    const payload = JSON.parse(fs.readFileSync(0, 'utf-8'));
    const added = await manager.addAccount(payload);
    process.stdout.write(`${JSON.stringify({ added: true, id: added.id })}\n`);
    return;
  }

  throw new Error(`unknown mode ${mode}`);
}

main().catch((error) => {
  process.stderr.write(`upstream_loader: ${error && error.message ? error.message : error}\n`);
  process.exitCode = 1;
});
