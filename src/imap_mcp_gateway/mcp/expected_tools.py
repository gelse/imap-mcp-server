"""The frozen tool-surface pin for upstream ``imap-mcp-server@2.2.0`` (M05-T03).

This module is TEST/VERIFICATION DATA — the exact tool name set the vendored
upstream registers, frozen here so :mod:`tests.test_tool_parity` can hold the
real upstream process against it. It is deliberately NOT imported by any
runtime module: the gateway's contract is verbatim pass-through ("exactly the
same tools"), so no wrapper-side filtering, renaming, or schema rewriting may
ever consult this list (M05 non-goal).

Sourcing (evidence-bound, not guessed) — every name below is a
``server.registerTool('<name>'`` call in the pinned upstream sources:

- upstream ``imap-mcp-server`` version ``2.2.0`` (``package.json`` ``"version"``
  field; the npm-published artifact's ``gitHead`` commit
  ``bd474262aea96ef29ba4ff7f0fa06cab06dd8bdd``);
- ``src/tools/account-tools.ts`` — 7 registrations;
- ``src/tools/email-tools.ts`` — 21 registrations;
- ``src/tools/folder-tools.ts`` — 4 registrations;
- ``src/tools/spam-tools.ts`` — 8 registrations;
- ``src/tools/index.ts`` registers all four groups unfiltered when neither
  ``IMAP_MCP_ENABLED_TOOLS`` nor ``IMAP_MCP_READ_ONLY`` is set — exactly the
  child environment the tool host configures — so ``tools/list`` exposes all
  40;
- cross-checked against a live ``tools/list`` response of the vendored 2.2.0
  entrypoint (40 tools; names identical to this set).

Upgrade policy (M05 design): bumping the upstream pin requires re-deriving
this list from the new sources and re-running the parity test.
"""

from __future__ import annotations

UPSTREAM_PINNED_VERSION = "2.2.0"
"""The exact upstream version this pin was derived from (never bump casually)."""

ACCOUNT_TOOLS: frozenset[str] = frozenset(
    {
        # src/tools/account-tools.ts
        "imap_add_account",
        "imap_update_account",
        "imap_list_accounts",
        "imap_remove_account",
        "imap_connect",
        "imap_disconnect",
        "imap_test_account",
    }
)

EMAIL_TOOLS: frozenset[str] = frozenset(
    {
        # src/tools/email-tools.ts
        "imap_search_emails",
        "imap_get_email",
        "imap_upload_file",
        "imap_download_attachment",
        "imap_mark_as_read",
        "imap_mark_as_unread",
        "imap_flag_email",
        "imap_unflag_email",
        "imap_add_keyword",
        "imap_remove_keyword",
        "imap_delete_email",
        "imap_move_email",
        "imap_bulk_delete",
        "imap_bulk_delete_by_search",
        "imap_get_latest_emails",
        "imap_send_email",
        "imap_save_draft",
        "imap_reply_to_email",
        "imap_forward_email",
        "imap_find_thread_messages",
        "imap_find_email_by_message_id",
    }
)

FOLDER_TOOLS: frozenset[str] = frozenset(
    {
        # src/tools/folder-tools.ts
        "imap_list_folders",
        "imap_folder_status",
        "imap_create_folder",
        "imap_get_unread_count",
    }
)

SPAM_TOOLS: frozenset[str] = frozenset(
    {
        # src/tools/spam-tools.ts
        "imap_check_spam",
        "imap_delete_spam",
        "imap_domain_stats",
        "imap_add_spam_domain",
        "imap_remove_spam_domain",
        "imap_add_whitelist_domain",
        "imap_list_spam_domains",
        "imap_delete_by_domain",
    }
)

EXPECTED_TOOL_NAMES: frozenset[str] = (
    ACCOUNT_TOOLS | EMAIL_TOOLS | FOLDER_TOOLS | SPAM_TOOLS
)
"""The full 40-name tool surface of upstream ``imap-mcp-server@2.2.0``.

Parity contract (M05-T03): a live ``tools/list`` of the vendored upstream
process must equal this set EXACTLY — no extras, no omissions. The groups
above exist so a drift failure can name which upstream file moved.
"""

EXPECTED_GROUP_SIZES: tuple[tuple[str, frozenset[str], int], ...] = (
    ("Account", ACCOUNT_TOOLS, 7),
    ("Email", EMAIL_TOOLS, 21),
    ("Folder", FOLDER_TOOLS, 4),
    ("Spam", SPAM_TOOLS, 8),
)
"""The per-group shape of the pin (Account 7, Email 21, Folder 4, Spam 8)."""
