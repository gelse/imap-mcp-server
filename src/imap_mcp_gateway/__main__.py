"""``python -m imap_mcp_gateway`` entry point (delegates to the composition root)."""

from __future__ import annotations

import sys

from imap_mcp_gateway import app

if __name__ == "__main__":
    sys.exit(app.run())
