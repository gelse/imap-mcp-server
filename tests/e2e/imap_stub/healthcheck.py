"""Compose healthcheck for the E2E stub: probe IMAP (143) and SMTP (25).

Exit 0 iff BOTH listeners accept a TCP connection; any failure exits 1 so
compose keeps retrying (``depends_on: service_healthy`` gates the gateway).
"""

from __future__ import annotations

import os
import socket
import sys

_TIMEOUT = 2.0


def _probe(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=_TIMEOUT):
            return True
    except OSError:
        return False


def main() -> None:
    imap_port = int(os.environ.get("IMAP_PORT", "143"))
    smtp_port = int(os.environ.get("SMTP_PORT", "25"))
    if _probe(imap_port) and _probe(smtp_port):
        return
    sys.exit(1)


if __name__ == "__main__":
    main()
