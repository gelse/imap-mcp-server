"""Shared pytest fixtures for the imap-mcp-gateway test suite."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path

import pytest

from imap_mcp_gateway.crypto import wrap
from imap_mcp_gateway.log import RedactCapableFormatter, get_logger

SPA_INDEX_HTML = (
    "<!doctype html>\n"
    '<html lang="en">\n'
    "  <head>\n"
    '    <meta charset="UTF-8" />\n'
    "    <title>IMAP MCP Gateway</title>\n"
    '    <script type="module" src="/assets/app-abc123.js"></script>\n'
    "  </head>\n"
    "  <body>\n"
    '    <div id="app"></div>\n'
    "  </body>\n"
    "</html>\n"
)
"""The synthetic SPA shell: a small, static, secret-free ``index.html``.

Mirrors the shape of the real Vite build (an absolute ``/assets/<hash>.js``
reference and an empty mount point) without needing npm — the unit suites
stay hermetic and toolchain-free.
"""

SPA_ASSET_JS = 'console.info("synthetic spa bundle");\n'
"""The synthetic hashed asset body: a static string, no secret material."""


@pytest.fixture
def spa_dist(tmp_path: Path) -> Path:
    """A synthetic SPA dist directory (``index.html`` + ``assets/``).

    The gateway serves the BUILT single-page application (M07-T05). The
    real ``frontend/dist`` is a build artifact (gitignored, produced by
    npm), so the unit suites use this synthetic stand-in instead: it keeps
    them hermetic, npm-free and fast, while exercising the exact same
    serving path (lazy per-request ``index.html`` read, hashed-asset
    mount, cache headers).

    Consumers pass it to the app under test as
    ``Settings(spa_dist_dir=spa_dist)``.
    """
    dist = tmp_path / "spa-dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text(SPA_INDEX_HTML, encoding="utf-8")
    (dist / "assets" / "app-abc123.js").write_text(SPA_ASSET_JS, encoding="utf-8")
    return dist


@pytest.fixture(autouse=True)
def fresh_process_wrap_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every test with no wrap key installed (fresh-process semantics).

    The server wrap key is loaded into memory exactly once per process
    (``crypto.wrap``'s single holder, wired by the startup gate). Without a
    central reset, one test's boot would leave the holder set and silently
    change what a LATER test's ``ensure_wrap_key``/wrap calls do in a
    different ``DATA_DIR`` — hidden test-order coupling. monkeypatch
    restores the prior value after each test.
    """
    monkeypatch.setattr(wrap, "_loaded_wrap_key", None)


class _LineCaptureHandler(logging.Handler):
    """Test handler that records formatted log lines in memory."""

    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.format(record))


@pytest.fixture
def captured_log_lines() -> Iterator[tuple[logging.Logger, list[str]]]:
    """Yield a gateway logger plus the list of its formatted log lines."""
    handler = _LineCaptureHandler()
    handler.setFormatter(RedactCapableFormatter())
    logger = get_logger("tests.captured-log")
    logger.addHandler(handler)
    try:
        yield logger, handler.lines
    finally:
        logger.removeHandler(handler)
