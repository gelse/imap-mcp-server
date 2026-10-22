"""Composition-root lifecycle tests (M01-T04): ``[boot]`` lines, data layout.

The lifespan runs through Starlette's TestClient, which drives the ASGI
lifespan protocol in-process on ``__enter__``/``__exit__``. The real-process
SIGTERM/SIGINT termination (exit code 0 after uvicorn's post-shutdown signal
re-raise) is covered here too, by the POSIX-only subprocess test
``test_signal_terminates_cleanly_with_one_boot_line_pair``.
"""

from __future__ import annotations

import logging
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from imap_mcp_gateway import __version__
from imap_mcp_gateway.app import (
    _boot_lifespan,
    _ensure_data_dirs,
    _terminate_cleanly,
    run,
)
from imap_mcp_gateway.config.env import Settings
from imap_mcp_gateway.config.paths import build_paths
from imap_mcp_gateway.log import RedactCapableFormatter
from imap_mcp_gateway.web.server import create_app


class _CaptureLinesHandler(logging.Handler):
    """Test handler recording formatted log lines in memory (pattern of conftest.py)."""

    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.format(record))


@pytest.fixture
def boot_log_lines() -> Iterator[list[str]]:
    """Capture the ``imap_mcp_gateway.app`` logger's formatted lines.

    Gateway loggers do not propagate (so ``caplog`` cannot see them); attach a
    handler to the module logger directly, like tests/conftest.py does.
    """
    handler = _CaptureLinesHandler()
    handler.setFormatter(RedactCapableFormatter())
    logger = logging.getLogger("imap_mcp_gateway.app")
    logger.addHandler(handler)
    try:
        yield handler.lines
    finally:
        logger.removeHandler(handler)


def test_lifespan_logs_one_start_and_one_shutdown_line(
    boot_log_lines: list[str],
    tmp_path: Path,
) -> None:
    paths = build_paths(tmp_path)
    app = create_app(Settings(data_dir=tmp_path), lifespan=_boot_lifespan(paths))
    with TestClient(app):
        pass  # startup logged on __enter__; shutdown logged on __exit__
    starts = [
        line
        for line in boot_log_lines
        if "[boot] starting imap-mcp-gateway" in line
    ]
    assert len(starts) == 1
    assert __version__ in starts[0]
    assert str(paths.data_dir) in starts[0]
    stops = [line for line in boot_log_lines if "[boot] shutdown complete" in line]
    assert len(stops) == 1


def test_ensure_data_dirs_creates_layout_at_0700(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)
    _ensure_data_dirs(paths)
    for directory in (paths.config_dir(), paths.users_dir(), paths.mail_dir()):
        assert directory.is_dir()
        assert (os.stat(directory).st_mode & 0o777) == 0o700
    # Re-running is idempotent and re-asserts the modes (ensure_dir contract).
    _ensure_data_dirs(paths)
    for directory in (paths.config_dir(), paths.users_dir(), paths.mail_dir()):
        assert (os.stat(directory).st_mode & 0o777) == 0o700


def test_run_version_flag_preserved(capsys: pytest.CaptureFixture[str]) -> None:
    """M01-T01 contract kept: ``--version`` prints and exits 0 without serving."""
    with pytest.raises(SystemExit) as excinfo:
        run(["--version"])
    assert excinfo.value.code == 0
    assert "imap-mcp-gateway" in capsys.readouterr().out


def test_terminate_cleanly_exits_zero() -> None:
    """The pre-installed signal handler converts a termination signal into exit 0.

    This is the handler uvicorn's post-shutdown signal re-raise lands on
    (uvicorn 0.32 restores the pre-serve handlers, then re-raises the captured
    signal); it must be a clean ``SystemExit(0)``, never the default
    disposition (which would kill the process with 128+signum / -signum).
    """
    for sig in (signal.SIGTERM, signal.SIGINT):
        with pytest.raises(SystemExit) as excinfo:
            _terminate_cleanly(int(sig), None)
        assert excinfo.value.code == 0


def _free_port() -> int:
    """Reserve a free TCP port from the OS (bind-and-close; the race is fine here)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _start_gateway_subprocess(tmp_path: Path) -> tuple[subprocess.Popen[str], str]:
    """Start ``python -m imap_mcp_gateway`` with a temp DATA_DIR on a free port.

    Returns the process (stdout merged with stderr) and its ``/healthz`` URL.
    """
    port = _free_port()
    env = {**os.environ, "DATA_DIR": str(tmp_path), "HTTP_PORT": str(port)}
    proc = subprocess.Popen(
        [sys.executable, "-m", "imap_mcp_gateway"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return proc, f"http://127.0.0.1:{port}/healthz"


def _wait_until_healthy(proc: subprocess.Popen[str], url: str, timeout: float = 15.0) -> None:
    """Poll ``/healthz`` until 200; fail with the child's output if it never does."""
    deadline = time.monotonic() + timeout
    last_error: str = ""
    while time.monotonic() < deadline and proc.poll() is None:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as response:
                if response.status == 200:
                    return
        except OSError as exc:  # URLError/ConnectionRefused before the bind
            last_error = str(exc)
        time.sleep(0.05)
    # Failure path: reap the child BEFORE reading the pipe, or read() would
    # block forever on a still-live writer (no pytest-timeout to save us).
    if proc.poll() is None:
        proc.kill()
    output, _ = proc.communicate()
    pytest.fail(
        f"gateway not healthy within {timeout}s (last poll error: {last_error!r}); "
        f"output:\n{output}"
    )


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-only: SIGTERM/SIGINT delivery to a subprocess",
)
@pytest.mark.parametrize(
    ("sig", "expected_rc"),
    [
        pytest.param(signal.SIGTERM, 0, id="sigterm"),  # hard acceptance: exit 0
        pytest.param(signal.SIGINT, 0, id="sigint"),  # must stay graceful too
    ],
)
def test_signal_terminates_cleanly_with_one_boot_line_pair(
    tmp_path: Path,
    sig: signal.Signals,
    expected_rc: int,
) -> None:
    """Milestone acceptance: SIGTERM/SIGINT exit 0 with one start + one stop line.

    Runs the real entry point: uvicorn performs the graceful shutdown (so the
    ``[boot] shutdown complete`` lifespan line is logged), then re-raises the
    captured signal — this test pins that the process still exits 0 instead of
    dying on the default disposition (which would be 128+signum).
    """
    proc, healthz_url = _start_gateway_subprocess(tmp_path)
    output: str
    try:
        _wait_until_healthy(proc, healthz_url)
        os.kill(proc.pid, sig)
        try:
            output, _ = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            output, _ = proc.communicate()
            pytest.fail(f"{sig.name} did not terminate the gateway within 10s; output:\n{output}")
    finally:
        if proc.poll() is None:  # never signalled / not reaped — clean up
            proc.kill()
            proc.communicate()
    assert proc.returncode == expected_rc, output
    starts = [
        line for line in output.splitlines() if "[boot] starting imap-mcp-gateway" in line
    ]
    assert len(starts) == 1, output
    stops = [line for line in output.splitlines() if "[boot] shutdown complete" in line]
    assert len(stops) == 1, output
