"""Smoke tests: package metadata and the structured-logging format contract."""

from __future__ import annotations

import logging
import re

import imap_mcp_gateway
from imap_mcp_gateway.log import get_logger


def test_package_exposes_version() -> None:
    assert isinstance(imap_mcp_gateway.__version__, str)
    assert imap_mcp_gateway.__version__


def test_get_logger_returns_configured_stdlib_logger() -> None:
    logger = get_logger("tests.smoke-stdlib")
    assert isinstance(logger, logging.Logger)
    assert logger.level == logging.INFO
    assert logger.propagate is False
    assert logger.handlers


def test_get_logger_is_idempotent() -> None:
    logger = get_logger("tests.smoke-idempotent")
    get_logger("tests.smoke-idempotent")
    assert len(logger.handlers) == 1


def test_logger_accepts_tag_via_extra(
    captured_log_lines: tuple[logging.Logger, list[str]],
) -> None:
    logger, lines = captured_log_lines
    logger.warning("gateway halting", extra={"tag": "boot"})
    line = lines[-1]
    assert "WARNING" in line
    assert "[boot]" in line
    assert "gateway halting" in line


def test_logger_formats_line_with_reserved_tag(
    captured_log_lines: tuple[logging.Logger, list[str]],
) -> None:
    logger, lines = captured_log_lines
    logger.info("[boot] starting imap-mcp-gateway")
    assert lines, "expected at least one formatted line"
    line = lines[-1]
    assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:", line), f"no timestamp: {line!r}"
    assert "INFO" in line
    assert "[boot]" in line
    assert "starting imap-mcp-gateway" in line


def test_logger_renders_structured_fields(
    captured_log_lines: tuple[logging.Logger, list[str]],
) -> None:
    logger, lines = captured_log_lines
    logger.info("[config] layout ready", extra={"fields": {"data_dir": "/data"}})
    line = lines[-1]
    assert "[config]" in line
    assert "layout ready" in line
    assert "data_dir=/data" in line
