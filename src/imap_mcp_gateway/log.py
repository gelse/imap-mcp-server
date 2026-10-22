"""Structured, greppable logging conventions for imap-mcp-gateway.

Every line has the shape::

    <timestamp> <LEVEL> [<tag>] <message>[ key=value ...]

Tags are reserved by convention (not enforced by code): ``[boot]``,
``[config]``, ``[auth]``, ``[security]`` and ``[mcp:<userId>]`` — the latter is
a template used for relaying tool-host stderr in M05. A tag is passed either
embedded at the start of the message (``log.info("[boot] starting")``) or via
``extra={"tag": "boot"}``. Structured fields ride along via
``extra={"fields": {...}}`` and render as sorted ``key=value`` pairs.

Redaction (M06-T02): :class:`RedactFilter` attaches to the loggers AND the
stdout handlers created by :func:`get_logger` and scrubs ``adm_``/``usr_``
key material, 64-hex secrets and ``scrypt$`` records from every channel this
module exposes — ``msg``/``args`` but also the ``fields`` values, the ``tag``
attribute and the ``exc_info``/``stack_info`` text, none of which pass through
``getMessage()``. The ONE exemption (:data:`REDACT_EXEMPT_MESSAGE_PREFIXES`)
is the first-boot ``[auth] admin key created …`` line: it is the operator's
only delivery channel for the admin key and is pinned by
``tests/test_admin_key_lifecycle.py``. The exemption matches a message
PREFIX only, and relayed tool-host text always arrives as
``[mcp:<userId>] <text>`` (a prefix no forged line can shed), so a hostile
child cannot smuggle key material past the filter by imitating the wording.

Reconciliation with M06-T01: the e2e harness (``tests/e2e/conftest.py``)
carries its own ``redact_keys`` helper, but it redacts only text destined for
PYTEST FAILURE REPORTS — advisory, after the fact. The filter here redacts
the application's own log stream at emit time. Distinct responsibilities;
neither substitutes for the other.

Untrusted text (e.g. the M05 tool-host stderr relay under ``[mcp:<userId>]``)
must be sanitized (newlines/control characters) before it reaches this formatter,
or a log line can be forged; enforce that at the relay or in the filter.

Testing note: handlers bind ``sys.stdout`` at construction and these loggers do
not propagate, so observe them in tests via an explicit handler (see
``tests/conftest.py``) or ``capfd`` — not ``capsys``/``caplog``.
"""

from __future__ import annotations

import logging
import re
import sys
import traceback
from typing import Any

RESERVED_LOG_TAGS: tuple[str, ...] = (
    "boot",
    "config",
    "auth",
    "security",
    "mcp:<userId>",
)
"""Tags reserved by convention; ``mcp:<userId>`` is a template, not a literal."""

_MESSAGE_TAG_RE = re.compile(r"^\[(?P<tag>[^\]]+)\]\s*(?P<rest>.*)$", re.DOTALL)

REDACTION_TOKEN = "[REDACTED]"
"""Replacement text substituted for every secret-shaped span."""

REDACT_EXEMPT_MESSAGE_PREFIXES: tuple[str, ...] = (
    "[auth] admin key created",
)
"""Message prefixes that survive redaction UNCHANGED.

Exactly one member: the first-boot admin-key delivery line in ``app.py``.
Matched against the RENDERED message (post-``getMessage()``), so a
``%``-style call whose formatted text starts with the prefix is exempt too.
Everything else — fields, tags, exception text — is still scrubbed on an
exempt record. Relay messages can never match: the M05 stderr relay emits
``log.info("[mcp:%s] %s", user_id, text)``, whose rendered message always
starts with ``[mcp:`` (see the module docstring).
"""

_ADMIN_KEY_RE = re.compile(r"\badm_[A-Za-z0-9_-]+")
_USER_KEY_RE = re.compile(r"\busr_[A-Za-z0-9_-]+")
# ``{64,}`` with no trailing boundary, and a hex-only (not ``\b``) left guard:
# a hex run LONGER than 64, or one glued to a non-hex word character
# (e.g. ``id=0x…``), must still be redacted. Same shape as the regression
# suite's ``HEX64_RE``.
_HEX64_RE = re.compile(r"(?<![0-9a-f])[0-9a-f]{64,}")
_SCRYPT_RECORD_RE = re.compile(r"scrypt\$\d+\$\d+\$\d+\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+")

_REDACTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    _ADMIN_KEY_RE,
    _USER_KEY_RE,
    _HEX64_RE,
    _SCRYPT_RECORD_RE,
)


def redact_text(text: str) -> str:
    """Replace every secret-shaped span in ``text`` with :data:`REDACTION_TOKEN`.

    The four shapes are the gateway's actual secret formats: ``adm_``/``usr_``
    prefixed keys (``crypto.keys``), 64-lowercase-hex material (AEK, wrap key,
    random ids) and ``scrypt$…$…$…$…$…`` hash records (``crypto.hash``). Pure
    string substitution — no record knowledge — so it is safe on any channel.
    """
    for pattern in _REDACTION_PATTERNS:
        text = pattern.sub(REDACTION_TOKEN, text)
    return text


class RedactFilter(logging.Filter):
    """Scrub key-shaped material from every field a record can carry.

    Attached (by :func:`get_logger`) to BOTH the logger and its stdout
    handler, so redaction holds for every handler — including ones tests
    attach later. Mutates the record in place before formatting: renders
    ``msg``/``args`` via ``getMessage()`` and replaces them, then scrubs the
    ``fields`` values, the ``tag`` attribute, pre-computed ``exc_text`` and
    ``stack_info``. ``exc_info`` is materialized to ``exc_text`` here (the
    formatter reuses a non-``None`` ``exc_text``) so exception text is
    scrubbed before any handler sees it. Idempotent: re-filtering a record
    whose secrets are already tokens is a no-op. Never raises — a filter
    exception would propagate into the logging call and out through the
    request path.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Redact ``record`` in place; always keeps the record (``True``)."""
        try:
            message = record.getMessage()
        except Exception:  # broken ``args``: fall back to the raw msg text
            # The filter is invoked from arbitrary call sites (including ones
            # logging untrusted text), so a %-format mismatch must not crash
            # the logging call — and the raw msg is STILL redacted below.
            message = str(record.msg)
        if not message.startswith(REDACT_EXEMPT_MESSAGE_PREFIXES):
            record.msg = redact_text(message)
            record.args = ()
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            # ``vars(record)[...]`` (not attribute assignment, not ``setattr``):
            # ``fields``/``tag`` are convention attributes logging does not
            # declare, so mypy rejects direct assignment on ``LogRecord``,
            # while ruff's B010 rejects ``setattr`` with a constant name.
            vars(record)["fields"] = {
                key: redact_text(value) if isinstance(value, str) else value
                for key, value in fields.items()
            }
        tag = getattr(record, "tag", None)
        if isinstance(tag, str):
            vars(record)["tag"] = redact_text(tag)
        if record.exc_info and record.exc_text is None:
            try:
                record.exc_text = "".join(
                    traceback.format_exception(*record.exc_info)
                )
            except Exception:  # malformed exc_info: leave it to the formatter
                record.exc_text = None
        if isinstance(record.exc_text, str):
            record.exc_text = redact_text(record.exc_text)
        if isinstance(record.stack_info, str):
            record.stack_info = redact_text(record.stack_info)
        return True


class RedactCapableFormatter(logging.Formatter):
    """Render records as ``<timestamp> <LEVEL> [<tag>] <message>[ key=value ...]``."""

    def __init__(self) -> None:
        super().__init__(datefmt="%Y-%m-%dT%H:%M:%S")

    def format(self, record: logging.LogRecord) -> str:
        """Format one record; see the module docstring for the line shape."""
        message = record.getMessage()
        tag = str(getattr(record, "tag", "") or "")
        if not tag:
            match = _MESSAGE_TAG_RE.match(message)
            if match is not None:
                tag = match.group("tag")
                message = match.group("rest")
        fields: dict[str, Any] = getattr(record, "fields", None) or {}
        field_text = "".join(f" {key}={value}" for key, value in sorted(fields.items()))
        timestamp = self.formatTime(record, self.datefmt)
        line = (
            f"{timestamp} {record.levelname} [{tag or '-'}] {message}{field_text}"
        )
        if record.exc_info:
            if record.exc_text is None:
                record.exc_text = self.formatException(record.exc_info)
            line = f"{line}\n{record.exc_text}"
        if record.stack_info:
            line = f"{line}\n{record.stack_info}"
        return line


def get_logger(name: str, *, level: int = logging.INFO) -> logging.Logger:
    """Return the stdlib logger ``name`` wired with a stdout ``RedactCapableFormatter``.

    Idempotent: repeated calls re-apply ``level`` but never duplicate handlers.
    Loggers created here do not propagate to the root logger. A
    :class:`RedactFilter` is attached to the logger AND its stdout handler
    (M06-T02): the logger-level instance covers every handler — including
    ones callers add later (test capture handlers) — and the handler-level
    instance covers the stdout handler even if the logger-level filter is
    ever removed.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(RedactCapableFormatter())
        handler.addFilter(RedactFilter())
        logger.addHandler(handler)
    if not any(isinstance(log_filter, RedactFilter) for log_filter in logger.filters):
        logger.addFilter(RedactFilter())
    logger.setLevel(level)
    logger.propagate = False
    return logger
