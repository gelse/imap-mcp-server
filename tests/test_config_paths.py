"""Unit tests for the env-driven Settings model and the typed data-layout paths.

Path helpers are exercised over a temporary ``DATA_DIR`` (never the real
``/data``), and the user-id guard is proven to reject traversal-style ids
before any filesystem access happens (the ``forbid_filesystem`` fixture turns
every fs call into a hard failure).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from imap_mcp_gateway.config.env import Settings
from imap_mcp_gateway.config.paths import Paths, build_paths, validate_user_id

VENDOR_SERVER_JS = "/opt/vendor/npm/node_modules/imap-mcp-server/dist/index.js"

SETTINGS_ENV_VARS = (
    "DATA_DIR",
    "HTTP_PORT",
    "LOG_LEVEL",
    "NODE_BIN",
    "IMAP_MCP_SERVER_JS",
    "MCP_IDLE_TIMEOUT_SECONDS",
)

VALID_USER_IDS = (
    "a",
    "-",
    "alice",
    "user-1",
    "abc-def-123",
    "a" * 64,  # exactly at the upper length bound
)

INVALID_USER_IDS = (
    "",  # empty
    "../etc",  # traversal
    "..",
    ".",
    "Alice",  # uppercase
    "álice",  # non-ASCII
    "a/b",
    "a\\b",
    "a b",
    "a_b",
    "a.b",
    "alice\n",  # trailing newline must not sneak past the anchor
    "a" * 65,  # over the length bound
)


@pytest.fixture(autouse=True)
def _clean_settings_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Delete every settings env var so Settings() defaults stay deterministic."""
    for var in SETTINGS_ENV_VARS:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def forbid_filesystem(monkeypatch: pytest.MonkeyPatch) -> None:
    """Turn every filesystem access into a hard test failure.

    Used to prove that invalid user ids raise ``ValueError`` before the
    filesystem is touched: with this fixture active, any ``mkdir``/``stat``/
    ``exists`` call aborts the test.
    """

    def _fail(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("unexpected filesystem access")

    monkeypatch.setattr(os, "mkdir", _fail)
    monkeypatch.setattr(os, "stat", _fail)
    monkeypatch.setattr(os, "lstat", _fail)
    monkeypatch.setattr(Path, "mkdir", _fail)
    monkeypatch.setattr(Path, "exists", _fail)
    monkeypatch.setattr(Path, "stat", _fail)


# --- env.py: Settings -------------------------------------------------------


def test_settings_defaults_match_the_milestone() -> None:
    settings = Settings()
    assert settings.data_dir == Path("/data")
    assert settings.http_port == 3000
    assert settings.log_level == "INFO"
    assert settings.node_bin == Path("/usr/local/bin/node")
    assert settings.imap_mcp_server_js == Path(VENDOR_SERVER_JS)
    assert settings.mcp_idle_timeout_seconds == 900


def test_settings_load_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATA_DIR", "/tmp/gateway-data")
    monkeypatch.setenv("HTTP_PORT", "8080")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("NODE_BIN", "/usr/bin/node")
    monkeypatch.setenv("IMAP_MCP_SERVER_JS", VENDOR_SERVER_JS)
    monkeypatch.setenv("MCP_IDLE_TIMEOUT_SECONDS", "60")

    settings = Settings()

    assert settings.data_dir == Path("/tmp/gateway-data")
    assert settings.http_port == 8080
    assert settings.log_level == "DEBUG"
    assert settings.node_bin == Path("/usr/bin/node")
    assert settings.imap_mcp_server_js == Path(VENDOR_SERVER_JS)
    assert settings.mcp_idle_timeout_seconds == 60


def test_settings_accepts_init_overrides(tmp_path: Path) -> None:
    """Init kwargs win over the environment (used for tests and wiring)."""
    monkeypatch_free = Settings(data_dir=tmp_path, http_port=9999)
    assert monkeypatch_free.data_dir == tmp_path
    assert monkeypatch_free.http_port == 9999
    assert monkeypatch_free.mcp_idle_timeout_seconds == 900


# --- paths.py: layout resolution -------------------------------------------


def test_paths_resolve_documented_layout(tmp_path: Path) -> None:
    paths = build_paths(tmp_path)

    assert paths.data_dir == tmp_path
    assert paths.config_dir() == tmp_path / "config"
    assert paths.admin_key_hash_path() == tmp_path / "config" / "admin-key.hash"
    assert paths.wrap_key_path() == tmp_path / "config" / "wrap.key"
    assert paths.users_dir() == tmp_path / "users"
    assert paths.user_dir("alice") == tmp_path / "users" / "alice"
    assert paths.user_record_path("alice") == tmp_path / "users" / "alice" / "user.json"
    assert paths.user_imap_store_dir("alice") == (
        tmp_path / "users" / "alice" / "imap-store"
    )
    assert paths.mail_dir() == tmp_path / "mail"
    assert paths.user_mail_dir("alice") == tmp_path / "mail" / "alice"


def test_build_paths_accepts_str_data_dir(tmp_path: Path) -> None:
    paths = build_paths(str(tmp_path))
    assert paths == Paths(data_dir=tmp_path)


def test_paths_built_from_settings_data_dir(tmp_path: Path) -> None:
    """The startup wiring shape: Settings resolves env, build_paths roots Paths."""
    settings = Settings(data_dir=tmp_path)
    paths = build_paths(settings.data_dir)
    assert paths.data_dir == tmp_path
    assert paths.user_record_path("alice") == tmp_path / "users" / "alice" / "user.json"


# --- paths.py: user-id guard ------------------------------------------------


@pytest.mark.parametrize("user_id", VALID_USER_IDS)
def test_valid_user_ids_are_accepted(tmp_path: Path, user_id: str) -> None:
    paths = build_paths(tmp_path)
    assert paths.user_dir(user_id) == tmp_path / "users" / user_id
    assert validate_user_id(user_id) == user_id


@pytest.mark.parametrize("user_id", INVALID_USER_IDS)
def test_invalid_user_ids_raise_value_error_before_filesystem_access(
    tmp_path: Path,
    user_id: str,
    forbid_filesystem: None,
) -> None:
    paths = build_paths(tmp_path)
    with pytest.raises(ValueError, match="invalid user id"):
        paths.user_dir(user_id)
    with pytest.raises(ValueError, match="invalid user id"):
        validate_user_id(user_id)


def test_every_user_scoped_helper_validates_before_fs_access(
    tmp_path: Path,
    forbid_filesystem: None,
) -> None:
    paths = build_paths(tmp_path)
    for helper in (
        paths.user_dir,
        paths.user_record_path,
        paths.user_imap_store_dir,
        paths.user_mail_dir,
    ):
        with pytest.raises(ValueError, match="invalid user id"):
            helper("../etc")
