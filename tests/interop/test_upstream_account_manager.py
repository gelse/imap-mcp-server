"""Upstream interop fixture (M04-T03) — the byte-format compatibility proof.

Writes ``accounts.json`` through the gateway store, then spawns the ONE
approved Node harness (``upstream_loader.cjs``) as a child process. The
harness loads the vendored, unmodified ``imap-mcp-server@2.2.0`` bundle (no
network) — the published package exports a single class,
``WebUIServer``, whose constructor instantiates upstream's
``AccountManager`` from ``$HOME/.imap-mcp`` — and the harness wires a fake
``$HOME`` whose ``.imap-mcp`` path is a symlink to the gateway's per-user
``imap-store`` directory. Through upstream's own instance it:

1. reads the gateway-written account back with its DECRYPTED password —
   proving our ``put_account`` bytes are exactly what upstream expects
   (acceptance: "a store written by ``put_account`` loads with upstream
   ``AccountManager`` and the decrypted password matches the input");
2. performs a tool-host-style ``addAccount`` write, after which the wrapper
   re-syncs (a fresh ``list_accounts``) and sees the addition — no stale
   list, no process restart. The upstream-written ciphertext is additionally
   decrypted on the Python side, proving the format works in both directions;
3. survives AEK rotation: after ``reencrypt_all`` under the new key (with the
   session key file re-materialized) upstream still decrypts the password.

Opt-in via ``pytest -m interop``. Skips cleanly — with a precise reason —
when Node or the vendored package is unavailable. The child gets a minimal
environment (``HOME`` + ``PATH``): no wrap key, no AEK hex, nothing sensitive
in env or argv; the AEK reaches the child only as the materialized ``.key``
file inside the store directory.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from imap_mcp_gateway.config.paths import Paths, build_paths
from imap_mcp_gateway.store.accounts import (
    encrypt_account_record,
    get_account,
    list_accounts,
    put_account,
    reencrypt_all,
)
from imap_mcp_gateway.store.session_keyfile import (
    cleanup_key_file,
    materialize_key_file,
)
from imap_mcp_gateway.store.upstream_format import decrypt_field
from imap_mcp_gateway.store.users import activate_aek, create_user
from imap_mcp_gateway.store.wrap_key import ensure_wrap_key

pytestmark = [pytest.mark.interop]

_HARNESS_PATH = Path(__file__).with_name("upstream_loader.cjs")
_PINNED_UPSTREAM_VERSION = "2.2.0"
_SPAWN_TIMEOUT_SECONDS = 120.0


def _node_bin() -> str | None:
    """Locate the Node binary: ``NODE_BIN`` override, then ``PATH``."""
    override = os.environ.get("NODE_BIN")
    if override:
        return override if Path(override).exists() else None
    return shutil.which("node")


def _upstream_package_root() -> Path | None:
    """Locate the vendored ``imap-mcp-server`` package root, pinned version.

    Search order: ``IMAP_MCP_UPSTREAM_PKG`` (dev override), the Docker image
    default ``/opt/vendor/npm/node_modules/imap-mcp-server`` (the
    ``Settings.imap_mcp_server_js`` location), and a repo-local
    ``vendor/npm/node_modules/imap-mcp-server`` dev-vendor layout. The
    package is consumed exactly as shipped — the version is checked against
    the pin, and the bundle's npm dependencies must be resolvable as
    siblings (the ``npm install --prefix`` layout the image uses).
    """
    candidates = [os.environ.get("IMAP_MCP_UPSTREAM_PKG")]
    candidates.append("/opt/vendor/npm/node_modules/imap-mcp-server")
    repo_root = Path(__file__).resolve().parents[2]
    candidates.append(str(repo_root / "vendor/npm/node_modules/imap-mcp-server"))
    for candidate in candidates:
        if not candidate:
            continue
        root = Path(candidate)
        server_js = root / "dist" / "web" / "server.js"
        manifest = root / "package.json"
        if not server_js.is_file() or not manifest.is_file():
            continue
        try:
            version = json.loads(manifest.read_text(encoding="utf-8")).get("version")
        except (json.JSONDecodeError, OSError):
            continue
        if version == _PINNED_UPSTREAM_VERSION:
            return root
    return None


@pytest.fixture
def upstream_tool() -> tuple[str, Path]:
    """Node binary + vendored package root, or a precisely-explained skip."""
    node_bin = _node_bin()
    if node_bin is None:
        pytest.skip("node executable not found (set NODE_BIN or put node on PATH)")
    package_root = _upstream_package_root()
    if package_root is None:
        pytest.skip(
            "vendored imap-mcp-server@"
            f"{_PINNED_UPSTREAM_VERSION} package not found — set "
            "IMAP_MCP_UPSTREAM_PKG to the package root with its npm "
            "dependencies installed alongside (npm install --prefix layout; "
            "looked at $IMAP_MCP_UPSTREAM_PKG, "
            "/opt/vendor/npm/node_modules/imap-mcp-server, and "
            "<repo>/vendor/npm/node_modules/imap-mcp-server)"
        )
    return node_bin, package_root


@dataclass(slots=True)
class _Session:
    """One user's live encryption session: paths, id, and the plaintext AEK hex."""

    paths: Paths
    user_id: str
    aek_hex: str
    home: Path

    def spawn(
        self,
        node_bin: str,
        package_root: Path,
        mode: str,
        account_id: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Run the harness child; return its single-line JSON verdict."""
        env = {
            "HOME": str(self.home),
            "PATH": os.environ.get("PATH", ""),
        }
        # The invariant under test: no key material in the child's environment.
        assert self.aek_hex not in json.dumps(env)
        argv = [node_bin, str(_HARNESS_PATH), str(package_root), mode]
        if account_id is not None:
            argv.append(account_id)
        proc = subprocess.run(
            argv,
            input=None if payload is None else json.dumps(payload),
            capture_output=True,
            text=True,
            env=env,
            timeout=_SPAWN_TIMEOUT_SECONDS,
            check=False,
        )
        assert proc.returncode == 0, (
            f"harness {mode} failed (rc={proc.returncode}): "
            f"stderr={proc.stderr!r} stdout={proc.stdout!r}"
        )
        lines = [line for line in proc.stdout.splitlines() if line.strip()]
        assert lines, f"harness produced no output: stderr={proc.stderr!r}"
        verdict = json.loads(lines[-1])
        assert isinstance(verdict, dict)
        return verdict


@pytest.fixture
def session(tmp_path: Path) -> _Session:
    """A user with an activated AEK, a seeded account, and a wired fake HOME.

    The fake home's ``.imap-mcp`` entry is a symlink to the gateway's
    per-user ``imap-store`` directory — exactly the indirection the M05 tool
    host needs so the unmodified upstream module (which hardcodes
    ``$HOME/.imap-mcp``) reads and writes OUR store.
    """
    paths = build_paths(tmp_path)
    ensure_wrap_key(paths)
    user_record, _ = create_user(paths, "alice")
    user_id = user_record.id
    aek_hex = activate_aek(paths, user_id)

    home = tmp_path / "home"
    home.mkdir()
    store_dir = paths.user_imap_store_dir(user_id)
    materialize_key_file(paths, user_id, aek_hex)  # creates the store dir
    (home / ".imap-mcp").symlink_to(store_dir, target_is_directory=True)
    return _Session(paths=paths, user_id=user_id, aek_hex=aek_hex, home=home)


def _seed_account(
    session: _Session,
    *,
    password: str = "correct horse battery staple",
    smtp_password: str = "smtp-secret-9",
) -> str:
    """Store one fully-populated account through ``put_account``; return its id."""
    payload = {
        "name": "Personal",
        "host": "imap.example.org",
        "port": 993,
        "user": "alice@example.org",
        "password": password,
        "tls": True,
        "allow_start_tls": False,
        "email": "alice@example.org",
        "smtp": {
            "host": "smtp.example.org",
            "port": 465,
            "secure": True,
            "user": "alice@example.org",
            "password": smtp_password,
        },
        "save_to_sent": True,
        "sent_folder": "Gesendet",
        "default_bcc": "audit@example.org",
        "allowed_from": ["bob@example.org"],
    }
    stored = put_account(
        session.paths,
        session.user_id,
        encrypt_account_record(payload, session.aek_hex),
    )
    return stored.id


def test_mode_of_accounts_json_is_0600(session: _Session) -> None:
    """The store file stays owner-only, in the gateway layout and upstream's."""
    account_id = _seed_account(session)
    store_file = session.paths.user_imap_store_dir(session.user_id) / "accounts.json"
    assert (os.stat(store_file).st_mode & 0o777) == 0o600
    assert get_account(session.paths, session.user_id, account_id) is not None


def test_gateway_store_reads_back_via_upstream_account_manager(
    session: _Session, upstream_tool: tuple[str, Path]
) -> None:
    """Acceptance 1: upstream decrypts our ``put_account`` bytes correctly."""
    node_bin, package_root = upstream_tool
    imap_password = "correct horse battery staple"
    smtp_password = "smtp-secret-9"
    account_id = _seed_account(
        session, password=imap_password, smtp_password=smtp_password
    )

    verdict = session.spawn(node_bin, package_root, "read", account_id)

    assert verdict["found"] is True
    account = verdict["account"]
    assert account["id"] == account_id
    assert account["password"] == imap_password  # the byte-format proof
    assert account["smtp"]["password"] == smtp_password  # nested field too
    # Metadata survived the round trip with upstream's camelCase keys.
    assert account["name"] == "Personal"
    assert account["host"] == "imap.example.org"
    assert account["port"] == 993
    assert account["allowStartTLS"] is False
    assert account["smtp"]["host"] == "smtp.example.org"
    assert account["sentFolder"] == "Gesendet"
    assert account["allowedFrom"] == ["bob@example.org"]


def test_upstream_add_account_is_visible_after_resync(
    session: _Session, upstream_tool: tuple[str, Path]
) -> None:
    """Acceptance 4: wrapper re-sync sees upstream (tool-host-style) writes."""
    node_bin, package_root = upstream_tool
    _seed_account(session)
    tool_payload = {
        "name": "Work",
        "host": "imap.work.example",
        "port": 993,
        "user": "bob@work.example",
        "password": "from-the-tool-host",
        "tls": True,
    }

    verdict = session.spawn(
        node_bin, package_root, "add", payload=tool_payload
    )
    added_id = verdict["id"]
    assert added_id

    # Re-sync WITHOUT process restart: the next listing reflects the write.
    accounts = list_accounts(session.paths, session.user_id)
    assert [account.name for account in accounts] == ["Personal", "Work"]
    work = accounts[1]
    assert work.id == added_id
    # The metadata view carries no credential fields: no password anywhere,
    # and the smtp projection (None here — the payload had no smtp block)
    # never carries smtp.user/smtp.password.
    dumped = work.model_dump()
    assert "password" not in dumped
    assert dumped["smtp"] is None

    # And the Python side can decrypt upstream-written ciphertext: the format
    # is bidirectional, not just "upstream happens to parse our file".
    record = get_account(session.paths, session.user_id, added_id)
    assert record is not None
    assert decrypt_field(session.aek_hex, record.password) == "from-the-tool-host"
    # Upstream's own save re-asserted owner-only permissions on the file.
    store_file = session.paths.user_imap_store_dir(session.user_id) / "accounts.json"
    assert (os.stat(store_file).st_mode & 0o777) == 0o600


def test_reencrypt_all_keeps_store_readable_under_new_key(
    session: _Session, upstream_tool: tuple[str, Path]
) -> None:
    """Acceptance 3: AEK rotation keeps the upstream-readable store green."""
    node_bin, package_root = upstream_tool
    imap_password = "correct horse battery staple"
    account_id = _seed_account(session, password=imap_password, smtp_password="")
    old_aek = session.aek_hex
    new_aek = os.urandom(32).hex()

    reencrypt_all(session.paths, session.user_id, old_aek, new_aek)

    # Swap the session key file: the tool-host session would see the new AEK.
    cleanup_key_file(session.paths, session.user_id)
    session.aek_hex = new_aek
    materialize_key_file(session.paths, session.user_id, new_aek)

    verdict = session.spawn(node_bin, package_root, "read", account_id)
    assert verdict["found"] is True
    assert verdict["account"]["password"] == imap_password  # new key, via upstream

    # The old key no longer decrypts (rotation is real, not additive).
    record = get_account(session.paths, session.user_id, account_id)
    assert record is not None
    with pytest.raises(ValueError):
        decrypt_field(old_aek, record.password)


def test_missing_account_reports_not_found_via_upstream(
    session: _Session, upstream_tool: tuple[str, Path]
) -> None:
    """Sanity: the child really reads OUR file (absent id stays absent)."""
    node_bin, package_root = upstream_tool
    _seed_account(session)

    verdict = session.spawn(node_bin, package_root, "read", "no-such-id")

    assert verdict["found"] is False
