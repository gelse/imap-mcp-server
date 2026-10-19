"""The M05-T03 tool-parity gate against the REAL upstream process.

The gateway's contract is verbatim pass-through ("exactly the same tools as
upstream ``imap-mcp-server``"), so the wrapper must pin — and continuously
prove — the tool surface of the pinned upstream: this module spawns the REAL
vendored ``imap-mcp-server@2.2.0`` entrypoint through the production
:class:`~imap_mcp_gateway.mcp.tool_host.NodeToolHost` (no network — a tools
exchange never touches IMAP), performs the MCP ``initialize`` handshake, calls
``tools/list``, and holds the returned name set against the frozen pin in
:mod:`imap_mcp_gateway.mcp.expected_tools` EXACTLY (no extras, no omissions).
A drift failure names the drift: the missing names (upstream dropped/renamed)
and the unexpected names (upstream added / pin stale) are listed explicitly.
Descriptions and schemas are spot-checked against upstream output, including
the ``imap_upload_file`` description, which embeds the tool host's configured
``IMAP_MAX_UPLOAD_SIZE``/``IMAP_UPLOAD_TTL_MS`` values — proving the finalized
M05-T03 env wiring reaches the real child.

Sourcing of the pin (see ``expected_tools.py`` for the full account): every
name is a ``server.registerTool('<name>'`` call in the pinned upstream sources
(``src/tools/account-tools.ts`` 7, ``email-tools.ts`` 21, ``folder-tools.ts``
4, ``spam-tools.ts`` 8 — version ``2.2.0``, npm ``gitHead``
``bd474262aea96ef29ba4ff7f0fa06cab06dd8bdd``), cross-checked against a live
``tools/list`` of the vendored entrypoint.

Node-absence decision (deliberate, and the reason this file exists in this
shape): the parity gate is a HARD GATE whenever the pinned upstream runtime is
available — the deployment image (``/opt/vendor/npm`` + node 22.12.x), the
repo-local dev-vendor layout (``<repo>/vendor/npm/node_modules/``), or any
``IMAP_MCP_UPSTREAM_PKG`` override. When the runtime is absent (bare dev
checkout without the vendored package, or no ``node`` binary) the gate cannot
observe upstream at all, and failing ``uv run pytest`` everywhere would get
the gate disabled — so the outcome is an EXPLICIT skip whose reason names
exactly what is missing and how to provide it (the same precisely-reasoned
skip convention as the four upstream-interop fixtures). It is never a silent
no-op: the skip reason names the missing piece and the remedy, the ``interop``
marker documents the runtime requirement (it is applied ONLY to the two tests
that need the real toolchain — the pin self-checks, the disposition unit
tests, and the stub-based tests run everywhere), and setting
``MCP_PARITY_GATE_REQUIRED=1`` (the CI/image wiring) flips every absence-skip
into a hard failure. Two cases are NEVER skippable anywhere: a package that
IS installed but not usable at the pin — another version, or a broken tree
(unreadable/invalid ``package.json``, missing ``dist/index.js``) — is
upstream drift by definition; and an explicitly configured but unusable
``NODE_BIN`` is a configuration error. Both fail unconditionally.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

import imap_mcp_gateway
from imap_mcp_gateway.config.env import Settings
from imap_mcp_gateway.config.paths import Paths, build_paths
from imap_mcp_gateway.crypto import wrap
from imap_mcp_gateway.mcp.expected_tools import (
    ACCOUNT_TOOLS,
    EMAIL_TOOLS,
    EXPECTED_GROUP_SIZES,
    EXPECTED_TOOL_NAMES,
    FOLDER_TOOLS,
    SPAM_TOOLS,
    UPSTREAM_PINNED_VERSION,
)
from imap_mcp_gateway.mcp.gateway import ToolHost
from imap_mcp_gateway.mcp.tool_host import NodeToolHostFactory
from imap_mcp_gateway.store.session_keyfile import key_file_path
from imap_mcp_gateway.store.user_schema import UserMetadata
from imap_mcp_gateway.store.users import activate_aek, create_user
from imap_mcp_gateway.store.wrap_key import ensure_wrap_key

_STUB_PATH = Path(__file__).with_name("stub_tool_host.py")

_GATE_REQUIRED_ENV = "MCP_PARITY_GATE_REQUIRED"
"""Set truthy where the parity gate MUST run (CI/image): absence skips become failures."""

_IMAGE_PACKAGE_ROOT = "/opt/vendor/npm/node_modules/imap-mcp-server"
"""The deployment image's vendored package root (``Settings.imap_mcp_server_js`` home)."""

_INITIALIZE_REQUEST: dict[str, Any] = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "tool-parity-probe", "version": "0.0.0"},
    },
}

# --- upstream toolchain discovery (pure, unit-tested) -----------------------------------


def _find_node_bin() -> tuple[str | None, str | None]:
    """The Node binary, or ``(None, reason)`` when unavailable.

    An explicitly configured but unusable ``NODE_BIN`` (not an executable
    file) is a CONFIGURATION ERROR — it returns a fail reason naming the
    override, never the polite "tooling absent" skip. Only an unset
    ``NODE_BIN`` with nothing on ``PATH`` is genuine absence.
    """
    override = os.environ.get("NODE_BIN")
    if override is not None:
        if Path(override).is_file() and os.access(override, os.X_OK):
            return override, None
        return None, (
            f"NODE_BIN={override!r} is set but is not an executable file — "
            "fix the override or unset it"
        )
    found = shutil.which("node")
    return (found, None) if found else (None, None)


def _upstream_package_candidates() -> list[str]:
    """The vendored ``imap-mcp-server`` package roots to probe, in order.

    ``IMAP_MCP_UPSTREAM_PKG`` (dev override), the package root derived from
    the tool host's own configured entrypoint (``Settings.imap_mcp_server_js``
    — the gate probes the exact tree the child would spawn whenever
    ``IMAP_MCP_UPSTREAM_PKG`` is unset or equal to it, so an
    ``IMAP_MCP_SERVER_JS`` override is honored here too), the Docker image
    default, and the repo-local dev-vendor layout the interop fixtures
    document. Duplicates are removed preserving order (the Settings-derived
    root IS the image default under default settings).
    """
    settings_entrypoint = Path(Settings().imap_mcp_server_js)
    repo_root = Path(__file__).resolve().parents[1]
    candidates = [
        os.environ.get("IMAP_MCP_UPSTREAM_PKG"),
        str(settings_entrypoint.parent.parent),
        _IMAGE_PACKAGE_ROOT,
        str(repo_root / "vendor/npm/node_modules/imap-mcp-server"),
    ]
    return list(dict.fromkeys(c for c in candidates if c))


def _find_vendored_server_js() -> tuple[Path | None, str | None]:
    """The pinned vendored entrypoint, or ``(None, reason)`` when unavailable.

    Candidates resolve in priority order and the FIRST PRESENT one decides —
    the gate observes the deployment reality, it never silently substitutes a
    lower-priority tree: a pinned candidate wins; a candidate that is present
    but NOT usable at the pin (another version, an unreadable/invalid
    ``package.json``, a missing ``dist/index.js``) is upstream drift and
    fails with a reason naming that tree; only genuinely ABSENT candidates
    fall through to the next entry. Drift never resolves to a skip.
    """
    for candidate in _upstream_package_candidates():
        if not candidate:
            continue
        root = Path(candidate)
        if not root.exists():
            continue  # absent → fall through to the next candidate
        manifest = root / "package.json"
        server_js = root / "dist" / "index.js"
        unusable: list[str] = []
        try:
            manifest_json: Any = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            unusable.append(f"package.json unreadable or invalid ({exc})")
        else:
            if not isinstance(manifest_json, dict):
                unusable.append("package.json is not a JSON object")
            elif manifest_json.get("version") != UPSTREAM_PINNED_VERSION:
                unusable.append(
                    f"version {manifest_json.get('version')!r} != pinned "
                    f"{UPSTREAM_PINNED_VERSION!r}"
                )
        if not server_js.is_file():
            unusable.append("dist/index.js missing")
        if unusable:
            return None, (
                f"vendored imap-mcp-server candidate at {root} is present but "
                "unusable at the pin ("
                + "; ".join(unusable)
                + ") — the deployed upstream has drifted from the pin; re-pin "
                "the vendored package and expected_tools.py together (M05 "
                "upgrade policy)"
            )
        return server_js, None
    return None, None  # genuinely absent (no package installed at all)


@dataclass(frozen=True, slots=True)
class _GateRequirement:
    """The parity gate's runtime prerequisites and, when unmet, why."""

    node_bin: str | None
    server_js: Path | None
    missing_reason: str | None  # tooling absent → skip (or fail when required)
    fail_reason: str | None  # deployment/config drift → always fail


def _require_upstream_toolchain() -> _GateRequirement:
    """Resolve the gate's prerequisites; classify absence vs. drift."""
    node_bin, node_error = _find_node_bin()
    server_js, drift_reason = _find_vendored_server_js()
    missing: list[str] = []
    if node_bin is None and node_error is None:
        missing.append("node executable not found (set NODE_BIN or put node on PATH)")
    if server_js is None and drift_reason is None:
        missing.append(
            "vendored imap-mcp-server@"
            f"{UPSTREAM_PINNED_VERSION} package not found — set "
            "IMAP_MCP_UPSTREAM_PKG to the package root with its npm "
            "dependencies installed alongside (npm install --prefix layout; "
            f"looked at: {', '.join(c for c in _upstream_package_candidates() if c)})"
        )
    return _GateRequirement(
        node_bin=node_bin,
        server_js=server_js,
        missing_reason="; ".join(missing) if missing else None,
        # Both defects are reported together: an operator repairing one must
        # see the other too (e.g. a drifted tree behind a broken NODE_BIN).
        fail_reason=(
            "; ".join(reason for reason in (node_error, drift_reason) if reason)
            or None
        ),
    )


def _gate_disposition(requirement: _GateRequirement) -> tuple[str, str]:
    """The gate's outcome for the resolved prerequisites: run/skip/fail + reason.

    The deliberate decision (see module docstring): tooling ABSENT → explicit
    skip with the precise reason, or hard failure when
    ``MCP_PARITY_GATE_REQUIRED`` is truthy; DRIFT (a package not usable at
    the pin, or an unusable ``NODE_BIN`` override) → hard failure
    unconditionally; prerequisites present → run.
    """
    if requirement.server_js is not None and requirement.node_bin is not None:
        return "run", ""
    if requirement.fail_reason is not None:
        return "fail", requirement.fail_reason
    assert requirement.missing_reason is not None
    if os.environ.get(_GATE_REQUIRED_ENV, "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }:
        return "fail", requirement.missing_reason
    return "skip", requirement.missing_reason


@pytest.fixture(scope="module")
def upstream() -> tuple[str, Path]:
    """Node binary + pinned vendored entrypoint, or the explicit gate outcome."""
    requirement = _require_upstream_toolchain()
    action, reason = _gate_disposition(requirement)
    if action == "fail":
        pytest.fail(reason)
    if action == "skip":
        pytest.skip(reason)
    assert requirement.node_bin is not None and requirement.server_js is not None
    return requirement.node_bin, requirement.server_js


# --- seeded per-user store (mirrors tests/test_tool_host.py) ----------------------------


@dataclass(slots=True)
class _ParityStore:
    """The seeded module store: one paths object and its activated user."""

    paths: Paths
    user: UserMetadata


@pytest.fixture(scope="module")
def parity_store(tmp_path_factory: pytest.TempPathFactory) -> _ParityStore:
    """One user with an activated AEK (the minimum a real tool host needs).

    The in-memory wrap-key holder is cleared BEFORE ``ensure_wrap_key``:
    module-scoped fixtures materialize before the conftest's per-test holder
    reset, so an earlier module's fixture (``tests/test_tool_host.py``'s
    ``seeded_store``) can leave the holder loaded with a DIFFERENT store's
    key — under which ``ensure_wrap_key`` would early-return without ever
    writing this store's ``config/wrap.key``, and the first per-test reload
    would hit the deliberate wipe guard (wrapped AEKs exist, key file
    missing). Clearing here gives this module the fresh-process semantics the
    conftest reset provides to test bodies. (The same direct-reset mechanism
    the conftest fixture itself uses; ``monkeypatch`` cannot be used in a
    module-scoped fixture.)
    """
    paths = build_paths(tmp_path_factory.mktemp("tool-parity"))
    wrap._loaded_wrap_key = None
    ensure_wrap_key(paths)
    record, _login_key = create_user(paths, "parity")
    activate_aek(paths, record.id)
    return _ParityStore(paths=paths, user=UserMetadata.from_record(record))


@pytest.fixture(autouse=True)
def _reload_wrap_key(
    parity_store: _ParityStore, fresh_process_wrap_state: None
) -> None:
    """Re-install the wrap key after conftest's per-test process reset."""
    ensure_wrap_key(parity_store.paths)


@pytest.fixture
def real_factory(
    parity_store: _ParityStore, upstream: tuple[str, Path]
) -> NodeToolHostFactory:
    """The production factory spawning the REAL vendored upstream entrypoint.

    ``mcp_idle_timeout_seconds`` is pinned explicitly so an ambient
    ``MCP_IDLE_TIMEOUT_SECONDS`` environment value (e.g. ``0``) cannot tear
    the real child down mid-test.
    """
    node_bin, server_js = upstream
    return NodeToolHostFactory(
        settings=Settings(
            data_dir=parity_store.paths.data_dir,
            node_bin=Path(node_bin),
            imap_mcp_server_js=server_js,
            mcp_idle_timeout_seconds=900,
        ),
        paths=parity_store.paths,
    )


@pytest.fixture
def stub_factory(parity_store: _ParityStore) -> NodeToolHostFactory:
    """The production factory pointed at the Python stub child (no Node)."""
    return NodeToolHostFactory(
        settings=Settings(
            data_dir=parity_store.paths.data_dir,
            node_bin=Path(sys.executable),
            imap_mcp_server_js=_STUB_PATH,
            mcp_idle_timeout_seconds=900,
        ),
        paths=parity_store.paths,
    )


# --- bridge helpers -----------------------------------------------------------------------


async def _exchange(host: ToolHost, request: dict[str, Any]) -> dict[str, Any]:
    """One request/response frame exchange with the live host; the reply."""
    await host.send_frame(json.dumps(request))
    reply: dict[str, Any] = json.loads(await host.receive_frame())
    assert reply.get("id") == request["id"], reply
    return reply


async def _initialize_session(host: ToolHost) -> dict[str, Any]:
    """The MCP initialize handshake with the real child; the reply result."""
    reply = await _exchange(host, _INITIALIZE_REQUEST)
    await host.send_frame(
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})
    )
    result: dict[str, Any] = reply["result"]
    return result


def _assert_name_parity(actual: AbstractSet[str]) -> None:
    """Hold ``actual`` against the frozen pin; the failure NAMES the drift."""
    missing = sorted(EXPECTED_TOOL_NAMES - actual)
    unexpected = sorted(actual - EXPECTED_TOOL_NAMES)
    problems: list[str] = []
    if missing:
        problems.append(
            "missing from the live upstream tools/list (upstream dropped or "
            "renamed these; the pin's groups say where they lived): "
            + ", ".join(missing)
        )
    if unexpected:
        problems.append(
            "unexpected in the live upstream tools/list (upstream added these "
            "or the pin is stale — re-derive expected_tools.py): "
            + ", ".join(unexpected)
        )
    assert not problems, (
        "upstream tool-set drift against the imap-mcp-server@"
        f"{UPSTREAM_PINNED_VERSION} pin:\n" + "\n".join(problems)
    )


# --- the pin itself (runs everywhere, no Node needed) -------------------------------------


def test_expected_tools_pin_is_self_consistent() -> None:
    """The frozen pin holds exactly the 40-name surface: 7 + 21 + 4 + 8."""
    assert len(EXPECTED_TOOL_NAMES) == 40
    seen: set[str] = set()
    for name, group, size in EXPECTED_GROUP_SIZES:
        assert len(group) == size, f"{name} group drifted from {size} tools"
        assert not seen & group, f"tool listed in two groups: {seen & group}"
        seen |= group
    assert seen == EXPECTED_TOOL_NAMES  # the union IS the pin, no strays
    assert all(tool.startswith("imap_") for tool in EXPECTED_TOOL_NAMES)
    assert EXPECTED_TOOL_NAMES == (
        ACCOUNT_TOOLS | EMAIL_TOOLS | FOLDER_TOOLS | SPAM_TOOLS
    )


def test_assert_name_parity_names_the_drift() -> None:
    """The parity failure message lists missing AND unexpected names explicitly.

    The hard gate's contract is a diagnosable failure: a drift report that
    does not name the offending tool names would force re-running the probe
    by hand every time.
    """
    with pytest.raises(AssertionError) as excinfo:
        _assert_name_parity(EXPECTED_TOOL_NAMES - {"imap_get_email"} | {"imap_new_tool"})
    message = str(excinfo.value)
    assert "imap_get_email" in message  # named as missing ...
    assert "missing from the live upstream tools/list" in message
    assert "imap_new_tool" in message  # ... and as unexpected
    assert "unexpected in the live upstream tools/list" in message


# --- the gate outcome decision (the Node-absence policy, unit-tested) ---------------------


def test_gate_skips_with_precise_reason_when_tooling_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Absent node + absent package → explicit skip; the reason names both."""
    monkeypatch.delenv("NODE_BIN", raising=False)
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    monkeypatch.setattr(
        "tests.test_tool_parity._upstream_package_candidates", lambda: [None]
    )
    monkeypatch.delenv(_GATE_REQUIRED_ENV, raising=False)

    requirement = _require_upstream_toolchain()
    action, reason = _gate_disposition(requirement)

    assert action == "skip"
    assert "node executable not found" in reason
    assert "vendored imap-mcp-server@2.2.0 package not found" in reason
    assert "IMAP_MCP_UPSTREAM_PKG" in reason  # the remedy is named


def test_gate_fails_when_required_even_without_tooling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``MCP_PARITY_GATE_REQUIRED=1`` flips the absence-skip into a failure."""
    monkeypatch.delenv("NODE_BIN", raising=False)
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    monkeypatch.setattr(
        "tests.test_tool_parity._upstream_package_candidates", lambda: [None]
    )
    monkeypatch.setenv(_GATE_REQUIRED_ENV, "1")

    action, reason = _gate_disposition(_require_upstream_toolchain())

    assert action == "fail"
    assert "node executable not found" in reason


@pytest.mark.parametrize(
    ("node_available", "expected_action", "expected_fragment"),
    [
        pytest.param(
            True,
            "skip",
            "vendored imap-mcp-server@2.2.0 package not found",
            id="node-only",
        ),
        pytest.param(
            False,
            "fail",
            "drifted from the pin",
            id="drift-beats-missing-node",
        ),
    ],
)
def test_gate_disposition_mixed_states(
    node_available: bool,
    expected_action: str,
    expected_fragment: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The mixed prerequisite states resolve as the policy prescribes.

    ``node-only``: node present but no package → absence skip whose reason
    names ONLY the package. ``drift-beats-missing-node``: a non-pinned
    package with no node at all → unconditional drift failure (drift is
    never skipped, whatever else is missing).
    """
    monkeypatch.delenv("NODE_BIN", raising=False)
    monkeypatch.delenv(_GATE_REQUIRED_ENV, raising=False)
    if node_available:
        monkeypatch.setattr(
            "tests.test_tool_parity._find_node_bin",
            lambda: ("/usr/bin/node", None),
        )
    else:
        monkeypatch.setattr(shutil, "which", lambda _name: None)
    if expected_fragment == "drifted from the pin":
        root = tmp_path / "imap-mcp-server"
        (root / "dist").mkdir(parents=True)
        (root / "dist" / "index.js").write_text("", encoding="utf-8")
        (root / "package.json").write_text(
            json.dumps({"version": "2.3.0"}), encoding="utf-8"
        )
        monkeypatch.setattr(
            "tests.test_tool_parity._upstream_package_candidates",
            lambda: [str(root)],
        )
    else:
        monkeypatch.setattr(
            "tests.test_tool_parity._upstream_package_candidates", lambda: [None]
        )

    requirement = _require_upstream_toolchain()
    action, reason = _gate_disposition(requirement)

    assert action == expected_action
    assert expected_fragment in reason
    if node_available:
        assert "node executable not found" not in reason


def test_gate_always_fails_on_a_non_pinned_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A deployed package at another version is drift: never skipped anywhere."""
    monkeypatch.delenv("NODE_BIN", raising=False)
    root = tmp_path / "imap-mcp-server"
    (root / "dist").mkdir(parents=True)
    (root / "dist" / "index.js").write_text("", encoding="utf-8")
    (root / "package.json").write_text(
        json.dumps({"version": "2.3.0"}), encoding="utf-8"
    )
    monkeypatch.setattr(
        "tests.test_tool_parity._upstream_package_candidates", lambda: [str(root)]
    )
    monkeypatch.delenv(_GATE_REQUIRED_ENV, raising=False)

    requirement = _require_upstream_toolchain()
    action, reason = _gate_disposition(requirement)

    assert requirement.server_js is None
    assert action == "fail"  # even without MCP_PARITY_GATE_REQUIRED
    assert "2.3.0" in reason and UPSTREAM_PINNED_VERSION in reason
    assert "drifted from the pin" in reason


@pytest.mark.parametrize(
    ("manifest_bytes", "manifest_text", "ship_index_js", "expected_fragment"),
    [
        pytest.param(
            None,
            "{not json",
            True,
            "package.json unreadable or invalid",
            id="invalid-json",
        ),
        pytest.param(
            None,
            "[]",
            True,
            "package.json is not a JSON object",
            id="non-object-manifest",
        ),
        pytest.param(
            b'{"version": "\xff\xfe"}',
            None,
            True,
            "package.json unreadable or invalid",
            id="invalid-utf8",
        ),
        pytest.param(
            None,
            json.dumps({"version": UPSTREAM_PINNED_VERSION}),
            False,
            "dist/index.js missing",
            id="missing-entrypoint",
        ),
    ],
)
def test_gate_always_fails_on_an_unusable_package(
    manifest_bytes: bytes | None,
    manifest_text: str | None,
    ship_index_js: bool,
    expected_fragment: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A present-but-unusable package is drift, not absence — every shape of it.

    A partially installed or corrupted vendored tree (invalid JSON, a
    non-object manifest, invalid UTF-8 bytes, a missing ``dist/index.js``)
    must never produce the polite "tooling absent" skip — that would run the
    suite green with the gate silently off on a broken deployment.
    """
    monkeypatch.delenv("NODE_BIN", raising=False)
    root = tmp_path / "imap-mcp-server"
    (root / "dist").mkdir(parents=True)
    if ship_index_js:
        (root / "dist" / "index.js").write_text("", encoding="utf-8")
    if manifest_bytes is not None:
        (root / "package.json").write_bytes(manifest_bytes)
    else:
        assert manifest_text is not None
        (root / "package.json").write_text(manifest_text, encoding="utf-8")
    monkeypatch.setattr(
        "tests.test_tool_parity._upstream_package_candidates", lambda: [str(root)]
    )
    monkeypatch.delenv(_GATE_REQUIRED_ENV, raising=False)

    requirement = _require_upstream_toolchain()
    action, reason = _gate_disposition(requirement)

    assert requirement.server_js is None
    assert action == "fail"  # never skipped in any environment
    assert "present but unusable" in reason
    assert str(root) in reason
    assert expected_fragment in reason


def test_gate_first_present_candidate_decides_over_later_pinned_ones(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A present drifted candidate decides; a pinned fallback never masks it.

    The gate observes the deployment reality: the first PRESENT candidate is
    authoritative (highest priority first), so a stale higher-priority tree
    fails the gate naming itself even when a pinned tree sits at a lower
    priority — the child would spawn the stale one, and a green suite must
    not hide that.
    """
    stale = tmp_path / "stale"
    (stale / "dist").mkdir(parents=True)
    (stale / "dist" / "index.js").write_text("", encoding="utf-8")
    (stale / "package.json").write_text(
        json.dumps({"version": "2.1.0"}), encoding="utf-8"
    )
    pinned = tmp_path / "pinned"
    (pinned / "dist").mkdir(parents=True)
    (pinned / "dist" / "index.js").write_text("", encoding="utf-8")
    (pinned / "package.json").write_text(
        json.dumps({"version": UPSTREAM_PINNED_VERSION}), encoding="utf-8"
    )
    monkeypatch.setattr(
        "tests.test_tool_parity._upstream_package_candidates",
        lambda: [str(stale), str(pinned)],
    )

    server_js, drift = _find_vendored_server_js()

    assert server_js is None
    assert drift is not None
    assert str(stale) in drift  # the DECIDING (present) candidate is named
    assert "2.1.0" in drift


def test_gate_uses_the_first_pinned_candidate_and_falls_through_absent_ones(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The usable half of first-present-decides: run on the first usable tree.

    A pinned candidate BEFORE a stale one must win (the gate returns on the
    first usable candidate instead of failing on any later unusable one), and
    genuinely ABSENT candidates fall through — the absent image-default path
    here stands in for the dev flow, where ``/opt/vendor`` does not exist and
    the repo-local ``vendor/npm`` tree must be found.
    """
    pinned = tmp_path / "pinned"
    (pinned / "dist").mkdir(parents=True)
    (pinned / "dist" / "index.js").write_text("", encoding="utf-8")
    (pinned / "package.json").write_text(
        json.dumps({"version": UPSTREAM_PINNED_VERSION}), encoding="utf-8"
    )
    stale = tmp_path / "stale"
    (stale / "dist").mkdir(parents=True)
    (stale / "dist" / "index.js").write_text("", encoding="utf-8")
    (stale / "package.json").write_text(
        json.dumps({"version": "2.1.0"}), encoding="utf-8"
    )
    monkeypatch.setattr(
        "tests.test_tool_parity._upstream_package_candidates",
        lambda: ["/does/not/exist", str(pinned), str(stale)],
    )

    server_js, drift = _find_vendored_server_js()

    assert drift is None  # the first usable candidate wins; nothing is failed
    assert server_js == pinned / "dist" / "index.js"


def test_gate_fails_on_an_unusable_node_bin_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unusable ``NODE_BIN`` is a configuration error, not absence.

    The override must fail the gate naming itself — a misleading
    "node executable not found" skip would hide a broken CI configuration.
    A valid override resolves normally (``sys.executable`` is an executable
    file on every runner).
    """
    monkeypatch.setenv("NODE_BIN", str(Path(sys.executable).parent))
    # a directory: exists, is not an executable FILE → unusable override
    node_bin, node_error = _find_node_bin()
    assert node_bin is None
    assert node_error is not None and "not an executable file" in node_error
    action, reason = _gate_disposition(
        _GateRequirement(
            node_bin=None,
            server_js=Path("/pinned/dist/index.js"),
            missing_reason=None,
            fail_reason=node_error,
        )
    )
    assert action == "fail"
    assert "not an executable file" in reason

    monkeypatch.setenv("NODE_BIN", sys.executable)  # valid override
    node_bin, node_error = _find_node_bin()
    assert node_bin == sys.executable
    assert node_error is None


def test_gate_discovery_skips_empty_candidates_and_resolves_the_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Discovery resolves the pinned package root and skips empty candidates."""
    root = tmp_path / "vendor-pkg"
    (root / "dist").mkdir(parents=True)
    (root / "dist" / "index.js").write_text("", encoding="utf-8")
    (root / "package.json").write_text(
        json.dumps({"version": UPSTREAM_PINNED_VERSION}), encoding="utf-8"
    )
    monkeypatch.setattr(
        "tests.test_tool_parity._upstream_package_candidates",
        lambda: [None, str(root)],
    )

    server_js, drift = _find_vendored_server_js()

    assert drift is None
    assert server_js == root / "dist" / "index.js"


# --- the hard gate: a real session's tools/list equals the pin EXACTLY ---------------------


@pytest.mark.interop  # needs node + the vendored package (the only such tests here)
async def test_tools_list_matches_expected_exactly(
    parity_store: _ParityStore, real_factory: NodeToolHostFactory
) -> None:
    """A real upstream session lists exactly the pinned 40 tools — no drift.

    Runs the production spawn path (``NodeToolHostFactory`` → ``NodeToolHost``
    → the vendored ``imap-mcp-server@2.2.0`` child) and drives the MCP
    handshake over the verbatim frame bridge. Also spot-checks descriptions
    and schemas against upstream output: ``imap_upload_file``'s description
    embeds the tool host's configured ``IMAP_MAX_UPLOAD_SIZE`` (26214400) and
    ``IMAP_UPLOAD_TTL_MS`` (3600000) — direct evidence the finalized M05-T03
    env wiring reaches the real child.
    """
    host = await real_factory.create(parity_store.user, "sess-parity-list")
    try:
        server_info = await _initialize_session(host)
        assert server_info["serverInfo"]["name"] == "imap-mcp-server"
        assert server_info["serverInfo"]["version"] == UPSTREAM_PINNED_VERSION

        reply = await _exchange(
            host, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
        )
        tools: list[dict[str, Any]] = reply["result"]["tools"]
        by_name = {tool["name"]: tool for tool in tools}
        _assert_name_parity(set(by_name))
        assert len(tools) == len(by_name) == 40  # no duplicates either

        # Descriptions spot-checks (verbatim from upstream src/tools/*.ts).
        accounts_tool = by_name["imap_list_accounts"]
        assert accounts_tool["description"] == "List all configured IMAP accounts"
        upload_tool = by_name["imap_upload_file"]
        assert upload_tool["description"] == (
            "Upload a file to the server for use as an email attachment. "
            "Returns a path that can be used with imap_send_email attachments. "
            "This allows sending large attachments without hitting context "
            "window limits. Max size: 26214400 bytes (configurable via "
            "IMAP_MAX_UPLOAD_SIZE). Uploads are auto-deleted after 3600000 ms "
            "(configurable via IMAP_UPLOAD_TTL_MS)."
        )
        download_tool = by_name["imap_download_attachment"]
        assert download_tool["description"].startswith(
            "Download a single attachment from an email (folder + uid + "
            "attachment filename/contentId, as listed by imap_get_email)."
        )
        assert by_name["imap_check_spam"]["description"].startswith(
            "Check emails in a folder for spam."
        )
        assert by_name["imap_list_folders"]["description"].startswith(
            "List all folders/mailboxes for an account (names, hierarchy "
            "delimiter, attributes, RFC 6154 special-use role)."
        )

        # Schema spot-checks (the SDK's JSON-Schema wrapping of upstream's),
        # asserted as the meaningful subset: whole-dict equality would couple
        # the pin to the vendored SDK's serialization quirks, which can float
        # with transitive dependency rebuilds without any upstream change.
        for schema_key, expected in (
            ("$schema", "http://json-schema.org/draft-07/schema#"),
            ("type", "object"),
        ):
            assert accounts_tool["inputSchema"][schema_key] == expected
            assert upload_tool["inputSchema"][schema_key] == expected
        assert accounts_tool["inputSchema"]["properties"] == {}
        upload_properties = upload_tool["inputSchema"]["properties"]
        assert set(upload_properties) == {"filename", "content", "contentType"}
        assert upload_properties["filename"] == {
            "type": "string",
            "description": "Filename to save as",
        }
        assert upload_properties["content"] == {
            "type": "string",
            "description": "Base64 encoded file content",
        }
        assert upload_tool["inputSchema"]["required"] == ["filename", "content"]
        assert all(
            isinstance(tool["inputSchema"], dict) for tool in by_name.values()
        )
    finally:
        await host.aclose()


# --- mail-directory wiring (M05-T03) --------------------------------------------------------


@pytest.mark.interop  # needs node + the vendored package
async def test_real_host_ensures_user_mail_dir_at_0700(
    parity_store: _ParityStore, real_factory: NodeToolHostFactory
) -> None:
    """Spawn ensures ``DATA_DIR/mail/<userId>`` at 0700; teardown keeps it.

    Against the REAL child: the per-user mail directory is created (with its
    ``mail/`` parent) before the upstream process starts — upstream resolves
    ``$IMAP_DOWNLOAD_DIR`` lazily per tool call — and it survives the session
    teardown, because downloads and upload staging must persist on the mail
    bind mount beyond the session. A FRESH user is created for this test so
    the pre-spawn absence of its mail subdirectory is guaranteed regardless
    of test order (the module-scoped user's directory may already exist from
    an earlier real-host test in this module).
    """
    paths = parity_store.paths
    record, _login_key = create_user(paths, "mailcheck")
    activate_aek(paths, record.id)
    mail_dir = paths.user_mail_dir(record.id)
    assert not mail_dir.exists()  # the spawn itself creates it

    host = await real_factory.create(UserMetadata.from_record(record), "sess-mail")
    try:
        assert mail_dir.is_dir()
        assert stat.S_IMODE(os.stat(mail_dir).st_mode) == 0o700
        assert paths.mail_dir().is_dir()  # the bind-mount parent came along
    finally:
        await host.aclose()

    assert mail_dir.is_dir()  # persists: never removed by teardown
    assert stat.S_IMODE(os.stat(mail_dir).st_mode) == 0o700
    assert not key_file_path(paths, record.id).exists()  # key gone, dir kept


async def test_stub_spawn_ensures_fresh_user_mail_dir_at_0700(
    parity_store: _ParityStore, stub_factory: NodeToolHostFactory
) -> None:
    """Toolchain-free pin of ``_ensure_mail_dir``: spawn creates ``0700``.

    The real-child test above covers the same guarantee but is skipped where
    node/the vendored package are absent — and this is the ONLY new
    production behavior of M05-T03 in ``tool_host.py``, so it must also be
    pinned by a test that runs everywhere (stub child, no Node).
    """
    paths = parity_store.paths
    record, _login_key = create_user(paths, "mailstub")
    activate_aek(paths, record.id)
    mail_dir = paths.user_mail_dir(record.id)
    assert not mail_dir.exists()  # the spawn itself creates it

    host = await stub_factory.create(UserMetadata.from_record(record), "sess-mail-stub")
    try:
        assert mail_dir.is_dir()
        assert stat.S_IMODE(os.stat(mail_dir).st_mode) == 0o700
    finally:
        await host.aclose()

    assert mail_dir.is_dir()  # persists: never removed by teardown
    assert stat.S_IMODE(os.stat(mail_dir).st_mode) == 0o700


async def test_download_attachment_fixture_writes_under_user_mail_dir(
    parity_store: _ParityStore, stub_factory: NodeToolHostFactory
) -> None:
    """An ``imap_download_attachment`` call writes under ``mail/<userId>/``.

    The mock-transport-stub proof of the acceptance criterion: the child only
    knows the download directory through its configured env
    (``IMAP_DOWNLOAD_DIR``), and the file it writes lands inside the calling
    user's own ``DATA_DIR/mail/<userId>/`` — never anywhere shared.
    """
    paths = parity_store.paths
    host = await stub_factory.create(parity_store.user, "sess-parity-download")
    try:
        reply = await _exchange(
            host,
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "imap_download_attachment",
                    "arguments": {"filename": "report.pdf"},
                },
            },
        )
        saved = json.loads(reply["result"]["content"][0]["text"])
        assert saved["saved"] is True

        mail_dir = paths.user_mail_dir(parity_store.user.id).resolve()
        expected_file = mail_dir / "report.pdf"
        assert saved["path"] == str(expected_file)
        assert expected_file.read_bytes() == b"stub-attachment-bytes"
        # Nothing leaked outside the per-user directory.
        assert sorted(p.name for p in mail_dir.iterdir()) == ["report.pdf"]
    finally:
        await host.aclose()


# --- the language boundary: the pin is verification data, never runtime data ---------------


def test_expected_tools_pin_is_never_runtime_data() -> None:
    """No runtime module references ``expected_tools`` — greppable boundary.

    Mirrors the wrap-key boundary tests' pattern: any runtime reference to
    the pin would enable wrapper-side tool filtering/validation, which the
    milestone forbids (verbatim pass-through is the contract — the wrapper
    must never decide which tools exist). Only the test module may import it.
    """
    runtime_root = Path(imap_mcp_gateway.__file__).resolve().parent
    offenders = [
        str(path)
        for path in sorted(runtime_root.rglob("*.py"))
        if path.name != "expected_tools.py"
        and "expected_tools" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []
