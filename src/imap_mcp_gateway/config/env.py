"""Process-wide configuration, resolved once from environment variables.

``Settings`` is the ONLY place the process reads the environment for
configuration: it is instantiated once at startup (``app.run``, the
composition root) and the values are passed on — e.g. the single ``Paths``
object built from ``data_dir``. No other module may call ``Settings()`` or
``os.environ`` for configuration.

Every field maps 1:1 to an environment variable of the same name
(case-insensitive, no prefix), the standard pydantic-settings env loading:
``DATA_DIR``, ``HTTP_PORT``, ``LOG_LEVEL``, ``NODE_BIN``,
``IMAP_MCP_SERVER_JS``, ``MCP_IDLE_TIMEOUT_SECONDS`` and ``SPA_DIST_DIR``.

``spa_dist_dir`` (M07-T05) points at the BUILT single-page application
(``frontend/dist`` by default): ``index.html`` is the shell served at
``/admin`` and ``/user``, ``assets/`` is the hashed-asset mount. The
default is RELATIVE on purpose — the runtime image's WORKDIR is ``/app``
and the image carries the build output at ``/app/frontend/dist``, so the
default resolves without an env var. The path is read LAZILY per request
(see ``web/spa.py``): an app built without a dist is legal (every unit
test), and only a request for a shell page fails loud.
"""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Gateway configuration sourced from the environment (see module docstring)."""

    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False)

    data_dir: Path = Path("/data")
    http_port: int = 3000
    log_level: str = "INFO"
    node_bin: Path = Path("/usr/local/bin/node")
    imap_mcp_server_js: Path = Path(
        "/opt/vendor/npm/node_modules/imap-mcp-server/dist/index.js"
    )
    mcp_idle_timeout_seconds: int = 900
    spa_dist_dir: Path = Path("frontend/dist")
