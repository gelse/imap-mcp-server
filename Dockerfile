# Deployment manifest for M01-T03, extended by M07-T06.
#
# Shape: one image that ships the pinned Python app AND a pinned Node.js 22.12.x
# runtime with the vendored upstream npm package — decision (d), the Node
# subprocess bridge (M01 deployment foundation, Risks): the Python
# gateway spawns `node /opt/vendor/npm/node_modules/imap-mcp-server/dist/index.js`
# per user session (M05-T02). The ONLY Node component that RUNS at runtime is
# the pinned, prebuilt upstream package plus the official Node binary it needs.
#
# Language boundary (M07 supersedes the former "no new Node/JS" rule): the
# SPA (Vue 3 + TypeScript) is now a product component, so the image build also
# uses a Node toolchain — in the `web-build` stage only, at BUILD time:
# `npm ci` from the committed lockfile, then the build, whose final leg is the
# secret/external-URL audit (a violation fails the image build). Nothing of
# that toolchain reaches the runtime stage: the runtime receives ONLY the built
# `frontend/dist` (hashed assets + index.html) — no node_modules, no dev
# dependencies, no frontend sources, no npm cache.
#
# npm supply chain mirrors the existing `vendor/npm` policy: exact-pinned
# versions, committed `frontend/package-lock.json` (the lockfile is
# authoritative — `npm ci` only, never `npm install`), `npm ci` executed only
# at image build time.
#
# The python and node base images ARE pinned by digest
# in the FROM lines below — to each tag's multi-arch manifest list, so the
# build resolves the host platform's variant automatically while the pinned
# content stays immutable: supply-chain reproducibility — the tags float
# whenever upstream rebuilds, the digests do not, so a rebuild always
# resolves the same base.

# --- Stage: node --------------------------------------------------------------
# Source stage for the pinned Node.js 22.12.x binary (Settings.node_bin default
# /usr/local/bin/node). The official image's node is a self-contained binary
# linked only against system libs (libstdc++/libgcc/libc), which the Python
# slim base provides (libstdc++6 installed in the runtime stage).
FROM node:22.12-bookworm-slim@sha256:35531c52ce27b6575d69755c73e65d4468dba93a25644eed56dc12879cae9213 AS node

# --- Stage: web-build --------------------------------------------------------
# Builds the SPA. Build-time only — nothing from this stage except the built
# dist/ reaches the runtime stage. The base is the SAME digest as the `node`
# stage above (one pinned toolchain, no new base image).
FROM node:22.12-bookworm-slim@sha256:35531c52ce27b6575d69755c73e65d4468dba93a25644eed56dc12879cae9213 AS web-build

WORKDIR /build/frontend

# Dependencies first so this layer survives source-only changes. The committed
# lockfile is authoritative (mirrors `uv sync --frozen` in the Python builder):
# `npm ci` never resolves a floating range and never rewrites the lockfile.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund

# The frontend sources. The build's final leg is scripts/audit-dist.mjs (no
# secret-shaped material, no external references, no inline scripts) — an audit
# violation fails the IMAGE BUILD.
COPY frontend/ ./
RUN npm run build

# --- Stage: builder -----------------------------------------------------------
FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258 AS builder

# Python build deps for uv sync (plan: "plus Python build deps") and the CA
# bundle npm needs for the registry.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Node.js 22.12.x + its npm (bin symlinks + node_modules/npm), used below to
# vendor the pinned npm package. Directory COPY merges with the Python image's
# /usr/local/{bin,lib} — no file name collisions.
COPY --from=node /usr/local/bin /usr/local/bin
COPY --from=node /usr/local/lib /usr/local/lib

# uv (tag left floating by explicit choice — only the python/node bases are
# digest-pinned).
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

ENV UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv

WORKDIR /app

# Dependencies first so this layer survives app-source-only changes. The lock
# is authoritative (--frozen); dev tools (pytest/ruff/mypy) stay out of the
# image; the project itself is installed after its source exists.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Vendor the pinned upstream package (version MUST match [tool.gateway] in
# pyproject.toml). This downloads the prebuilt upstream release only — the
# system's ONLY Node component (see the language boundary note in the task).
# Kept above the app-source COPY: the vendored tree depends only on the node
# toolchain above and this literal pin, so the layer is cached across
# source-only edits.
RUN npm install --prefix /opt/vendor/npm imap-mcp-server@2.2.0

COPY src ./src
RUN uv sync --frozen --no-dev

# --- Stage: runtime -----------------------------------------------------------
FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258 AS runtime

# libstdc++6/libgcc-s1 for the copied node binary. node lands exactly at the
# Settings.node_bin default (/usr/local/bin/node) — no override needed.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=node /usr/local/bin/node /usr/local/bin/node

# Vendored upstream package at the Settings.imap_mcp_server_js default path.
# Root-owned read-only: the app never writes here.
COPY --from=builder /opt/vendor/npm /opt/vendor/npm

# Python environment and app source at the same paths the builder's editable
# install references (/app/.venv -> /app/src), so the copied venv stays valid.
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/src /app/src

# The built SPA: hashed assets + index.html, nothing else (no node_modules, no
# dev dependencies, no frontend sources, no npm cache). Root-owned read-only.
# Serve-path contract: the runtime WORKDIR /app plus the SPA dist-dir default
# `frontend/dist` resolves to /app/frontend/dist inside the container — no env
# var needed; SPA_DIST_DIR remains available as an override.
COPY --from=web-build /build/frontend/dist /app/frontend/dist

ENV PATH="/app/.venv/bin:${PATH}" \
    DATA_DIR=/data \
    HTTP_PORT=3000 \
    HOME=/home/app

WORKDIR /app

# Unprivileged runtime user (uid 1000); uid matches the documented host
# bind-mount ownership (data/ dirs owned by uid 1000).
RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin app

USER app
EXPOSE 3000
# The probe reads HTTP_PORT at runtime (default 3000, matching ENV above), so
# overriding HTTP_PORT at run time needs no healthcheck change.
HEALTHCHECK --interval=5s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import os,urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('HTTP_PORT','3000')+'/healthz', timeout=2).status==200 else 1)"
CMD ["python", "-m", "imap_mcp_gateway"]
