"""Liveness probe route backing the image HEALTHCHECK and the compose healthcheck."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/healthz")
def healthz() -> dict[str, str]:
    """Liveness probe; the ``{"status": "ok"}`` body is an operator-facing contract."""
    return {"status": "ok"}
