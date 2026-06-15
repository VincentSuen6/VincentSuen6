"""
auth.py — API Key Middleware
============================
Protects all /api/v1/* endpoints with a bearer-style API key check.
Keys are read from SOAR_API_KEYS (comma-separated) so multiple callers
(Wazuh forwarder, soar-hub, CI pipeline) can each hold their own key
and individual keys can be rotated without restarting the server.

Exempt paths (no key required):
  /health     — container orchestration probes must not need a secret
  /metrics    — Prometheus scraper runs inside the Docker network
  /api/events — SSE stream is read-only; add auth here if dashboard is public

Usage:
  Set SOAR_API_KEYS="key-abc123,key-def456" in .env or docker-compose.
  Callers include the header: X-API-Key: key-abc123
"""

import os
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware

_RAW_KEYS = os.getenv("SOAR_API_KEYS", "")
_VALID_KEYS: set[str] = {k.strip() for k in _RAW_KEYS.split(",") if k.strip()}

_EXEMPT_PREFIXES = ("/health", "/metrics", "/api/events")


class APIKeyMiddleware(BaseHTTPMiddleware):
    """
    Checks the X-API-Key header for every request whose path starts with /api/v1.
    Returns 401 if the header is absent and 403 if the key is not in the valid set.
    Returns 503 if no keys are configured at all (misconfiguration guard).
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Let exempt paths through unconditionally
        if any(path.startswith(p) for p in _EXEMPT_PREFIXES):
            return await call_next(request)

        # Only enforce auth on /api/ routes
        if not path.startswith("/api/"):
            return await call_next(request)

        if not _VALID_KEYS:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="API key auth is not configured. Set SOAR_API_KEYS env var.",
            )

        key = request.headers.get("X-API-Key", "").strip()
        if not key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing X-API-Key header.",
                headers={"WWW-Authenticate": "ApiKey"},
            )
        if key not in _VALID_KEYS:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid API key.",
            )

        return await call_next(request)
