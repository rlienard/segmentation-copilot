"""Authentication for the FastAPI service.

Phase 2 ships static bearer-token auth keyed by `SCOPILOT_API__API_KEYS`.
The dependency surface — `AuthContext` + `get_auth_context` — stays stable
when OIDC arrives in Phase 6 hardening; only `_verify_token()` swaps to a
JWKS check.

Set `SCOPILOT_API__REQUIRE_AUTH=false` for local dev / tests; every
request then resolves to the configured `default_tenant_id`.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, status

from segmentation_copilot.config import Settings, get_settings


@dataclass(frozen=True)
class AuthContext:
    """Resolved identity + tenant for the request."""

    tenant_id: str
    actor: str
    """Stable identifier we log into audit_events (token sha / OIDC sub)."""


def _verify_token(token: str, settings: Settings) -> AuthContext | None:
    if token in settings.api.api_keys:
        # Token-prefix as the audit actor; never the full secret.
        return AuthContext(tenant_id=settings.default_tenant_id, actor=f"token:{token[:8]}")
    return None


async def get_auth_context(
    authorization: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> AuthContext:
    if not settings.api.require_auth:
        return AuthContext(tenant_id=settings.default_tenant_id, actor="anonymous")

    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing or malformed Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization.split(" ", 1)[1].strip()
    ctx = _verify_token(token, settings)
    if ctx is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return ctx
