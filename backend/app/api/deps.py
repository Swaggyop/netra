"""
NETRA — FastAPI dependency injection.

Provides database sessions, Neo4j sessions, the event bus,
and authentication dependencies for all API routes.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config import get_settings
from backend.app.core.events import EventBus, create_event_bus
from backend.app.core.security import (
    Role,
    TokenPayload,
    decode_token,
    has_permission,
)
from backend.app.models.base import get_db

logger = logging.getLogger(__name__)

# ── HTTP Bearer scheme ───────────────────────────────────────

_bearer_scheme = HTTPBearer(auto_error=False)


# ── Database session ─────────────────────────────────────────

async def db_session() -> AsyncSession:  # type: ignore[misc]
    """Yields a scoped async SQLAlchemy session."""
    async for session in get_db():
        yield session  # type: ignore[misc]


DbSession = Annotated[AsyncSession, Depends(db_session)]


# ── Event bus ────────────────────────────────────────────────

_event_bus: EventBus | None = None


async def get_event_bus() -> EventBus:
    """Return the application-wide EventBus instance."""
    global _event_bus  # noqa: PLW0603
    if _event_bus is None:
        _event_bus = create_event_bus()
        await _event_bus.start()
    return _event_bus


EventBusDep = Annotated[EventBus, Depends(get_event_bus)]


# ── Authentication (OWASP A01, A07) ─────────────────────────

async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> TokenPayload:
    """
    Decode and validate the JWT from the Authorization header.

    Raises 401 if missing/invalid, includes rate limiting context.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_token(credentials.credentials)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check token type
    if payload.type != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type — use an access token",
        )

    # Check expiry (jose does this, but be explicit)
    if payload.exp < datetime.now(UTC):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )

    return payload


CurrentUser = Annotated[TokenPayload, Depends(get_current_user)]


# ── Role-based access ───────────────────────────────────────

def require_role(required: Role):
    """
    FastAPI dependency factory: ensure the user has sufficient permissions.

    Usage:
        @router.post("/sources/{id}/toggle", dependencies=[Depends(require_role(Role.ADMIN))])
    """
    async def _check(user: CurrentUser) -> TokenPayload:
        if not has_permission(user.role, required):
            logger.warning(
                "Access denied: user %s (role=%s) tried to access resource requiring %s",
                user.sub, user.role, required,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role: {required.value} or higher",
            )
        return user
    return _check


RequireAnalyst = Annotated[TokenPayload, Depends(require_role(Role.ANALYST))]
RequireAdmin = Annotated[TokenPayload, Depends(require_role(Role.ADMIN))]
