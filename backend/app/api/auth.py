"""
NETRA — Authentication API (OWASP A07).

Handles login, token refresh, and user management.
Account lockout after 5 failed attempts (brute force protection).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.api.deps import CurrentUser, DbSession, RequireAdmin, require_role
from backend.app.core.security import (
    AuditAction,
    Role,
    TokenPair,
    build_audit_entry,
    create_token_pair,
    hash_password,
    verify_password,
)
from backend.app.models.actors import AuditLog, User

router = APIRouter(prefix="/auth", tags=["auth"])

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 30


# ── Request / Response schemas ───────────────────────────────

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=128)
    password: str = Field(..., min_length=8, max_length=128)


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=128, pattern=r"^[a-zA-Z0-9_]+$")
    password: str = Field(..., min_length=8, max_length=128)
    role: str = Field(default="viewer", pattern=r"^(viewer|analyst|admin)$")


class RefreshRequest(BaseModel):
    refresh_token: str


class UserResponse(BaseModel):
    user_id: str
    username: str
    role: str
    is_active: bool
    last_login: datetime | None


# ── Endpoints ────────────────────────────────────────────────

@router.post("/login", response_model=TokenPair)
async def login(body: LoginRequest, db: DbSession) -> TokenPair:
    """Authenticate and receive JWT access + refresh tokens."""
    # Find user
    result = await db.execute(
        select(User).where(User.username == body.username)
    )
    user = result.scalar_one_or_none()

    if user is None:
        # Don't reveal whether the username exists (OWASP A07)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    now = datetime.now(UTC).replace(tzinfo=None)

    # Check account lockout
    if user.locked_until and user.locked_until > now:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Account locked until {user.locked_until.isoformat()}",
        )

    # Verify password
    if not verify_password(body.password, user.hashed_password):
        # Increment failed attempts
        user.failed_login_count += 1
        if user.failed_login_count >= MAX_FAILED_ATTEMPTS:
            user.locked_until = now + timedelta(minutes=LOCKOUT_DURATION_MINUTES)

        # Audit failed login
        db.add(AuditLog(**build_audit_entry(
            actor=body.username,
            action=AuditAction.LOGIN_FAILED,
            target=body.username,
            detail={"failed_count": user.failed_login_count},
        )))
        await db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    # Successful login — reset counters
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login = now

    # Audit successful login
    db.add(AuditLog(**build_audit_entry(
        actor=user.user_id,
        action=AuditAction.LOGIN,
        target=user.username,
    )))
    await db.commit()

    return create_token_pair(user.user_id, user.role)


@router.post("/refresh", response_model=TokenPair)
async def refresh_token(body: RefreshRequest) -> TokenPair:
    """Exchange a valid refresh token for a new token pair."""
    from backend.app.core.security import TokenType, decode_token
    from jose import JWTError

    try:
        payload = decode_token(body.refresh_token)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    if payload.type != TokenType.REFRESH:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not a refresh token",
        )

    return create_token_pair(payload.sub, payload.role)


@router.post(
    "/register",
    response_model=UserResponse,
    dependencies=[Depends(require_role(Role.ADMIN))],
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    body: RegisterRequest,
    db: DbSession,
    current_user: CurrentUser,
) -> UserResponse:
    """Create a new user account (admin only)."""
    # Check if username already exists
    existing = await db.execute(
        select(User).where(User.username == body.username)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists",
        )

    user = User(
        user_id=str(uuid.uuid4()),
        username=body.username,
        hashed_password=hash_password(body.password),
        role=body.role,
    )
    db.add(user)

    # Audit
    db.add(AuditLog(**build_audit_entry(
        actor=current_user.sub,
        action=AuditAction.USER_CREATE,
        target=body.username,
        detail={"role": body.role},
    )))
    await db.commit()

    return UserResponse(
        user_id=user.user_id,
        username=user.username,
        role=user.role,
        is_active=user.is_active,
        last_login=user.last_login,
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: CurrentUser,
    db: DbSession,
) -> UserResponse:
    """Get current authenticated user's info."""
    result = await db.execute(
        select(User).where(User.user_id == current_user.sub)
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return UserResponse(
        user_id=user.user_id,
        username=user.username,
        role=user.role,
        is_active=user.is_active,
        last_login=user.last_login,
    )
