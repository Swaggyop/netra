"""
NETRA — SQLAlchemy base and async session factory.

All models inherit from Base.  The async session factory is used by
FastAPI dependency injection (see api/deps.py).
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import MetaData, func
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Naming convention for constraints — makes Alembic migrations deterministic
NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Shared base for all ORM models."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)

    # Common columns — override in models if needed
    created_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC).replace(tzinfo=None),
        server_default=func.now(),
    )


# ── Engine + session factory ─────────────────────────────────
# Lazy-init: call init_db() at app startup.

_engine = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def init_db(database_url: str) -> None:
    """Initialise the async engine and session factory."""
    global _engine, _session_factory  # noqa: PLW0603

    _engine = create_async_engine(
        database_url,
        echo=False,
        pool_size=20,
        max_overflow=10,
        pool_pre_ping=True,          # detect stale connections
        pool_recycle=300,             # recycle every 5 min
        connect_args={
            "server_settings": {
                # OWASP A03: set statement_timeout to prevent slow query DoS
                "statement_timeout": "30000",  # 30s
            }
        },
    )
    _session_factory = async_sessionmaker(
        _engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return the session factory. Raises if init_db() was not called."""
    if _session_factory is None:
        raise RuntimeError("Database not initialised — call init_db() first")
    return _session_factory


async def get_db() -> AsyncSession:  # type: ignore[misc]
    """FastAPI dependency: yields a scoped async session."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session  # type: ignore[misc]
            await session.commit()
        except Exception:
            await session.rollback()
            raise
