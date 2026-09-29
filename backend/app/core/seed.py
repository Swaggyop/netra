"""
NETRA — Database seed script.

Usage: python -m backend.app.core.seed

Seeds:
1. Source registry (all approved sources)
2. Default admin user
"""

from __future__ import annotations

import asyncio
import uuid

from backend.app.config import get_settings
from backend.app.core.registry import seed_sources
from backend.app.core.security import hash_password
from backend.app.models.actors import User
from backend.app.models.base import get_session_factory, init_db


async def seed() -> None:
    """Run all seed operations."""
    settings = get_settings()
    init_db(settings.database_url)

    factory = get_session_factory()
    async with factory() as session:
        # Seed sources
        count = await seed_sources(session)
        print(f"Sources seeded: {count}")

        # Seed default admin (only if no users exist)
        from sqlalchemy import select, func
        result = await session.execute(select(func.count()).select_from(User))
        user_count = result.scalar()

        if user_count == 0:
            admin = User(
                user_id=str(uuid.uuid4()),
                username="admin",
                hashed_password=hash_password("admin_changeme"),  # CHANGE IN PRODUCTION
                role="admin",
            )
            session.add(admin)
            await session.commit()
            print("Default admin user created (username: admin, password: admin_changeme)")
            print("WARNING: CHANGE THIS PASSWORD IMMEDIATELY IN PRODUCTION")
        else:
            print(f"Users already exist ({user_count}), skipping admin seed")


if __name__ == "__main__":
    asyncio.run(seed())
