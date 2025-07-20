from contextlib import asynccontextmanager
from typing import Any, AsyncIterator
import logging

from src.config import settings
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from src.core.models import Base
from src.constants.database import (
    DEFAULT_POOL_SIZE,
    DEFAULT_MAX_OVERFLOW,
    DEFAULT_POOL_TIMEOUT,
    DEFAULT_POOL_RECYCLE,
)
from src.middleware.database import setup_database_monitoring

# Configure logger
logger = logging.getLogger(__name__)


# Heavily inspired by https://praciano.com.br/fastapi-and-async-sqlalchemy-20-with-pytest-done-right.html
class DatabaseSessionManager:
    def __init__(self, host: str, engine_kwargs: dict[str, Any] = {}):
        # Apply default pool settings if not provided in engine_kwargs
        default_engine_kwargs = {
            "pool_size": DEFAULT_POOL_SIZE,
            "max_overflow": DEFAULT_MAX_OVERFLOW,
            "pool_timeout": DEFAULT_POOL_TIMEOUT,
            "pool_recycle": DEFAULT_POOL_RECYCLE,
        }
        # Update with user-provided kwargs (which will override defaults if specified)
        default_engine_kwargs.update(engine_kwargs)
        
        self._engine = create_async_engine(host, **default_engine_kwargs)
        self._sessionmaker = async_sessionmaker(autocommit=False, bind=self._engine, expire_on_commit=False)

    async def close(self):
        if self._engine is None:
            raise Exception("DatabaseSessionManager is not initialized")
        await self._engine.dispose()

        self._engine = None
        self._sessionmaker = None
    async def connect(self) -> None:
        if self._engine is None:
            raise Exception("DatabaseSessionManager is not initialized")

        # Set up database monitoring
        try:
            setup_database_monitoring(self._engine)
            logger.info("Database monitoring set up successfully")
        except Exception as e:
            logger.warning(f"Failed to set up database monitoring: {str(e)}")

        async with self._engine.begin() as connection:
            try:
                if settings.debug:
                    await connection.run_sync(Base.metadata.create_all)
            except Exception:
                await connection.rollback()
                raise

    async def session(self) -> AsyncIterator[AsyncSession]:
        if self._sessionmaker is None:
            raise Exception("DatabaseSessionManager is not initialized")

        session = self._sessionmaker()
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


sessionmanager = DatabaseSessionManager(settings.db_url, {"echo": settings.echo_sql})


async def get_session()-> AsyncIterator[AsyncSession]:
    async for session in sessionmanager.session():
        yield session