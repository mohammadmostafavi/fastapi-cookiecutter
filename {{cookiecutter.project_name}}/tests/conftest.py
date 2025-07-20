"""
Common test fixtures and configuration for all tests.
"""

import asyncio
import pytest
import pytest_asyncio
from typing import AsyncGenerator, Generator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import AsyncClient

from src.config import settings
from src.core.models import Base
from src.database import get_session
from src.main import app as main_app
from src.middleware.register import register_middleware
from src.celery import celery_app


# Test database URL - use SQLite in-memory for tests
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

# Configure Celery for testing
@pytest.fixture(scope="session", autouse=True)
def configure_celery():
    """
    Configure Celery for testing.
    
    This fixture configures Celery to run tasks synchronously during tests.
    It is automatically used for all tests.
    """
    # Configure Celery to run tasks synchronously
    celery_app.conf.update(
        task_always_eager=True,
        task_eager_propagates=True,
        broker_url='memory://',
        backend='memory://'
    )
    
    return celery_app


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """
    Create an instance of the default event loop for each test case.
    This is needed for pytest-asyncio.
    """
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session")
async def test_engine():
    """
    Create a test database engine.
    """
    engine = create_async_engine(
        TEST_DATABASE_URL,
        poolclass=NullPool,
        echo=False,
    )
    
    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield engine
    
    # Drop all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    
    # Dispose of the engine
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def test_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """
    Create a test database session.
    """
    # Create a session factory
    session_factory = async_sessionmaker(
        bind=test_engine,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )
    
    # Create a session
    async with session_factory() as session:
        yield session
        # Roll back any changes made during the test
        await session.rollback()


@pytest.fixture(scope="function")
def test_app(test_session) -> FastAPI:
    """
    Create a test FastAPI application.
    """
    # Create a test app with the test database session
    app = FastAPI()
    
    # Register middleware
    register_middleware(app)
    
    # Override the get_session dependency
    async def override_get_session():
        yield test_session
    
    app.dependency_overrides[get_session] = override_get_session
    
    return app


@pytest.fixture(scope="function")
def test_client(test_app) -> TestClient:
    """
    Create a test client for the FastAPI application.
    """
    return TestClient(test_app)


@pytest_asyncio.fixture(scope="function")
async def async_test_client(test_app) -> AsyncGenerator[AsyncClient, None]:
    """
    Create an async test client for the FastAPI application.
    """
    async with AsyncClient(app=test_app, base_url="http://test") as client:
        yield client


@pytest.fixture(scope="function")
def app_client() -> TestClient:
    """
    Create a test client for the main FastAPI application.
    """
    return TestClient(main_app)


@pytest_asyncio.fixture(scope="function")
async def async_app_client() -> AsyncGenerator[AsyncClient, None]:
    """
    Create an async test client for the main FastAPI application.
    """
    async with AsyncClient(app=main_app, base_url="http://test") as client:
        yield client