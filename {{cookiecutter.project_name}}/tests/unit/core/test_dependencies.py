"""
Tests for dependency injection in src.core.dependencies.
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.dependencies import (
    DependencyContainer,
    container,
    get_repository,
    get_service,
)
from src.core.repository import Repository
from src.database import get_session


@pytest.mark.unit
class TestDependencyContainer:
    """Tests for the DependencyContainer class."""
    
    def test_register_and_get(self):
        """Test registering and retrieving a dependency."""
        # Create a container
        container = DependencyContainer()
        
        # Create a mock dependency
        mock_dependency = MagicMock()
        
        # Register the dependency
        container.register("test_dependency", mock_dependency)
        
        # Get the dependency
        retrieved_dependency = container.get("test_dependency")
        
        # Verify the dependency was retrieved correctly
        assert retrieved_dependency is mock_dependency
    
    def test_register_factory(self):
        """Test registering and using a factory function."""
        # Create a container
        container = DependencyContainer()
        
        # Create a mock dependency and factory
        mock_dependency = MagicMock()
        mock_factory = MagicMock(return_value=mock_dependency)
        
        # Register the factory
        container.register_factory("test_factory", mock_factory)
        
        # Get the dependency
        retrieved_dependency = container.get("test_factory")
        
        # Verify the factory was called and the dependency was retrieved
        mock_factory.assert_called_once()
        assert retrieved_dependency is mock_dependency
    
    def test_factory_caching(self):
        """Test that factory-created dependencies are cached."""
        # Create a container
        container = DependencyContainer()
        
        # Create a mock dependency and factory
        mock_dependency = MagicMock()
        mock_factory = MagicMock(return_value=mock_dependency)
        
        # Register the factory
        container.register_factory("test_factory", mock_factory)
        
        # Get the dependency twice
        first_retrieval = container.get("test_factory")
        second_retrieval = container.get("test_factory")
        
        # Verify the factory was called only once and both retrievals return the same instance
        mock_factory.assert_called_once()
        assert first_retrieval is second_retrieval
    
    def test_dependency_not_found(self):
        """Test that KeyError is raised when a dependency is not found."""
        # Create a container
        container = DependencyContainer()
        
        # Try to get a non-existent dependency
        with pytest.raises(KeyError) as exc_info:
            container.get("non_existent")
        
        # Verify the error message
        assert "Dependency 'non_existent' not found in container" in str(exc_info.value)


@pytest.mark.unit
class TestRepositoryFactory:
    """Tests for the get_repository factory function."""
    
    def test_get_repository(self):
        """Test that get_repository returns a function that creates a repository."""
        # Create a mock repository class
        class MockRepository:
            def __init__(self, session):
                self.session = session
        
        # Create the factory function
        repository_factory = get_repository(MockRepository)
        
        # Verify the factory function has the correct signature
        assert repository_factory.__annotations__["session"] == AsyncSession
        
        # Create a mock session
        mock_session = MagicMock(spec=AsyncSession)
        
        # Call the factory function
        repository = repository_factory(mock_session)
        
        # Verify the repository was created with the session
        assert isinstance(repository, MockRepository)
        assert repository.session is mock_session


@pytest.mark.unit
class TestServiceFactory:
    """Tests for the get_service factory function."""
    
    def test_get_service(self):
        """Test that get_service returns a function that creates a service."""
        # Create a mock service class
        class MockService:
            def __init__(self, session):
                self.session = session
        
        # Create the factory function
        service_factory = get_service(MockService)
        
        # Verify the factory function has the correct signature
        assert service_factory.__annotations__["session"] == AsyncSession
        
        # Create a mock session
        mock_session = MagicMock(spec=AsyncSession)
        
        # Call the factory function
        service = service_factory(mock_session)
        
        # Verify the service was created with the session
        assert isinstance(service, MockService)
        assert service.session is mock_session


@pytest.mark.unit
class TestGlobalContainer:
    """Tests for the global container instance."""
    
    def test_global_container_exists(self):
        """Test that the global container exists."""
        assert container is not None
        assert isinstance(container, DependencyContainer)