"""
Tests for auth repositories in src.apps.auth.repositories.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from sqlalchemy import select

from src.apps.auth.repositories import UserRepository, RoleRepository, PermissionRepository
from src.apps.auth.models import User, Role, Permission


@pytest.mark.unit
@pytest.mark.asyncio
class TestUserRepository:
    """Tests for the UserRepository class."""
    
    @pytest.fixture
    def mock_db(self):
        """Create a mock database session."""
        mock_session = AsyncMock()
        return mock_session
    
    @pytest.fixture
    def user_repository(self, mock_db):
        """Create a UserRepository instance with a mock database session."""
        return UserRepository(mock_db)
    
    async def test_init(self, user_repository):
        """Test that UserRepository is initialized correctly."""
        assert user_repository.model_class == User
        assert user_repository._db is not None
    
    async def test_get_by_username_found(self, user_repository, mock_db):
        """Test getting a user by username when the user exists."""
        # Create a mock user
        mock_user = MagicMock(spec=User)
        mock_user.username = "testuser"
        
        # Set up the mock session to return the user
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db.execute.return_value = mock_result
        
        # Call the method
        result = await user_repository.get_by_username("testuser")
        
        # Verify the result
        assert result == mock_user
        
        # Verify the query
        mock_db.execute.assert_called_once()
        query = mock_db.execute.call_args[0][0]
        assert str(query).startswith("SELECT")
        assert "FROM users" in str(query)
        assert "WHERE" in str(query)
        assert "users.username" in str(query)
        assert "users.deleted_at IS NULL" in str(query)
    
    async def test_get_by_username_not_found(self, user_repository, mock_db):
        """Test getting a user by username when the user doesn't exist."""
        # Set up the mock session to return None
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result
        
        # Call the method
        result = await user_repository.get_by_username("nonexistent")
        
        # Verify the result
        assert result is None
        
        # Verify the query
        mock_db.execute.assert_called_once()
    
    async def test_get_by_email_found(self, user_repository, mock_db):
        """Test getting a user by email when the user exists."""
        # Create a mock user
        mock_user = MagicMock(spec=User)
        mock_user.email = "test@example.com"
        
        # Set up the mock session to return the user
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db.execute.return_value = mock_result
        
        # Call the method
        result = await user_repository.get_by_email("test@example.com")
        
        # Verify the result
        assert result == mock_user
        
        # Verify the query
        mock_db.execute.assert_called_once()
        query = mock_db.execute.call_args[0][0]
        assert str(query).startswith("SELECT")
        assert "FROM users" in str(query)
        assert "WHERE" in str(query)
        assert "users.email" in str(query)
        assert "users.deleted_at IS NULL" in str(query)
    
    async def test_get_by_email_not_found(self, user_repository, mock_db):
        """Test getting a user by email when the user doesn't exist."""
        # Set up the mock session to return None
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result
        
        # Call the method
        result = await user_repository.get_by_email("nonexistent@example.com")
        
        # Verify the result
        assert result is None
        
        # Verify the query
        mock_db.execute.assert_called_once()


@pytest.mark.unit
class TestRoleRepository:
    """Tests for the RoleRepository class."""
    
    @pytest.fixture
    def mock_db(self):
        """Create a mock database session."""
        mock_session = AsyncMock()
        return mock_session
    
    @pytest.fixture
    def role_repository(self, mock_db):
        """Create a RoleRepository instance with a mock database session."""
        return RoleRepository(mock_db)
    
    def test_init(self, role_repository):
        """Test that RoleRepository is initialized correctly."""
        assert role_repository.model_class == Role
        assert role_repository._db is not None


@pytest.mark.unit
class TestPermissionRepository:
    """Tests for the PermissionRepository class."""
    
    @pytest.fixture
    def mock_db(self):
        """Create a mock database session."""
        mock_session = AsyncMock()
        return mock_session
    
    @pytest.fixture
    def permission_repository(self, mock_db):
        """Create a PermissionRepository instance with a mock database session."""
        return PermissionRepository(mock_db)
    
    def test_init(self, permission_repository):
        """Test that PermissionRepository is initialized correctly."""
        assert permission_repository.model_class == Permission
        assert permission_repository._db is not None