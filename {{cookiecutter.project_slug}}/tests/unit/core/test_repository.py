"""
Tests for the Repository class in src.core.repository.
"""

import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from sqlalchemy import Column, String, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError

from src.core.models import BaseModel
from src.core.repository import Repository
from src.core.exceptions import DatabaseException


# Create a test model for testing the repository
class TestModel(BaseModel):
    """Test model for testing the Repository class."""
    __tablename__ = "test_models"
    
    name = Column(String(50), nullable=False)
    description = Column(String(200), nullable=True)


@pytest.mark.unit
@pytest.mark.asyncio
class TestRepository:
    """Tests for the Repository class."""
    
    @pytest.fixture
    def mock_db(self):
        """Create a mock database session."""
        mock_session = AsyncMock(spec=AsyncSession)
        return mock_session
    
    @pytest.fixture
    def repository(self, mock_db):
        """Create a repository instance with a mock database session."""
        return Repository(mock_db, TestModel)
    
    async def test_create_success(self, repository, mock_db):
        """Test creating a model instance successfully."""
        # Set up the mock
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        
        # Call the method
        result = await repository.create(name="Test", description="Test description")
        
        # Verify the result
        assert isinstance(result, TestModel)
        assert result.name == "Test"
        assert result.description == "Test description"
        
        # Verify the mock was called
        mock_db.add.assert_called_once()
        mock_db.commit.assert_called_once()
        mock_db.refresh.assert_called_once()
    
    async def test_create_failure(self, repository, mock_db):
        """Test handling of database errors when creating a model instance."""
        # Set up the mock to raise an exception
        mock_db.commit = AsyncMock(side_effect=SQLAlchemyError("Database error"))
        
        # Call the method and check for exception
        with pytest.raises(DatabaseException) as exc_info:
            await repository.create(name="Test")
        
        # Verify the exception
        assert "Failed to create TestModel" in str(exc_info.value)
        
        # Verify the mock was called
        mock_db.add.assert_called_once()
        mock_db.commit.assert_called_once()
    
    async def test_get_by_id(self, repository, mock_db):
        """Test getting a model instance by ID."""
        # Create a mock result
        mock_model = TestModel(id=1, name="Test")
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_model
        
        # Set up the mock
        mock_db.execute = AsyncMock(return_value=mock_result)
        
        # Call the method
        result = await repository.get_by_id(1)
        
        # Verify the result
        assert result == mock_model
        
        # Verify the mock was called with the correct query
        mock_db.execute.assert_called_once()
        query = mock_db.execute.call_args[0][0]
        assert str(query).startswith("SELECT")
        assert "FROM test_models" in str(query)
        assert "WHERE" in str(query)
        assert "test_models.id = :id_1" in str(query)
        assert "test_models.deleted_at IS NULL" in str(query)
    
    async def test_get_all(self, repository, mock_db):
        """Test getting all model instances."""
        # Create mock results
        mock_models = [
            TestModel(id=1, name="Test 1"),
            TestModel(id=2, name="Test 2")
        ]
        mock_result = MagicMock()
        mock_result.scalars().all.return_value = mock_models
        
        # Set up the mock
        mock_db.execute = AsyncMock(return_value=mock_result)
        
        # Call the method
        result = await repository.get_all()
        
        # Verify the result
        assert result == mock_models
        
        # Verify the mock was called with the correct query
        mock_db.execute.assert_called_once()
        query = mock_db.execute.call_args[0][0]
        assert str(query).startswith("SELECT")
        assert "FROM test_models" in str(query)
        assert "WHERE" in str(query)
        assert "test_models.deleted_at IS NULL" in str(query)
    
    async def test_filter(self, repository, mock_db):
        """Test filtering model instances by attributes."""
        # Create mock results
        mock_models = [TestModel(id=1, name="Test", description="Matching description")]
        mock_result = MagicMock()
        mock_result.scalars().all.return_value = mock_models
        
        # Set up the mock
        mock_db.execute = AsyncMock(return_value=mock_result)
        
        # Call the method
        result = await repository.filter(mock_db, name="Test", description="Matching description")
        
        # Verify the result
        assert result == mock_models
        
        # Verify the mock was called with the correct query
        mock_db.execute.assert_called_once()
        query = mock_db.execute.call_args[0][0]
        assert str(query).startswith("SELECT")
        assert "FROM test_models" in str(query)
        assert "WHERE" in str(query)
        assert "test_models.name = :name_1" in str(query)
        assert "test_models.description = :description_1" in str(query)
        assert "test_models.deleted_at IS NULL" in str(query)
    
    async def test_update_success(self, repository, mock_db):
        """Test updating a model instance successfully."""
        # Create a mock model
        mock_model = TestModel(id=1, name="Test", description="Old description")
        
        # Set up the mock
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        
        # Call the method
        result = await repository.update(mock_model, name="Updated", description="New description")
        
        # Verify the result
        assert result == mock_model
        assert result.name == "Updated"
        assert result.description == "New description"
        
        # Verify the mock was called
        mock_db.add.assert_called_once_with(mock_model)
        mock_db.commit.assert_called_once()
        mock_db.refresh.assert_called_once_with(mock_model)
    
    async def test_update_failure(self, repository, mock_db):
        """Test handling of database errors when updating a model instance."""
        # Create a mock model
        mock_model = TestModel(id=1, name="Test")
        
        # Set up the mock to raise an exception
        mock_db.commit = AsyncMock(side_effect=SQLAlchemyError("Database error"))
        
        # Call the method and check for exception
        with pytest.raises(DatabaseException) as exc_info:
            await repository.update(mock_model, name="Updated")
        
        # Verify the exception
        assert "Failed to update TestModel" in str(exc_info.value)
        
        # Verify the mock was called
        mock_db.add.assert_called_once_with(mock_model)
        mock_db.commit.assert_called_once()
    
    async def test_delete_success(self, repository, mock_db):
        """Test soft deleting a model instance successfully."""
        # Create a mock model
        mock_model = TestModel(id=1, name="Test", deleted_at=None)
        
        # Set up the mock
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        
        # Call the method
        result = await repository.delete(mock_model)
        
        # Verify the result
        assert result == mock_model
        assert result.deleted_at is not None  # Should be set to func.now()
        
        # Verify the mock was called
        mock_db.add.assert_called_once_with(mock_model)
        mock_db.commit.assert_called_once()
        mock_db.refresh.assert_called_once_with(mock_model)
    
    async def test_delete_failure(self, repository, mock_db):
        """Test handling of database errors when deleting a model instance."""
        # Create a mock model
        mock_model = TestModel(id=1, name="Test")
        
        # Set up the mock to raise an exception
        mock_db.commit = AsyncMock(side_effect=SQLAlchemyError("Database error"))
        
        # Call the method and check for exception
        with pytest.raises(DatabaseException) as exc_info:
            await repository.delete(mock_model)
        
        # Verify the exception
        assert "Failed to delete TestModel" in str(exc_info.value)
        
        # Verify the mock was called
        mock_db.add.assert_called_once_with(mock_model)
        mock_db.commit.assert_called_once()
    
    async def test_restore_success(self, repository, mock_db):
        """Test restoring a soft-deleted model instance successfully."""
        # Create a mock model with deleted_at set
        mock_model = TestModel(id=1, name="Test", deleted_at="2023-01-01")
        
        # Set up the mock
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        
        # Call the method
        result = await repository.restore(mock_model)
        
        # Verify the result
        assert result == mock_model
        assert result.deleted_at is None
        
        # Verify the mock was called
        mock_db.add.assert_called_once_with(mock_model)
        mock_db.commit.assert_called_once()
        mock_db.refresh.assert_called_once_with(mock_model)
    
    async def test_restore_failure(self, repository, mock_db):
        """Test handling of database errors when restoring a model instance."""
        # Create a mock model
        mock_model = TestModel(id=1, name="Test", deleted_at="2023-01-01")
        
        # Set up the mock to raise an exception
        mock_db.commit = AsyncMock(side_effect=SQLAlchemyError("Database error"))
        
        # Call the method and check for exception
        with pytest.raises(DatabaseException) as exc_info:
            await repository.restore(mock_model)
        
        # Verify the exception
        assert "Failed to restore TestModel" in str(exc_info.value)
        
        # Verify the mock was called
        mock_db.add.assert_called_once_with(mock_model)
        mock_db.commit.assert_called_once()
    
    async def test_hard_delete_success(self, repository, mock_db):
        """Test hard deleting a model instance successfully."""
        # Create a mock model
        mock_model = TestModel(id=1, name="Test")
        
        # Set up the mock
        mock_db.delete = AsyncMock()
        mock_db.commit = AsyncMock()
        
        # Call the method
        await repository.hard_delete(mock_model)
        
        # Verify the mock was called
        mock_db.delete.assert_called_once_with(mock_model)
        mock_db.commit.assert_called_once()
    
    async def test_hard_delete_failure(self, repository, mock_db):
        """Test handling of database errors when hard deleting a model instance."""
        # Create a mock model
        mock_model = TestModel(id=1, name="Test")
        
        # Set up the mock to raise an exception
        mock_db.delete = AsyncMock()
        mock_db.commit = AsyncMock(side_effect=SQLAlchemyError("Database error"))
        
        # Call the method and check for exception
        with pytest.raises(DatabaseException) as exc_info:
            await repository.hard_delete(mock_model)
        
        # Verify the exception
        assert "Failed to hard delete TestModel" in str(exc_info.value)
        
        # Verify the mock was called
        mock_db.delete.assert_called_once_with(mock_model)
        mock_db.commit.assert_called_once()