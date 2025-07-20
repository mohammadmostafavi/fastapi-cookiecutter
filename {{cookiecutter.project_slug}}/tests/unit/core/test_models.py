"""
Tests for database models in src.core.models.
"""

import pytest
from sqlalchemy import Column, String, create_engine
from sqlalchemy.orm import sessionmaker

from src.core.models import Base, BaseModel


# Create a concrete model class for testing
class TestModel(BaseModel):
    """Test model for testing BaseModel functionality."""
    __tablename__ = "test_models"
    
    name = Column(String(50), nullable=False)
    description = Column(String(200), nullable=True)


@pytest.mark.unit
class TestBaseModel:
    """Tests for the BaseModel class."""
    
    @pytest.fixture
    def setup_database(self):
        """Set up an in-memory SQLite database for testing."""
        # Create an in-memory SQLite database
        engine = create_engine("sqlite:///:memory:")
        
        # Create all tables
        Base.metadata.create_all(engine)
        
        # Create a session factory
        Session = sessionmaker(bind=engine)
        session = Session()
        
        yield session
        
        # Clean up
        session.close()
        Base.metadata.drop_all(engine)
    
    def test_model_initialization(self):
        """Test that a model can be initialized with attributes."""
        model = TestModel(name="Test", description="Test description")
        
        assert model.name == "Test"
        assert model.description == "Test description"
        assert model.id is None  # ID is not set until the model is persisted
        assert model.created_at is None  # created_at is set by the database
        assert model.updated_at is None  # updated_at is set by the database
        assert model.deleted_at is None
    
    def test_model_repr(self):
        """Test the __repr__ method."""
        model = TestModel(id=1, name="Test")
        
        assert repr(model) == "<TestModel 1>"
    
    def test_model_update(self):
        """Test the update method."""
        model = TestModel(name="Test", description="Test description")
        
        # Update the model
        updated_model = model.update(name="Updated", description="Updated description")
        
        # Check that the model was updated
        assert updated_model.name == "Updated"
        assert updated_model.description == "Updated description"
        
        # Check that the update method returns self
        assert updated_model is model
    
    def test_model_update_protected_fields(self):
        """Test that protected fields cannot be updated."""
        model = TestModel(id=1, name="Test")
        
        # Try to update protected fields
        model.update(id=2, created_at="2023-01-01", updated_at="2023-01-01", deleted_at="2023-01-01")
        
        # Check that protected fields were not updated
        assert model.id == 1
        assert model.created_at is None
        assert model.updated_at is None
        assert model.deleted_at is None
    
    def test_model_update_nonexistent_field(self):
        """Test that nonexistent fields are ignored."""
        model = TestModel(name="Test")
        
        # Try to update a nonexistent field
        model.update(nonexistent="value")
        
        # Check that the model was not updated
        assert not hasattr(model, "nonexistent")
    
    def test_model_persistence(self, setup_database):
        """Test that a model can be persisted to the database."""
        session = setup_database
        
        # Create and persist a model
        model = TestModel(name="Test", description="Test description")
        session.add(model)
        session.commit()
        
        # Check that the model was persisted
        assert model.id is not None
        assert model.created_at is not None
        assert model.updated_at is not None
        
        # Retrieve the model from the database
        retrieved_model = session.query(TestModel).filter_by(id=model.id).first()
        
        # Check that the retrieved model has the correct attributes
        assert retrieved_model.id == model.id
        assert retrieved_model.name == "Test"
        assert retrieved_model.description == "Test description"
        assert retrieved_model.created_at == model.created_at
        assert retrieved_model.updated_at == model.updated_at
        assert retrieved_model.deleted_at is None
    
    def test_model_update_persistence(self, setup_database):
        """Test that model updates are persisted to the database."""
        session = setup_database
        
        # Create and persist a model
        model = TestModel(name="Test", description="Test description")
        session.add(model)
        session.commit()
        
        # Update the model
        model.update(name="Updated", description="Updated description")
        session.commit()
        
        # Retrieve the model from the database
        retrieved_model = session.query(TestModel).filter_by(id=model.id).first()
        
        # Check that the retrieved model has the updated attributes
        assert retrieved_model.name == "Updated"
        assert retrieved_model.description == "Updated description"