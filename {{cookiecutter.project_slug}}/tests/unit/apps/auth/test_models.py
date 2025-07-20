"""
Tests for auth models in src.apps.auth.models.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.core.models import Base
from src.core.utils import check_password
from src.apps.auth.models import User, Role, Permission


@pytest.mark.unit
class TestAuthModels:
    """Tests for the auth models."""
    
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
    
    def test_permission_model(self, setup_database):
        """Test the Permission model."""
        session = setup_database
        
        # Create a permission
        permission = Permission(name="Can view users", codename="view_users")
        session.add(permission)
        session.commit()
        
        # Retrieve the permission
        retrieved_permission = session.query(Permission).filter_by(codename="view_users").first()
        
        # Verify the permission
        assert retrieved_permission is not None
        assert retrieved_permission.name == "Can view users"
        assert retrieved_permission.codename == "view_users"
        assert retrieved_permission.id is not None
    
    def test_role_model(self, setup_database):
        """Test the Role model."""
        session = setup_database
        
        # Create permissions
        view_permission = Permission(name="Can view users", codename="view_users")
        edit_permission = Permission(name="Can edit users", codename="edit_users")
        session.add_all([view_permission, edit_permission])
        session.commit()
        
        # Create a role with permissions
        role = Role(name="Editor")
        role.permissions = [view_permission, edit_permission]
        session.add(role)
        session.commit()
        
        # Retrieve the role
        retrieved_role = session.query(Role).filter_by(name="Editor").first()
        
        # Verify the role
        assert retrieved_role is not None
        assert retrieved_role.name == "Editor"
        assert retrieved_role.id is not None
        assert len(retrieved_role.permissions) == 2
        assert any(p.codename == "view_users" for p in retrieved_role.permissions)
        assert any(p.codename == "edit_users" for p in retrieved_role.permissions)
    
    def test_user_model(self, setup_database):
        """Test the User model."""
        session = setup_database
        
        # Create a user
        user = User(
            username="testuser",
            first_name="Test",
            last_name="User",
            email="test@example.com",
            password="password123",
            is_staff=1,
            is_active=1,
            is_superuser=0
        )
        session.add(user)
        session.commit()
        
        # Retrieve the user
        retrieved_user = session.query(User).filter_by(username="testuser").first()
        
        # Verify the user
        assert retrieved_user is not None
        assert retrieved_user.username == "testuser"
        assert retrieved_user.first_name == "Test"
        assert retrieved_user.last_name == "User"
        assert retrieved_user.email == "test@example.com"
        assert retrieved_user.is_staff == 1
        assert retrieved_user.is_active == 1
        assert retrieved_user.is_superuser == 0
        assert retrieved_user.id is not None
        assert retrieved_user.roles == []
        assert retrieved_user.permissions == []
    
    def test_user_with_roles_and_permissions(self, setup_database):
        """Test a user with roles and permissions."""
        session = setup_database
        
        # Create permissions
        view_permission = Permission(name="Can view users", codename="view_users")
        edit_permission = Permission(name="Can edit users", codename="edit_users")
        delete_permission = Permission(name="Can delete users", codename="delete_users")
        session.add_all([view_permission, edit_permission, delete_permission])
        
        # Create roles
        editor_role = Role(name="Editor")
        editor_role.permissions = [view_permission, edit_permission]
        admin_role = Role(name="Admin")
        admin_role.permissions = [view_permission, edit_permission, delete_permission]
        session.add_all([editor_role, admin_role])
        
        # Create a user with roles and direct permissions
        user = User(
            username="adminuser",
            email="admin@example.com",
            password="password123"
        )
        user.roles = [editor_role, admin_role]
        user.permissions = [delete_permission]  # Direct permission
        session.add(user)
        session.commit()
        
        # Retrieve the user
        retrieved_user = session.query(User).filter_by(username="adminuser").first()
        
        # Verify the user's roles and permissions
        assert retrieved_user is not None
        assert len(retrieved_user.roles) == 2
        assert any(r.name == "Editor" for r in retrieved_user.roles)
        assert any(r.name == "Admin" for r in retrieved_user.roles)
        assert len(retrieved_user.permissions) == 1
        assert retrieved_user.permissions[0].codename == "delete_users"
        
        # Verify role permissions
        editor_role = next(r for r in retrieved_user.roles if r.name == "Editor")
        assert len(editor_role.permissions) == 2
        assert any(p.codename == "view_users" for p in editor_role.permissions)
        assert any(p.codename == "edit_users" for p in editor_role.permissions)
    
    def test_user_update_method(self, setup_database):
        """Test the User.update method."""
        session = setup_database
        
        # Create a user
        user = User(
            username="updateuser",
            first_name="Update",
            last_name="User",
            email="update@example.com",
            password="password123"
        )
        session.add(user)
        session.commit()
        
        # Update the user
        user.update(
            first_name="Updated",
            last_name="Name",
            is_staff=1
        )
        session.commit()
        
        # Retrieve the user
        retrieved_user = session.query(User).filter_by(username="updateuser").first()
        
        # Verify the updates
        assert retrieved_user.first_name == "Updated"
        assert retrieved_user.last_name == "Name"
        assert retrieved_user.is_staff == 1
        assert retrieved_user.email == "update@example.com"  # Should not change
    
    def test_user_update_password(self, setup_database):
        """Test updating a user's password."""
        session = setup_database
        
        # Create a user
        user = User(
            username="passworduser",
            email="password@example.com",
            password="password123"
        )
        session.add(user)
        session.commit()
        
        # Get the original password hash
        original_password = user.password
        
        # Update the password
        user.update(password="newpassword456")
        session.commit()
        
        # Retrieve the user
        retrieved_user = session.query(User).filter_by(username="passworduser").first()
        
        # Verify the password was updated and hashed
        assert retrieved_user.password != original_password
        assert retrieved_user.password != "newpassword456"  # Should be hashed
        assert check_password("newpassword456", retrieved_user.password)
    
    def test_user_update_roles(self, setup_database):
        """Test updating a user's roles."""
        session = setup_database
        
        # Create roles
        editor_role = Role(name="Editor")
        admin_role = Role(name="Admin")
        session.add_all([editor_role, admin_role])
        
        # Create a user
        user = User(
            username="roleuser",
            email="role@example.com",
            password="password123"
        )
        user.roles = [editor_role]
        session.add(user)
        session.commit()
        
        # Update the user's roles
        user.update(roles=[admin_role])
        session.commit()
        
        # Retrieve the user
        retrieved_user = session.query(User).filter_by(username="roleuser").first()
        
        # Verify the roles were updated
        assert len(retrieved_user.roles) == 1
        assert retrieved_user.roles[0].name == "Admin"
    
    def test_user_update_permissions(self, setup_database):
        """Test updating a user's permissions."""
        session = setup_database
        
        # Create permissions
        view_permission = Permission(name="Can view users", codename="view_users")
        edit_permission = Permission(name="Can edit users", codename="edit_users")
        session.add_all([view_permission, edit_permission])
        
        # Create a user
        user = User(
            username="permuser",
            email="perm@example.com",
            password="password123"
        )
        user.permissions = [view_permission]
        session.add(user)
        session.commit()
        
        # Update the user's permissions
        user.update(permissions=[edit_permission])
        session.commit()
        
        # Retrieve the user
        retrieved_user = session.query(User).filter_by(username="permuser").first()
        
        # Verify the permissions were updated
        assert len(retrieved_user.permissions) == 1
        assert retrieved_user.permissions[0].codename == "edit_users"
    
    def test_user_update_protected_fields(self, setup_database):
        """Test that protected fields cannot be updated."""
        session = setup_database
        
        # Create a user
        user = User(
            username="protecteduser",
            email="protected@example.com",
            password="password123"
        )
        session.add(user)
        session.commit()
        
        # Try to update protected fields
        user.update(
            username="newusername",
            email="newemail@example.com",
            id=999,
            created_at="2023-01-01",
            updated_at="2023-01-01",
            deleted_at="2023-01-01"
        )
        session.commit()
        
        # Retrieve the user
        retrieved_user = session.query(User).filter_by(id=user.id).first()
        
        # Verify protected fields were not updated
        assert retrieved_user.username == "protecteduser"  # Should not change
        assert retrieved_user.email == "protected@example.com"  # Should not change
        assert retrieved_user.id != 999  # Should not change