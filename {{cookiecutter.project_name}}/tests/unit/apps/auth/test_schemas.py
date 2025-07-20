"""
Tests for auth schemas in src.apps.auth.schemas.
"""

import pytest
import json
from pydantic import ValidationError

from src.apps.auth.schemas import (
    UserCreate,
    UserUpdate,
    UserLogin,
    UserResponse,
    Token,
    TokenPayload,
    RefreshToken,
    PasswordResetRequest,
    PasswordResetConfirm,
)


@pytest.mark.unit
class TestUserCreate:
    """Tests for the UserCreate schema."""
    
    def test_valid_user_create(self):
        """Test creating a valid UserCreate instance."""
        user_data = {
            "username": "testuser",
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "password": "Password123!"
        }
        
        user = UserCreate(**user_data)
        
        assert user.username == "testuser"
        assert user.first_name == "Test"
        assert user.last_name == "User"
        assert user.email == "test@example.com"
        assert user.password == "Password123!"
    
    def test_user_create_without_optional_fields(self):
        """Test creating a UserCreate instance without optional fields."""
        user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "Password123!"
        }
        
        user = UserCreate(**user_data)
        
        assert user.username == "testuser"
        assert user.first_name is None
        assert user.last_name is None
        assert user.email == "test@example.com"
        assert user.password == "Password123!"
    
    def test_user_create_invalid_username(self):
        """Test that UserCreate validates username."""
        user_data = {
            "username": "u",  # Too short
            "email": "test@example.com",
            "password": "Password123!"
        }
        
        with pytest.raises(ValidationError) as exc_info:
            UserCreate(**user_data)
        
        errors = exc_info.value.errors()
        assert any(error["loc"] == ("username",) for error in errors)
    
    def test_user_create_invalid_email(self):
        """Test that UserCreate validates email."""
        user_data = {
            "username": "testuser",
            "email": "invalid-email",  # Invalid email format
            "password": "Password123!"
        }
        
        with pytest.raises(ValidationError) as exc_info:
            UserCreate(**user_data)
        
        errors = exc_info.value.errors()
        assert any(error["loc"] == ("email",) for error in errors)
    
    def test_user_create_invalid_password(self):
        """Test that UserCreate validates password."""
        user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "pass"  # Too short
        }
        
        with pytest.raises(ValidationError) as exc_info:
            UserCreate(**user_data)
        
        errors = exc_info.value.errors()
        assert any(error["loc"] == ("password",) for error in errors)
    
    def test_user_create_missing_required_fields(self):
        """Test that UserCreate requires all required fields."""
        user_data = {
            "username": "testuser",
            # Missing email and password
        }
        
        with pytest.raises(ValidationError) as exc_info:
            UserCreate(**user_data)
        
        errors = exc_info.value.errors()
        assert len(errors) == 2
        field_names = [error["loc"][0] for error in errors]
        assert "email" in field_names
        assert "password" in field_names


@pytest.mark.unit
class TestUserUpdate:
    """Tests for the UserUpdate schema."""
    
    def test_valid_user_update_all_fields(self):
        """Test creating a valid UserUpdate instance with all fields."""
        user_data = {
            "username": "testuser",
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "password": "Password123!",
            "is_staff": True,
            "is_active": True,
            "is_superuser": False
        }
        
        user = UserUpdate(**user_data)
        
        assert user.username == "testuser"
        assert user.first_name == "Test"
        assert user.last_name == "User"
        assert user.email == "test@example.com"
        assert user.password == "Password123!"
        assert user.is_staff is True
        assert user.is_active is True
        assert user.is_superuser is False
    
    def test_valid_user_update_partial(self):
        """Test creating a valid UserUpdate instance with partial fields."""
        user_data = {
            "first_name": "Updated",
            "is_staff": True
        }
        
        user = UserUpdate(**user_data)
        
        assert user.username is None
        assert user.first_name == "Updated"
        assert user.last_name is None
        assert user.email is None
        assert user.password is None
        assert user.is_staff is True
        assert user.is_active is None
        assert user.is_superuser is None
    
    def test_user_update_empty(self):
        """Test creating a UserUpdate instance with no fields."""
        user_data = {}
        
        user = UserUpdate(**user_data)
        
        assert user.username is None
        assert user.first_name is None
        assert user.last_name is None
        assert user.email is None
        assert user.password is None
        assert user.is_staff is None
        assert user.is_active is None
        assert user.is_superuser is None
    
    def test_user_update_invalid_fields(self):
        """Test that UserUpdate validates fields when provided."""
        user_data = {
            "username": "u",  # Too short
            "email": "invalid-email",  # Invalid email format
            "password": "pass"  # Too short
        }
        
        with pytest.raises(ValidationError) as exc_info:
            UserUpdate(**user_data)
        
        errors = exc_info.value.errors()
        assert len(errors) == 3
        field_names = [error["loc"][0] for error in errors]
        assert "username" in field_names
        assert "email" in field_names
        assert "password" in field_names


@pytest.mark.unit
class TestUserLogin:
    """Tests for the UserLogin schema."""
    
    def test_valid_user_login(self):
        """Test creating a valid UserLogin instance."""
        login_data = {
            "username": "testuser",
            "password": "Password123!"
        }
        
        login = UserLogin(**login_data)
        
        assert login.username == "testuser"
        assert login.password == "Password123!"
    
    def test_user_login_missing_fields(self):
        """Test that UserLogin requires all fields."""
        login_data = {
            "username": "testuser"
            # Missing password
        }
        
        with pytest.raises(ValidationError) as exc_info:
            UserLogin(**login_data)
        
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert errors[0]["loc"] == ("password",)
    
    def test_user_login_invalid_fields(self):
        """Test that UserLogin validates fields."""
        login_data = {
            "username": "u",  # Too short
            "password": "pass"  # Too short
        }
        
        with pytest.raises(ValidationError) as exc_info:
            UserLogin(**login_data)
        
        errors = exc_info.value.errors()
        assert len(errors) == 2
        field_names = [error["loc"][0] for error in errors]
        assert "username" in field_names
        assert "password" in field_names


@pytest.mark.unit
class TestUserResponse:
    """Tests for the UserResponse schema."""
    
    def test_valid_user_response(self):
        """Test creating a valid UserResponse instance."""
        user_data = {
            "id": 1,
            "username": "testuser",
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "is_staff": True,
            "is_active": True,
            "is_superuser": False
        }
        
        user = UserResponse(**user_data)
        
        assert user.id == 1
        assert user.username == "testuser"
        assert user.first_name == "Test"
        assert user.last_name == "User"
        assert user.email == "test@example.com"
        assert user.is_staff is True
        assert user.is_active is True
        assert user.is_superuser is False
    
    def test_user_response_default_values(self):
        """Test that UserResponse sets default values."""
        user_data = {
            "id": 1,
            "username": "testuser",
            "email": "test@example.com"
        }
        
        user = UserResponse(**user_data)
        
        assert user.id == 1
        assert user.username == "testuser"
        assert user.first_name is None
        assert user.last_name is None
        assert user.email == "test@example.com"
        assert user.is_staff is False  # Default value
        assert user.is_active is True  # Default value
        assert user.is_superuser is False  # Default value
    
    def test_user_response_missing_required_fields(self):
        """Test that UserResponse requires all required fields."""
        user_data = {
            "username": "testuser",
            # Missing id and email
        }
        
        with pytest.raises(ValidationError) as exc_info:
            UserResponse(**user_data)
        
        errors = exc_info.value.errors()
        assert len(errors) == 2
        field_names = [error["loc"][0] for error in errors]
        assert "id" in field_names
        assert "email" in field_names


@pytest.mark.unit
class TestToken:
    """Tests for the Token schema."""
    
    def test_valid_token(self):
        """Test creating a valid Token instance."""
        token_data = {
            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        }
        
        token = Token(**token_data)
        
        assert token.access_token == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        assert token.refresh_token == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        assert token.token_type == "bearer"  # Default value
    
    def test_token_custom_token_type(self):
        """Test creating a Token instance with a custom token type."""
        token_data = {
            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "token_type": "custom"
        }
        
        token = Token(**token_data)
        
        assert token.token_type == "custom"
    
    def test_token_missing_required_fields(self):
        """Test that Token requires all required fields."""
        token_data = {
            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            # Missing refresh_token
        }
        
        with pytest.raises(ValidationError) as exc_info:
            Token(**token_data)
        
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert errors[0]["loc"] == ("refresh_token",)


@pytest.mark.unit
class TestTokenPayload:
    """Tests for the TokenPayload schema."""
    
    def test_valid_token_payload(self):
        """Test creating a valid TokenPayload instance."""
        payload_data = {
            "sub": "123",
            "exp": 1625097600,
            "iat": 1625011200,
            "type": "access",
            "roles": ["admin", "user"],
            "permissions": ["read", "write"]
        }
        
        payload = TokenPayload(**payload_data)
        
        assert payload.sub == "123"
        assert payload.exp == 1625097600
        assert payload.iat == 1625011200
        assert payload.type == "access"
        assert payload.roles == ["admin", "user"]
        assert payload.permissions == ["read", "write"]
    
    def test_token_payload_default_values(self):
        """Test that TokenPayload sets default values."""
        payload_data = {
            "sub": "123",
            "exp": 1625097600,
            "iat": 1625011200,
            "type": "access"
        }
        
        payload = TokenPayload(**payload_data)
        
        assert payload.roles == []  # Default value
        assert payload.permissions == []  # Default value
    
    def test_token_payload_missing_required_fields(self):
        """Test that TokenPayload requires all required fields."""
        payload_data = {
            "sub": "123",
            "exp": 1625097600
            # Missing iat and type
        }
        
        with pytest.raises(ValidationError) as exc_info:
            TokenPayload(**payload_data)
        
        errors = exc_info.value.errors()
        assert len(errors) == 2
        field_names = [error["loc"][0] for error in errors]
        assert "iat" in field_names
        assert "type" in field_names


@pytest.mark.unit
class TestRefreshToken:
    """Tests for the RefreshToken schema."""
    
    def test_valid_refresh_token(self):
        """Test creating a valid RefreshToken instance."""
        token_data = {
            "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        }
        
        token = RefreshToken(**token_data)
        
        assert token.refresh_token == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    
    def test_refresh_token_missing_required_fields(self):
        """Test that RefreshToken requires all required fields."""
        token_data = {}  # Missing refresh_token
        
        with pytest.raises(ValidationError) as exc_info:
            RefreshToken(**token_data)
        
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert errors[0]["loc"] == ("refresh_token",)


@pytest.mark.unit
class TestPasswordResetRequest:
    """Tests for the PasswordResetRequest schema."""
    
    def test_valid_password_reset_request(self):
        """Test creating a valid PasswordResetRequest instance."""
        reset_data = {
            "email": "test@example.com"
        }
        
        reset = PasswordResetRequest(**reset_data)
        
        assert reset.email == "test@example.com"
    
    def test_password_reset_request_invalid_email(self):
        """Test that PasswordResetRequest validates email."""
        reset_data = {
            "email": "invalid-email"  # Invalid email format
        }
        
        with pytest.raises(ValidationError) as exc_info:
            PasswordResetRequest(**reset_data)
        
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert errors[0]["loc"] == ("email",)
    
    def test_password_reset_request_missing_required_fields(self):
        """Test that PasswordResetRequest requires all required fields."""
        reset_data = {}  # Missing email
        
        with pytest.raises(ValidationError) as exc_info:
            PasswordResetRequest(**reset_data)
        
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert errors[0]["loc"] == ("email",)


@pytest.mark.unit
class TestPasswordResetConfirm:
    """Tests for the PasswordResetConfirm schema."""
    
    def test_valid_password_reset_confirm(self):
        """Test creating a valid PasswordResetConfirm instance."""
        confirm_data = {
            "token": "some-reset-token",
            "password": "NewPassword123!"
        }
        
        confirm = PasswordResetConfirm(**confirm_data)
        
        assert confirm.token == "some-reset-token"
        assert confirm.password == "NewPassword123!"
    
    def test_password_reset_confirm_invalid_password(self):
        """Test that PasswordResetConfirm validates password."""
        confirm_data = {
            "token": "some-reset-token",
            "password": "pass"  # Too short
        }
        
        with pytest.raises(ValidationError) as exc_info:
            PasswordResetConfirm(**confirm_data)
        
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert errors[0]["loc"] == ("password",)
    
    def test_password_reset_confirm_missing_required_fields(self):
        """Test that PasswordResetConfirm requires all required fields."""
        confirm_data = {
            "token": "some-reset-token"
            # Missing password
        }
        
        with pytest.raises(ValidationError) as exc_info:
            PasswordResetConfirm(**confirm_data)
        
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert errors[0]["loc"] == ("password",)