"""
Tests for auth exceptions in src.apps.auth.exceptions.
"""

import pytest
from fastapi import status

from src.apps.auth.exceptions import (
    UserNotFoundException,
    UserAlreadyExistsException,
    InvalidCredentialsException,
)
from src.core.exceptions import (
    NotFoundException,
    ConflictException,
    UnauthorizedException,
)


@pytest.mark.unit
class TestUserNotFoundException:
    """Tests for the UserNotFoundException class."""
    
    def test_inheritance(self):
        """Test that UserNotFoundException inherits from NotFoundException."""
        assert issubclass(UserNotFoundException, NotFoundException)
    
    def test_default_attributes(self):
        """Test that UserNotFoundException has the correct default attributes."""
        exc = UserNotFoundException()
        
        assert exc.error_code == "user_not_found"
        assert exc.message == "User not found"
        assert exc.status_code == status.HTTP_404_NOT_FOUND
    
    def test_custom_message(self):
        """Test that UserNotFoundException accepts a custom message."""
        custom_message = "The specified user could not be found"
        exc = UserNotFoundException(message=custom_message)
        
        assert exc.message == custom_message
        assert exc.error_code == "user_not_found"  # Should not change
    
    def test_custom_details(self):
        """Test that UserNotFoundException accepts custom details."""
        details = {"user_id": 123}
        exc = UserNotFoundException(details=details)
        
        assert exc.details == details
        assert exc.error_code == "user_not_found"
        assert exc.message == "User not found"


@pytest.mark.unit
class TestUserAlreadyExistsException:
    """Tests for the UserAlreadyExistsException class."""
    
    def test_inheritance(self):
        """Test that UserAlreadyExistsException inherits from ConflictException."""
        assert issubclass(UserAlreadyExistsException, ConflictException)
    
    def test_default_attributes(self):
        """Test that UserAlreadyExistsException has the correct default attributes."""
        exc = UserAlreadyExistsException()
        
        assert exc.error_code == "user_already_exists"
        assert exc.message == "User with this username or email already exists"
        assert exc.status_code == status.HTTP_409_CONFLICT
    
    def test_custom_message(self):
        """Test that UserAlreadyExistsException accepts a custom message."""
        custom_message = "A user with this email already exists"
        exc = UserAlreadyExistsException(message=custom_message)
        
        assert exc.message == custom_message
        assert exc.error_code == "user_already_exists"  # Should not change
    
    def test_custom_details(self):
        """Test that UserAlreadyExistsException accepts custom details."""
        details = {"username": "john_doe", "email": "john@example.com"}
        exc = UserAlreadyExistsException(details=details)
        
        assert exc.details == details
        assert exc.error_code == "user_already_exists"
        assert exc.message == "User with this username or email already exists"


@pytest.mark.unit
class TestInvalidCredentialsException:
    """Tests for the InvalidCredentialsException class."""
    
    def test_inheritance(self):
        """Test that InvalidCredentialsException inherits from UnauthorizedException."""
        assert issubclass(InvalidCredentialsException, UnauthorizedException)
    
    def test_default_attributes(self):
        """Test that InvalidCredentialsException has the correct default attributes."""
        exc = InvalidCredentialsException()
        
        assert exc.error_code == "invalid_credentials"
        assert exc.message == "Invalid username or password"
        assert exc.status_code == status.HTTP_401_UNAUTHORIZED
    
    def test_custom_message(self):
        """Test that InvalidCredentialsException accepts a custom message."""
        custom_message = "The provided credentials are incorrect"
        exc = InvalidCredentialsException(message=custom_message)
        
        assert exc.message == custom_message
        assert exc.error_code == "invalid_credentials"  # Should not change
    
    def test_custom_details(self):
        """Test that InvalidCredentialsException accepts custom details."""
        details = {"attempts": 3, "max_attempts": 5}
        exc = InvalidCredentialsException(details=details)
        
        assert exc.details == details
        assert exc.error_code == "invalid_credentials"
        assert exc.message == "Invalid username or password"