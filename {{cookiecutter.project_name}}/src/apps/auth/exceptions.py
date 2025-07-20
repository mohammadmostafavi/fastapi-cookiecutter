from src.core.exceptions import (
    NotFoundException,
    ConflictException,
    UnauthorizedException,
)

class UserNotFoundException(NotFoundException):
    """Exception for user not found"""
    error_code = "user_not_found"
    message = "User not found"


class UserAlreadyExistsException(ConflictException):
    """Exception for duplicate user"""
    error_code = "user_already_exists"
    message = "User with this username or email already exists"


class InvalidCredentialsException(UnauthorizedException):
    """Exception for invalid login credentials"""
    error_code = "invalid_credentials"
    message = "Invalid username or password"

