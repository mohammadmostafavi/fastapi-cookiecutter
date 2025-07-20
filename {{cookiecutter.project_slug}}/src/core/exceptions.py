from typing import Any, Dict, List, Optional, Union
from fastapi import status


class AppException(Exception):
    """
    Base exception class for all application exceptions.
    All custom exceptions should inherit from this class.
    """
    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR
    error_code: str = "internal_error"
    message: str = "An unexpected error occurred"
    
    def __init__(
        self, 
        message: Optional[str] = None, 
        error_code: Optional[str] = None,
        status_code: Optional[int] = None,
        details: Optional[Union[List[Dict[str, Any]], Dict[str, Any]]] = None
    ):
        """
        Initialize the exception with custom values.
        
        Args:
            message: Custom error message
            error_code: Custom error code
            status_code: Custom HTTP status code
            details: Additional error details
        """
        if message is not None:
            self.message = message
        if error_code is not None:
            self.error_code = error_code
        if status_code is not None:
            self.status_code = status_code
        self.details = details
        super().__init__(self.message)


# 4xx Client Errors

class BadRequestException(AppException):
    """Exception for invalid request data"""
    status_code = status.HTTP_400_BAD_REQUEST
    error_code = "bad_request"
    message = "Invalid request data"


class UnauthorizedException(AppException):
    """Exception for authentication failures"""
    status_code = status.HTTP_401_UNAUTHORIZED
    error_code = "unauthorized"
    message = "Authentication required"


class ForbiddenException(AppException):
    """Exception for permission/authorization failures"""
    status_code = status.HTTP_403_FORBIDDEN
    error_code = "forbidden"
    message = "You don't have permission to perform this action"


class NotFoundException(AppException):
    """Exception for resource not found"""
    status_code = status.HTTP_404_NOT_FOUND
    error_code = "not_found"
    message = "Resource not found"


class ConflictException(AppException):
    """Exception for resource conflicts (e.g., duplicate entries)"""
    status_code = status.HTTP_409_CONFLICT
    error_code = "conflict"
    message = "Resource conflict"


class ValidationException(AppException):
    """Exception for validation errors"""
    status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    error_code = "validation_error"
    message = "Validation error"


# 5xx Server Errors

class InternalServerException(AppException):
    """Exception for unexpected server errors"""
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    error_code = "internal_error"
    message = "An unexpected error occurred"


class ServiceUnavailableException(AppException):
    """Exception for service unavailability"""
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    error_code = "service_unavailable"
    message = "Service temporarily unavailable"


class DatabaseException(AppException):
    """Exception for database errors"""
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    error_code = "database_error"
    message = "Database error occurred"


class DatabaseConnectionException(DatabaseException):
    """Exception for database connection errors"""
    error_code = "database_connection_error"
    message = "Database connection error occurred"


class DatabaseRetryableException(DatabaseException):
    """Exception for database errors that can be retried"""
    error_code = "database_retryable_error"
    message = "A retryable database error occurred"



class NotImplementedException(AppException):
    """Exception for not implemented functionality"""
    status_code = status.HTTP_501_NOT_IMPLEMENTED
    error_code = "not_implemented"
    message = "This functionality is not implemented yet"