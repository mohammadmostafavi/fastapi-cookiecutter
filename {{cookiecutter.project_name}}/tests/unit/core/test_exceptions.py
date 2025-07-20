"""
Tests for custom exceptions in src.core.exceptions.
"""

import pytest
from fastapi import status

from src.core.exceptions import (
    AppException,
    BadRequestException,
    UnauthorizedException,
    ForbiddenException,
    NotFoundException,
    ConflictException,
    ValidationException,
    InternalServerException,
    ServiceUnavailableException,
    DatabaseException,
    DatabaseConnectionException,
    DatabaseRetryableException,
    NotImplementedException,
)


@pytest.mark.unit
class TestAppException:
    """Tests for the base AppException class."""

    def test_default_values(self):
        """Test that AppException has the correct default values."""
        exc = AppException()
        assert exc.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert exc.error_code == "internal_error"
        assert exc.message == "An unexpected error occurred"
        assert exc.details is None
        assert str(exc) == "An unexpected error occurred"

    def test_custom_message(self):
        """Test that AppException accepts a custom message."""
        message = "Custom error message"
        exc = AppException(message=message)
        assert exc.message == message
        assert str(exc) == message

    def test_custom_error_code(self):
        """Test that AppException accepts a custom error code."""
        error_code = "custom_error"
        exc = AppException(error_code=error_code)
        assert exc.error_code == error_code

    def test_custom_status_code(self):
        """Test that AppException accepts a custom status code."""
        status_code = status.HTTP_418_IM_A_TEAPOT
        exc = AppException(status_code=status_code)
        assert exc.status_code == status_code

    def test_custom_details(self):
        """Test that AppException accepts custom details."""
        details = {"field": "value", "error": "Invalid value"}
        exc = AppException(details=details)
        assert exc.details == details

    def test_all_custom_values(self):
        """Test that AppException accepts all custom values."""
        message = "Custom error message"
        error_code = "custom_error"
        status_code = status.HTTP_418_IM_A_TEAPOT
        details = {"field": "value", "error": "Invalid value"}
        
        exc = AppException(
            message=message,
            error_code=error_code,
            status_code=status_code,
            details=details
        )
        
        assert exc.message == message
        assert exc.error_code == error_code
        assert exc.status_code == status_code
        assert exc.details == details
        assert str(exc) == message


@pytest.mark.unit
class TestClientExceptions:
    """Tests for client error exceptions (4xx)."""

    def test_bad_request_exception(self):
        """Test BadRequestException default values."""
        exc = BadRequestException()
        assert exc.status_code == status.HTTP_400_BAD_REQUEST
        assert exc.error_code == "bad_request"
        assert exc.message == "Invalid request data"

    def test_unauthorized_exception(self):
        """Test UnauthorizedException default values."""
        exc = UnauthorizedException()
        assert exc.status_code == status.HTTP_401_UNAUTHORIZED
        assert exc.error_code == "unauthorized"
        assert exc.message == "Authentication required"

    def test_forbidden_exception(self):
        """Test ForbiddenException default values."""
        exc = ForbiddenException()
        assert exc.status_code == status.HTTP_403_FORBIDDEN
        assert exc.error_code == "forbidden"
        assert exc.message == "You don't have permission to perform this action"

    def test_not_found_exception(self):
        """Test NotFoundException default values."""
        exc = NotFoundException()
        assert exc.status_code == status.HTTP_404_NOT_FOUND
        assert exc.error_code == "not_found"
        assert exc.message == "Resource not found"

    def test_conflict_exception(self):
        """Test ConflictException default values."""
        exc = ConflictException()
        assert exc.status_code == status.HTTP_409_CONFLICT
        assert exc.error_code == "conflict"
        assert exc.message == "Resource conflict"

    def test_validation_exception(self):
        """Test ValidationException default values."""
        exc = ValidationException()
        assert exc.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        assert exc.error_code == "validation_error"
        assert exc.message == "Validation error"

    def test_custom_client_exception(self):
        """Test that client exceptions accept custom values."""
        message = "Custom validation error"
        details = [{"field": "username", "error": "Username already exists"}]
        
        exc = ValidationException(message=message, details=details)
        
        assert exc.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        assert exc.error_code == "validation_error"
        assert exc.message == message
        assert exc.details == details


@pytest.mark.unit
class TestServerExceptions:
    """Tests for server error exceptions (5xx)."""

    def test_internal_server_exception(self):
        """Test InternalServerException default values."""
        exc = InternalServerException()
        assert exc.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert exc.error_code == "internal_error"
        assert exc.message == "An unexpected error occurred"

    def test_service_unavailable_exception(self):
        """Test ServiceUnavailableException default values."""
        exc = ServiceUnavailableException()
        assert exc.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        assert exc.error_code == "service_unavailable"
        assert exc.message == "Service temporarily unavailable"

    def test_database_exception(self):
        """Test DatabaseException default values."""
        exc = DatabaseException()
        assert exc.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert exc.error_code == "database_error"
        assert exc.message == "Database error occurred"

    def test_database_connection_exception(self):
        """Test DatabaseConnectionException default values."""
        exc = DatabaseConnectionException()
        assert exc.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert exc.error_code == "database_connection_error"
        assert exc.message == "Database connection error occurred"

    def test_database_retryable_exception(self):
        """Test DatabaseRetryableException default values."""
        exc = DatabaseRetryableException()
        assert exc.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert exc.error_code == "database_retryable_error"
        assert exc.message == "A retryable database error occurred"

    def test_not_implemented_exception(self):
        """Test NotImplementedException default values."""
        exc = NotImplementedException()
        assert exc.status_code == status.HTTP_501_NOT_IMPLEMENTED
        assert exc.error_code == "not_implemented"
        assert exc.message == "This functionality is not implemented yet"

    def test_custom_server_exception(self):
        """Test that server exceptions accept custom values."""
        message = "Custom database error"
        details = {"query": "SELECT * FROM users", "error": "Connection timeout"}
        
        exc = DatabaseException(message=message, details=details)
        
        assert exc.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert exc.error_code == "database_error"
        assert exc.message == message
        assert exc.details == details


@pytest.mark.unit
class TestExceptionInheritance:
    """Tests for exception inheritance."""

    def test_client_exceptions_inherit_from_app_exception(self):
        """Test that client exceptions inherit from AppException."""
        assert issubclass(BadRequestException, AppException)
        assert issubclass(UnauthorizedException, AppException)
        assert issubclass(ForbiddenException, AppException)
        assert issubclass(NotFoundException, AppException)
        assert issubclass(ConflictException, AppException)
        assert issubclass(ValidationException, AppException)

    def test_server_exceptions_inherit_from_app_exception(self):
        """Test that server exceptions inherit from AppException."""
        assert issubclass(InternalServerException, AppException)
        assert issubclass(ServiceUnavailableException, AppException)
        assert issubclass(DatabaseException, AppException)
        assert issubclass(NotImplementedException, AppException)

    def test_database_exceptions_inherit_from_database_exception(self):
        """Test that database-specific exceptions inherit from DatabaseException."""
        assert issubclass(DatabaseConnectionException, DatabaseException)
        assert issubclass(DatabaseRetryableException, DatabaseException)

    def test_exception_instances(self):
        """Test that exception instances are instances of their parent classes."""
        assert isinstance(BadRequestException(), AppException)
        assert isinstance(DatabaseConnectionException(), DatabaseException)
        assert isinstance(DatabaseConnectionException(), AppException)