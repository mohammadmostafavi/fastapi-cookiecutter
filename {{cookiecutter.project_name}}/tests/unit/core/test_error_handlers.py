"""
Tests for error handlers in src.core.error_handlers.
"""

import pytest
import json
from unittest.mock import MagicMock, patch
from fastapi import Request, status
from fastapi.exceptions import RequestValidationError
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from pydantic import ValidationError, BaseModel

from src.core.error_handlers import (
    app_exception_handler,
    validation_exception_handler,
    sqlalchemy_exception_handler,
    pydantic_validation_exception_handler,
    generic_exception_handler,
    register_exception_handlers,
)
from src.core.exceptions import AppException, BadRequestException, InternalServerException
from src.core.schemas import ErrorResponse


@pytest.mark.unit
@pytest.mark.asyncio
class TestAppExceptionHandler:
    """Tests for the app_exception_handler function."""

    async def test_app_exception_handler_client_error(self):
        """Test handling of client error AppExceptions (4xx)."""
        # Create a mock request
        mock_request = MagicMock(spec=Request)
        
        # Create a client error exception
        exc = BadRequestException(
            message="Invalid input data",
            details={"field": "username", "error": "Username is required"}
        )
        
        # Call the handler
        with patch('src.core.error_handlers.logger') as mock_logger:
            response = await app_exception_handler(mock_request, exc)
        
        # Verify the response
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        
        # Parse the response content
        content = json.loads(response.body.decode())
        assert content["error_code"] == "bad_request"
        assert content["message"] == "Invalid input data"
        assert content["details"] == {"field": "username", "error": "Username is required"}
        
        # Verify logging
        mock_logger.log.assert_called_once()
        args = mock_logger.log.call_args[0]
        assert args[0] == pytest.approx(30)  # WARNING level

    async def test_app_exception_handler_server_error(self):
        """Test handling of server error AppExceptions (5xx)."""
        # Create a mock request
        mock_request = MagicMock(spec=Request)
        
        # Create a server error exception
        exc = InternalServerException(
            message="Database connection failed",
            details={"error": "Connection timeout"}
        )
        
        # Call the handler
        with patch('src.core.error_handlers.logger') as mock_logger:
            response = await app_exception_handler(mock_request, exc)
        
        # Verify the response
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        
        # Parse the response content
        content = json.loads(response.body.decode())
        assert content["error_code"] == "internal_error"
        assert content["message"] == "Database connection failed"
        assert content["details"] == {"error": "Connection timeout"}
        
        # Verify logging
        mock_logger.log.assert_called_once()
        args = mock_logger.log.call_args[0]
        assert args[0] == pytest.approx(40)  # ERROR level


@pytest.mark.unit
@pytest.mark.asyncio
class TestValidationExceptionHandler:
    """Tests for the validation_exception_handler function."""

    async def test_validation_exception_handler(self):
        """Test handling of RequestValidationError."""
        # Create a mock request
        mock_request = MagicMock(spec=Request)
        
        # Create a validation error
        validation_errors = [
            {
                "loc": ["body", "username"],
                "msg": "field required",
                "type": "value_error.missing"
            },
            {
                "loc": ["body", "password"],
                "msg": "field required",
                "type": "value_error.missing"
            }
        ]
        exc = RequestValidationError(errors=validation_errors)
        
        # Call the handler
        with patch('src.core.error_handlers.logger') as mock_logger:
            response = await validation_exception_handler(mock_request, exc)
        
        # Verify the response
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        
        # Parse the response content
        content = json.loads(response.body.decode())
        assert content["error_code"] == "validation_error"
        assert content["message"] == "Request validation error"
        assert len(content["details"]) == 2
        assert content["details"][0]["loc"] == ["body", "username"]
        assert content["details"][0]["msg"] == "field required"
        assert content["details"][0]["type"] == "value_error.missing"
        
        # Verify logging
        mock_logger.warning.assert_called_once()


@pytest.mark.unit
@pytest.mark.asyncio
class TestSQLAlchemyExceptionHandler:
    """Tests for the sqlalchemy_exception_handler function."""

    async def test_sqlalchemy_integrity_error(self):
        """Test handling of SQLAlchemy IntegrityError."""
        # Create a mock request
        mock_request = MagicMock(spec=Request)
        
        # Create an integrity error
        exc = IntegrityError("statement", "params", "orig")
        
        # Call the handler
        with patch('src.core.error_handlers.logger') as mock_logger:
            response = await sqlalchemy_exception_handler(mock_request, exc)
        
        # Verify the response
        assert response.status_code == status.HTTP_409_CONFLICT
        
        # Parse the response content
        content = json.loads(response.body.decode())
        assert content["error_code"] == "integrity_error"
        assert content["message"] == "Database integrity error"
        assert "detail" in content["details"]
        
        # Verify logging
        mock_logger.error.assert_called_once()

    async def test_sqlalchemy_general_error(self):
        """Test handling of general SQLAlchemyError."""
        # Create a mock request
        mock_request = MagicMock(spec=Request)
        
        # Create a general SQLAlchemy error
        exc = SQLAlchemyError("Database error")
        
        # Call the handler
        with patch('src.core.error_handlers.logger') as mock_logger:
            response = await sqlalchemy_exception_handler(mock_request, exc)
        
        # Verify the response
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        
        # Parse the response content
        content = json.loads(response.body.decode())
        assert content["error_code"] == "database_error"
        assert content["message"] == "Database error occurred"
        assert "detail" in content["details"]
        
        # Verify logging
        mock_logger.error.assert_called_once()


@pytest.mark.unit
@pytest.mark.asyncio
class TestPydanticValidationExceptionHandler:
    """Tests for the pydantic_validation_exception_handler function."""

    async def test_pydantic_validation_exception_handler(self):
        """Test handling of Pydantic ValidationError."""
        # Create a mock request
        mock_request = MagicMock(spec=Request)
        
        # Create a Pydantic model and validation error
        class TestModel(BaseModel):
            name: str
            age: int
        
        try:
            TestModel.model_validate({"name": "John", "age": "not_an_int"})
        except ValidationError as e:
            exc = e
        
        # Call the handler
        with patch('src.core.error_handlers.logger') as mock_logger:
            response = await pydantic_validation_exception_handler(mock_request, exc)
        
        # Verify the response
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        
        # Parse the response content
        content = json.loads(response.body.decode())
        assert content["error_code"] == "validation_error"
        assert content["message"] == "Data validation error"
        assert len(content["details"]) > 0
        
        # Verify logging
        mock_logger.warning.assert_called_once()


@pytest.mark.unit
@pytest.mark.asyncio
class TestGenericExceptionHandler:
    """Tests for the generic_exception_handler function."""

    async def test_generic_exception_handler(self):
        """Test handling of generic Exception."""
        # Create a mock request
        mock_request = MagicMock(spec=Request)
        
        # Create a generic exception
        exc = Exception("Something went wrong")
        
        # Call the handler
        with patch('src.core.error_handlers.logger') as mock_logger:
            response = await generic_exception_handler(mock_request, exc)
        
        # Verify the response
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        
        # Parse the response content
        content = json.loads(response.body.decode())
        assert content["error_code"] == "internal_error"
        assert content["message"] == "An unexpected error occurred"
        assert content["details"]["detail"] == "Something went wrong"
        
        # Verify logging
        mock_logger.error.assert_called_once()

    async def test_generic_exception_handler_empty_message(self):
        """Test handling of generic Exception with empty message."""
        # Create a mock request
        mock_request = MagicMock(spec=Request)
        
        # Create a generic exception with empty message
        exc = Exception("")
        
        # Call the handler
        with patch('src.core.error_handlers.logger') as mock_logger:
            response = await generic_exception_handler(mock_request, exc)
        
        # Verify the response
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        
        # Parse the response content
        content = json.loads(response.body.decode())
        assert content["error_code"] == "internal_error"
        assert content["message"] == "An unexpected error occurred"
        assert content["details"] is None
        
        # Verify logging
        mock_logger.error.assert_called_once()


@pytest.mark.unit
class TestRegisterExceptionHandlers:
    """Tests for the register_exception_handlers function."""

    def test_register_exception_handlers(self):
        """Test that exception handlers are registered correctly."""
        # Create a mock FastAPI app
        mock_app = MagicMock()
        
        # Call the function
        register_exception_handlers(mock_app)
        
        # Verify that add_exception_handler was called for each exception type
        assert mock_app.add_exception_handler.call_count == 5
        
        # Verify the exception types and handlers
        calls = mock_app.add_exception_handler.call_args_list
        assert calls[0][0][0] == AppException
        assert calls[0][0][1] == app_exception_handler
        
        assert calls[1][0][0] == RequestValidationError
        assert calls[1][0][1] == validation_exception_handler
        
        assert calls[2][0][0] == SQLAlchemyError
        assert calls[2][0][1] == sqlalchemy_exception_handler
        
        assert calls[3][0][0] == ValidationError
        assert calls[3][0][1] == pydantic_validation_exception_handler
        
        assert calls[4][0][0] == Exception
        assert calls[4][0][1] == generic_exception_handler