import logging
from typing import Union, Dict, Any

from fastapi import Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from pydantic import ValidationError

from src.core.exceptions import AppException
from src.core.schemas import ErrorResponse, ErrorDetail

# Configure logger
logger = logging.getLogger(__name__)


async def app_exception_handler(request: Request, exc: AppException) -> JSONResponse:
    """
    Handler for custom application exceptions.
    Converts AppException to a standardized error response.
    """
    # Log the exception
    log_level = logging.ERROR if exc.status_code >= 500 else logging.WARNING
    logger.log(
        log_level,
        f"AppException: {exc.error_code} - {exc.message}",
        exc_info=True if exc.status_code >= 500 else False
    )
    
    # Create error response
    error_response = ErrorResponse(
        error_code=exc.error_code,
        message=exc.message,
        details=exc.details
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content=error_response.model_dump()
    )


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """
    Handler for request validation exceptions.
    Converts validation errors to a standardized error response.
    """
    # Log the exception
    logger.warning(f"Validation error: {str(exc)}")
    
    # Convert validation errors to ErrorDetail objects
    details = []
    for error in exc.errors():
        details.append(
            ErrorDetail(
                loc=error.get("loc", []),
                msg=error.get("msg", ""),
                type=error.get("type", "")
            )
        )
    
    # Create error response
    error_response = ErrorResponse(
        error_code="validation_error",
        message="Request validation error",
        details=details
    )
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=error_response.model_dump()
    )


async def sqlalchemy_exception_handler(request: Request, exc: SQLAlchemyError) -> JSONResponse:
    """
    Handler for SQLAlchemy exceptions.
    Converts database errors to a standardized error response.
    """
    # Log the exception
    logger.error(f"Database error: {str(exc)}", exc_info=True)
    
    # Determine the error type
    if isinstance(exc, IntegrityError):
        error_code = "integrity_error"
        message = "Database integrity error"
        status_code = status.HTTP_409_CONFLICT
    else:
        error_code = "database_error"
        message = "Database error occurred"
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    
    # Create error response
    error_response = ErrorResponse(
        error_code=error_code,
        message=message,
        details={"detail": str(exc)}
    )
    
    return JSONResponse(
        status_code=status_code,
        content=error_response.model_dump()
    )


async def pydantic_validation_exception_handler(request: Request, exc: ValidationError) -> JSONResponse:
    """
    Handler for Pydantic validation exceptions.
    Converts validation errors to a standardized error response.
    """
    # Log the exception
    logger.warning(f"Pydantic validation error: {str(exc)}")
    
    # Convert validation errors to ErrorDetail objects
    details = []
    for error in exc.errors():
        details.append(
            ErrorDetail(
                loc=error.get("loc", []),
                msg=error.get("msg", ""),
                type=error.get("type", "")
            )
        )
    
    # Create error response
    error_response = ErrorResponse(
        error_code="validation_error",
        message="Data validation error",
        details=details
    )
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=error_response.model_dump()
    )


async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Handler for all other exceptions.
    Converts any unhandled exception to a standardized error response.
    """
    # Log the exception
    logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)
    
    # Create error response
    error_response = ErrorResponse(
        error_code="internal_error",
        message="An unexpected error occurred",
        details={"detail": str(exc)} if str(exc) else None
    )
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=error_response.model_dump()
    )


def register_exception_handlers(app):
    """
    Register all exception handlers with the FastAPI application.
    """
    # Register handlers for custom exceptions
    app.add_exception_handler(AppException, app_exception_handler)
    
    # Register handlers for standard exceptions
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(SQLAlchemyError, sqlalchemy_exception_handler)
    app.add_exception_handler(ValidationError, pydantic_validation_exception_handler)
    
    # Register handler for all other exceptions
    app.add_exception_handler(Exception, generic_exception_handler)