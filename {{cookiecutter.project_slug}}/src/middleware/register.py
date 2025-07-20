"""
Middleware registration module.

This module provides functions for registering all middleware components with the FastAPI application.
"""

from fastapi import FastAPI
from src.middleware.error_handlers import register_exception_handlers
from src.apps.logs.middlewares import RequestLoggingMiddleware
from src.middleware.authorization import RoleBasedMiddleware
from src.middleware.security import add_cors_middleware, add_security_headers_middleware
from src.core.validation import OutputSanitizationMiddleware


def register_middleware(app: FastAPI) -> None:
    """
    Register all middleware components with the FastAPI application.
    
    Args:
        app: The FastAPI application
    """
    # Register exception handlers
    register_exception_handlers(app)

    # Add security headers middleware
    add_security_headers_middleware(app)
    
    # Add CORS middleware
    add_cors_middleware(app)

    # Add request logging middleware
    app.add_middleware(RequestLoggingMiddleware)
    
    # Add role-based authorization middleware
    app.add_middleware(RoleBasedMiddleware)
    
    # Add output sanitization middleware
    # This should be added last to ensure it processes the response just before it's sent to the client
    app.add_middleware(OutputSanitizationMiddleware)

    # Add rate limiting middleware
    # Commented out for now, as it's just a placeholder implementation
    # app.add_middleware(RateLimitingMiddleware, max_requests=MAX_LOGIN_ATTEMPTS, window_seconds=LOGIN_COOLDOWN_MINUTES * 60)