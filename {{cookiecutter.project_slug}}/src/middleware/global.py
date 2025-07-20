"""
Request processing middleware.

This module contains middleware components for processing requests and responses.
"""

import time
import logging
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response
from src.constants.auth import MAX_LOGIN_ATTEMPTS, LOGIN_COOLDOWN_MINUTES

# Configure logger
logger = logging.getLogger(__name__)


class RateLimitingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for rate limiting requests.
    
    This is a placeholder implementation. In a real application, this would use
    a cache or database to track request counts.
    """
    
    def __init__(self, app, max_requests: int = MAX_LOGIN_ATTEMPTS, window_seconds: int = LOGIN_COOLDOWN_MINUTES * 60):
        """
        Initialize the middleware.
        
        Args:
            app: The FastAPI application
            max_requests: Maximum number of requests allowed in the time window
            window_seconds: Time window in seconds
        """
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # In a real implementation, this would be a Redis cache or similar
        self._request_counts = {}
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """
        Process the request and apply rate limiting.
        
        Args:
            request: The incoming request
            call_next: The next middleware or route handler
            
        Returns:
            The response from the next middleware or route handler
        """
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        
        # In a real implementation, this would check a distributed cache
        # and increment the request count atomically
        current_count = self._request_counts.get(client_ip, 0)
        
        if current_count >= self.max_requests:
            # Log rate limit exceeded
            logger.warning(f"Rate limit exceeded for {client_ip}")
            
            # Return 429 Too Many Requests
            from fastapi.responses import JSONResponse
            from src.core.schemas import ErrorResponse
            
            error_response = ErrorResponse(
                error_code="rate_limit_exceeded",
                message=f"Rate limit exceeded. Try again in {self.window_seconds} seconds.",
                details={"max_requests": self.max_requests, "window_seconds": self.window_seconds}
            )
            
            return JSONResponse(
                status_code=429,
                content=error_response.model_dump()
            )
        
        # Increment request count
        self._request_counts[client_ip] = current_count + 1
        
        # Process the request
        return await call_next(request)

