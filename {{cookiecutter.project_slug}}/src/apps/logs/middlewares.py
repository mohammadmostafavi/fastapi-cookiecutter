import time
import logging
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

# Configure logger
logger = logging.getLogger(__name__)
class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for logging request information.

    This middleware logs information about each request, including:
    - Request method
    - Request path
    - Client IP
    - Processing time
    - Response status code
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """
        Process the request and log information.

        Args:
            request: The incoming request
            call_next: The next middleware or route handler

        Returns:
            The response from the next middleware or route handler
        """
        # Record start time
        start_time = time.time()

        # Get client IP
        client_ip = request.client.host if request.client else "unknown"

        # Log request information
        logger.info(
            f"Request started: {request.method} {request.url.path} from {client_ip}"
        )

        # Process the request
        try:
            response = await call_next(request)

            # Calculate processing time
            process_time = time.time() - start_time

            # Log response information
            logger.info(
                f"Request completed: {request.method} {request.url.path} "
                f"from {client_ip} - Status: {response.status_code} "
                f"- Took: {process_time:.4f}s"
            )

            # Add processing time header
            response.headers["X-Process-Time"] = str(process_time)

            return response
        except Exception as e:
            # Log error
            logger.error(
                f"Request failed: {request.method} {request.url.path} "
                f"from {client_ip} - Error: {str(e)}"
            )
            raise