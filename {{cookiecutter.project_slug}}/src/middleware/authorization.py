"""
Authorization middleware.

This module provides middleware for implementing role-based access control
in the application.
"""

from typing import Optional, Callable, Dict, List, Any
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.status import HTTP_403_FORBIDDEN
import re

# Removed static role constants in favor of database roles


class RoleBasedMiddleware(BaseHTTPMiddleware):
    """
    Middleware for implementing role-based access control.

    This middleware checks if the user has the required role to access
    specific URL patterns.
    """

    def __init__(
        self,
        app,
        role_patterns: Optional[Dict[str, List[str]]] = None,
        get_user_role: Optional[Callable[[Request], str]] = None,
    ):
        """
        Initialize the middleware.

        Args:
            app: The FastAPI application
            role_patterns: A dictionary mapping URL patterns to required roles
            get_user_role: A function that extracts the user's role from the request
        """
        super().__init__(app)
        self.role_patterns = role_patterns or {}
        self.get_user_role = get_user_role or self._default_get_user_role

    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Process the request.

        Args:
            request: The incoming request
            call_next: The next middleware or route handler

        Returns:
            The response from the next middleware or route handler
        """
        # Skip role check for OPTIONS requests (CORS preflight)
        if request.method == "OPTIONS":
            return await call_next(request)

        # Get the path from the request
        path = request.url.path

        # Check if the path matches any of the role patterns
        required_roles = self._get_required_roles(path)

        # If no roles are required, allow access
        if not required_roles:
            return await call_next(request)

        # Get the user's role from the request
        user_role = await self.get_user_role(request)

        # If the user has no role, deny access
        if not user_role:
            return JSONResponse(
                status_code=HTTP_403_FORBIDDEN,
                content={"detail": "Access denied: authentication required"},
            )

        # If the user has the admin role, allow access to everything
        if user_role == "admin":
            return await call_next(request)

        # Check if the user's role is in the required roles
        if user_role in required_roles:
            return await call_next(request)

        # If we get here, the user doesn't have the required role
        return JSONResponse(
            status_code=HTTP_403_FORBIDDEN,
            content={
                "detail": f"Access denied: one of {required_roles} roles required"
            },
        )

    def _get_required_roles(self, path: str) -> List[str]:
        """
        Get the required roles for a path.

        Args:
            path: The request path

        Returns:
            A list of required roles
        """
        for pattern, roles in self.role_patterns.items():
            if re.match(pattern, path):
                return roles
        return []

    async def _default_get_user_role(self, request: Request) -> Optional[str]:
        """
        Default implementation for getting the user's role.

        Extracts the user's role from the JWT token in the request header.

        Args:
            request: The incoming request

        Returns:
            The user's role or None if not authenticated
        """
        # Get the authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return None

        # Extract the token
        token = auth_header.replace("Bearer ", "")

        try:
            # Import the decode_token function
            from src.core.authorization import decode_token

            # Decode the token
            token_data = decode_token(token)

            # Check if token is an access token
            if token_data.type != "access":
                return None

            # Get the roles from the token
            roles = token_data.roles

            # Return the highest priority role
            if "admin" in roles:
                return "admin"
            elif "staff" in roles:
                return "staff"
            elif "user" in roles:
                return "user"
            else:
                return None
        except Exception:
            # If token validation fails, return None
            return None


def get_authorization_middleware(
    role_patterns: Optional[Dict[str, List[str]]] = None,
    get_user_role: Optional[Callable[[Request], str]] = None,
) -> RoleBasedMiddleware:
    """
    Create an instance of the RoleBasedMiddleware.

    Args:
        role_patterns: A dictionary mapping URL patterns to required roles
        get_user_role: A function that extracts the user's role from the request

    Returns:
        An instance of the RoleBasedMiddleware
    """
    return lambda app: RoleBasedMiddleware(
        app,
        role_patterns,
        get_user_role,
    )
