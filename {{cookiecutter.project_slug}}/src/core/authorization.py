"""
Authorization decorators and utilities.

This module provides decorators and utilities for implementing permission-based
access control in the application.
"""

from functools import wraps
from typing import List, Optional, Callable, Any, Union
from datetime import datetime, timedelta
import time
import jwt
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from src.database import get_session
from src.apps.auth.models import User
from src.config import settings
from src.constants.auth import (
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES,
    JWT_REFRESH_TOKEN_EXPIRE_DAYS,
)
from src.apps.auth.schemas import TokenPayload


# Define a type for the current user dependency
CurrentUser = Callable[..., User]

# OAuth2 password bearer for token extraction
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def create_access_token(
    user_id: int, roles: List[str] = None, permissions: List[str] = None
) -> str:
    """
    Create a JWT access token.

    Args:
        user_id: The user ID
        roles: The user's roles
        permissions: The user's permissions

    Returns:
        JWT access token
    """
    roles = roles or []
    permissions = permissions or []

    # Set expiration time
    expire = datetime.utcnow() + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)

    # Create payload
    payload = {
        "sub": str(user_id),
        "exp": int(expire.timestamp()),
        "iat": int(time.time()),
        "type": "access",
        "roles": roles,
        "permissions": permissions,
    }

    # Encode token
    encoded_jwt = jwt.encode(
        payload, settings.oauth_token_secret, algorithm=settings.jwt_algorithm
    )

    return encoded_jwt


def create_refresh_token(user_id: int) -> str:
    """
    Create a JWT refresh token.

    Args:
        user_id: The user ID

    Returns:
        JWT refresh token
    """
    # Set expiration time
    expire = datetime.utcnow() + timedelta(days=JWT_REFRESH_TOKEN_EXPIRE_DAYS)

    # Create payload
    payload = {
        "sub": str(user_id),
        "exp": int(expire.timestamp()),
        "iat": int(time.time()),
        "type": "refresh",
    }

    # Encode token
    encoded_jwt = jwt.encode(
        payload, settings.oauth_token_secret, algorithm=settings.jwt_algorithm
    )

    return encoded_jwt


def decode_token(token: str) -> TokenPayload:
    """
    Decode a JWT token.

    Args:
        token: The JWT token

    Returns:
        The decoded token payload

    Raises:
        HTTPException: If the token is invalid
    """
    try:
        # Decode token
        payload = jwt.decode(
            token, settings.oauth_token_secret, algorithms=[settings.jwt_algorithm]
        )

        # Create token payload
        token_data = TokenPayload(
            sub=payload["sub"],
            exp=payload["exp"],
            iat=payload["iat"],
            type=payload["type"],
            roles=payload.get("roles", []),
            permissions=payload.get("permissions", []),
        )

        return token_data
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    token: str = Depends(oauth2_scheme), session: AsyncSession = Depends(get_session)
) -> User:
    """
    Get the current authenticated user from the JWT token.

    Args:
        token: The JWT token
        session: The database session

    Returns:
        The current user

    Raises:
        HTTPException: If the user is not authenticated or the token is invalid
    """
    # Decode token
    token_data = decode_token(token)

    # Check if token is an access token
    if token_data.type != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Get user ID from token
    user_id = int(token_data.sub)

    # Get user from database
    from src.apps.auth.repositories import UserRepository
    from src.core.dependencies import container

    user_repository = container.get("user_repository")
    user = await user_repository.get_by_id(session, user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Inactive user",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def has_permission(
    permission: str, current_user: CurrentUser = Depends(get_current_user)
):
    """
    Decorator to check if the current user has the specified permission.

    Args:
        permission: The permission to check
        current_user: A dependency that returns the current user

    Returns:
        A dependency that checks if the user has the permission
    """

    async def _has_permission() -> User:
        user = await current_user()

        # Superusers have all permissions
        if user.is_superuser:
            return user

        # Check if the user has the specific permission directly
        if any(p.codename == permission for p in user.permissions):
            return user

        # Check if the user has the permission through a role
        for role in user.roles:
            if any(p.codename == permission for p in role.permissions):
                return user

        # If we get here, the user doesn't have the permission
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied: {permission} required",
        )

    return _has_permission


def has_permissions(
    permissions: List[str],
    require_all: bool = True,
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Decorator to check if the current user has the specified permissions.

    Args:
        permissions: The permissions to check
        require_all: If True, the user must have all permissions; if False, any one is sufficient
        current_user: A dependency that returns the current user

    Returns:
        A dependency that checks if the user has the permissions
    """

    async def _has_permissions() -> User:
        user = await current_user()

        # Superusers have all permissions
        if user.is_superuser:
            return user

        # Get all permissions the user has (directly and through roles)
        user_permissions = set(p.codename for p in user.permissions)
        for role in user.roles:
            user_permissions.update(p.codename for p in role.permissions)

        # Check if the user has the required permissions
        if require_all:
            # User must have all permissions
            if all(p in user_permissions for p in permissions):
                return user
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: all of {permissions} required",
            )
        else:
            # User must have at least one permission
            if any(p in user_permissions for p in permissions):
                return user
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: any of {permissions} required",
            )

    return _has_permissions


def has_role(role: str, current_user: CurrentUser = Depends(get_current_user)):
    """
    Decorator to check if the current user has the specified role.

    Args:
        role: The role to check
        current_user: A dependency that returns the current user

    Returns:
        A dependency that checks if the user has the role
    """

    async def _has_role() -> User:
        user = await current_user()

        # Superusers have all roles
        if user.is_superuser:
            return user

        # Check if the user has the specific role
        if any(r.name == role for r in user.roles):
            return user

        # If we get here, the user doesn't have the role
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role required: {role}",
        )

    return _has_role


def has_roles(
    roles: List[str],
    require_all: bool = False,
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Decorator to check if the current user has the specified roles.

    Args:
        roles: The roles to check
        require_all: If True, the user must have all roles; if False, any one is sufficient
        current_user: A dependency that returns the current user

    Returns:
        A dependency that checks if the user has the roles
    """

    async def _has_roles() -> User:
        user = await current_user()

        # Superusers have all roles
        if user.is_superuser:
            return user

        # Get all roles the user has
        user_roles = set(r.name for r in user.roles)

        # Check if the user has the required roles
        if require_all:
            # User must have all roles
            if all(r in user_roles for r in roles):
                return user
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Roles required: all of {roles}",
            )
        else:
            # User must have at least one role
            if any(r in user_roles for r in roles):
                return user
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Roles required: any of {roles}",
            )

    return _has_roles


def require_permission(permission: str):
    """
    Decorator for route handlers to require a specific permission.

    Args:
        permission: The permission required to access the route

    Returns:
        A decorator that adds the permission check to the route handler
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(
            *args, user: User = Depends(has_permission(permission)), **kwargs
        ):
            return await func(*args, **kwargs)

        return wrapper

    return decorator


def require_permissions(permissions: List[str], require_all: bool = True):
    """
    Decorator for route handlers to require specific permissions.

    Args:
        permissions: The permissions required to access the route
        require_all: If True, all permissions are required; if False, any one is sufficient

    Returns:
        A decorator that adds the permission check to the route handler
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(
            *args,
            user: User = Depends(has_permissions(permissions, require_all)),
            **kwargs,
        ):
            return await func(*args, **kwargs)

        return wrapper

    return decorator


def require_role(role: str):
    """
    Decorator for route handlers to require a specific role.

    Args:
        role: The role required to access the route

    Returns:
        A decorator that adds the role check to the route handler
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, user: User = Depends(has_role(role)), **kwargs):
            return await func(*args, **kwargs)

        return wrapper

    return decorator


def require_roles(roles: List[str], require_all: bool = False):
    """
    Decorator for route handlers to require specific roles.

    Args:
        roles: The roles required to access the route
        require_all: If True, all roles are required; if False, any one is sufficient

    Returns:
        A decorator that adds the role check to the route handler
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(
            *args, user: User = Depends(has_roles(roles, require_all)), **kwargs
        ):
            return await func(*args, **kwargs)

        return wrapper

    return decorator
