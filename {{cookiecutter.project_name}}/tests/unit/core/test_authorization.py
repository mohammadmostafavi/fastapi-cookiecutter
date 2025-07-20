"""
Tests for authorization utilities in src.core.authorization.
"""

import pytest
import jwt
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import HTTPException, status

from src.core.authorization import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user,
    has_permission,
    has_permissions,
    has_role,
    has_roles,
    require_permission,
    require_permissions,
    require_role,
    require_roles,
)
from src.apps.auth.schemas import TokenPayload
from src.config import settings


@pytest.mark.unit
class TestTokenManagement:
    """Tests for token management functions."""

    def test_create_access_token(self):
        """Test creating an access token."""
        user_id = 123
        roles = ["admin", "user"]
        permissions = ["read", "write"]
        
        token = create_access_token(user_id, roles, permissions)
        
        # Decode the token to verify its contents
        payload = jwt.decode(
            token, settings.oauth_token_secret, algorithms=[settings.jwt_algorithm]
        )
        
        assert payload["sub"] == str(user_id)
        assert payload["type"] == "access"
        assert payload["roles"] == roles
        assert payload["permissions"] == permissions
        assert "exp" in payload
        assert "iat" in payload

    def test_create_access_token_default_values(self):
        """Test creating an access token with default values."""
        user_id = 123
        
        token = create_access_token(user_id)
        
        # Decode the token to verify its contents
        payload = jwt.decode(
            token, settings.oauth_token_secret, algorithms=[settings.jwt_algorithm]
        )
        
        assert payload["sub"] == str(user_id)
        assert payload["type"] == "access"
        assert payload["roles"] == []
        assert payload["permissions"] == []

    def test_create_refresh_token(self):
        """Test creating a refresh token."""
        user_id = 123
        
        token = create_refresh_token(user_id)
        
        # Decode the token to verify its contents
        payload = jwt.decode(
            token, settings.oauth_token_secret, algorithms=[settings.jwt_algorithm]
        )
        
        assert payload["sub"] == str(user_id)
        assert payload["type"] == "refresh"
        assert "exp" in payload
        assert "iat" in payload

    def test_decode_token_valid(self):
        """Test decoding a valid token."""
        user_id = 123
        roles = ["admin", "user"]
        permissions = ["read", "write"]
        
        token = create_access_token(user_id, roles, permissions)
        token_data = decode_token(token)
        
        assert token_data.sub == str(user_id)
        assert token_data.type == "access"
        assert token_data.roles == roles
        assert token_data.permissions == permissions
        assert token_data.exp is not None
        assert token_data.iat is not None

    def test_decode_token_expired(self):
        """Test decoding an expired token."""
        # Create a payload with an expired token
        user_id = 123
        expire = datetime.utcnow() - timedelta(minutes=1)  # Expired 1 minute ago
        
        payload = {
            "sub": str(user_id),
            "exp": int(expire.timestamp()),
            "iat": int(datetime.utcnow().timestamp()),
            "type": "access",
            "roles": [],
            "permissions": [],
        }
        
        # Encode token
        token = jwt.encode(
            payload, settings.oauth_token_secret, algorithm=settings.jwt_algorithm
        )
        
        # Attempt to decode the expired token
        with pytest.raises(HTTPException) as exc_info:
            decode_token(token)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Token expired" in exc_info.value.detail

    def test_decode_token_invalid(self):
        """Test decoding an invalid token."""
        # Create an invalid token
        token = "invalid.token.format"
        
        # Attempt to decode the invalid token
        with pytest.raises(HTTPException) as exc_info:
            decode_token(token)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Invalid token" in exc_info.value.detail


@pytest.mark.unit
@pytest.mark.asyncio
class TestUserAuthentication:
    """Tests for user authentication functions."""

    async def test_get_current_user_valid(self):
        """Test getting the current user with a valid token."""
        user_id = 123
        mock_user = AsyncMock()
        mock_user.is_active = True
        
        # Create a valid access token
        token = create_access_token(user_id)
        
        # Mock the user repository
        mock_repository = AsyncMock()
        mock_repository.get_by_id.return_value = mock_user
        
        # Mock the container
        mock_container = MagicMock()
        mock_container.get.return_value = mock_repository
        
        # Patch the dependencies
        with patch('src.core.dependencies.container', mock_container):
            # Call get_current_user
            user = await get_current_user(token, AsyncMock())
            
            # Verify the result
            assert user == mock_user
            mock_repository.get_by_id.assert_called_once()

    async def test_get_current_user_refresh_token(self):
        """Test that get_current_user rejects refresh tokens."""
        user_id = 123
        
        # Create a refresh token
        token = create_refresh_token(user_id)
        
        # Attempt to get the current user with a refresh token
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(token, AsyncMock())
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Invalid token type" in exc_info.value.detail

    async def test_get_current_user_not_found(self):
        """Test that get_current_user raises an exception when the user is not found."""
        user_id = 123
        
        # Create a valid access token
        token = create_access_token(user_id)
        
        # Mock the user repository to return None
        mock_repository = AsyncMock()
        mock_repository.get_by_id.return_value = None
        
        # Mock the container
        mock_container = MagicMock()
        mock_container.get.return_value = mock_repository
        
        # Patch the dependencies
        with patch('src.core.dependencies.container', mock_container):
            # Attempt to get the current user
            with pytest.raises(HTTPException) as exc_info:
                await get_current_user(token, AsyncMock())
            
            assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
            assert "User not found" in exc_info.value.detail

    async def test_get_current_user_inactive(self):
        """Test that get_current_user raises an exception when the user is inactive."""
        user_id = 123
        mock_user = AsyncMock()
        mock_user.is_active = False
        
        # Create a valid access token
        token = create_access_token(user_id)
        
        # Mock the user repository
        mock_repository = AsyncMock()
        mock_repository.get_by_id.return_value = mock_user
        
        # Mock the container
        mock_container = MagicMock()
        mock_container.get.return_value = mock_repository
        
        # Patch the dependencies
        with patch('src.core.dependencies.container', mock_container):
            # Attempt to get the current user
            with pytest.raises(HTTPException) as exc_info:
                await get_current_user(token, AsyncMock())
            
            assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
            assert "Inactive user" in exc_info.value.detail


@pytest.mark.unit
@pytest.mark.asyncio
class TestPermissionChecking:
    """Tests for permission checking functions."""

    async def test_has_permission_superuser(self):
        """Test that superusers have all permissions."""
        # Create a mock user with superuser status
        mock_user = AsyncMock()
        mock_user.is_superuser = True
        mock_user.permissions = []
        mock_user.roles = []
        
        # Create a mock current_user dependency
        mock_current_user = AsyncMock(return_value=mock_user)
        
        # Create the has_permission dependency
        permission_check = has_permission("some_permission", mock_current_user)
        
        # Call the permission check
        result = await permission_check()
        
        # Verify the result
        assert result == mock_user
        mock_current_user.assert_called_once()

    async def test_has_permission_direct(self):
        """Test that users with direct permissions pass the check."""
        # Create a mock permission
        mock_permission = MagicMock()
        mock_permission.codename = "read"
        
        # Create a mock user with the permission
        mock_user = AsyncMock()
        mock_user.is_superuser = False
        mock_user.permissions = [mock_permission]
        mock_user.roles = []
        
        # Create a mock current_user dependency
        mock_current_user = AsyncMock(return_value=mock_user)
        
        # Create the has_permission dependency
        permission_check = has_permission("read", mock_current_user)
        
        # Call the permission check
        result = await permission_check()
        
        # Verify the result
        assert result == mock_user
        mock_current_user.assert_called_once()

    async def test_has_permission_through_role(self):
        """Test that users with permissions through roles pass the check."""
        # Create a mock permission
        mock_permission = MagicMock()
        mock_permission.codename = "read"
        
        # Create a mock role with the permission
        mock_role = MagicMock()
        mock_role.permissions = [mock_permission]
        
        # Create a mock user with the role
        mock_user = AsyncMock()
        mock_user.is_superuser = False
        mock_user.permissions = []
        mock_user.roles = [mock_role]
        
        # Create a mock current_user dependency
        mock_current_user = AsyncMock(return_value=mock_user)
        
        # Create the has_permission dependency
        permission_check = has_permission("read", mock_current_user)
        
        # Call the permission check
        result = await permission_check()
        
        # Verify the result
        assert result == mock_user
        mock_current_user.assert_called_once()

    async def test_has_permission_denied(self):
        """Test that users without the permission are denied."""
        # Create a mock user without the permission
        mock_user = AsyncMock()
        mock_user.is_superuser = False
        mock_user.permissions = []
        mock_user.roles = []
        
        # Create a mock current_user dependency
        mock_current_user = AsyncMock(return_value=mock_user)
        
        # Create the has_permission dependency
        permission_check = has_permission("read", mock_current_user)
        
        # Call the permission check
        with pytest.raises(HTTPException) as exc_info:
            await permission_check()
        
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "Permission denied" in exc_info.value.detail
        mock_current_user.assert_called_once()

    async def test_has_permissions_all_required_pass(self):
        """Test that users with all required permissions pass the check."""
        # Create mock permissions
        mock_permission1 = MagicMock()
        mock_permission1.codename = "read"
        mock_permission2 = MagicMock()
        mock_permission2.codename = "write"
        
        # Create a mock user with the permissions
        mock_user = AsyncMock()
        mock_user.is_superuser = False
        mock_user.permissions = [mock_permission1, mock_permission2]
        mock_user.roles = []
        
        # Create a mock current_user dependency
        mock_current_user = AsyncMock(return_value=mock_user)
        
        # Create the has_permissions dependency
        permissions_check = has_permissions(["read", "write"], True, mock_current_user)
        
        # Call the permissions check
        result = await permissions_check()
        
        # Verify the result
        assert result == mock_user
        mock_current_user.assert_called_once()

    async def test_has_permissions_all_required_fail(self):
        """Test that users without all required permissions are denied."""
        # Create a mock permission
        mock_permission = MagicMock()
        mock_permission.codename = "read"
        
        # Create a mock user with only one of the required permissions
        mock_user = AsyncMock()
        mock_user.is_superuser = False
        mock_user.permissions = [mock_permission]
        mock_user.roles = []
        
        # Create a mock current_user dependency
        mock_current_user = AsyncMock(return_value=mock_user)
        
        # Create the has_permissions dependency
        permissions_check = has_permissions(["read", "write"], True, mock_current_user)
        
        # Call the permissions check
        with pytest.raises(HTTPException) as exc_info:
            await permissions_check()
        
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "Permission denied" in exc_info.value.detail
        mock_current_user.assert_called_once()

    async def test_has_permissions_any_required_pass(self):
        """Test that users with any of the required permissions pass the check."""
        # Create a mock permission
        mock_permission = MagicMock()
        mock_permission.codename = "read"
        
        # Create a mock user with one of the required permissions
        mock_user = AsyncMock()
        mock_user.is_superuser = False
        mock_user.permissions = [mock_permission]
        mock_user.roles = []
        
        # Create a mock current_user dependency
        mock_current_user = AsyncMock(return_value=mock_user)
        
        # Create the has_permissions dependency
        permissions_check = has_permissions(["read", "write"], False, mock_current_user)
        
        # Call the permissions check
        result = await permissions_check()
        
        # Verify the result
        assert result == mock_user
        mock_current_user.assert_called_once()

    async def test_has_permissions_any_required_fail(self):
        """Test that users without any of the required permissions are denied."""
        # Create a mock permission
        mock_permission = MagicMock()
        mock_permission.codename = "delete"
        
        # Create a mock user without any of the required permissions
        mock_user = AsyncMock()
        mock_user.is_superuser = False
        mock_user.permissions = [mock_permission]
        mock_user.roles = []
        
        # Create a mock current_user dependency
        mock_current_user = AsyncMock(return_value=mock_user)
        
        # Create the has_permissions dependency
        permissions_check = has_permissions(["read", "write"], False, mock_current_user)
        
        # Call the permissions check
        with pytest.raises(HTTPException) as exc_info:
            await permissions_check()
        
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "Permission denied" in exc_info.value.detail
        mock_current_user.assert_called_once()


@pytest.mark.unit
@pytest.mark.asyncio
class TestRoleChecking:
    """Tests for role checking functions."""

    async def test_has_role_superuser(self):
        """Test that superusers have all roles."""
        # Create a mock user with superuser status
        mock_user = AsyncMock()
        mock_user.is_superuser = True
        mock_user.roles = []
        
        # Create a mock current_user dependency
        mock_current_user = AsyncMock(return_value=mock_user)
        
        # Create the has_role dependency
        role_check = has_role("admin", mock_current_user)
        
        # Call the role check
        result = await role_check()
        
        # Verify the result
        assert result == mock_user
        mock_current_user.assert_called_once()

    async def test_has_role_direct(self):
        """Test that users with the role pass the check."""
        # Create a mock role
        mock_role = MagicMock()
        mock_role.name = "admin"
        
        # Create a mock user with the role
        mock_user = AsyncMock()
        mock_user.is_superuser = False
        mock_user.roles = [mock_role]
        
        # Create a mock current_user dependency
        mock_current_user = AsyncMock(return_value=mock_user)
        
        # Create the has_role dependency
        role_check = has_role("admin", mock_current_user)
        
        # Call the role check
        result = await role_check()
        
        # Verify the result
        assert result == mock_user
        mock_current_user.assert_called_once()

    async def test_has_role_denied(self):
        """Test that users without the role are denied."""
        # Create a mock role
        mock_role = MagicMock()
        mock_role.name = "user"
        
        # Create a mock user without the required role
        mock_user = AsyncMock()
        mock_user.is_superuser = False
        mock_user.roles = [mock_role]
        
        # Create a mock current_user dependency
        mock_current_user = AsyncMock(return_value=mock_user)
        
        # Create the has_role dependency
        role_check = has_role("admin", mock_current_user)
        
        # Call the role check
        with pytest.raises(HTTPException) as exc_info:
            await role_check()
        
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "Role required" in exc_info.value.detail
        mock_current_user.assert_called_once()

    async def test_has_roles_all_required_pass(self):
        """Test that users with all required roles pass the check."""
        # Create mock roles
        mock_role1 = MagicMock()
        mock_role1.name = "admin"
        mock_role2 = MagicMock()
        mock_role2.name = "moderator"
        
        # Create a mock user with all required roles
        mock_user = AsyncMock()
        mock_user.is_superuser = False
        mock_user.roles = [mock_role1, mock_role2]
        
        # Create a mock current_user dependency
        mock_current_user = AsyncMock(return_value=mock_user)
        
        # Create the has_roles dependency
        roles_check = has_roles(["admin", "moderator"], True, mock_current_user)
        
        # Call the roles check
        result = await roles_check()
        
        # Verify the result
        assert result == mock_user
        mock_current_user.assert_called_once()

    async def test_has_roles_all_required_fail(self):
        """Test that users without all required roles are denied."""
        # Create a mock role
        mock_role = MagicMock()
        mock_role.name = "admin"
        
        # Create a mock user with only one of the required roles
        mock_user = AsyncMock()
        mock_user.is_superuser = False
        mock_user.roles = [mock_role]
        
        # Create a mock current_user dependency
        mock_current_user = AsyncMock(return_value=mock_user)
        
        # Create the has_roles dependency
        roles_check = has_roles(["admin", "moderator"], True, mock_current_user)
        
        # Call the roles check
        with pytest.raises(HTTPException) as exc_info:
            await roles_check()
        
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "Roles required" in exc_info.value.detail
        mock_current_user.assert_called_once()

    async def test_has_roles_any_required_pass(self):
        """Test that users with any of the required roles pass the check."""
        # Create a mock role
        mock_role = MagicMock()
        mock_role.name = "admin"
        
        # Create a mock user with one of the required roles
        mock_user = AsyncMock()
        mock_user.is_superuser = False
        mock_user.roles = [mock_role]
        
        # Create a mock current_user dependency
        mock_current_user = AsyncMock(return_value=mock_user)
        
        # Create the has_roles dependency
        roles_check = has_roles(["admin", "moderator"], False, mock_current_user)
        
        # Call the roles check
        result = await roles_check()
        
        # Verify the result
        assert result == mock_user
        mock_current_user.assert_called_once()

    async def test_has_roles_any_required_fail(self):
        """Test that users without any of the required roles are denied."""
        # Create a mock role
        mock_role = MagicMock()
        mock_role.name = "user"
        
        # Create a mock user without any of the required roles
        mock_user = AsyncMock()
        mock_user.is_superuser = False
        mock_user.roles = [mock_role]
        
        # Create a mock current_user dependency
        mock_current_user = AsyncMock(return_value=mock_user)
        
        # Create the has_roles dependency
        roles_check = has_roles(["admin", "moderator"], False, mock_current_user)
        
        # Call the roles check
        with pytest.raises(HTTPException) as exc_info:
            await roles_check()
        
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "Roles required" in exc_info.value.detail
        mock_current_user.assert_called_once()


@pytest.mark.unit
@pytest.mark.asyncio
class TestRouteDecorators:
    """Tests for route decorator functions."""

    async def test_require_permission(self):
        """Test the require_permission decorator."""
        # Create a mock handler function
        mock_handler = AsyncMock(return_value="handler result")
        
        # Create a mock user
        mock_user = AsyncMock()
        
        # Create a mock has_permission dependency
        mock_has_permission = AsyncMock(return_value=mock_user)
        
        # Patch the has_permission function
        with patch('src.core.authorization.has_permission', return_value=mock_has_permission):
            # Apply the decorator
            decorated_handler = require_permission("read")(mock_handler)
            
            # Call the decorated handler
            result = await decorated_handler()
            
            # Verify the result
            assert result == "handler result"
            mock_handler.assert_called_once()

    async def test_require_permissions(self):
        """Test the require_permissions decorator."""
        # Create a mock handler function
        mock_handler = AsyncMock(return_value="handler result")
        
        # Create a mock user
        mock_user = AsyncMock()
        
        # Create a mock has_permissions dependency
        mock_has_permissions = AsyncMock(return_value=mock_user)
        
        # Patch the has_permissions function
        with patch('src.core.authorization.has_permissions', return_value=mock_has_permissions):
            # Apply the decorator
            decorated_handler = require_permissions(["read", "write"], True)(mock_handler)
            
            # Call the decorated handler
            result = await decorated_handler()
            
            # Verify the result
            assert result == "handler result"
            mock_handler.assert_called_once()

    async def test_require_role(self):
        """Test the require_role decorator."""
        # Create a mock handler function
        mock_handler = AsyncMock(return_value="handler result")
        
        # Create a mock user
        mock_user = AsyncMock()
        
        # Create a mock has_role dependency
        mock_has_role = AsyncMock(return_value=mock_user)
        
        # Patch the has_role function
        with patch('src.core.authorization.has_role', return_value=mock_has_role):
            # Apply the decorator
            decorated_handler = require_role("admin")(mock_handler)
            
            # Call the decorated handler
            result = await decorated_handler()
            
            # Verify the result
            assert result == "handler result"
            mock_handler.assert_called_once()

    async def test_require_roles(self):
        """Test the require_roles decorator."""
        # Create a mock handler function
        mock_handler = AsyncMock(return_value="handler result")
        
        # Create a mock user
        mock_user = AsyncMock()
        
        # Create a mock has_roles dependency
        mock_has_roles = AsyncMock(return_value=mock_user)
        
        # Patch the has_roles function
        with patch('src.core.authorization.has_roles', return_value=mock_has_roles):
            # Apply the decorator
            decorated_handler = require_roles(["admin", "moderator"], False)(mock_handler)
            
            # Call the decorated handler
            result = await decorated_handler()
            
            # Verify the result
            assert result == "handler result"
            mock_handler.assert_called_once()