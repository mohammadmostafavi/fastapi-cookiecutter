from typing import Sequence, Optional, List, Tuple
import re
import time
import jwt
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
from fastapi import Depends, HTTPException, status

from src.core.authorization import (
    create_access_token,
    create_refresh_token,
    decode_token,
)
from ..models import User
from ..schemas import UserCreate, UserUpdate, Token
from ..repositories import UserRepository
from src.core.utils import make_password, check_password
from src.database import get_session
from src.core.exceptions import (
    InternalServerException,
    ValidationException,
)
from ..exceptions import UserAlreadyExistsException, UserNotFoundException, InvalidCredentialsException
from src.constants.auth import (
    PASSWORD_MIN_LENGTH,
    PASSWORD_REQUIRE_UPPERCASE,
    PASSWORD_REQUIRE_LOWERCASE,
    PASSWORD_REQUIRE_DIGITS,
    PASSWORD_REQUIRE_SPECIAL_CHARS,
    PASSWORD_SPECIAL_CHARS,
)
from src.config import settings


class UserService:
    """
    Service class for user-related operations.
    """

    def __init__(self, user_repository: UserRepository):
        """
        Initialize the service with dependencies.

        Args:
            user_repository: Repository for user operations
        """
        self.user_repository = user_repository

    def validate_password(self, password: str) -> None:
        """
        Validate a password against the password policy.

        Args:
            password: The password to validate

        Raises:
            ValidationException: If the password does not meet the requirements
        """
        errors = []

        # Check length
        if len(password) < PASSWORD_MIN_LENGTH:
            errors.append(f"Password must be at least {PASSWORD_MIN_LENGTH} characters long")

        # Check for uppercase letters
        if PASSWORD_REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")

        # Check for lowercase letters
        if PASSWORD_REQUIRE_LOWERCASE and not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")

        # Check for digits
        if PASSWORD_REQUIRE_DIGITS and not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one digit")

        # Check for special characters
        if PASSWORD_REQUIRE_SPECIAL_CHARS and not any(c in PASSWORD_SPECIAL_CHARS for c in password):
            errors.append(f"Password must contain at least one special character ({PASSWORD_SPECIAL_CHARS})")

        if errors:
            raise ValidationException(
                message="Password validation failed",
                details={"errors": errors}
            )

    async def create_user(self, user: UserCreate) -> User:
        """
        Create a new user.

        Args:
            user: User data

        Returns:
            Created user

        Raises:
            UserAlreadyExistsException: If the user already exists
            ValidationException: If the password does not meet the requirements
            InternalServerException: If an unexpected error occurs
        """
        try:
            # Validate the password
            user_data = user.model_dump(exclude_unset=True)
            if "password" in user_data:
                # Validate password against policy
                self.validate_password(user_data["password"])
                # Hash the password
                user_data["password"] = make_password(user_data["password"])

            # Create the user using the repository
            user = await self.user_repository.create(**user_data)
            return user
        except IntegrityError:
            raise UserAlreadyExistsException()
        except Exception as e:
            raise InternalServerException(message=f"An unexpected error occurred: {str(e)}")

    async def get_users(self) -> List[User]:
        """
        Get all users.

        Returns:
            List of users
        """
        users = await self.user_repository.get_all()
        return users

    async def get_user_by_id(self, user_id: int, raise_exception: bool = False) -> Optional[User]:
        """
        Get a user by ID.

        Args:
            user_id: User ID
            raise_exception: Whether to raise an exception if the user is not found

        Returns:
            User or None if not found and raise_exception is False

        Raises:
            UserNotFoundException: If the user is not found and raise_exception is True
        """
        user = await self.user_repository.get_by_id(user_id)
        if user is None and raise_exception:
            raise UserNotFoundException(message=f"User with ID {user_id} not found")
        return user

    async def update_user(self, user_id: int, user_data: UserUpdate, raise_not_found: bool = False) -> Optional[User]:
        """
        Update a user.

        Args:
            user_id: User ID
            user_data: User data to update
            raise_not_found: Whether to raise an exception if the user is not found

        Returns:
            Updated user or None if not found and raise_not_found is False

        Raises:
            UserNotFoundException: If the user is not found and raise_not_found is True
            UserAlreadyExistsException: If the user with updated data already exists
            ValidationException: If the password does not meet the requirements
        """
        try:
            # Get the user first using the get_user_by_id method
            user = await self.get_user_by_id(user_id, raise_exception=raise_not_found)
            if not user:
                return None

            # Prepare the update data
            update_data = user_data.model_dump(exclude_unset=True)

            # Handle special fields like password
            if "password" in update_data:
                # Validate password against policy
                self.validate_password(update_data["password"])
                # Hash the password
                update_data["password"] = make_password(update_data["password"])

            # Update the user using the repository
            user = await self.user_repository.update(user, **update_data)
            return user
        except IntegrityError:
            raise UserAlreadyExistsException()

    async def delete_user(self, user_id: int, raise_not_found: bool = False) -> Optional[User]:
        """
        Delete a user.

        Args:
            user_id: User ID
            raise_not_found: Whether to raise an exception if the user is not found

        Returns:
            Deleted user or None if not found and raise_not_found is False

        Raises:
            UserNotFoundException: If the user is not found and raise_not_found is True
        """
        # Get the user first using the get_user_by_id method
        user = await self.get_user_by_id(user_id, raise_exception=raise_not_found)
        if not user:
            return None

        # Soft delete the user using the repository
        user = await self.user_repository.delete(user)
        return user

    async def verify_credentials(self, username: str, password: str) -> Tuple[User, List[str], List[str]]:
        """
        Verify user credentials.

        Args:
            username: The username
            password: The password

        Returns:
            A tuple containing the user, roles, and permissions

        Raises:
            InvalidCredentialsException: If the credentials are invalid
        """
        # Get the user by username
        user = await self.user_repository.get_by_username(username)

        # Check if the user exists
        if user is None:
            raise InvalidCredentialsException()

        # Check if the user is active
        if not user.is_active:
            raise InvalidCredentialsException(message="User account is inactive")

        # Check if the password is correct
        if not check_password(password, user.password):
            raise InvalidCredentialsException()

        # Get the user's roles and permissions
        # roles = [role.name for role in user.roles]
        # permissions = [permission.codename for permission in user.permissions]
        #
        # Add permissions from roles
        # for role in user.roles:
        #     permissions.extend([permission.codename for permission in role.permissions])
        #
        # Remove duplicates from permissions
        # permissions = list(set(permissions))
        #
        # Update the user's last login time
        # user.last_login = datetime.utcnow()
        # await self.user_repository.update(user)
        roles = []
        permissions = []

        return user, roles, permissions

    async def request_password_reset(self, email: str) -> str:
        """
        Request a password reset.

        Args:
            email: The user's email

        Returns:
            The password reset token

        Raises:
            UserNotFoundException: If the user is not found
        """
        # Get the user by email
        user = await self.user_repository.get_by_email(email)

        # Check if the user exists
        if user is None:
            raise UserNotFoundException(message=f"User with email {email} not found")

        raise NotImplementedError("Password reset not implemented yet")
        return token

    async def confirm_password_reset(self, token: str, new_password: str) -> User:
        """
        Confirm a password reset.

        Args:
            token: The password reset token
            new_password: The new password

        Returns:
            The updated user

        Raises:
            HTTPException: If the token is invalid
            UserNotFoundException: If the user is not found
            ValidationException: If the password does not meet the requirements
        """
        try:
            # Decode the token
            payload = jwt.decode(
                token,
                settings.oauth_token_secret,
                algorithms=[settings.jwt_algorithm]
            )

            # Check if token is a password reset token
            if payload.get("type") != "password_reset":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid token type",
                )

            # Check if token is expired
            if datetime.fromtimestamp(payload.get("exp")) < datetime.utcnow():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Token expired",
                )

            # Get user ID from token
            user_id = int(payload.get("sub"))

            # Get user from database
            user = await self.get_user_by_id(user_id, raise_exception=True)

            # Validate the new password
            self.validate_password(new_password)

            # Update the user's password
            user_data = UserUpdate(password=new_password)
            user = await self.update_user(user_id, user_data, raise_not_found=True)

            return user
        except jwt.InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token",
            )

    async def get_token(self,username: str, password: str) -> Token:
        # Verify credentials
        user_obj, roles, permissions = await self.verify_credentials(
            username, password
        )

        # Generate tokens
        access_token = create_access_token(user_obj.id, roles, permissions)
        refresh_token = create_refresh_token(user_obj.id)
        return Token(access_token=access_token, refresh_token=refresh_token)

    async def refresh_token(self, refresh_token: str) -> Token:
        try:
            # Decode the refresh token
            token_data = decode_token(refresh_token)

            # Check if token is a refresh token
            if token_data.type != "refresh":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # Get user ID from token
            user_id = int(token_data.sub)

            # Get user from database
            user = await self.get_user_by_id(user_id, raise_exception=True)

            # Get user roles and permissions
            roles = [role.name for role in user.roles]
            permissions = [permission.codename for permission in user.permissions]

            # Add permissions from roles
            for role in user.roles:
                permissions.extend([permission.codename for permission in role.permissions])

            # Remove duplicates from permissions
            permissions = list(set(permissions))

            # Generate new tokens
            new_access_token = create_access_token(user.id, roles, permissions)
            new_refresh_token = create_refresh_token(user.id)

            # Return new tokens
            return Token(
                access_token=new_access_token,
                refresh_token=new_refresh_token,
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid refresh token: {str(e)}",
                headers={"WWW-Authenticate": "Bearer"},
            )


# Dependency function for UserService
def get_user_service(
        db: AsyncSession = Depends(get_session),
) -> UserService:
    """
    Get a UserService instance with its dependencies.

    Args:
        db: Database session

    Returns:
        UserService instance
    """
    from src.core.dependencies import container

    # Get the user repository from the container
    user_repository = UserRepository(db=db)

    # Create and return the service
    return UserService(user_repository)
