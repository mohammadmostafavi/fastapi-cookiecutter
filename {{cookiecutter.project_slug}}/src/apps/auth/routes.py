from fastapi import APIRouter, Depends, HTTPException, status
from .services import UserService, get_user_service
from .schemas import (
    UserCreate,
    UserResponse,
    UserLogin,
    UserUpdate,
    Token,
    RefreshToken,
    PasswordResetConfirm,
    PasswordResetRequest,
    TokenPayload,
)
from src.core.schemas import ErrorResponse
from src.core.authorization import (
    require_permission,
    require_permissions,
    require_role,
    require_roles,
)
# Removed static role and permission constants in favor of string literals

auth_router = APIRouter()


@auth_router.get(
    "/user",
    response_model=list[UserResponse],
    responses={
        401: {"model": ErrorResponse, "description": "Not authenticated"},
        403: {"model": ErrorResponse, "description": "Permission denied"},
        500: {"model": ErrorResponse, "description": "Internal server error"},
    },
)
@require_permission("read")
async def read_users(user_service: UserService = Depends(get_user_service)):
    """
    Get all users.

    Requires:
        Permission: read

    Raises:
        InternalServerException: If an unexpected error occurs
    """
    return await user_service.get_users()


@auth_router.post(
    "/user",
    response_model=UserResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Not authenticated"},
        403: {"model": ErrorResponse, "description": "Permission denied"},
        409: {
            "model": ErrorResponse,
            "description": "User with this username or email already exists",
        },
        422: {"model": ErrorResponse, "description": "Password validation failed"},
        500: {"model": ErrorResponse, "description": "Internal server error"},
    },
)
@require_permission("write")
async def create_new_user(
    user: UserCreate, user_service: UserService = Depends(get_user_service)
):
    """
    Create a new user.

    Requires:
        Permission: write

    Raises:
        UserAlreadyExistsException: If the user already exists
        ValidationException: If the password does not meet the requirements
        InternalServerException: If an unexpected error occurs
    """
    return await user_service.create_user(user)


@auth_router.get(
    "/user/{user_id}",
    response_model=UserResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Not authenticated"},
        403: {"model": ErrorResponse, "description": "Permission denied"},
        404: {"model": ErrorResponse, "description": "User not found"},
    },
)
@require_permission("read")
async def read_user(
    user_id: int, user_service: UserService = Depends(get_user_service)
):
    """
    Get a user by ID.

    Requires:
        Permission: read

    Raises:
        UserNotFoundException: If the user is not found
    """
    # This will raise UserNotFoundException if the user is not found
    user = await user_service.get_user_by_id(user_id, raise_exception=True)
    return user


@auth_router.put(
    "/user/{user_id}",
    response_model=UserResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Not authenticated"},
        403: {"model": ErrorResponse, "description": "Permission denied"},
        404: {"model": ErrorResponse, "description": "User not found"},
        409: {
            "model": ErrorResponse,
            "description": "User with this username or email already exists",
        },
        422: {"model": ErrorResponse, "description": "Password validation failed"},
    },
)
@auth_router.patch(
    "/user/{user_id}",
    response_model=UserResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Not authenticated"},
        403: {"model": ErrorResponse, "description": "Permission denied"},
        404: {"model": ErrorResponse, "description": "User not found"},
        409: {
            "model": ErrorResponse,
            "description": "User with this username or email already exists",
        },
        422: {"model": ErrorResponse, "description": "Password validation failed"},
    },
)
@require_permission("write")
async def update_user_info(
    user_id: int,
    user_data: UserUpdate,
    user_service: UserService = Depends(get_user_service),
):
    """
    Update a user.

    Requires:
        Permission: write

    Raises:
        UserNotFoundException: If the user is not found
        UserAlreadyExistsException: If the user with updated data already exists
        ValidationException: If the password does not meet the requirements
    """
    # This will raise UserNotFoundException if the user is not found
    user = await user_service.update_user(user_id, user_data, raise_not_found=True)
    return user


@auth_router.delete(
    "/user/{user_id}",
    responses={
        401: {"model": ErrorResponse, "description": "Not authenticated"},
        403: {"model": ErrorResponse, "description": "Permission denied"},
        404: {"model": ErrorResponse, "description": "User not found"},
    },
)
@require_permissions(["delete", "admin"], require_all=False)
async def delete_user(
    user_id: int, user_service: UserService = Depends(get_user_service)
):
    """
    Delete a user.

    Requires:
        Permission: delete OR admin

    Raises:
        UserNotFoundException: If the user is not found
    """
    # This will raise UserNotFoundException if the user is not found
    await user_service.delete_user(user_id, raise_not_found=True)
    return {"message": f"User {user_id} deleted successfully"}


@auth_router.post(
    "/login",
    response_model=Token,
    responses={
        401: {"model": ErrorResponse, "description": "Invalid credentials"},
    },
)
async def login_user(
    user: UserLogin, user_service: UserService = Depends(get_user_service)
):
    """
    Login a user and return access and refresh tokens.

    Raises:
        InvalidCredentialsException: If the credentials are invalid
    """

    token_payload = await user_service.get_token(user.username,user.password)
    return token_payload


@auth_router.post(
    "/refresh",
    response_model=Token,
    responses={
        401: {"model": ErrorResponse, "description": "Invalid refresh token"},
    },
)
async def refresh_token_endpoint(
    refresh_token_data: RefreshToken,
    user_service: UserService = Depends(get_user_service),
):
    """
    Refresh an access token using a refresh token.

    Raises:
        HTTPException: If the refresh token is invalid
    """
    token_payload = await user_service.refresh_token(refresh_token_data.refresh_token)
    return token_payload


@auth_router.post(
    "/password-reset/request",
    responses={
        200: {"description": "Password reset email sent"},
        404: {"model": ErrorResponse, "description": "User not found"},
        500: {"model": ErrorResponse, "description": "Internal server error"},
    },
)
async def request_password_reset(
    reset_request: PasswordResetRequest,
    user_service: UserService = Depends(get_user_service),
):
    """
    Request a password reset.

    This endpoint sends a password reset email to the user.

    Raises:
        UserNotFoundException: If the user is not found
        InternalServerException: If an unexpected error occurs
    """
    # Generate a password reset token
    await user_service.request_password_reset(reset_request.email)

    # Return success message
    return {"message": "Password reset email sent"}


@auth_router.post(
    "/password-reset/confirm",
    responses={
        200: {"description": "Password reset successful"},
        400: {"model": ErrorResponse, "description": "Invalid token"},
        404: {"model": ErrorResponse, "description": "User not found"},
        422: {"model": ErrorResponse, "description": "Password validation failed"},
        500: {"model": ErrorResponse, "description": "Internal server error"},
    },
)
async def confirm_password_reset(
    reset_confirm: PasswordResetConfirm,
    user_service: UserService = Depends(get_user_service),
):
    """
    Confirm a password reset.

    This endpoint resets the user's password using a token.

    Raises:
        HTTPException: If the token is invalid
        UserNotFoundException: If the user is not found
        ValidationException: If the password does not meet the requirements
        InternalServerException: If an unexpected error occurs
    """
    # Reset the password
    await user_service.confirm_password_reset(
        reset_confirm.token, reset_confirm.password
    )

    # Return success message
    return {"message": "Password reset successful"}
