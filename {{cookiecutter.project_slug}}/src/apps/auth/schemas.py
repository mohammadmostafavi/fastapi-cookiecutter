from pydantic import BaseModel, EmailStr, Field, validator
from typing import List, Optional

from src.core.validation import (
    ValidatedModel,
    validate_username_field,
    validate_password_field,
    validate_name_field,
)

class UserCreate(ValidatedModel):
    username: str = Field(..., min_length=3, max_length=32, description="Username for the user")
    first_name: Optional[str] = Field(None, min_length=1, max_length=64, description="First name of the user")
    last_name: Optional[str] = Field(None, min_length=1, max_length=64, description="Last name of the user")
    email: EmailStr = Field(..., description="Email address of the user")
    password: str = Field(..., min_length=8, description="Password for the user")

    # Custom validators
    _validate_username = validator('username')(validate_username_field)
    _validate_password = validator('password')(validate_password_field)
    _validate_first_name = validator('first_name')(validate_name_field)
    _validate_last_name = validator('last_name')(validate_name_field)

class UserUpdate(ValidatedModel):
    username: Optional[str] = Field(None, min_length=3, max_length=32, description="Username for the user")
    first_name: Optional[str] = Field(None, min_length=1, max_length=64, description="First name of the user")
    last_name: Optional[str] = Field(None, min_length=1, max_length=64, description="Last name of the user")
    email: Optional[EmailStr] = Field(None, description="Email address of the user")
    password: Optional[str] = Field(None, min_length=8, description="Password for the user")
    is_staff: Optional[bool] = Field(None, description="Whether the user is staff")
    is_active: Optional[bool] = Field(None, description="Whether the user is active")
    is_superuser: Optional[bool] = Field(None, description="Whether the user is a superuser")

    # Custom validators
    _validate_username = validator('username')(validate_username_field)
    _validate_password = validator('password')(validate_password_field)
    _validate_first_name = validator('first_name')(validate_name_field)
    _validate_last_name = validator('last_name')(validate_name_field)

class UserLogin(ValidatedModel):
    username: str = Field(..., min_length=3, max_length=32, description="Username for the user")
    password: str = Field(..., min_length=8, description="Password for the user")

    # Custom validators
    _validate_username = validator('username')(validate_username_field)

class UserResponse(ValidatedModel):
    id: int = Field(..., description="Unique identifier for the user")
    username: str = Field(..., min_length=3, max_length=32, description="Username for the user")
    first_name: Optional[str] = Field(None, min_length=1, max_length=64, description="First name of the user")
    last_name: Optional[str] = Field(None, min_length=1, max_length=64, description="Last name of the user")
    email: EmailStr = Field(..., description="Email address of the user")
    is_staff: bool = Field(False, description="Whether the user is staff")
    is_active: bool = Field(True, description="Whether the user is active")
    is_superuser: bool = Field(False, description="Whether the user is a superuser")
    # roles: list[str] = []
    # permissions: list[str] = []

    class Config:
        orm_mode = True  # Enable ORM mode to read data from ORM models

class Token(ValidatedModel):
    """
    Schema for JWT token response.
    """
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field("bearer", description="Token type")

class TokenPayload(ValidatedModel):
    """
    Schema for JWT token payload.
    """
    sub: str = Field(..., description="Subject (user ID)")
    exp: int = Field(..., description="Expiration time")
    iat: int = Field(..., description="Issued at")
    type: str = Field(..., description="Token type (access or refresh)")
    roles: List[str] = Field(default_factory=list, description="User roles")
    permissions: List[str] = Field(default_factory=list, description="User permissions")

class RefreshToken(ValidatedModel):
    """
    Schema for refresh token request.
    """
    refresh_token: str = Field(..., description="JWT refresh token")

class PasswordResetRequest(ValidatedModel):
    """
    Schema for password reset request.
    """
    email: EmailStr = Field(..., description="Email address for password reset")

class PasswordResetConfirm(ValidatedModel):
    """
    Schema for password reset confirmation.
    """
    token: str = Field(..., description="Password reset token")
    password: str = Field(..., min_length=8, description="New password")
    
    # Custom validators
    _validate_password = validator('password')(validate_password_field)
