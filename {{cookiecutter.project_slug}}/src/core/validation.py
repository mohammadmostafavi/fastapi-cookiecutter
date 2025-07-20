"""
Validation and sanitization utilities for API input and output.

This module provides utilities for:
1. Input validation - Validating and sanitizing incoming request data
2. Output sanitization - Sanitizing outgoing response data
3. Data transformation - Converting data between different formats
4. Custom validators - Complex business rule validation
"""

import re
import html
import json
from typing import Any, Callable, Dict, List, Optional, Type, TypeVar, Union, cast
from datetime import datetime
from pydantic import BaseModel, Field, validator, root_validator
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from src.core.exceptions import ValidationException

# Type variable for generic functions
T = TypeVar('T')
ModelType = TypeVar('ModelType', bound=BaseModel)

# Regular expressions for validation
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{3,32}$')
PASSWORD_PATTERN = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')
NAME_PATTERN = re.compile(r'^[a-zA-Z\s\'-]{1,64}$')
PHONE_PATTERN = re.compile(r'^\+?[0-9]{10,15}$')
URL_PATTERN = re.compile(r'^https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(/[-\w%!$&\'()*+,;=:]+)*(?:\?[-\w%!$&\'()*+,;=:/?]+)?$')

# HTML tags to allow in rich text (for sanitization)
ALLOWED_HTML_TAGS = {
    'a': ['href', 'title', 'target'],
    'b': [],
    'i': [],
    'strong': [],
    'em': [],
    'p': [],
    'br': [],
    'ul': [],
    'ol': [],
    'li': [],
    'h1': [],
    'h2': [],
    'h3': [],
    'h4': [],
    'h5': [],
    'h6': [],
}

# Input validation functions

def validate_username(username: str) -> str:
    """
    Validate a username.
    
    Requirements:
    - 3-32 characters
    - Alphanumeric characters, underscores, and hyphens only
    
    Args:
        username: The username to validate
        
    Returns:
        The validated username
        
    Raises:
        ValidationException: If the username is invalid
    """
    if not USERNAME_PATTERN.match(username):
        raise ValidationException(
            message="Invalid username format",
            details={
                "username": "Username must be 3-32 characters and contain only letters, numbers, underscores, and hyphens"
            }
        )
    return username


def validate_password(password: str) -> str:
    """
    Validate a password.
    
    Requirements:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least one special character (@$!%*?&)
    
    Args:
        password: The password to validate
        
    Returns:
        The validated password
        
    Raises:
        ValidationException: If the password is invalid
    """
    if not PASSWORD_PATTERN.match(password):
        raise ValidationException(
            message="Invalid password format",
            details={
                "password": "Password must be at least 8 characters and contain at least one uppercase letter, "
                           "one lowercase letter, one number, and one special character (@$!%*?&)"
            }
        )
    return password


def validate_name(name: str) -> str:
    """
    Validate a name (first name, last name).
    
    Requirements:
    - 1-64 characters
    - Letters, spaces, apostrophes, and hyphens only
    
    Args:
        name: The name to validate
        
    Returns:
        The validated name
        
    Raises:
        ValidationException: If the name is invalid
    """
    if not NAME_PATTERN.match(name):
        raise ValidationException(
            message="Invalid name format",
            details={
                "name": "Name must be 1-64 characters and contain only letters, spaces, apostrophes, and hyphens"
            }
        )
    return name


def validate_phone(phone: str) -> str:
    """
    Validate a phone number.
    
    Requirements:
    - 10-15 digits
    - Optional leading + sign
    
    Args:
        phone: The phone number to validate
        
    Returns:
        The validated phone number
        
    Raises:
        ValidationException: If the phone number is invalid
    """
    if not PHONE_PATTERN.match(phone):
        raise ValidationException(
            message="Invalid phone number format",
            details={
                "phone": "Phone number must be 10-15 digits with an optional leading + sign"
            }
        )
    return phone


def validate_url(url: str) -> str:
    """
    Validate a URL.
    
    Requirements:
    - Valid HTTP or HTTPS URL
    
    Args:
        url: The URL to validate
        
    Returns:
        The validated URL
        
    Raises:
        ValidationException: If the URL is invalid
    """
    if not URL_PATTERN.match(url):
        raise ValidationException(
            message="Invalid URL format",
            details={
                "url": "URL must be a valid HTTP or HTTPS URL"
            }
        )
    return url


# Data transformation utilities

def to_camel_case(snake_str: str) -> str:
    """
    Convert a snake_case string to camelCase.
    
    Args:
        snake_str: The snake_case string to convert
        
    Returns:
        The camelCase string
    """
    components = snake_str.split('_')
    return components[0] + ''.join(x.title() for x in components[1:])


def to_snake_case(camel_str: str) -> str:
    """
    Convert a camelCase string to snake_case.
    
    Args:
        camel_str: The camelCase string to convert
        
    Returns:
        The snake_case string
    """
    # Insert underscore before uppercase letters and convert to lowercase
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', camel_str)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


def transform_keys(data: Dict[str, Any], transform_func: Callable[[str], str]) -> Dict[str, Any]:
    """
    Transform all keys in a dictionary using the provided function.
    
    Args:
        data: The dictionary to transform
        transform_func: The function to apply to each key
        
    Returns:
        A new dictionary with transformed keys
    """
    result = {}
    for key, value in data.items():
        if isinstance(value, dict):
            value = transform_keys(value, transform_func)
        elif isinstance(value, list):
            value = [
                transform_keys(item, transform_func) if isinstance(item, dict) else item
                for item in value
            ]
        result[transform_func(key)] = value
    return result


def to_camel_case_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert all keys in a dictionary from snake_case to camelCase.
    
    Args:
        data: The dictionary to convert
        
    Returns:
        A new dictionary with camelCase keys
    """
    return transform_keys(data, to_camel_case)


def to_snake_case_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert all keys in a dictionary from camelCase to snake_case.
    
    Args:
        data: The dictionary to convert
        
    Returns:
        A new dictionary with snake_case keys
    """
    return transform_keys(data, to_snake_case)


# Output sanitization functions

def sanitize_html(html_content: str, allowed_tags: Dict[str, List[str]] = ALLOWED_HTML_TAGS) -> str:
    """
    Sanitize HTML content by removing disallowed tags and attributes.
    
    Args:
        html_content: The HTML content to sanitize
        allowed_tags: A dictionary of allowed tags and their allowed attributes
        
    Returns:
        The sanitized HTML content
    """
    # This is a simplified implementation. In a production environment,
    # consider using a dedicated HTML sanitization library like bleach.
    return html.escape(html_content)


def sanitize_string(value: str) -> str:
    """
    Sanitize a string by escaping HTML entities.
    
    Args:
        value: The string to sanitize
        
    Returns:
        The sanitized string
    """
    return html.escape(value)


def sanitize_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize all string values in a dictionary.
    
    Args:
        data: The dictionary to sanitize
        
    Returns:
        A new dictionary with sanitized values
    """
    result = {}
    for key, value in data.items():
        if isinstance(value, str):
            result[key] = sanitize_string(value)
        elif isinstance(value, dict):
            result[key] = sanitize_dict(value)
        elif isinstance(value, list):
            result[key] = [
                sanitize_dict(item) if isinstance(item, dict)
                else sanitize_string(item) if isinstance(item, str)
                else item
                for item in value
            ]
        else:
            result[key] = value
    return result


# Custom validators for Pydantic models

class ValidatedModel(BaseModel):
    """
    Base model with additional validation capabilities.
    """
    
    @classmethod
    def validate_model(cls: Type[ModelType], data: Dict[str, Any]) -> ModelType:
        """
        Validate data against the model and return a model instance.
        
        Args:
            data: The data to validate
            
        Returns:
            A model instance
            
        Raises:
            ValidationException: If validation fails
        """
        try:
            return cls(**data)
        except Exception as e:
            raise ValidationException(
                message="Validation error",
                details={"errors": str(e)}
            )
    
    class Config:
        """Pydantic configuration"""
        validate_assignment = True  # Validate values when attributes are assigned
        extra = "forbid"  # Forbid extra attributes
        
        @classmethod
        def schema_extra(cls, schema: Dict[str, Any]) -> None:
            """
            Customize the JSON schema for better documentation.
            
            Args:
                schema: The schema to customize
            """
            for prop in schema.get("properties", {}).values():
                prop.pop("title", None)
                
            if "required" in schema:
                schema["required"] = sorted(schema["required"])


# Middleware for output sanitization

class OutputSanitizationMiddleware(BaseHTTPMiddleware):
    """
    Middleware for sanitizing API responses.
    """
    
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """
        Process the request and sanitize the response.
        
        Args:
            request: The incoming request
            call_next: The next middleware or endpoint
            
        Returns:
            The sanitized response
        """
        # Process the request normally
        response = await call_next(request)
        
        # Check if the response is JSON
        if response.headers.get("content-type") == "application/json":
            # Get the response body
            body = b""
            async for chunk in response.body_iterator:
                body += chunk
            
            # Parse the JSON
            try:
                data = json.loads(body.decode())
                
                # Sanitize the data
                sanitized_data = sanitize_dict(data)
                
                # Create a new response with sanitized data
                return Response(
                    content=json.dumps(sanitized_data),
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type="application/json"
                )
            except json.JSONDecodeError:
                # If the response is not valid JSON, return it as is
                return Response(
                    content=body,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type=response.media_type
                )
        
        # If the response is not JSON, return it as is
        return response


# Pydantic field validators

def validate_username_field(cls, v: str) -> str:
    """
    Pydantic validator for username fields.
    """
    if v is None:
        return v
    return validate_username(v)


def validate_password_field(cls, v: str) -> str:
    """
    Pydantic validator for password fields.
    """
    if v is None:
        return v
    return validate_password(v)


def validate_name_field(cls, v: str) -> str:
    """
    Pydantic validator for name fields.
    """
    if v is None:
        return v
    return validate_name(v)


def validate_phone_field(cls, v: str) -> str:
    """
    Pydantic validator for phone fields.
    """
    if v is None:
        return v
    return validate_phone(v)


def validate_url_field(cls, v: str) -> str:
    """
    Pydantic validator for URL fields.
    """
    if v is None:
        return v
    return validate_url(v)