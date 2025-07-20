"""
Tests for validation and sanitization utilities.
"""

import pytest
import json
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel, Field, validator

from src.core.validation import (
    validate_username,
    validate_password,
    validate_name,
    validate_phone,
    validate_url,
    to_camel_case,
    to_snake_case,
    to_camel_case_dict,
    to_snake_case_dict,
    sanitize_string,
    sanitize_dict,
    ValidatedModel,
    OutputSanitizationMiddleware,
)
from src.core.exceptions import ValidationException


# Input validation tests

def test_validate_username_valid():
    """Test that valid usernames pass validation."""
    valid_usernames = [
        "user123",
        "john_doe",
        "jane-doe",
        "admin",
        "user_123_456",
    ]
    
    for username in valid_usernames:
        assert validate_username(username) == username


def test_validate_username_invalid():
    """Test that invalid usernames fail validation."""
    invalid_usernames = [
        "us",  # Too short
        "a" * 33,  # Too long
        "user@123",  # Invalid character
        "user 123",  # Space not allowed
        "user.123",  # Period not allowed
    ]
    
    for username in invalid_usernames:
        with pytest.raises(ValidationException):
            validate_username(username)


def test_validate_password_valid():
    """Test that valid passwords pass validation."""
    valid_passwords = [
        "Password123!",
        "SecureP@ss1",
        "Abcdef1@gh",
        "P@ssw0rd",
        "C0mpl3x!P@ssw0rd",
    ]
    
    for password in valid_passwords:
        assert validate_password(password) == password


def test_validate_password_invalid():
    """Test that invalid passwords fail validation."""
    invalid_passwords = [
        "password",  # No uppercase, no number, no special char
        "Password",  # No number, no special char
        "password123",  # No uppercase, no special char
        "Password!",  # No number
        "PASS123!",  # No lowercase
        "Pass1!",  # Too short
    ]
    
    for password in invalid_passwords:
        with pytest.raises(ValidationException):
            validate_password(password)


def test_validate_name_valid():
    """Test that valid names pass validation."""
    valid_names = [
        "John",
        "Jane Doe",
        "Mary-Jane",
        "O'Connor",
        "John Smith Jr.",
    ]
    
    for name in valid_names:
        assert validate_name(name) == name


def test_validate_name_invalid():
    """Test that invalid names fail validation."""
    invalid_names = [
        "",  # Empty
        "a" * 65,  # Too long
        "John123",  # Numbers not allowed
        "John@Doe",  # Special chars not allowed (except ', -, space)
    ]
    
    for name in invalid_names:
        with pytest.raises(ValidationException):
            validate_name(name)


def test_validate_phone_valid():
    """Test that valid phone numbers pass validation."""
    valid_phones = [
        "1234567890",
        "+1234567890",
        "123456789012345",
        "+123456789012345",
    ]
    
    for phone in valid_phones:
        assert validate_phone(phone) == phone


def test_validate_phone_invalid():
    """Test that invalid phone numbers fail validation."""
    invalid_phones = [
        "123456789",  # Too short
        "1234567890123456",  # Too long
        "+12345678901234567",  # Too long with +
        "123-456-7890",  # Hyphens not allowed
        "123 456 7890",  # Spaces not allowed
        "123.456.7890",  # Periods not allowed
    ]
    
    for phone in invalid_phones:
        with pytest.raises(ValidationException):
            validate_phone(phone)


def test_validate_url_valid():
    """Test that valid URLs pass validation."""
    valid_urls = [
        "http://example.com",
        "https://example.com",
        "http://example.com/path",
        "https://example.com/path?query=value",
        "https://sub.example.com/path",
    ]
    
    for url in valid_urls:
        assert validate_url(url) == url


def test_validate_url_invalid():
    """Test that invalid URLs fail validation."""
    invalid_urls = [
        "example.com",  # Missing protocol
        "ftp://example.com",  # Invalid protocol
        "http:/example.com",  # Missing slash
        "http://",  # Missing domain
    ]
    
    for url in invalid_urls:
        with pytest.raises(ValidationException):
            validate_url(url)


# Data transformation tests

def test_to_camel_case():
    """Test converting snake_case to camelCase."""
    assert to_camel_case("snake_case") == "snakeCase"
    assert to_camel_case("snake_case_string") == "snakeCaseString"
    assert to_camel_case("already_camel_case") == "alreadyCamelCase"
    assert to_camel_case("single") == "single"
    assert to_camel_case("") == ""


def test_to_snake_case():
    """Test converting camelCase to snake_case."""
    assert to_snake_case("camelCase") == "camel_case"
    assert to_snake_case("camelCaseString") == "camel_case_string"
    assert to_snake_case("CamelCase") == "camel_case"
    assert to_snake_case("single") == "single"
    assert to_snake_case("") == ""


def test_to_camel_case_dict():
    """Test converting all keys in a dictionary from snake_case to camelCase."""
    snake_dict = {
        "user_id": 1,
        "first_name": "John",
        "last_name": "Doe",
        "user_profile": {
            "profile_picture": "http://example.com/pic.jpg",
            "contact_info": {
                "email_address": "john@example.com",
                "phone_number": "1234567890"
            }
        },
        "user_roles": ["admin", "user"]
    }
    
    expected_camel_dict = {
        "userId": 1,
        "firstName": "John",
        "lastName": "Doe",
        "userProfile": {
            "profilePicture": "http://example.com/pic.jpg",
            "contactInfo": {
                "emailAddress": "john@example.com",
                "phoneNumber": "1234567890"
            }
        },
        "userRoles": ["admin", "user"]
    }
    
    assert to_camel_case_dict(snake_dict) == expected_camel_dict


def test_to_snake_case_dict():
    """Test converting all keys in a dictionary from camelCase to snake_case."""
    camel_dict = {
        "userId": 1,
        "firstName": "John",
        "lastName": "Doe",
        "userProfile": {
            "profilePicture": "http://example.com/pic.jpg",
            "contactInfo": {
                "emailAddress": "john@example.com",
                "phoneNumber": "1234567890"
            }
        },
        "userRoles": ["admin", "user"]
    }
    
    expected_snake_dict = {
        "user_id": 1,
        "first_name": "John",
        "last_name": "Doe",
        "user_profile": {
            "profile_picture": "http://example.com/pic.jpg",
            "contact_info": {
                "email_address": "john@example.com",
                "phone_number": "1234567890"
            }
        },
        "user_roles": ["admin", "user"]
    }
    
    assert to_snake_case_dict(camel_dict) == expected_snake_dict


# Output sanitization tests

def test_sanitize_string():
    """Test sanitizing strings by escaping HTML entities."""
    assert sanitize_string("<script>alert('XSS')</script>") == "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;"
    assert sanitize_string("<b>Bold</b>") == "&lt;b&gt;Bold&lt;/b&gt;"
    assert sanitize_string("Normal text") == "Normal text"
    assert sanitize_string("") == ""


def test_sanitize_dict():
    """Test sanitizing all string values in a dictionary."""
    unsanitized_dict = {
        "name": "<script>alert('XSS')</script>",
        "description": "<b>Bold</b>",
        "tags": ["<i>Tag1</i>", "<u>Tag2</u>"],
        "metadata": {
            "html": "<p>Paragraph</p>",
            "count": 42
        }
    }
    
    expected_sanitized_dict = {
        "name": "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;",
        "description": "&lt;b&gt;Bold&lt;/b&gt;",
        "tags": ["&lt;i&gt;Tag1&lt;/i&gt;", "&lt;u&gt;Tag2&lt;/u&gt;"],
        "metadata": {
            "html": "&lt;p&gt;Paragraph&lt;/p&gt;",
            "count": 42
        }
    }
    
    assert sanitize_dict(unsanitized_dict) == expected_sanitized_dict


# Custom validators tests

class TestUser(ValidatedModel):
    """Test model for ValidatedModel."""
    username: str = Field(..., min_length=3, max_length=32)
    password: str = Field(..., min_length=8)
    
    @validator("username")
    def validate_username(cls, v):
        return validate_username(v)
    
    @validator("password")
    def validate_password(cls, v):
        return validate_password(v)


def test_validated_model_valid():
    """Test that valid data passes validation in ValidatedModel."""
    valid_data = {
        "username": "john_doe",
        "password": "Password123!"
    }
    
    user = TestUser.validate_model(valid_data)
    assert user.username == "john_doe"
    assert user.password == "Password123!"


def test_validated_model_invalid():
    """Test that invalid data fails validation in ValidatedModel."""
    invalid_data = [
        {"username": "jo", "password": "Password123!"},  # Username too short
        {"username": "john_doe", "password": "pass"},  # Password too short
        {"username": "john@doe", "password": "Password123!"},  # Invalid username
        {"username": "john_doe", "password": "password"},  # Invalid password
    ]
    
    for data in invalid_data:
        with pytest.raises(ValidationException):
            TestUser.validate_model(data)


# Middleware tests

def test_output_sanitization_middleware():
    """Test that OutputSanitizationMiddleware sanitizes responses."""
    app = FastAPI()
    
    @app.get("/test")
    def test_endpoint():
        return {
            "name": "<script>alert('XSS')</script>",
            "description": "<b>Bold</b>"
        }
    
    app.add_middleware(OutputSanitizationMiddleware)
    client = TestClient(app)
    
    response = client.get("/test")
    assert response.status_code == 200
    
    data = response.json()
    assert data["name"] == "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;"
    assert data["description"] == "&lt;b&gt;Bold&lt;/b&gt;"