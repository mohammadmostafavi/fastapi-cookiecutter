# Validation and Sanitization Guide

This document provides guidelines and examples for implementing data validation and sanitization in the FastAPI application.

## Table of Contents

1. [Introduction](#introduction)
2. [Input Validation](#input-validation)
3. [Output Sanitization](#output-sanitization)
4. [Data Transformation](#data-transformation)
5. [Custom Validators](#custom-validators)
6. [Best Practices](#best-practices)

## Introduction

Data validation and sanitization are critical components of secure and reliable API development. This guide outlines the approach and utilities available in the project for:

- Validating input data to ensure it meets business requirements
- Sanitizing output data to prevent security vulnerabilities
- Transforming data between different formats
- Implementing custom validation rules for complex business logic

## Input Validation

### Using Pydantic Models

The primary method for input validation is through Pydantic models. All request schemas should inherit from `ValidatedModel` instead of `BaseModel` to leverage enhanced validation capabilities.

```python
from pydantic import Field
from src.core.validation import ValidatedModel, validate_username_field

class UserCreate(ValidatedModel):
    username: str = Field(..., min_length=3, max_length=32, description="Username for the user")
    email: EmailStr = Field(..., description="Email address of the user")
    password: str = Field(..., min_length=8, description="Password for the user")
    
    # Custom validators
    _validate_username = validator('username')(validate_username_field)
```

### Field Constraints

Use Pydantic's `Field` to define constraints:

- `min_length` / `max_length`: For string length validation
- `ge` / `le` / `gt` / `lt`: For numeric range validation
- `regex`: For pattern matching
- `description`: For API documentation

### Validation Functions

The following validation functions are available in `src.core.validation`:

| Function | Description | Validation Rules |
|----------|-------------|------------------|
| `validate_username` | Validates usernames | 3-32 chars, alphanumeric, underscores, hyphens |
| `validate_password` | Validates passwords | Min 8 chars, uppercase, lowercase, number, special char |
| `validate_name` | Validates names | 1-64 chars, letters, spaces, apostrophes, hyphens |
| `validate_phone` | Validates phone numbers | 10-15 digits, optional leading + |
| `validate_url` | Validates URLs | Valid HTTP or HTTPS URL |

### Using Validators in Pydantic Models

To apply custom validation to a field, use the `validator` decorator:

```python
from pydantic import validator
from src.core.validation import validate_password_field

class UserCreate(ValidatedModel):
    password: str = Field(..., min_length=8)
    
    # Method 1: Using predefined validator functions
    _validate_password = validator('password')(validate_password_field)
    
    # Method 2: Using custom validator methods
    @validator('password')
    def validate_password(cls, v):
        if 'password' in v.lower():
            raise ValidationException(
                message="Password cannot contain the word 'password'",
                details={"password": "Insecure password"}
            )
        return v
```

## Output Sanitization

### Middleware Approach

The application uses the `OutputSanitizationMiddleware` to automatically sanitize all JSON responses. This middleware is registered in the application startup and sanitizes all string values in the response to prevent XSS attacks.

No additional code is required in the route handlers as the sanitization happens automatically.

### Manual Sanitization

For cases where you need to manually sanitize data:

```python
from src.core.validation import sanitize_string, sanitize_dict

# Sanitize a single string
safe_text = sanitize_string("<script>alert('XSS')</script>")

# Sanitize an entire dictionary
data = {
    "name": "<b>Bold Name</b>",
    "description": "<script>alert('XSS')</script>"
}
safe_data = sanitize_dict(data)
```

## Data Transformation

### Case Conversion

The following utilities are available for case conversion:

| Function | Description | Example |
|----------|-------------|---------|
| `to_camel_case` | Convert snake_case to camelCase | `user_name` → `userName` |
| `to_snake_case` | Convert camelCase to snake_case | `userName` → `user_name` |
| `to_camel_case_dict` | Convert all keys in a dict to camelCase | `{"user_id": 1}` → `{"userId": 1}` |
| `to_snake_case_dict` | Convert all keys in a dict to snake_case | `{"userId": 1}` → `{"user_id": 1}` |

These utilities are useful for API responses that need to follow JavaScript naming conventions or for processing incoming data from external systems.

## Custom Validators

### Creating Custom Validators

For complex business rules, create custom validators that encapsulate the validation logic:

```python
from src.core.exceptions import ValidationException

def validate_order_status_transition(current_status: str, new_status: str) -> bool:
    """
    Validate that a status transition is allowed.
    
    Args:
        current_status: The current order status
        new_status: The new order status
        
    Returns:
        True if the transition is valid
        
    Raises:
        ValidationException: If the transition is invalid
    """
    allowed_transitions = {
        "pending": ["processing", "cancelled"],
        "processing": ["shipped", "cancelled"],
        "shipped": ["delivered", "returned"],
        "delivered": ["returned"],
        "cancelled": [],
        "returned": []
    }
    
    if new_status not in allowed_transitions.get(current_status, []):
        raise ValidationException(
            message=f"Invalid status transition from {current_status} to {new_status}",
            details={
                "current_status": current_status,
                "new_status": new_status,
                "allowed_transitions": allowed_transitions.get(current_status, [])
            }
        )
    
    return True
```

### Using ValidatedModel

The `ValidatedModel` class provides additional validation capabilities beyond standard Pydantic models:

- Forbids extra attributes by default
- Validates values when attributes are assigned
- Provides a `validate_model` method that raises `ValidationException` instead of Pydantic's validation errors
- Customizes the JSON schema for better documentation

```python
from src.core.validation import ValidatedModel

class MyModel(ValidatedModel):
    name: str
    age: int
    
    class Config:
        # Additional configuration options
        extra = "forbid"  # Forbid extra attributes (default for ValidatedModel)
        validate_assignment = True  # Validate values when attributes are assigned (default for ValidatedModel)
```

## Best Practices

1. **Always validate input data**: Use Pydantic models with appropriate field constraints and validators for all API endpoints.

2. **Use descriptive error messages**: When validation fails, provide clear error messages that help the client understand what went wrong.

3. **Sanitize all output data**: Ensure that all data returned to clients is properly sanitized to prevent XSS attacks.

4. **Separate validation logic**: For complex validation rules, create separate validator functions that can be reused across the application.

5. **Document validation rules**: Include validation rules in API documentation so clients know what to expect.

6. **Test validation and sanitization**: Write tests for validation and sanitization to ensure they work as expected.

7. **Handle validation errors gracefully**: Use exception handlers to convert validation errors into appropriate HTTP responses.

8. **Validate at the appropriate level**: Some validation should happen at the schema level, while others might need to happen at the service or repository level.

9. **Consider performance**: For high-volume APIs, balance validation thoroughness with performance considerations.

10. **Keep security in mind**: Validation and sanitization are important security controls - don't bypass them for convenience.