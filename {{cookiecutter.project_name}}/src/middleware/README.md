# Middleware

This directory contains middleware components for the application. Middleware components are used to process requests and responses before they reach the route handlers or after they leave the route handlers.

## Contents

- `__init__.py`: Package initialization file
- `error_handlers.py`: Exception handlers for converting exceptions to standardized responses

## Usage

Middleware components can be registered with the FastAPI application in the `main.py` file. For example:

```python
from src.middleware.error_handlers import register_exception_handlers

# Register exception handlers
register_exception_handlers(app)
```

## Adding New Middleware

When adding new middleware, follow these guidelines:

1. Create a new file in this directory for the middleware
2. Use descriptive names for the middleware functions
3. Add proper documentation for the middleware
4. Register the middleware in the `main.py` file

## Types of Middleware

- **Global Middleware**: Applied to all routes in the application
- **Router-specific Middleware**: Applied only to routes in a specific router
- **Exception Handlers**: Special middleware for handling exceptions