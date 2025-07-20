# FastAPI Style Guide Project

A FastAPI project following best practices for structure, organization, and code style.

## Project Structure

The project follows a modular structure with clear separation of concerns:

```
src/
├── apps/                  # Domain-specific modules
│   ├── auth/              # Authentication module
│   │   ├── exceptions.py  # Auth-specific exceptions
│   │   ├── models.py      # Database models
│   │   ├── repositories.py # Data access layer
│   │   ├── routes.py      # API endpoints
│   │   ├── schemas.py     # Pydantic models
│   │   └── services.py    # Business logic
│   └── logs/              # Logging module
│       ├── models.py      # Database models
│       ├── repositories.py # Data access layer
│       └── services.py    # Business logic
├── constants/             # Application constants
│   ├── app.py             # Application-wide constants
│   ├── auth.py            # Authentication constants
│   └── database.py        # Database constants
├── core/                  # Core functionality
│   ├── decorators.py      # Reusable decorators
│   ├── dependencies.py    # Dependency injection
│   ├── exceptions.py      # Base exceptions
│   ├── models.py          # Base models
│   ├── repository.py      # Base repository
│   ├── schemas.py         # Base schemas
│   └── utils.py           # Utility functions
├── middleware/            # Middleware components
│   ├── error_handlers.py  # Exception handlers
│   └── request_middleware.py # Request processing
├── config.py              # Application configuration
├── database.py            # Database connection
└── main.py                # Application entry point
```

## Key Features

- **Modular Structure**: Domain-specific code is organized into separate modules
- **Separation of Concerns**: Clear separation between models, repositories, services, and routes
- **Dependency Injection**: Uses FastAPI's dependency injection system
- **Standardized Error Handling**: Consistent error responses across the API
- **Middleware**: Request processing and error handling middleware
- **Constants**: Centralized constants for easy maintenance
- **Security**: HTTPS, CORS, security headers, and Content Security Policy

## Security Features

The application implements several security best practices:

### CORS Settings

Cross-Origin Resource Sharing (CORS) is properly configured:

- Configurable allowed origins, methods, and headers
- Credentials support for authenticated cross-origin requests
- Preflight request handling

Configuration options:
```
CORS_ALLOW_ORIGINS=https://example.com,https://api.example.com
CORS_ALLOW_CREDENTIALS=True
CORS_ALLOW_METHODS=GET,POST,PUT,DELETE,OPTIONS,PATCH
CORS_ALLOW_HEADERS=Authorization,Content-Type,Accept
CORS_EXPOSE_HEADERS=
CORS_MAX_AGE=600
```

### Security Headers

The application sets various security headers to protect against common web vulnerabilities:

- **X-Content-Type-Options**: Prevents MIME type sniffing
- **X-Frame-Options**: Protects against clickjacking
- **X-XSS-Protection**: Helps prevent cross-site scripting attacks
- **Strict-Transport-Security**: Enforces HTTPS usage
- **Referrer-Policy**: Controls referrer information

Configuration options:
```
HSTS_MAX_AGE=31536000  # 1 year in seconds
```

### Content Security Policy

Content Security Policy (CSP) is implemented to prevent cross-site scripting and other code injection attacks:

- Restricts which resources can be loaded
- Configurable directives for scripts, styles, images, etc.
- Can be enabled/disabled as needed

Configuration options:
```
CSP_ENABLED=True
CSP_DEFAULT_SRC='self'
CSP_SCRIPT_SRC='self'
CSP_STYLE_SRC='self' 'unsafe-inline'
CSP_IMG_SRC='self' data:
CSP_CONNECT_SRC='self'
CSP_FONT_SRC='self'
CSP_OBJECT_SRC='none'
CSP_MEDIA_SRC='self'
CSP_FRAME_SRC='none'
CSP_REPORT_URI=
```

## Development Guidelines

### Adding New Features

1. Determine which domain the feature belongs to (auth, logs, etc.)
2. Create a new module in the `apps` directory if needed
3. Follow the existing structure for models, repositories, services, and routes
4. Use the dependency injection system for dependencies
5. Add appropriate error handling

### Code Style

- Use descriptive variable and function names
- Add docstrings to all functions, classes, and modules
- Follow PEP 8 guidelines for Python code
- Use type hints for function parameters and return values
- Write unit tests for all functionality

## Running the Application

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
uvicorn src.main:app --reload
```

## API Documentation

Once the application is running, you can access the API documentation at:

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc