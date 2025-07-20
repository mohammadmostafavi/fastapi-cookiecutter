import os

"""
Application-wide constants.

This module contains constants used throughout the application.
"""
# Application metadata
APP_NAME = {{cookiecutter.project_name}}
APP_VERSION = "0.1.0"
APP_DESCRIPTION = {{cookiecutter.project_description}}

# Debug settings
DEBUG = os.getenv("DEBUG", "False").lower() == "true"

# API settings
API_PREFIX = "/api"
API_V1_PREFIX = "/v1"
DEFAULT_RESPONSES = {
    400: {"description": "Bad Request"},
    401: {"description": "Unauthorized"},
    403: {"description": "Forbidden"},
    404: {"description": "Not Found"},
    500: {"description": "Internal Server Error"},
}

# Logging settings
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Cache settings
CACHE_TTL_SHORT = 60  # 1 minute
CACHE_TTL_MEDIUM = 300  # 5 minutes
CACHE_TTL_LONG = 3600  # 1 hour
CACHE_TTL_VERY_LONG = 86400  # 1 day

# File upload settings
MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10 MB
ALLOWED_UPLOAD_EXTENSIONS = [".jpg", ".jpeg", ".png", ".pdf", ".doc", ".docx"]
