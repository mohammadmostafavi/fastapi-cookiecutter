import os

"""
CORS configuration constants.

This module contains constants related to Cross-Origin Resource Sharing (CORS) configuration.
"""

CORS_ALLOW_ORIGINS = os.getenv("CORS_ALLOW_ORIGINS", "*").split(",")
CORS_ALLOW_CREDENTIALS = os.getenv("CORS_ALLOW_CREDENTIALS", "True").lower() == "true"
CORS_ALLOW_METHODS = os.getenv(
    "CORS_ALLOW_METHODS", "GET,POST,PUT,DELETE,OPTIONS,PATCH"
).split(",")
CORS_ALLOW_HEADERS = os.getenv("CORS_ALLOW_HEADERS", "*").split(",")
CORS_EXPOSE_HEADERS = os.getenv("CORS_EXPOSE_HEADERS", "").split(",")
CORS_MAX_AGE = int(os.getenv("CORS_MAX_AGE", "600"))
