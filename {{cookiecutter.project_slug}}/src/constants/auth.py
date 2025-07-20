import os

"""
Authentication-related constants.

This module contains constants related to authentication and authorization.
"""
# OAuth settings
OAUTH_TOKEN_SECRET = os.getenv("OAUTH_TOKEN_SECRET", "my_dev_secret")

# JWT settings
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 30
JWT_REFRESH_TOKEN_EXPIRE_DAYS = 7

# Password settings
PASSWORD_MIN_LENGTH = 8
PASSWORD_REQUIRE_UPPERCASE = True
PASSWORD_REQUIRE_LOWERCASE = True
PASSWORD_REQUIRE_DIGITS = True
PASSWORD_REQUIRE_SPECIAL_CHARS = True
PASSWORD_SPECIAL_CHARS = "!@#$%^&*()-_=+[]{}|;:,.<>?/~"

# Password hashing settings
PASSWORD_HASH_NAME = "pbkdf2_sha256"
PASSWORD_DEFAULT_ITERATIONS = 390000
PASSWORD_SALT_LENGTH = 16

# Authentication rate limiting
MAX_LOGIN_ATTEMPTS = 5
LOGIN_COOLDOWN_MINUTES = 15
