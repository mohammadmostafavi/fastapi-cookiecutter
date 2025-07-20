"""
Database-related constants.

This module contains constants related to database configuration and operations.
"""

import os

DB_URL = os.getenv("DB_URL", "postgresql+asyncpg://user:password@localhost:5432/mydb")

# Database connection pool settings
DEFAULT_POOL_SIZE = 5
DEFAULT_MAX_OVERFLOW = 10
DEFAULT_POOL_TIMEOUT = 30
DEFAULT_POOL_RECYCLE = 1800  # 30 minutes

# Query execution settings
DEFAULT_STATEMENT_TIMEOUT = 60  # seconds
DEFAULT_QUERY_CACHE_SIZE = 100

# Pagination defaults
DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100

# Retry settings
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_DELAY = 0.1  # seconds
DEFAULT_RETRY_BACKOFF = 2  # exponential backoff factor
DEFAULT_RETRY_MAX_DELAY = 10  # seconds

# Health check settings
HEALTH_CHECK_TIMEOUT = 5  # seconds
HEALTH_CHECK_INTERVAL = 60  # seconds

# Performance monitoring settings
SLOW_QUERY_THRESHOLD = 1.0  # seconds
QUERY_SAMPLE_RATE = 0.1  # sample 10% of queries for detailed logging
MAX_QUERY_LOG_LENGTH = 1000  # characters
