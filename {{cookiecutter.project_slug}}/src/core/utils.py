import hashlib
import secrets
import base64
import hmac
import asyncio
import logging
import functools
import time
from typing import Type, Callable, TypeVar, List, Optional, Any, Union, cast

from sqlalchemy.exc import SQLAlchemyError, OperationalError, IntegrityError, DBAPIError

from src.constants.auth import (
    PASSWORD_HASH_NAME,
    PASSWORD_DEFAULT_ITERATIONS,
    PASSWORD_SALT_LENGTH
)
from src.constants.database import (
    DEFAULT_MAX_RETRIES,
    DEFAULT_RETRY_DELAY,
    DEFAULT_RETRY_BACKOFF,
    DEFAULT_RETRY_MAX_DELAY
)
from src.core.exceptions import DatabaseRetryableException, DatabaseConnectionException

# Configure logger
logger = logging.getLogger(__name__)

# Type variable for the retry decorator
T = TypeVar('T')

# Exceptions that should be retried by default
DEFAULT_RETRYABLE_EXCEPTIONS = (
    OperationalError,  # Connection errors, timeouts, etc.
    DatabaseRetryableException,  # Custom retryable exceptions
)

def with_retry(
    max_retries: int = DEFAULT_MAX_RETRIES,
    retry_delay: float = DEFAULT_RETRY_DELAY,
    backoff_factor: float = DEFAULT_RETRY_BACKOFF,
    max_delay: float = DEFAULT_RETRY_MAX_DELAY,
    retryable_exceptions: tuple = DEFAULT_RETRYABLE_EXCEPTIONS
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator for retrying database operations that fail due to transient errors.
    
    Args:
        max_retries: Maximum number of retry attempts
        retry_delay: Initial delay between retries in seconds
        backoff_factor: Factor by which the delay increases with each retry
        max_delay: Maximum delay between retries in seconds
        retryable_exceptions: Tuple of exception types that should trigger a retry
        
    Returns:
        Decorated function with retry logic
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> T:
            last_exception = None
            delay = retry_delay
            
            for attempt in range(max_retries + 1):
                try:
                    if attempt > 0:
                        logger.info(
                            f"Retry attempt {attempt}/{max_retries} for {func.__name__} "
                            f"after {delay:.2f}s delay"
                        )
                    
                    return await func(*args, **kwargs)
                    
                except retryable_exceptions as e:
                    last_exception = e
                    
                    if attempt >= max_retries:
                        logger.error(
                            f"Max retries ({max_retries}) exceeded for {func.__name__}: {str(e)}"
                        )
                        raise
                    
                    # Log the exception
                    logger.warning(
                        f"Retryable exception in {func.__name__} (attempt {attempt+1}/{max_retries}): {str(e)}"
                    )
                    
                    # Calculate delay with exponential backoff
                    delay = min(delay * backoff_factor, max_delay)
                    
                    # Wait before retrying
                    await asyncio.sleep(delay)
                
                except Exception as e:
                    # Non-retryable exception, log and re-raise
                    logger.error(f"Non-retryable exception in {func.__name__}: {str(e)}")
                    raise
            
            # This should never be reached due to the raise in the loop,
            # but added for type safety
            assert last_exception is not None
            raise last_exception
            
        return wrapper
    
    return decorator

def make_password(password: str, salt: str = None, iterations: int = PASSWORD_DEFAULT_ITERATIONS) -> str:
    """
    Create a password hash.
    """
    if salt is None:
        salt = secrets.token_hex(PASSWORD_SALT_LENGTH)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), iterations)
    hash_b64 = base64.b64encode(dk).decode().strip()
    return f"{PASSWORD_HASH_NAME}${iterations}${salt}${hash_b64}"


def check_password(password: str, encoded: str) -> bool:
    """
    Verify a password hash.
    """
    try:
        algorithm, iterations, salt, hash_b64 = encoded.split('$', 3)
        assert algorithm == PASSWORD_HASH_NAME
        iterations = int(iterations)
    except (ValueError, AssertionError):
        return False

    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), iterations)
    calculated_hash = base64.b64encode(dk).decode().strip()

    # Use hmac.compare_digest for timing-safe comparison
    return hmac.compare_digest(calculated_hash, hash_b64)

