"""
Tests for utility functions in src.core.utils.
"""

import pytest
import asyncio
from unittest.mock import patch, MagicMock

from sqlalchemy.exc import OperationalError

from src.core.utils import with_retry, make_password, check_password
from src.core.exceptions import DatabaseRetryableException


@pytest.mark.unit
class TestPasswordUtils:
    """Tests for password utility functions."""

    def test_make_password_with_default_salt(self):
        """Test that make_password generates a hash with a default salt."""
        password = "SecurePassword123!"
        hashed = make_password(password)
        
        # Check format: algorithm$iterations$salt$hash
        parts = hashed.split('$')
        assert len(parts) == 4
        assert parts[0] == "pbkdf2_sha256"  # Default algorithm
        assert parts[1].isdigit()  # Iterations should be a number
        assert len(parts[2]) > 0  # Salt should not be empty
        assert len(parts[3]) > 0  # Hash should not be empty

    def test_make_password_with_custom_salt(self):
        """Test that make_password uses the provided salt."""
        password = "SecurePassword123!"
        salt = "testingsalt"
        hashed = make_password(password, salt=salt)
        
        parts = hashed.split('$')
        assert parts[2] == salt

    def test_make_password_with_custom_iterations(self):
        """Test that make_password uses the provided iteration count."""
        password = "SecurePassword123!"
        iterations = 10000
        hashed = make_password(password, iterations=iterations)
        
        parts = hashed.split('$')
        assert int(parts[1]) == iterations

    def test_check_password_valid(self):
        """Test that check_password correctly verifies a valid password."""
        password = "SecurePassword123!"
        hashed = make_password(password)
        
        assert check_password(password, hashed) is True

    def test_check_password_invalid(self):
        """Test that check_password correctly rejects an invalid password."""
        password = "SecurePassword123!"
        wrong_password = "WrongPassword123!"
        hashed = make_password(password)
        
        assert check_password(wrong_password, hashed) is False

    def test_check_password_invalid_format(self):
        """Test that check_password handles invalid hash formats."""
        password = "SecurePassword123!"
        invalid_hash = "invalid_hash_format"
        
        assert check_password(password, invalid_hash) is False

    def test_check_password_wrong_algorithm(self):
        """Test that check_password rejects hashes with wrong algorithm."""
        password = "SecurePassword123!"
        wrong_algorithm_hash = "wrong_algo$10000$salt$hash"
        
        assert check_password(password, wrong_algorithm_hash) is False


@pytest.mark.unit
@pytest.mark.asyncio
class TestWithRetry:
    """Tests for the with_retry decorator."""

    async def test_successful_execution(self):
        """Test that the decorated function executes successfully without retries."""
        mock_func = MagicMock()
        mock_func.return_value = asyncio.Future()
        mock_func.return_value.set_result("success")
        
        @with_retry()
        async def test_func():
            return await mock_func()
        
        result = await test_func()
        
        assert result == "success"
        assert mock_func.call_count == 1

    async def test_retry_on_retryable_exception(self):
        """Test that the function retries on retryable exceptions."""
        mock_func = MagicMock()
        
        # First call raises a retryable exception, second call succeeds
        first_call = asyncio.Future()
        first_call.set_exception(OperationalError("Connection lost", None, None))
        
        second_call = asyncio.Future()
        second_call.set_result("success after retry")
        
        mock_func.side_effect = [first_call, second_call]
        
        @with_retry(max_retries=3, retry_delay=0.01)
        async def test_func():
            return await mock_func()
        
        result = await test_func()
        
        assert result == "success after retry"
        assert mock_func.call_count == 2

    async def test_retry_on_custom_retryable_exception(self):
        """Test that the function retries on custom retryable exceptions."""
        mock_func = MagicMock()
        
        # First call raises a custom retryable exception, second call succeeds
        first_call = asyncio.Future()
        first_call.set_exception(DatabaseRetryableException("Temporary error"))
        
        second_call = asyncio.Future()
        second_call.set_result("success after retry")
        
        mock_func.side_effect = [first_call, second_call]
        
        @with_retry(max_retries=3, retry_delay=0.01)
        async def test_func():
            return await mock_func()
        
        result = await test_func()
        
        assert result == "success after retry"
        assert mock_func.call_count == 2

    async def test_max_retries_exceeded(self):
        """Test that the function raises an exception after max retries."""
        mock_func = MagicMock()
        
        # All calls raise retryable exceptions
        error = OperationalError("Connection lost", None, None)
        future = asyncio.Future()
        future.set_exception(error)
        mock_func.return_value = future
        
        @with_retry(max_retries=2, retry_delay=0.01)
        async def test_func():
            return await mock_func()
        
        with pytest.raises(OperationalError):
            await test_func()
        
        assert mock_func.call_count == 3  # Initial attempt + 2 retries

    async def test_non_retryable_exception(self):
        """Test that the function doesn't retry on non-retryable exceptions."""
        mock_func = MagicMock()
        
        # Raise a non-retryable exception
        error = ValueError("Non-retryable error")
        future = asyncio.Future()
        future.set_exception(error)
        mock_func.return_value = future
        
        @with_retry(max_retries=3, retry_delay=0.01)
        async def test_func():
            return await mock_func()
        
        with pytest.raises(ValueError):
            await test_func()
        
        assert mock_func.call_count == 1  # No retries

    async def test_backoff_delay(self):
        """Test that the retry delay increases with each retry."""
        mock_func = MagicMock()
        mock_sleep = MagicMock()
        
        # All calls raise retryable exceptions
        error = OperationalError("Connection lost", None, None)
        future = asyncio.Future()
        future.set_exception(error)
        mock_func.return_value = future
        
        @with_retry(max_retries=3, retry_delay=0.1, backoff_factor=2)
        async def test_func():
            return await mock_func()
        
        with patch('asyncio.sleep', mock_sleep):
            with pytest.raises(OperationalError):
                await test_func()
        
        # Check that sleep was called with increasing delays
        assert mock_sleep.call_count == 3
        assert mock_sleep.call_args_list[0][0][0] == 0.1  # First retry: 0.1s
        assert mock_sleep.call_args_list[1][0][0] == 0.2  # Second retry: 0.1 * 2 = 0.2s
        assert mock_sleep.call_args_list[2][0][0] == 0.4  # Third retry: 0.2 * 2 = 0.4s