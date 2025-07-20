"""
Database monitoring middleware.

This module provides middleware for monitoring database performance and logging slow queries.
"""

import logging
import time
import random
from typing import Dict, Any, Optional, List, Callable

from sqlalchemy.engine import Engine
from sqlalchemy.event import listen
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine

from src.constants.database import (
    SLOW_QUERY_THRESHOLD,
    QUERY_SAMPLE_RATE,
    MAX_QUERY_LOG_LENGTH,
)

# Configure logger
logger = logging.getLogger(__name__)

# Global query statistics
query_stats: Dict[str, Any] = {
    "total_queries": 0,
    "slow_queries": 0,
    "total_time": 0.0,
    "max_time": 0.0,
    "slow_queries_list": [],  # Limited list of recent slow queries
}


def setup_database_monitoring(engine: AsyncEngine) -> None:
    """
    Set up database monitoring for the given engine.
    
    Args:
        engine: SQLAlchemy async engine
    """
    # Get the underlying sync engine
    sync_engine = engine.sync_engine
    
    # Set up event listeners
    listen(sync_engine, "before_cursor_execute", before_cursor_execute)
    listen(sync_engine, "after_cursor_execute", after_cursor_execute)
    
    logger.info("Database monitoring set up successfully")


def before_cursor_execute(
    conn, cursor, statement, parameters, context, executemany
) -> None:
    """
    Event hook that fires before a query is executed.
    
    Args:
        conn: Connection
        cursor: Cursor
        statement: SQL statement
        parameters: Query parameters
        context: Execution context
        executemany: Whether this is an executemany operation
    """
    # Store the start time in the context
    context._query_start_time = time.time()
    
    # Sample a percentage of queries for detailed logging
    context._log_query = random.random() < QUERY_SAMPLE_RATE


def after_cursor_execute(
    conn, cursor, statement, parameters, context, executemany
) -> None:
    """
    Event hook that fires after a query is executed.
    
    Args:
        conn: Connection
        cursor: Cursor
        statement: SQL statement
        parameters: Query parameters
        context: Execution context
        executemany: Whether this is an executemany operation
    """
    # Calculate query execution time
    execution_time = time.time() - context._query_start_time
    
    # Update global statistics
    query_stats["total_queries"] += 1
    query_stats["total_time"] += execution_time
    
    if execution_time > query_stats["max_time"]:
        query_stats["max_time"] = execution_time
    
    # Log slow queries
    if execution_time >= SLOW_QUERY_THRESHOLD:
        query_stats["slow_queries"] += 1
        
        # Truncate the statement if it's too long
        if len(statement) > MAX_QUERY_LOG_LENGTH:
            truncated_statement = statement[:MAX_QUERY_LOG_LENGTH] + "..."
        else:
            truncated_statement = statement
        
        # Log the slow query
        logger.warning(
            f"Slow query detected ({execution_time:.4f}s): {truncated_statement}"
        )
        
        # Add to the slow queries list (limited size)
        slow_query_info = {
            "statement": truncated_statement,
            "parameters": str(parameters),
            "execution_time": execution_time,
            "timestamp": time.time(),
        }
        
        # Keep only the most recent slow queries (max 100)
        query_stats["slow_queries_list"].append(slow_query_info)
        if len(query_stats["slow_queries_list"]) > 100:
            query_stats["slow_queries_list"].pop(0)
    
    # Sample logging for normal queries
    elif context._log_query:
        # Truncate the statement if it's too long
        if len(statement) > MAX_QUERY_LOG_LENGTH:
            truncated_statement = statement[:MAX_QUERY_LOG_LENGTH] + "..."
        else:
            truncated_statement = statement
        
        # Log the query
        logger.debug(
            f"Query executed ({execution_time:.4f}s): {truncated_statement}"
        )


def get_database_stats() -> Dict[str, Any]:
    """
    Get database performance statistics.
    
    Returns:
        Dict with database performance statistics
    """
    stats = query_stats.copy()
    
    # Calculate average query time
    if stats["total_queries"] > 0:
        stats["avg_time"] = stats["total_time"] / stats["total_queries"]
    else:
        stats["avg_time"] = 0.0
    
    # Calculate slow query percentage
    if stats["total_queries"] > 0:
        stats["slow_query_percentage"] = (stats["slow_queries"] / stats["total_queries"]) * 100
    else:
        stats["slow_query_percentage"] = 0.0
    
    return stats