"""
Health check module.

This module provides functions for checking the health of the application and its dependencies.
"""

import logging
import time
from typing import Dict, Any, Optional

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import text
from sqlalchemy.exc import SQLAlchemyError

from src.database import get_session
from src.constants.database import HEALTH_CHECK_TIMEOUT
from src.core.exceptions import DatabaseConnectionException
from src.middleware.database import get_database_stats

# Configure logger
logger = logging.getLogger(__name__)

# Create router
health_router = APIRouter(tags=["health"])


@health_router.get("/health", status_code=status.HTTP_200_OK)
async def health_check(db: AsyncSession = Depends(get_session)) -> Dict[str, Any]:
    """
    Check the health of the application and its dependencies.
    
    Returns:
        Dict with health status information
    """
    start_time = time.time()
    
    # Initialize response
    response = {
        "status": "healthy",
        "timestamp": start_time,
        "components": {}
    }
    
    # Check database health
    db_health = await check_database_health(db)
    response["components"]["database"] = db_health
    
    # Add database performance statistics
    try:
        db_stats = get_database_stats()
        response["components"]["database"]["performance"] = db_stats
    except Exception as e:
        logger.warning(f"Failed to get database performance statistics: {str(e)}")
        response["components"]["database"]["performance"] = {"error": str(e)}
    
    # If any component is not healthy, set overall status to unhealthy
    if not db_health["healthy"]:
        response["status"] = "unhealthy"
    
    # Add response time
    response["response_time_ms"] = round((time.time() - start_time) * 1000, 2)
    
    return response


async def check_database_health(db: AsyncSession) -> Dict[str, Any]:
    """
    Check the health of the database connection.
    
    Args:
        db: Database session
        
    Returns:
        Dict with database health status information
    """
    start_time = time.time()
    result = {
        "healthy": False,
        "response_time_ms": 0,
        "error": None
    }
    
    try:
        # Execute a simple query with timeout
        query = text("SELECT 1")
        await db.execute(query)
        
        # If we get here, the database is healthy
        result["healthy"] = True
        
    except SQLAlchemyError as e:
        # Log the error
        logger.error(f"Database health check failed: {str(e)}")
        
        # Add error details to the result
        result["error"] = {
            "type": type(e).__name__,
            "message": str(e)
        }
    
    # Add response time
    result["response_time_ms"] = round((time.time() - start_time) * 1000, 2)
    
    return result