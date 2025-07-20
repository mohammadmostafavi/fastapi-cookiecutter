from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Depends
from .models import Log
from .repositories import LogRepository
from src.database import get_session


class LogService:
    """
    Service class for log-related operations.
    """
    
    def __init__(self, db: AsyncSession, log_repository: LogRepository):
        """
        Initialize the service with dependencies.
        
        Args:
            db: Database session
            log_repository: Repository for log operations
        """
        self.db = db
        self.log_repository = log_repository
    
    async def save_log(self, action: str) -> Log:
        """
        Save a log entry.
        
        Args:
            action: The action to log
            
        Returns:
            The created log entry
        """
        log = await self.log_repository.create(self.db, action=action)
        return log


# Dependency function for LogService
def get_log_service(
    db: AsyncSession = Depends(get_session),
) -> LogService:
    """
    Get a LogService instance with its dependencies.
    
    Args:
        db: Database session
        
    Returns:
        LogService instance
    """
    from src.core.dependencies import container
    
    # Get the log repository from the container
    log_repository = LogRepository(db=db)
    
    # Create and return the service
    return LogService(db, log_repository)
