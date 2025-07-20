from functools import wraps
from sqlalchemy.ext.asyncio import AsyncSession
from src.apps.logs.services import get_log_service, LogService

def db_logger(action: str):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            db: AsyncSession = kwargs.get("db")  # Get DB session
            if not db:
                raise ValueError("Database session 'db' is required in kwargs")
            log_service: LogService = get_log_service(db=db)
            await log_service.save_log(action)
            return await func(*args, **kwargs)
        return wrapper
    return decorator
