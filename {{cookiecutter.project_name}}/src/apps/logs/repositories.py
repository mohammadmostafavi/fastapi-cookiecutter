from sqlalchemy.ext.asyncio import AsyncSession
from src.core.repository import Repository
from .models import Log


class LogRepository(Repository):
    """
    Repository for Log model operations.
    """
    def __init__(self, db: AsyncSession):
        super().__init__(db=db,model_class=Log)