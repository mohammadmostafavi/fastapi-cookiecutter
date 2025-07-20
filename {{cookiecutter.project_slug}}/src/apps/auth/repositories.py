from src.core.repository import Repository
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from .models import User, Role, Permission


class UserRepository(Repository):
    """
    Repository for User model operations.
    """

    def __init__(self, db: AsyncSession):
        super().__init__(db=db, model_class=User)

    async def get_by_username(self, username: str) -> Optional[User]:
        """
        Get a user by username.

        Args:
            db: Database session
            username: The username to search for

        Returns:
            The user or None if not found
        """
        query = (
            select(self.model_class)
            .where(self.model_class.username == username)
            .where(self.model_class.deleted_at == None)
        )
        result = await self._db.execute(query)
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> Optional[User]:
        """
        Get a user by email.

        Args:
            db: Database session
            email: The email to search for

        Returns:
            The user or None if not found
        """
        query = (
            select(self.model_class)
            .where(self.model_class.email == email)
            .where(self.model_class.deleted_at == None)
        )
        result = await self._db.execute(query)
        return result.scalar_one_or_none()


class RoleRepository(Repository):
    """
    Repository for Role model operations.
    """

    def __init__(self, db=None):
        super().__init__(db=db, model_class=Role)


class PermissionRepository(Repository):
    """
    Repository for Permission model operations.
    """

    def __init__(self, db=None):
        super().__init__(db=db, model_class=Permission)
