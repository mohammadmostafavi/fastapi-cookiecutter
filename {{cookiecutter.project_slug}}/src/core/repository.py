from typing import TypeVar, Generic, Type, List, Optional, Any, Dict
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError

from src.core.models import BaseModel
from src.core.utils import with_retry
from src.core.exceptions import DatabaseException, DatabaseConnectionException

T = TypeVar('T', bound=BaseModel)


class Repository(Generic[T]):
    """
    Generic repository for database operations.
    This class provides common CRUD operations for models.
    """

    def __init__(self, db:AsyncSession, model_class: Type[T]):
        """
        Initialize the repository with a model class.
        :param db: Database session
        :param model_class: The model class to use for operations
        """
        self.model_class = model_class
        self._db = db

    @with_retry()
    async def create(self, **kwargs) -> T:
        """
        Create a new instance of the model and save it to the database.
        This operation is retried automatically if a retryable database error occurs.
        
        :param kwargs: Model attributes
        :return: Created model instance
        :raises: DatabaseException if the operation fails after retries
        """
        try:
            instance = self.model_class(**kwargs)
            self._db.add(instance)
            await self._db.commit()
            await self._db.refresh(instance)
            return instance
        except SQLAlchemyError as e:
            # Wrap SQLAlchemy exceptions in our custom exception
            raise DatabaseException(message=f"Failed to create {self.model_class.__name__}: {str(e)}")

    async def get_by_id(self, id: int) -> Optional[T]:
        """
        Get a model instance by ID.
        :param id: Model ID
        :return: Model instance or None if not found
        """
        query = (
            select(self.model_class)
            .where(self.model_class.id == id)
            .where(self.model_class.deleted_at == None)
        )
        result = await self._db.execute(query)
        return result.scalar_one_or_none()

    async def get_all(self) -> List[T]:
        """
        Get all model instances that are not soft-deleted.
        :return: List of model instances
        """
        query = select(self.model_class).where(self.model_class.deleted_at == None)
        result = await self._db.execute(query)
        return result.scalars().all()

    async def filter(self, db: AsyncSession, **kwargs) -> List[T]:
        """
        Filter model instances by attributes.
        :param db: Database session
        :param kwargs: Filter criteria
        :return: List of model instances
        """
        query = select(self.model_class)
        for key, value in kwargs.items():
            if hasattr(self.model_class, key):
                query = query.where(getattr(self.model_class, key) == value)
        query = query.where(self.model_class.deleted_at == None)
        result = await self._db.execute(query)
        return result.scalars().all()

    @with_retry()
    async def update(self, instance: T, **kwargs) -> T:
        """
        Update a model instance and save it to the database.
        This operation is retried automatically if a retryable database error occurs.
        
        :param db: Database session
        :param instance: Model instance to update
        :param kwargs: Attributes to update
        :return: Updated model instance
        :raises: DatabaseException if the operation fails after retries
        """
        try:
            instance.update(**kwargs)
            instance.updated_at = func.now()
            self._db.add(instance)
            await self._db.commit()
            await self._db.refresh(instance)
            return instance
        except SQLAlchemyError as e:
            # Wrap SQLAlchemy exceptions in our custom exception
            raise DatabaseException(message=f"Failed to update {self.model_class.__name__}: {str(e)}")

    @with_retry()
    async def delete(self, instance: T) -> T:
        """
        Soft delete a model instance by setting deleted_at to the current time.
        This operation is retried automatically if a retryable database error occurs.
        
        :param db: Database session
        :param instance: Model instance to delete
        :return: Deleted model instance
        :raises: DatabaseException if the operation fails after retries
        """
        try:
            instance.deleted_at = func.now()
            instance.updated_at = func.now()
            self._db.add(instance)
            await self._db.commit()
            await self._db.refresh(instance)
            return instance
        except SQLAlchemyError as e:
            # Wrap SQLAlchemy exceptions in our custom exception
            raise DatabaseException(message=f"Failed to delete {self.model_class.__name__}: {str(e)}")

    @with_retry()
    async def restore(self, instance: T) -> T:
        """
        Restore a soft-deleted model instance by setting deleted_at to None.
        This operation is retried automatically if a retryable database error occurs.
        
        :param db: Database session
        :param instance: Model instance to restore
        :return: Restored model instance
        :raises: DatabaseException if the operation fails after retries
        """
        try:
            instance.deleted_at = None
            instance.updated_at = func.now()
            self._db.add(instance)
            await self._db.commit()
            await self._db.refresh(instance)
            return instance
        except SQLAlchemyError as e:
            # Wrap SQLAlchemy exceptions in our custom exception
            raise DatabaseException(message=f"Failed to restore {self.model_class.__name__}: {str(e)}")

    @with_retry()
    async def hard_delete(self, instance: T) -> None:
        """
        Hard delete a model instance from the database.
        This operation is retried automatically if a retryable database error occurs.
        
        :param db: Database session
        :param instance: Model instance to delete
        :raises: DatabaseException if the operation fails after retries
        """
        try:
            await self._db.delete(instance)
            await self._db.commit()
        except SQLAlchemyError as e:
            # Wrap SQLAlchemy exceptions in our custom exception
            raise DatabaseException(message=f"Failed to hard delete {self.model_class.__name__}: {str(e)}")