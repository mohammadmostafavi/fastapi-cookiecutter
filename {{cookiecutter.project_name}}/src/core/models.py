from sqlalchemy import Column, Integer, DateTime, func
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class BaseModel(Base):
    """
    Base model for all database models with common fields and metadata.
    This class should be used for database schema definition only.
    Business logic and data access should be handled in separate repository/service classes.
    """
    __abstract__ = True
    __mapper_args__ = {"eager_defaults": True}

    id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), server_onupdate=func.now())
    deleted_at = Column(DateTime, nullable=True)

    def __repr__(self):
        return f"<{self.__class__.__name__} {self.id}>"

    def update(self, **kwargs):
        """
        Update the instance with the provided keyword arguments.
        This method only updates the instance in memory, not in the database.
        :param kwargs: Attributes to update
        :return: self
        """
        for key, value in kwargs.items():
            if hasattr(self, key):
                if key not in ["id", "created_at", "updated_at", "deleted_at"]:
                    setattr(self, key, value)
        return self
