from typing import Dict, Type, TypeVar, Any, Callable, Optional
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.repository import Repository
from src.database import get_session

T = TypeVar('T')


class DependencyContainer:
    """
    A container for managing dependencies in the application.
    This class provides methods for registering and retrieving dependencies.
    """
    
    def __init__(self):
        self._dependencies: Dict[str, Any] = {}
        self._factories: Dict[str, Callable[..., Any]] = {}


    def register(self, name: str, dependency: Any) -> None:
        """
        Register a dependency with the container.

        Args:
            name: The name of the dependency
            dependency: The dependency instance
        """
        self._dependencies[name] = dependency

    def register_factory(self, name: str, factory: Callable[..., Any]) -> None:
        """
        Register a factory function for creating dependencies.
        
        Args:
            name: The name of the dependency
            factory: A function that creates the dependency
        """
        self._factories[name] = factory
    
    def get(self, name: str) -> Any:
        """
        Get a dependency from the container.
        
        Args:
            name: The name of the dependency
            
        Returns:
            The dependency instance
            
        Raises:
            KeyError: If the dependency is not registered
        """
        if name in self._dependencies:
            return self._dependencies[name]
        
        if name in self._factories:
            # Create the dependency using the factory
            dependency = self._factories[name]()
            # Cache the dependency for future use
            self._dependencies[name] = dependency
            return dependency
        
        raise KeyError(f"Dependency '{name}' not found in container")


# Create a global dependency container
container = DependencyContainer()

# Generic repository factory
def get_repository(repository_class: Type[T]) -> Callable[[AsyncSession], T]:
    """
    Create a dependency function for a repository.
    
    Args:
        repository_class: The repository class
        
    Returns:
        A function that creates a repository instance with the session
    """
    def _get_repository(session: AsyncSession = Depends(get_session)) -> T:
        return repository_class(session)
    
    return _get_repository


# Generic service factory
def get_service(service_class: Type[T]) -> Callable[..., T]:
    """
    Create a dependency function for a service.
    
    Args:
        service_class: The service class
        
    Returns:
        A function that creates a service instance with its dependencies
    """
    def _get_service(session: AsyncSession = Depends(get_session)) -> T:
        return service_class(session)
    
    return _get_service