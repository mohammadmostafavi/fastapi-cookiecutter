# Authorization System

This document describes the authorization system implemented in the application.

## Overview

The authorization system provides two main mechanisms for controlling access to resources:

1. **Permission-based access control**: Fine-grained control over what actions a user can perform.
2. **Role-based access control**: Coarse-grained control based on user roles.

These mechanisms can be used independently or together to implement a comprehensive authorization strategy.

## Models

The authorization system is built on the following models:

- **User**: Represents a user in the system. Users can have permissions directly assigned to them and can belong to roles.
- **Permission**: Represents a specific action that can be performed. Permissions have a name and a codename.
- **Role**: Represents a role in the system. Roles can have permissions assigned to them.

The relationships between these models are:

- Users can have multiple permissions directly assigned to them (many-to-many).
- Users can belong to multiple roles (many-to-many).
- Roles can have multiple permissions assigned to them (many-to-many).

## Common Permissions

The system commonly uses the following permissions:

- `read`: Permission to read resources.
- `write`: Permission to create or update resources.
- `delete`: Permission to delete resources.
- `admin`: Permission to perform administrative actions.

These permissions are stored in the database and referenced by their string identifiers.

## Common Roles

The system commonly uses the following roles:

- `admin`: Administrator role with full access to all resources.
- `staff`: Staff role with access to most resources.
- `user`: Regular user role with limited access.

These roles are stored in the database and referenced by their string identifiers.

## Permission-Based Access Control

Permission-based access control is implemented using decorators that check if the current user has the required permissions to access a resource.

### Decorators

The following decorators are available for permission-based access control:

#### `require_permission(permission)`

Requires the user to have a specific permission to access the route.

```python
from src.core.authorization import require_permission

@app.get("/resource")
@require_permission("read")
async def read_resource():
    # This route requires the read permission
    return {"message": "Resource read successfully"}
```

#### `require_permissions(permissions, require_all=True)`

Requires the user to have multiple permissions to access the route. If `require_all` is `True`, the user must have all the specified permissions. If `require_all` is `False`, the user must have at least one of the specified permissions.

```python
from src.core.authorization import require_permissions

@app.post("/resource")
@require_permissions(["write", "admin"], require_all=False)
async def create_resource():
    # This route requires either the write permission or the admin permission
    return {"message": "Resource created successfully"}
```

### Permission Checking

The decorators use the following functions to check if a user has the required permissions:

#### `has_permission(permission, current_user)`

Checks if the user has a specific permission. The permission can be assigned directly to the user or through a role.

#### `has_permissions(permissions, require_all=True, current_user)`

Checks if the user has multiple permissions. If `require_all` is `True`, the user must have all the specified permissions. If `require_all` is `False`, the user must have at least one of the specified permissions.

## Role-Based Access Control

Role-based access control is implemented using decorators that check if the current user has the required roles to access a resource, and middleware that checks if the user has the required role to access specific URL patterns.

### Decorators

The following decorators are available for role-based access control:

#### `require_role(role)`

Requires the user to have a specific role to access the route.

```python
from src.core.authorization import require_role

@app.get("/admin/dashboard")
@require_role("admin")
async def admin_dashboard():
    # This route requires the admin role
    return {"message": "Admin dashboard"}
```

#### `require_roles(roles, require_all=False)`

Requires the user to have multiple roles to access the route. If `require_all` is `True`, the user must have all the specified roles. If `require_all` is `False`, the user must have at least one of the specified roles.

```python
from src.core.authorization import require_roles

@app.get("/staff/dashboard")
@require_roles(["admin", "staff"], require_all=False)
async def staff_dashboard():
    # This route requires either the admin role or the staff role
    return {"message": "Staff dashboard"}
```

### Role Checking

The decorators use the following functions to check if a user has the required roles:

#### `has_role(role, current_user)`

Checks if the user has a specific role.

#### `has_roles(roles, require_all=False, current_user)`

Checks if the user has multiple roles. If `require_all` is `True`, the user must have all the specified roles. If `require_all` is `False`, the user must have at least one of the specified roles.

### Middleware

The `RoleBasedMiddleware` checks if the user has the required role to access specific URL patterns. The middleware is configured with a dictionary mapping URL patterns to required roles.

```python
from src.middleware.authorization import RoleBasedMiddleware

src.add_middleware(RoleBasedMiddleware, role_patterns={
    r"^/api/v1/admin/.*$": ["admin"],
    r"^/api/v1/staff/.*$": ["admin", "staff"],
    r"^/api/v1/user/.*$": ["admin", "staff", "user"],
})
```

## Special Cases

The authorization system handles the following special case:

- **Superusers**: Users with the `is_superuser` flag set to `True` have all permissions and roles.

Note: The system no longer has special handling for "admin" role or "admin" permission. All roles and permissions are now treated equally and stored in the database. Any special relationships between roles and permissions should be defined in the database.

## Current User

The authorization system relies on a `get_current_user` function to retrieve the current authenticated user. This function is a placeholder that should be implemented to extract the user from the JWT token in the request header.

```python
async def get_current_user(session: AsyncSession = Depends(get_session)) -> Optional[User]:
    # TODO: Implement JWT token validation and user retrieval
    # For now, this is a placeholder that always raises an unauthorized exception
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )
```

## Usage Examples

### Permission-Based Access Control

```python
from fastapi import APIRouter, Depends
from src.core.authorization import require_permission, require_permissions

router = APIRouter()

@router.get("/resource")
@require_permission("read")
async def read_resource():
    # This route requires the read permission
    return {"message": "Resource read successfully"}

@router.post("/resource")
@require_permission("write")
async def create_resource():
    # This route requires the write permission
    return {"message": "Resource created successfully"}

@router.put("/resource/{resource_id}")
@require_permission("write")
async def update_resource(resource_id: int):
    # This route requires the write permission
    return {"message": f"Resource {resource_id} updated successfully"}

@router.delete("/resource/{resource_id}")
@require_permissions(["delete", "admin"], require_all=False)
async def delete_resource(resource_id: int):
    # This route requires either the delete permission or the admin permission
    return {"message": f"Resource {resource_id} deleted successfully"}
```

### Role-Based Access Control

```python
from fastapi import APIRouter, Depends
from src.core.authorization import require_role, require_roles

router = APIRouter()

@router.get("/admin/dashboard")
@require_role("admin")
async def admin_dashboard():
    # This route requires the admin role
    return {"message": "Admin dashboard"}

@router.get("/staff/dashboard")
@require_roles(["admin", "staff"], require_all=False)
async def staff_dashboard():
    # This route requires either the admin role or the staff role
    return {"message": "Staff dashboard"}

@router.get("/user/dashboard")
@require_roles(["admin", "staff", "user"], require_all=False)
async def user_dashboard():
    # This route requires any role
    return {"message": "User dashboard"}
```

## Best Practices

1. **Use the most specific permission or role**: Always use the most specific permission or role that is required for the action.
2. **Prefer permission-based access control**: Permission-based access control provides more fine-grained control than role-based access control.
3. **Document required permissions and roles**: Always document the required permissions and roles in the route docstring.
4. **Handle authentication and authorization errors**: Always handle authentication and authorization errors in the response model.
5. **Test with different user roles and permissions**: Always test the authorization system with different user roles and permissions to ensure it works as expected.