from src.core.models import BaseModel
from src.core.utils import make_password
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, UniqueConstraint, Table


UserPermission = Table(
    "user_permissions",
    BaseModel.metadata,
    Column("user_id", Integer, ForeignKey("users.id"), primary_key=True),
    Column("permission_id", Integer, ForeignKey("permissions.id"), primary_key=True),
    UniqueConstraint("user_id", "permission_id", name="uq_user_permission")
)

UserRole = Table(
    "user_roles",
    BaseModel.metadata,
    Column("user_id", Integer, ForeignKey("users.id"), primary_key=True),
    Column("role_id", Integer, ForeignKey("roles.id"), primary_key=True),
    UniqueConstraint("user_id", "role_id", name="uq_user_role")
)
RolePermission = Table(
    "role_permissions",
    BaseModel.metadata,
    Column("role_id", Integer, ForeignKey("roles.id"), primary_key=True),
    Column("permission_id", Integer, ForeignKey("permissions.id"), primary_key=True),
    UniqueConstraint("role_id", "permission_id", name="uq_role_permission")
)


class Permission(BaseModel):
    __tablename__ = "permissions"
    name = Column(String(150), unique=True, nullable=False)
    codename = Column(String(150), unique=True, nullable=False)

class User(BaseModel):
    __tablename__ = "users"
    username = Column(String(150), unique=True, nullable=False)
    first_name = Column(String(150), nullable=True)
    last_name = Column(String(150), nullable=True)
    email = Column(String(150), unique=True, nullable=False)
    password = Column(String(255), nullable=False)
    is_staff = Column(Integer, default=0)
    is_active = Column(Integer, default=1)
    is_superuser = Column(Integer, default=0)
    last_login = Column(DateTime, nullable=True)
    roles = relationship("Role",secondary=UserRole, lazy="selectin")
    permissions = relationship("Permission", secondary=UserPermission, lazy="selectin")

    def update(self, **kwargs):
        """
        Update the instance with the provided keyword arguments.
        :param kwargs:
        :return:
        """
        for key, value in kwargs.items():
            if hasattr(self, key):
                if key == "roles":
                    self.roles = value
                elif key == "permissions":
                    self.permissions = value
                elif key == "password":
                    setattr(self, key, make_password(value))
                elif key not in ["id", "_session", "created_at", "updated_at", "deleted_at", "username", "email"]:
                    setattr(self, key, value)
        return self

class Role(BaseModel):
    __tablename__ = "roles"
    name = Column(String(150), unique=True, nullable=False)
    permissions = relationship("Permission", secondary=RolePermission)



