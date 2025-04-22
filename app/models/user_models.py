import re

from datetime import datetime
from enum import Enum
from sqlmodel import SQLModel, Field, Column
from pydantic import EmailStr, SecretStr, field_validator
from sqlalchemy import DateTime, func


class UserRole(str, Enum):
    """Enum for user roles."""
    USER = "user"
    ADMIN = "admin"


class UserBase(SQLModel):
    """Base model for user data."""
    username: str = Field(..., min_length=3, max_length=20, regex="^[a-zA-Z0-9_-]+$")
    email: EmailStr = Field(..., index=True)
    first_name: str | None = Field(default=None, max_length=50)
    last_name: str | None = Field(default=None, max_length=50)
    role: UserRole = Field(default=UserRole.USER)


class UserCreate(UserBase):
    """Request model for creating a new user."""
    password: SecretStr

    @field_validator("password")
    def validate_password(cls, v: SecretStr) -> SecretStr:
        password = v.get_secret_value()
        # Minimum 8 characters
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
        # At least 1 uppercase letter
        if not re.search(r"[A-Z]", password):
            raise ValueError("Password must contain at least 1 uppercase letter")
        # At least 1 lowercase letter
        if not re.search(r"[a-z]", password):
            raise ValueError("Password must contain at least 1 lowercase letter")
        # At least 1 digit
        if not re.search(r"\d", password):
            raise ValueError("Password must contain at least 1 number")
        # At least 1 special character
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            raise ValueError("Password must contain at least 1 special character")
        
        return v


class UserUpdate(SQLModel):
    """Model for updating user data."""
    username: str | None = None
    email: EmailStr | None = None
    first_name: str | None = None
    last_name: str | None = None
    role: UserRole | None = None
    old_password: SecretStr | None = None
    new_password: SecretStr | None = None


class UserPublic(UserBase):
    """Public model for user data."""
    id: int


class User(UserBase, table=True):
    """Database model for user data."""
    __tablename__ = "users"
    id: int | None = Field(default=None, primary_key=True)
    hashed_password: str = Field(nullable=False)
    created_at: datetime = Field(sa_column=Column(DateTime(timezone=True), server_default=func.now()))
    updated_at: datetime = Field(sa_column=Column(DateTime(timezone=True), onupdate=func.now()))
