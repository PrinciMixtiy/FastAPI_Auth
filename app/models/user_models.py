from datetime import datetime, timezone

from sqlmodel import SQLModel, Field
from pydantic import EmailStr


class UserBase(SQLModel):
    username: str = Field(index=True, unique=True)
    email: EmailStr = Field(index=True)
    first_name: str | None = Field(default=None)
    last_name: str | None = Field(default=None)


class UserCreate(UserBase):
    password: str


class UserUpdate(UserCreate):
    username: str | None = None
    email: EmailStr | None = None
    first_name: str | None = None
    last_name: str | None = None
    password: str | None = None


class UserPublic(UserBase):
    id: int | None = Field(default=None, primary_key=True)
    is_active: bool = Field(default=True)
    is_superuser: bool = Field(default=False)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class User(UserPublic, table=True):
    __tablename__ = "users"
    hashed_password: str
