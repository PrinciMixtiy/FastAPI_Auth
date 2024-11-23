from datetime import datetime

from sqlmodel import SQLModel, Field
from pydantic import EmailStr


class UserBase(SQLModel):
    username: str = Field(index=True, unique=True)
    email: EmailStr = Field(index=True)
    first_name: str | None = Field(default=None)
    last_name: str | None = Field(default=None)
    

class UserCreate(UserBase):
    password: str
    
    
class UserPublic(UserBase):
    is_active: bool = Field(default=True)
    is_superuser: bool = Field(default=False)
    created_at: datetime = Field(default=datetime.now())
    

class User(UserPublic, table=True):
    __tablename__ = "users"
    
    id: int | None = Field(default=None, primary_key=True)
    hashed_password: str
