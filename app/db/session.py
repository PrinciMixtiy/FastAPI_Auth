from typing import Annotated

from fastapi import Depends
from sqlmodel import Session, create_engine
from app.models.user_models import User

DATABASE_URL = "sqlite:///../database.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})


def get_session():
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]
