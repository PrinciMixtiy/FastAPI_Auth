from typing import Annotated

from fastapi import Depends
from sqlmodel import SQLModel, Session, create_engine
from app.models.user import User

DATABASE_URL = "sqlite:///../database.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)
    
    
def get_session():
    with Session(engine) as session:
        yield session
        

SessionDep = Annotated[Session, Depends(get_session)]

if __name__ == "__main__":
    create_db_and_tables()
