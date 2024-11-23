from datetime import datetime, timedelta, timezone
from os import environ
from typing import Annotated

import jwt
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from passlib.context import CryptContext
from sqlmodel import select

from app.db.session import Session, SessionDep
from app.models.user import User, UserPublic
from app.schemas.auth_schemas import TokenData

load_dotenv()

SECRET_KEY = environ["SECRET_KEY"]
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def create_token(data: dict, expires_delta: timedelta) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    
    except ExpiredSignatureError:
        raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
    except InvalidTokenError:
        raise CREDENTIALS_EXCEPTION


def get_user(username: str, session: Session) -> User:
    user = session.exec(select(User).where(User.username==username)).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    return user


def authenticate_user(username: str, password: str, session: Session) -> UserPublic:
    user = get_user(username=username, session=session)
    if not verify_password(password, user.hashed_password):
        raise CREDENTIALS_EXCEPTION
    return user
    

def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], session: SessionDep) -> UserPublic:
    payload = decode_token(token=token)
    username: str = payload.get("sub")
    if not username:
        raise CREDENTIALS_EXCEPTION
    token_data = TokenData(username=username)
    user = get_user(username=token_data.username, session=session)
    return user


def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
) -> UserPublic:
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
