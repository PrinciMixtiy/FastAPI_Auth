from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import select

from app.db.session import SessionDep
from app.dependencies import (ACCESS_TOKEN_EXPIRE_MINUTES,
                              REFRESH_TOKEN_EXPIRE_DAYS, authenticate_user,
                              encode_token, decode_token,
                              get_current_active_user, hash_password,
                              validate_password)
from app.models.user_models import User, UserCreate, UserPublic
from app.schemas.auth_schemas import RefreshToken, Token

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)


@router.post("/register", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
async def create_user(user: UserCreate, session: SessionDep):
    user_data = user.model_dump()

    if session.exec(select(User).where(User.username == user_data["username"])).first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exists."
        )

    if session.exec(select(User).where(User.username == user_data["username"])).first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already used."
        )

    validate_password(user_data["password"])
    hashed_password = hash_password(user_data["password"])
    user_db = User(**user_data, hashed_password=hashed_password)

    session.add(user_db)
    session.commit()
    session.refresh(user_db)

    return user_db


@router.post("/login", response_model=Token, status_code=status.HTTP_200_OK)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: SessionDep
) -> Token:
    user = authenticate_user(form_data.username, form_data.password, session)

    access_data = {"sub": user.username, "admin": user.is_superuser}
    refresh_data = {"sub": user.username}

    access_token = encode_token(
        data=access_data, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    refresh_token = encode_token(
        data=refresh_data, expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )

    return Token(access_token=access_token, refresh_token=refresh_token, token_type="bearer")


@router.post("/refresh", response_model=Token)
async def refresh_token(refresh: RefreshToken):
    payload = decode_token(refresh.refresh_token)
    username = payload.get("sub")

    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token.",
        )

    access_token = encode_token(
        {"sub": username}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    refresh_token = encode_token(
        {"sub": username}, timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )

    return Token(access_token=access_token, refresh_token=refresh_token ,token_type="bearer")


@router.get("/me", response_model=UserPublic, status_code=status.HTTP_200_OK)
async def read_users_me(
    current_user: Annotated[UserPublic, Depends(get_current_active_user)],
):
    return current_user
