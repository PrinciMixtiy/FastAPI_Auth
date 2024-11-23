from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from app.db.session import SessionDep
from app.dependencies import (ACCESS_TOKEN_EXPIRE_MINUTES,
                              REFRESH_TOKEN_EXPIRE_DAYS, authenticate_user,
                              create_token, decode_token,
                              get_current_active_user, hash_password)
from app.models.user import User, UserCreate, UserPublic
from app.schemas.auth_schemas import RefreshToken, Token

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserPublic)
async def create_user(user: UserCreate, session: SessionDep):
    user_data = user.model_dump()
    hashed_password = hash_password(user_data["password"])
    user_db = User(**user_data, hashed_password=hashed_password)
    session.add(user_db)
    session.commit()
    session.refresh(user_db)
    return user_db


@router.post("/login", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: SessionDep
) -> Token:
    user = authenticate_user(form_data.username, form_data.password, session)
    
    access_token = create_token(
        data={"sub": user.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    refresh_token = create_token(
        data={"sub": user.username}, expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )

    return Token(access_token=access_token, refresh_token=refresh_token ,token_type="bearer")


@router.post("/refresh", response_model=Token)
async def refresh_token(refresh: RefreshToken):
    payload = decode_token(refresh.refresh_token)
    username = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token.",
        )

    access_token = create_token(
        {"sub": username}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    refresh_token = create_token(
        {"sub": username}, timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )

    return Token(access_token=access_token, refresh_token=refresh_token ,token_type="bearer")


@router.get("/me/", response_model=UserPublic)
async def read_users_me(
    current_user: Annotated[UserPublic, Depends(get_current_active_user)],
):
    return current_user
