from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import select

from app.db.session import SessionDep
from app.utilities.dependencies import RoleChecker
from app.models.user_models import User, UserPublic, UserUpdate, UserRole
from app.utilities.exceptions import PermissionDenied, InvalidCredentials
from app.utilities.encoders import verify_password, hash_password

router = APIRouter(
    prefix="/users",
    tags=["Users"]
)


@router.get("/{user_id}", response_model=User, status_code=status.HTTP_200_OK)
def get_user_by_id(
    user_id: int, session: SessionDep,
    _: Annotated[User, Depends(RoleChecker(allowed_roles=[UserRole.ADMIN]))]
):
    user = session.get(User, user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    return user


@router.get("/", response_model=list[UserPublic], status_code=status.HTTP_200_OK)
def list_users(
    session: SessionDep,
    _: Annotated[User, Depends(RoleChecker(allowed_roles=[UserRole.ADMIN]))]
):
    users = session.exec(select(User)).all()
    return users


@router.patch("/{user_id}", response_model=UserPublic, status_code=status.HTTP_200_OK)
def update_user(
        user_id: int, user_update: UserUpdate,
        current_user: Annotated[User, Depends(RoleChecker(allowed_roles=[UserRole.ADMIN]))],
        session: SessionDep
):
    authorized = current_user.role == UserRole.ADMIN or current_user.id == user_id
    if not authorized:
        raise PermissionDenied

    user = session.get(User, user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    user_update_data = user_update.model_dump(exclude_unset=True)

    if user_update_data.get("old_password") and user_update_data.get("new_password"):
        if verify_password(user_update_data["old_password"], user.hashed_password):
            raise InvalidCredentials()
        user_update_data["hashed_password"] = hash_password(user_update_data["new_password"])

    user.sqlmodel_update(user_update_data)

    session.add(user)
    session.commit()
    session.refresh(user)

    return user


@router.delete("/{user_id}", status_code=status.HTTP_200_OK, response_model=UserPublic)
def delete_user(
        user_id: int,
        current_user: Annotated[User, Depends(RoleChecker(allowed_roles=[UserRole.ADMIN, UserRole.USER]))],
        session: SessionDep
):
    authorized = current_user.role == UserRole.ADMIN or current_user.id == user_id
    if not authorized:
        raise PermissionDenied()

    user = session.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    user.is_active = False

    session.add(user)
    session.commit()
    session.refresh(user)

    return user
