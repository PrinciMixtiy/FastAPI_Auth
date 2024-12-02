from typing import Annotated
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status

from app.db.session import SessionDep
from app.dependencies import check_user_admin, get_current_active_user, hash_password
from app.models.user_models import User, UserPublic, UserUpdate

ADMIN_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Require admin privilege.",
    headers={"WWW-Authenticate": "Bearer"},
)

router = APIRouter(
    prefix="/users",
    tags=["Users"]
)


@router.get("/{user_id}", response_model=User, status_code=status.HTTP_200_OK)
def get_user_by_id(
        user_id: int, admin: Annotated[bool, Depends(check_user_admin)],
        session: SessionDep
):
    if not admin:
        raise ADMIN_EXCEPTION

    user = session.get(User, user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    return user


@router.patch("/{user_id}", response_model=UserPublic, status_code=status.HTTP_200_OK)
def update_user(
        user_id: int, user_update: UserUpdate,
        current_user: Annotated[UserPublic, Depends(get_current_active_user)],
        session: SessionDep
):
    authorized = current_user.is_superuser or current_user.id == user_id
    if not authorized:
        raise ADMIN_EXCEPTION

    user = session.get(User, user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    user_update_data = user_update.model_dump(exclude_unset=True)

    if user_update_data.get("password"):
        user_update_data["hashed_password"] = hash_password(user_update_data["password"])

    user_update_data["updated_at"] = datetime.now()
    user.sqlmodel_update(user_update_data)

    session.add(user)
    session.commit()
    session.refresh(user)

    return user


@router.delete("/{user_id}", status_code=status.HTTP_200_OK)
def delete_user(
        user_id: int, admin: Annotated[bool, Depends(check_user_admin)],
        current_user: Annotated[UserPublic, Depends(get_current_active_user)],
        session: SessionDep
):
    authorized = current_user.is_superuser or current_user.id == user_id
    if not authorized:
        raise ADMIN_EXCEPTION

    user = session.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    user.is_active = False
    user.updated_at = datetime.now()

    session.add(user)
    session.commit()
    session.refresh(user)

    return {"ok": True, "msg": "User deleted successfully."}
