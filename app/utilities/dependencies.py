from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from sqlmodel import select
from loguru import logger

from app.db.session import Session, SessionDep
from app.models.user_models import User
from app.schemas.auth_schemas import TokenData
from app.utilities.exceptions import (
    InvalidCredentials,
    PermissionDenied,
)
from app.utilities.encoders import (
    verify_password,
    decode_token,
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_user(username: str, session: Session) -> User:
    """
    Retrieve a user by their username.

    Args:
        username (str): The username of the user to retrieve.
        session (Session): The database session.

    Returns:
        User: The retrieved user.

    Raises:
        HTTPException: If the user is not found.
    """
    user = session.exec(select(User).where(User.username == username)).first()

    if not user:
        logger.warning(f"User not found: {username}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    return user


def get_user_by_email(session: Session, email: str) -> User:
    """
    Retrieve a user by their email.

    Args:
        session (Session): The database session.
        email (str): The email of the user to retrieve.

    Returns:
        User: The retrieved user.

    Raises:
        HTTPException: If the user is not found.
    """
    user = session.exec(select(User).where(User.email == email)).first()

    if not user:
        logger.warning(f"User not found with email: {email}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    return user


def authenticate_user(username: str, password: str, session: Session) -> User:
    """
    Authenticate a user by username and password.

    Args:
        username (str): The username of the user.
        password (str): The password to verify.
        session (Session): The database session.

    Returns:
        User: The authenticated user.

    Raises:
        HTTPException: If the user is inactive or credentials are invalid.
    """
    user = get_user(username=username, session=session)

    if not user.is_active:
        logger.warning(f"Inactive user login attempt: {username}")
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Inactive user.",
        )

    if not verify_password(password, user.hashed_password):
        logger.warning(f"Invalid password attempt for user: {username}")
        raise InvalidCredentials()

    logger.info(f"User authenticated successfully: {username}")
    return user


def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    session: SessionDep,
) -> User:
    """
    Get the current authenticated user from the token.

    Args:
        token (str): The OAuth2 token.
        session (Session): The database session.

    Returns:
        User: The authenticated user.

    Raises:
        HTTPException: If the token is invalid or the user is not found.
    """
    payload = decode_token(token=token)
    username: str = payload.get("sub")

    if not username:
        logger.warning("Invalid token: Missing username")
        raise InvalidCredentials()

    token_data = TokenData(username=username)
    user = get_user(username=token_data.username, session=session)

    return user


def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """
    Get the current active user.

    Args:
        current_user (User): The current authenticated user.

    Returns:
        User: The active user.

    Raises:
        HTTPException: If the user is inactive.
    """
    if not current_user.is_active:
        logger.warning(f"Inactive user access attempt: {current_user.username}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user",
        )

    return current_user


class RoleChecker:
    """
    Role-based access control.

    Args:
        allowed_roles (list[str]): List of allowed roles or ["*"] for all roles.
    """

    def __init__(self, allowed_roles: list[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, user: Annotated[User, Depends(get_current_active_user)]) -> User:
        """
        Check if the user has the required role.

        Args:
            user (User): The current authenticated user.

        Returns:
            User: The user if authorized.

        Raises:
            HTTPException: If the user is not authorized.
        """
        if user.role in self.allowed_roles or "*" in self.allowed_roles:
            return user

        logger.warning(f"Unauthorized access attempt by user: {user.username}")
        raise PermissionDenied()
