import jwt
import re

from datetime import timedelta, datetime, timezone
from jwt import ExpiredSignatureError, InvalidTokenError
from passlib.context import CryptContext
from app.utilities.constants import (
    SECRET_KEY,
    ALGORITHM,
)
from app.utilities.exceptions import (
    TokenExpired,
    InvalidCredentials,
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def encode_token(data: dict, expires_delta: timedelta) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload

    except ExpiredSignatureError:
        raise TokenExpired()

    except InvalidTokenError:
        raise InvalidCredentials()
    

def validate_password(password: str) -> None:
    """
    Validate a password against predefined rules.

    Args:
        password (str): The password to validate.

    Raises:
        HTTPException: If the password does not meet the requirements.
    """
    validation_rules = [
        (lambda p: len(p) >= 6, "Password must be at least 6 characters long."),
        (lambda p: re.search(
            r'[A-Z]', p), "Password must contain at least one uppercase letter."),
        (lambda p: re.search(
            r'[a-z]', p), "Password must contain at least one lowercase letter."),
        (lambda p: re.search(r'[0-9]', p),
         "Password must contain at least one number."),
        (lambda p: re.search(
            r'[@$!%*?&#]', p), "Password must contain at least one special character."),
    ]
