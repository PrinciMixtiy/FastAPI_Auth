from fastapi import HTTPException, status
from loguru import logger

from .constants import (
    INVALID_CREDENTIALS_MSG,
    ACCOUNT_LOCKED_MSG,
    BRUTE_FORCE_LOCKOUT_MSG,
    RATE_LIMIT_EXCEEDED_MSG,
    TOKEN_EXPIRED_MSG,
    PERMISSION_DENIED_MSG,
    SECURITY_LOG_MSG
)


# Base Exception (for inheritance)
class AuthException(HTTPException):
    """Base exception with automated logging"""
    def __init__(self, detail: str, status_code: int, event_type: str = None):
        if event_type:
            logger.warning(SECURITY_LOG_MSG.format(
                event_type=event_type,
                details=detail
            ))
        super().__init__(status_code=status_code, detail=detail)

# Specific Exceptions
# Authentication Errors
class InvalidCredentials(AuthException):
    def __init__(self):
        super().__init__(
            detail=INVALID_CREDENTIALS_MSG,
            status_code=status.HTTP_401_UNAUTHORIZED,
            event_type="invalid_credentials"
        )

class AccountLocked(AuthException):
    def __init__(self, temp_lock: bool = False):
        msg = BRUTE_FORCE_LOCKOUT_MSG if temp_lock else ACCOUNT_LOCKED_MSG
        super().__init__(
            detail=msg,
            status_code=status.HTTP_403_FORBIDDEN,
            event_type="account_locked"
        )

# Rate Limiting
class RateLimitExceeded(AuthException):
    def __init__(self):
        super().__init__(
            detail=RATE_LIMIT_EXCEEDED_MSG,
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            event_type="rate_limit_exceeded"
        )

# Security Events
class SuspiciousActivity(AuthException):
    def __init__(self, activity: str):
        super().__init__(
            detail=f"Suspicious activity detected: {activity}",
            status_code=status.HTTP_403_FORBIDDEN,
            event_type="suspicious_activity"
        )

class TokenExpired(AuthException):
    def __init__(self):
        super().__init__(
            detail=TOKEN_EXPIRED_MSG,
            status_code=status.HTTP_401_UNAUTHORIZED,
            event_type="token_expired"
        )

class PermissionDenied(AuthException):
    def __init__(self):
        super().__init__(
            detail=PERMISSION_DENIED_MSG,
            status_code=status.HTTP_403_FORBIDDEN,
            event_type="permission_denied"
        )
