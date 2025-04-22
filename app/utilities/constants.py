from os import environ
from dotenv import load_dotenv

load_dotenv()

# JWT Configuration
SECRET_KEY = environ["SECRET_KEY"]
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Password & Security
MIN_PASSWORD_LENGTH = 8
MAX_LOGIN_ATTEMPTS = 5
PASSWORD_RESET_EXPIRE_MINUTES = 15

# Rate Limiting
RATE_LIMIT_LOGIN = "5/minute"
RATE_LIMIT_PASSWORD_RESET = "3/hour"

# Error Messages
INVALID_CREDENTIALS_MSG = "Invalid email or password"
ACCOUNT_INACTIVE_MSG = "Account is inactive"
ACCOUNT_LOCKED_MSG = "Account locked (too many failed attempts)"
EMAIL_NOT_VERIFIED_MSG = "Email not verified"
TOKEN_EXPIRED_MSG = "Token expired"
TOKEN_INVALID_MSG = "Invalid token"
PERMISSION_DENIED_MSG = "Permission denied"
RATE_LIMIT_EXCEEDED_MSG = "Too many requests. Please try again later."
BRUTE_FORCE_LOCKOUT_MSG = "Account temporarily locked due to suspicious activity"
SECURITY_LOG_MSG = "Security event: {event_type} - {details}"
