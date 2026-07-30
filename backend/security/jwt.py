"""
JWT Utility Module

Responsibilities:
- Create JWT access tokens
- Decode and validate JWTs
- Raise authentication exceptions
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import jwt
from jwt import ExpiredSignatureError, InvalidTokenError

from backend.core.config import settings
from backend.exceptions.auth import InvalidTokenError as SentinelInvalidTokenError


def create_access_token(subject: str) -> str:
    """
    Create a signed JWT access token.

    Args:
        subject: User identifier (typically username or user ID)

    Returns:
        Encoded JWT string
    """

    now = datetime.now(timezone.utc)

    payload = {
        "sub": subject,
        "iat": now,
        "exp": now + timedelta(
            minutes=settings.security.access_token_expire_minutes
        ),
    }

    return jwt.encode(
        payload,
        settings.security.secret_key,
        algorithm=settings.security.algorithm,
    )


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Decode and validate a JWT.

    Args:
        token: JWT string

    Returns:
        Decoded payload

    Raises:
        InvalidTokenError
    """

    try:
        payload = jwt.decode(
            token,
            settings.security.secret_key,
            algorithms=[settings.security.algorithm],
        )

        return payload

    except ExpiredSignatureError as exc:
        raise SentinelInvalidTokenError("Token has expired.") from exc

    except InvalidTokenError as exc:
        raise SentinelInvalidTokenError("Invalid authentication token.") from exc