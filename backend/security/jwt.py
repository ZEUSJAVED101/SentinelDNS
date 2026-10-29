"""
JWT Utility Module

Responsibilities:
- Create signed JWT access tokens
- Distinguish authenticated sessions from pending enrollment
- Decode and validate JWTs
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from jwt import ExpiredSignatureError, InvalidTokenError

from backend.core.config import settings
from backend.exceptions.auth import (
    InvalidTokenError as SentinelInvalidTokenError,
)


def create_access_token(
    subject: str,
    *,
    purpose: str = "unverified",
    mfa_completed: bool = False,
    expires_minutes: int | None = None,
) -> str:
    """Create a signed JWT with explicit authentication state."""

    lifetime = (
        expires_minutes
        if expires_minutes is not None
        else settings.security.access_token_expire_minutes
    )

    if lifetime < 1:
        raise ValueError("Token lifetime must be at least one minute.")

    now = datetime.now(timezone.utc)

    payload = {
        "sub": subject,
        "iat": now,
        "exp": now + timedelta(minutes=lifetime),
        "purpose": purpose,
        "mfa_completed": mfa_completed,
    }

    return jwt.encode(
        payload,
        settings.security.secret_key,
        algorithm=settings.security.algorithm,
    )


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode a JWT and validate its signature and expiration."""

    try:
        return jwt.decode(
            token,
            settings.security.secret_key,
            algorithms=[settings.security.algorithm],
        )

    except ExpiredSignatureError as exc:
        raise SentinelInvalidTokenError(
            "Token has expired."
        ) from exc

    except InvalidTokenError as exc:
        raise SentinelInvalidTokenError(
            "Invalid authentication token."
        ) from exc
