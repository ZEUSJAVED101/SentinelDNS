"""
Security dependencies.

Provides reusable authentication and authorization dependencies
for FastAPI routes.

Authentication supports:

- Authorization: Bearer <JWT>
- Secure HttpOnly browser session cookie

Security principles:

- JWT is never exposed to frontend JavaScript through the cookie
- Bearer authentication remains supported for API clients
- Invalid credentials are rejected
- Inactive users are rejected
- Role-based authorization remains unchanged
"""

from __future__ import annotations

from typing import Callable

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from backend.exceptions.auth import (
    AuthenticationRequiredError,
    InvalidTokenError,
    PermissionDeniedError,
    UserInactiveError,
)
from backend.repositories.user_repository import UserRepository
from backend.security.jwt import decode_access_token
from database.database import get_db
from database.enums.user_role import UserRole
from database.models.user import User


# ==========================================================
# Browser Session Cookie
# ==========================================================

AUTH_COOKIE_NAME = "sentineldns_session"


# ==========================================================
# Current User Dependency
# ==========================================================

def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    """
    Validate the JWT and return the authenticated user.

    Authentication order:

    1. Authorization: Bearer <JWT>
    2. HttpOnly browser session cookie

    Bearer authentication takes priority so existing API
    clients remain fully compatible.
    """

    token: str | None = None

    # ------------------------------------------------------
    # 1. Authorization header
    # ------------------------------------------------------

    authorization = request.headers.get(
        "Authorization",
        "",
    ).strip()

    if authorization:

        scheme, separator, credentials = (
            authorization.partition(" ")
        )

        if (
            separator
            and scheme.lower() == "bearer"
            and credentials.strip()
        ):

            token = credentials.strip()

    # ------------------------------------------------------
    # 2. Browser session cookie
    # ------------------------------------------------------

    if not token:

        cookie_token = request.cookies.get(
            AUTH_COOKIE_NAME,
        )

        if cookie_token:

            token = cookie_token.strip()

    # ------------------------------------------------------
    # No authentication supplied.
    # ------------------------------------------------------

    if not token:

        raise AuthenticationRequiredError()

    # ------------------------------------------------------
    # Validate JWT.
    # ------------------------------------------------------

    payload = decode_access_token(
        token,
    )

    username = payload.get(
        "sub",
    )

    if not username:

        raise InvalidTokenError()

    # ------------------------------------------------------
    # Load user from database.
    # ------------------------------------------------------

    repository = UserRepository(
        db,
    )

    user = repository.get_by_username(
        username,
    )

    if user is None:

        raise InvalidTokenError()

    # ------------------------------------------------------
    # Verify account status.
    # ------------------------------------------------------

    if not user.is_active:

        raise UserInactiveError()

    return user


# ==========================================================
# Role-Based Authorization
# ==========================================================

def require_role(
    role: UserRole,
) -> Callable:
    """
    Factory for role-based authorization dependencies.
    """

    def dependency(
        current_user: User = Depends(
            get_current_user,
        ),
    ) -> User:

        if current_user.role != role:

            raise PermissionDeniedError()

        return current_user

    return dependency


# ==========================================================
# Admin Authorization
# ==========================================================

require_admin = require_role(
    UserRole.ADMIN,
)