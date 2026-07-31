"""
Security dependencies.

Provides reusable authentication and authorization dependencies
for FastAPI routes.
"""

from __future__ import annotations

from typing import Callable

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
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
# OAuth2 Scheme
# ==========================================================

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/auth/login",
)


# ==========================================================
# Current User Dependency
# ==========================================================

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """
    Validate the JWT and return the authenticated user.
    """

    if not token:
        raise AuthenticationRequiredError()

    payload = decode_access_token(token)

    username = payload.get("sub")

    if username is None:
        raise InvalidTokenError()

    repository = UserRepository(db)

    user = repository.get_by_username(username)

    if user is None:
        raise InvalidTokenError()

    if not user.is_active:
        raise UserInactiveError()

    return user


# ==========================================================
# Role-Based Authorization
# ==========================================================

def require_role(role: UserRole) -> Callable:
    """
    Factory for role-based authorization dependencies.
    """

    def dependency(
        current_user: User = Depends(get_current_user),
    ) -> User:

        if current_user.role != role:
            raise PermissionDeniedError()

        return current_user

    return dependency


require_admin = require_role(UserRole.ADMIN)