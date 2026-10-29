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

AUTH_COOKIE_NAME = "sentineldns_session"
SERVER_SESSION_COOKIE_NAME = "sentineldns_server_session"


def _get_token_payload(request: Request) -> dict:
    token: str | None = None

    authorization = request.headers.get("Authorization", "").strip()

    if authorization:
        scheme, separator, credentials = authorization.partition(" ")
        if separator and scheme.lower() == "bearer" and credentials.strip():
            token = credentials.strip()

    using_browser_cookie = False

    if not token:
        cookie_token = request.cookies.get(AUTH_COOKIE_NAME)
        if cookie_token:
            token = cookie_token.strip()
            using_browser_cookie = True

    if not token:
        raise AuthenticationRequiredError()

    if using_browser_cookie:
        current_server_session = getattr(
            request.app.state, "server_session_id", None
        )
        browser_server_session = request.cookies.get(
            SERVER_SESSION_COOKIE_NAME
        )

        if (
            not current_server_session
            or not browser_server_session
            or browser_server_session != current_server_session
        ):
            raise AuthenticationRequiredError()

    payload = decode_access_token(token)

    if not isinstance(payload, dict):
        raise InvalidTokenError()

    return payload


def _get_active_user(payload: dict, db: Session) -> User:
    username = payload.get("sub")

    if not isinstance(username, str) or not username.strip():
        raise InvalidTokenError()

    repository = UserRepository(db)
    user = repository.get_by_username(username)

    if user is None:
        raise InvalidTokenError()

    if not user.is_active:
        raise UserInactiveError()

    return user


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    """Return a user only when the token proves MFA is complete."""
    payload = _get_token_payload(request)

    if (
        payload.get("purpose") != "authenticated"
        or payload.get("mfa_completed") is not True
    ):
        raise AuthenticationRequiredError()

    return _get_active_user(payload, db)


def get_totp_enrollment_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    """Allow an admin with a pending token to access enrollment only."""
    payload = _get_token_payload(request)

    if (
        payload.get("purpose") != "totp_enrollment"
        or payload.get("mfa_completed") is not False
    ):
        raise AuthenticationRequiredError()

    user = _get_active_user(payload, db)

    if user.role != UserRole.ADMIN:
        raise PermissionDeniedError()

    return user


def require_role(role: UserRole) -> Callable:
    def dependency(
        current_user: User = Depends(get_current_user),
    ) -> User:
        if current_user.role != role:
            raise PermissionDeniedError()

        return current_user

    return dependency


require_admin = require_role(UserRole.ADMIN)
