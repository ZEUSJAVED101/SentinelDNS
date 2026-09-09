"""
SentinelDNS Security Dependencies

Responsibilities:
- Authenticate browser sessions
- Authenticate Bearer-token API clients
- Validate JWT access tokens
- Verify the current user exists and is active
- Enforce role-based authorization

Security model:

- Browser JWT is stored only in an HttpOnly cookie.
- API clients may use Authorization: Bearer <JWT>.
- Browser sessions are bound to the current SentinelDNS
  server instance.
- Restarting the SentinelDNS server invalidates old browser
  sessions.
- Client addresses and DNS query information are never
  handled here.
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
# Browser Authentication Cookie
# ==========================================================

AUTH_COOKIE_NAME = "sentineldns_session"

# Cookie containing the current server-instance identifier.
#
# This is NOT the JWT.
#
# It allows SentinelDNS to invalidate all browser sessions
# whenever the application is restarted.

SERVER_SESSION_COOKIE_NAME = (
    "sentineldns_server_session"
)


# ==========================================================
# Current User
# ==========================================================

def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    """
    Validate authentication and return the current user.

    Authentication order:

    1. Authorization: Bearer <JWT>
    2. HttpOnly browser JWT cookie

    Browser authentication additionally requires the current
    server-session cookie.

    Therefore:

        Server restart
              ↓
        New server session ID
              ↓
        Old browser session rejected
              ↓
        User must log in again
    """

    token: str | None = None

    # ------------------------------------------------------
    # 1. Authorization header
    #
    # Bearer authentication is intended for API clients.
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
    # 2. Browser session
    # ------------------------------------------------------

    using_browser_cookie = False

    if not token:

        cookie_token = request.cookies.get(
            AUTH_COOKIE_NAME,
        )

        if cookie_token:

            token = cookie_token.strip()
            using_browser_cookie = True

    # ------------------------------------------------------
    # No authentication supplied.
    # ------------------------------------------------------

    if not token:

        raise AuthenticationRequiredError()

    # ------------------------------------------------------
    # Browser sessions must belong to the current server
    # instance.
    #
    # Bearer API clients are intentionally not subject to
    # this browser-session requirement.
    # ------------------------------------------------------

    if using_browser_cookie:

        current_server_session = getattr(
            request.app.state,
            "server_session_id",
            None,
        )

        browser_server_session = (
            request.cookies.get(
                SERVER_SESSION_COOKIE_NAME,
            )
        )

        if (
            not current_server_session
            or not browser_server_session
            or browser_server_session
            != current_server_session
        ):

            raise AuthenticationRequiredError()

    # ------------------------------------------------------
    # Decode and validate JWT.
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