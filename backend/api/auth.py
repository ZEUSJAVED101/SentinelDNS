"""
SentinelDNS Authentication API

Responsibilities:
- Register users
- Authenticate users
- Generate JWT access tokens
- Establish browser authentication session
- Logout browser sessions
- Return current authenticated user
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm

from backend.schemas.auth import Token
from backend.schemas.user import UserCreate, UserResponse
from backend.security.dependencies import (
    AUTH_COOKIE_NAME,
    SERVER_SESSION_COOKIE_NAME,
    get_current_user,
)
from backend.services.authentication_service import (
    AuthenticationService,
)
from backend.services.dependencies import get_auth_service
from database.models.user import User


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


# ==========================================================
# REGISTER
# ==========================================================

@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    user: UserCreate,
    service: AuthenticationService = Depends(
        get_auth_service,
    ),
) -> UserResponse:

    return service.register(
        user,
    )


# ==========================================================
# LOGIN
# ==========================================================

@router.post(
    "/login",
    response_model=Token,
)
def login(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    service: AuthenticationService = Depends(
        get_auth_service,
    ),
) -> Token:
    """
    Authenticate a user and establish a browser session.
    """

    token = service.authenticate(
        username=form_data.username,
        password=form_data.password,
    )

    server_session_id = getattr(
        request.app.state,
        "server_session_id",
        None,
    )

    if not server_session_id:

        raise RuntimeError(
            "SentinelDNS server session is unavailable."
        )

    # ------------------------------------------------------
    # HttpOnly JWT cookie
    # ------------------------------------------------------

    response.set_cookie(
        key=AUTH_COOKIE_NAME,
        value=token.access_token,
        httponly=True,
        secure=False,
        samesite="strict",
        max_age=60 * 60,
        path="/",
    )

    # ------------------------------------------------------
    # Current server-instance cookie
    # ------------------------------------------------------

    response.set_cookie(
        key=SERVER_SESSION_COOKIE_NAME,
        value=server_session_id,
        httponly=True,
        secure=False,
        samesite="strict",
        max_age=60 * 60,
        path="/",
    )

    return token


# ==========================================================
# LOGOUT
# ==========================================================

@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
)
def logout(
    response: Response,
) -> Response:

    response.delete_cookie(
        key=AUTH_COOKIE_NAME,
        path="/",
    )

    response.delete_cookie(
        key=SERVER_SESSION_COOKIE_NAME,
        path="/",
    )

    return response


# ==========================================================
# CURRENT USER
# ==========================================================

@router.get(
    "/me",
    response_model=UserResponse,
)
def me(
    current_user: User = Depends(
        get_current_user,
    ),
) -> UserResponse:

    return UserResponse.model_validate(
        current_user,
    )