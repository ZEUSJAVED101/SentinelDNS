"""
SentinelDNS Authentication API

Responsibilities:
- Authenticate the administrator
- Generate JWT access tokens
- Establish the browser authentication session
- Logout browser sessions
- Return the current administrator

Public account registration is intentionally disabled. SentinelDNS is
operated as a single-administrator security appliance.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm

from backend.schemas.auth import Token
from backend.schemas.user import UserResponse
from backend.security.dependencies import (
    AUTH_COOKIE_NAME,
    SERVER_SESSION_COOKIE_NAME,
    get_current_user,
)
from backend.services.authentication_service import AuthenticationService
from backend.services.dependencies import get_auth_service
from database.models.user import User

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


@router.post(
    "/login",
    response_model=Token,
)
def login(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    service: AuthenticationService = Depends(get_auth_service),
) -> Token:
    """Authenticate an administrator and establish a browser session."""

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

    response.set_cookie(
        key=AUTH_COOKIE_NAME,
        value=token.access_token,
        httponly=True,
        secure=False,
        samesite="strict",
        max_age=60 * 60,
        path="/",
    )

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


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
)
def logout(response: Response) -> Response:
    """Clear the browser authentication cookies."""

    response.delete_cookie(
        key=AUTH_COOKIE_NAME,
        path="/",
    )
    response.delete_cookie(
        key=SERVER_SESSION_COOKIE_NAME,
        path="/",
    )
    return response


@router.get(
    "/me",
    response_model=UserResponse,
)
def me(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """Return the authenticated administrator."""

    return UserResponse.model_validate(current_user)
