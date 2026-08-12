"""
Authentication API routes.

Supports:

- User registration
- JWT login
- Secure browser session cookie
- Current-user lookup

Security principles:

- JWT remains available to API clients
- Browser JWT is stored in an HttpOnly cookie
- Cookie is never readable by JavaScript
- Secure flag is enabled automatically outside debug mode
- SameSite=Lax protects against cross-site requests
"""

from __future__ import annotations

from fastapi import (
    APIRouter,
    Depends,
    Response,
    status,
)
from fastapi.security import OAuth2PasswordRequestForm

from backend.core.config import settings
from backend.schemas.auth import Token
from backend.schemas.user import (
    UserCreate,
    UserResponse,
)
from backend.security.dependencies import (
    AUTH_COOKIE_NAME,
    get_current_user,
)
from backend.services.authentication_service import (
    AuthenticationService,
)
from backend.services.dependencies import (
    get_auth_service,
)
from database.models.user import User


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


# ==========================================================
# COOKIE CONFIGURATION
# ==========================================================

AUTH_COOKIE_MAX_AGE = (
    settings.security.access_token_expire_minutes
    * 60
)

AUTH_COOKIE_SECURE = (
    not settings.application.debug
)

AUTH_COOKIE_SAMESITE = "lax"


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
    """
    Register a new user.
    """

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
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    service: AuthenticationService = Depends(
        get_auth_service,
    ),
) -> Token:
    """
    Authenticate a user.

    Returns the existing JWT response for API clients and
    additionally establishes a secure browser session cookie.
    """

    token = service.authenticate(
        username=form_data.username,
        password=form_data.password,
    )

    # ------------------------------------------------------
    # HttpOnly cookie
    #
    # JavaScript cannot access this cookie.
    # ------------------------------------------------------

    response.set_cookie(
        key=AUTH_COOKIE_NAME,
        value=token.access_token,
        max_age=AUTH_COOKIE_MAX_AGE,
        httponly=True,
        secure=AUTH_COOKIE_SECURE,
        samesite=AUTH_COOKIE_SAMESITE,
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
    """
    End the browser session.

    JWTs are stateless, so this removes the browser's
    authentication cookie. Existing bearer tokens remain
    valid until their normal expiration.
    """

    response.delete_cookie(
        key=AUTH_COOKIE_NAME,
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
    """
    Return the currently authenticated user.
    """

    return UserResponse.model_validate(
        current_user,
    )