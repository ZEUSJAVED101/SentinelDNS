"""
Authentication API routes.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from fastapi.security import OAuth2PasswordRequestForm

from backend.schemas.auth import Token
from backend.schemas.user import UserCreate, UserResponse
from backend.security.dependencies import get_current_user
from backend.services.authentication_service import AuthenticationService
from backend.services.dependencies import get_auth_service
from database.models.user import User

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


# ==========================================================
# Register
# ==========================================================

@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    user: UserCreate,
    service: AuthenticationService = Depends(get_auth_service),
) -> UserResponse:
    """
    Register a new user.
    """
    return service.register(user)


# ==========================================================
# Login
# ==========================================================

@router.post(
    "/login",
    response_model=Token,
)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    service: AuthenticationService = Depends(get_auth_service),
) -> Token:
    """
    Authenticate a user and return an access token.
    """

    return service.authenticate(
        username=form_data.username,
        password=form_data.password,
    )


# ==========================================================
# Current User
# ==========================================================

@router.get(
    "/me",
    response_model=UserResponse,
)
def me(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """
    Return the currently authenticated user.
    """

    return UserResponse.model_validate(current_user)