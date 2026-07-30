"""
Authentication API

Responsibilities:
- Register new users
- Authenticate users
- Return JWT access tokens
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from backend.schemas.auth import LoginRequest, Token
from backend.schemas.user import UserCreate, UserResponse
from backend.services.authentication_service import AuthenticationService
from backend.services.dependencies import get_auth_service

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
    status_code=201,
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
    credentials: LoginRequest,
    service: AuthenticationService = Depends(get_auth_service),
) -> Token:
    """
    Authenticate a user and return a JWT access token.
    """
    return service.authenticate(credentials)