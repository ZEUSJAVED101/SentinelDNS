"""
Authentication Service

Responsibilities:
- Register new users
- Authenticate users
- Generate JWT access tokens
- Coordinate repositories and security utilities
"""

from __future__ import annotations

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.exceptions.auth import (
    EmailAlreadyExistsError,
    InvalidCredentialsError,
    UserInactiveError,
    UsernameAlreadyExistsError,
)
from backend.repositories.user_repository import UserRepository
from backend.schemas.auth import Token
from backend.schemas.user import UserCreate, UserResponse
from backend.security.jwt import create_access_token
from backend.security.password import hash_password, verify_password
from database.models.user import User


class AuthenticationService:
    """
    Handles user registration and authentication.
    """

    def __init__(self, session: Session) -> None:
        self._session = session
        self._users = UserRepository(session)

    # ==========================================================
    # Registration
    # ==========================================================

    def register(self, user: UserCreate) -> UserResponse:
        """
        Register a new user.
        """

        if self._users.username_exists(user.username):
            raise UsernameAlreadyExistsError()

        if self._users.email_exists(user.email):
            raise EmailAlreadyExistsError()

        db_user = User(
            username=user.username,
            email=user.email,
            password_hash=hash_password(user.password),
        )

        try:
            self._users.create(db_user)
            self._session.commit()
            self._session.refresh(db_user)

            return UserResponse.model_validate(db_user)

        except SQLAlchemyError:
            self._session.rollback()
            raise

    # ==========================================================
    # Authentication
    # ==========================================================

    def authenticate(
        self,
        username: str,
        password: str,
    ) -> Token:
        """
        Authenticate a user and return a JWT access token.
        """

        user = self._users.get_by_username(username)

        if user is None:
            raise InvalidCredentialsError()

        if not verify_password(
            password,
            user.password_hash,
        ):
            raise InvalidCredentialsError()

        if not user.is_active:
            raise UserInactiveError()

        access_token = create_access_token(
            subject=user.username,
        )

        return Token(
            access_token=access_token,
            token_type="bearer",
        )