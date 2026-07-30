"""
User Repository for SentinelDNS.

Contains user-specific database queries.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.repositories.base_repository import BaseRepository
from database.models.user import User


class UserRepository(BaseRepository[User]):
    """
    Repository providing user-specific database operations.
    """

    def __init__(self, session: Session) -> None:
        super().__init__(session, User)

    def get_by_username(self, username: str) -> User | None:
        """
        Retrieve a user by username.
        """
        statement = select(User).where(User.username == username)
        return self._session.scalar(statement)

    def get_by_email(self, email: str) -> User | None:
        """
        Retrieve a user by email.
        """
        statement = select(User).where(User.email == email)
        return self._session.scalar(statement)

    def username_exists(self, username: str) -> bool:
        """
        Check whether a username already exists.
        """
        return self.get_by_username(username) is not None

    def email_exists(self, email: str) -> bool:
        """
        Check whether an email already exists.
        """
        return self.get_by_email(email) is not None