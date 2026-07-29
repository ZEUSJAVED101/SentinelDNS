"""
User model for SentinelDNS.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, Enum, String
from sqlalchemy.orm import Mapped, mapped_column

from database.base import Base
from database.enums.user_role import UserRole
from database.mixins import TimestampMixin


class User(TimestampMixin, Base):
    """
    User account.
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True,
    )

    uuid: Mapped[str] = mapped_column(
        String(36),
        unique=True,
        nullable=False,
        default=lambda: str(uuid.uuid4()),
    )

    username: Mapped[str] = mapped_column(
    String(50),
    unique=True,
    nullable=False,
    )

    email: Mapped[str] = mapped_column(
    String(255),
    unique=True,
    nullable=False,
    )

    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole),
        default=UserRole.USER,
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )