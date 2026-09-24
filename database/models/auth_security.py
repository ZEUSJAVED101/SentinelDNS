"""Authentication security persistence models for SentinelDNS."""
from __future__ import annotations
from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from database.base import Base
from database.mixins import TimestampMixin

class UserRecoveryQuestion(TimestampMixin, Base):
    """One hashed recovery question/answer pair for an administrator."""
    __tablename__ = "user_recovery_questions"
    __table_args__ = (UniqueConstraint("user_id", "slot", name="uq_recovery_question_user_slot"),)
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    slot: Mapped[int] = mapped_column(Integer, nullable=False)
    question: Mapped[str] = mapped_column(String(500), nullable=False)
    answer_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    user: Mapped["User"] = relationship("User", back_populates="recovery_questions")

class UserRecoveryCode(TimestampMixin, Base):
    """Single-use recovery code stored only as a hash."""
    __tablename__ = "user_recovery_codes"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    code_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    user: Mapped["User"] = relationship("User", back_populates="recovery_codes")

from database.models.user import User  # noqa: E402
__all__ = ["UserRecoveryQuestion", "UserRecoveryCode"]
