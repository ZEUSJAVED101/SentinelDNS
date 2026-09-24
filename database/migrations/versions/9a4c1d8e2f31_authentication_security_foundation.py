"""Add authentication security foundation.

Revision ID: 9a4c1d8e2f31
Revises: 68b7230238b6
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
revision: str = "9a4c1d8e2f31"
down_revision: Union[str, Sequence[str], None] = "68b7230238b6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.add_column(sa.Column("totp_secret_encrypted", sa.String(length=1024), nullable=True))
        batch_op.add_column(sa.Column("totp_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch_op.add_column(sa.Column("totp_confirmed_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("failed_login_attempts", sa.Integer(), nullable=False, server_default="0"))
        batch_op.add_column(sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("last_failed_login_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True))
    op.create_table("user_recovery_questions",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False), sa.Column("slot", sa.Integer(), nullable=False),
        sa.Column("question", sa.String(length=500), nullable=False), sa.Column("answer_hash", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False), sa.Column("version", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("user_id", "slot", name="uq_recovery_question_user_slot"))
    op.create_index("ix_user_recovery_questions_user_id", "user_recovery_questions", ["user_id"], unique=False)
    op.create_table("user_recovery_codes",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False), sa.Column("code_hash", sa.String(length=255), nullable=False), sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False), sa.Column("version", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("code_hash"))
    op.create_index("ix_user_recovery_codes_user_id", "user_recovery_codes", ["user_id"], unique=False)

def downgrade() -> None:
    op.drop_index("ix_user_recovery_codes_user_id", table_name="user_recovery_codes")
    op.drop_table("user_recovery_codes")
    op.drop_index("ix_user_recovery_questions_user_id", table_name="user_recovery_questions")
    op.drop_table("user_recovery_questions")
    with op.batch_alter_table("users", schema=None) as batch_op:
        for column in ("password_changed_at", "last_login_at", "last_failed_login_at", "locked_until", "failed_login_attempts", "totp_confirmed_at", "totp_enabled", "totp_secret_encrypted"):
            batch_op.drop_column(column)
