"""Create the persistent SentinelDNS audit log.

The table may already exist when this migration is introduced because the
application database can have been initialized before Alembic recorded this
revision. The upgrade is therefore intentionally idempotent for the table and
its indexes.
"""

from alembic import op
import sqlalchemy as sa


revision = "audit_log_01"
down_revision = "9a4c1d8e2f31"
branch_labels = None
depends_on = None


_INDEXES = {
    "ix_audit_log_actor_user_id": ["actor_user_id"],
    "ix_audit_log_action": ["action"],
    "ix_audit_log_result": ["result"],
    "ix_audit_log_created_at": ["created_at"],
}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if "audit_log" not in inspector.get_table_names():
        op.create_table(
            "audit_log",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("event_uuid", sa.String(length=36), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
            sa.Column("actor_user_id", sa.Integer(), nullable=True),
            sa.Column("actor_username", sa.String(length=50), nullable=True),
            sa.Column("action", sa.String(length=100), nullable=False),
            sa.Column("result", sa.String(length=30), nullable=False),
            sa.Column("resource", sa.String(length=100), nullable=True),
            sa.Column("details", sa.Text(), nullable=True),
            sa.ForeignKeyConstraint(["actor_user_id"], ["users.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("event_uuid"),
        )

    existing_indexes = {item["name"] for item in sa.inspect(bind).get_indexes("audit_log")}
    for index_name, columns in _INDEXES.items():
        if index_name not in existing_indexes:
            op.create_index(index_name, "audit_log", columns)


def downgrade() -> None:
    bind = op.get_bind()
    if "audit_log" not in sa.inspect(bind).get_table_names():
        return

    existing_indexes = {item["name"] for item in sa.inspect(bind).get_indexes("audit_log")}
    for index_name in reversed(list(_INDEXES)):
        if index_name in existing_indexes:
            op.drop_index(index_name, table_name="audit_log")
    op.drop_table("audit_log")
