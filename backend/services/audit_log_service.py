"""Audit log service for sanitized administrative events."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from database.models.audit_log import AuditLog
from database.models.user import User


class AuditLogService:
    """Create and retrieve persistent audit events."""

    @staticmethod
    def record(
        db: Session,
        *,
        action: str,
        result: str,
        actor: User | None = None,
        resource: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditLog:
        """Persist a sanitized event. Secrets must never be supplied in details."""

        event = AuditLog(
            actor_user_id=actor.id if actor is not None else None,
            actor_username=actor.username if actor is not None else None,
            action=action,
            result=result,
            resource=resource,
            details=(json.dumps(details, separators=(",", ":")) if details else None),
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event

    @staticmethod
    def list_recent(
        db: Session,
        *,
        limit: int = 100,
    ) -> list[AuditLog]:
        """Return the newest audit events, bounded to 100 records."""

        bounded_limit = max(1, min(limit, 100))
        statement = (
            select(AuditLog)
            .order_by(desc(AuditLog.created_at), desc(AuditLog.id))
            .limit(bounded_limit)
        )
        return list(db.scalars(statement).all())

    @staticmethod
    def serialize(event: AuditLog) -> dict[str, Any]:
        """Convert an event into the frontend-safe response shape."""

        details: Any = None
        if event.details:
            try:
                details = json.loads(event.details)
            except (TypeError, ValueError):
                details = None

        created_at = event.created_at
        if isinstance(created_at, datetime):
            timestamp = created_at.isoformat()
        else:
            timestamp = str(created_at)

        return {
            "id": event.id,
            "timestamp": timestamp,
            "actor": event.actor_username,
            "action": event.action,
            "result": event.result,
            "resource": event.resource,
            "details": details,
        }
