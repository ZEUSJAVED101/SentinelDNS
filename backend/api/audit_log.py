"""Authenticated Audit Log pages and API."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from backend.security.dependencies import get_current_user
from backend.services.audit_log_service import AuditLogService
from database.database import get_db
from database.models.user import User


PROJECT_ROOT = Path(__file__).resolve().parents[2]
TEMPLATES_DIRECTORY = PROJECT_ROOT / "backend" / "templates"

templates = Jinja2Templates(directory=TEMPLATES_DIRECTORY)

router = APIRouter(tags=["Audit Log"])


@router.get("/audit-log", response_class=Response)
async def audit_log_page(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    """Render the authenticated administrator Audit Log page."""

    response = templates.TemplateResponse(
        request=request,
        name="audit_log/index.html",
        context={
            "application": "SentinelDNS",
            "version": "1.0.0",
            "user": current_user,
        },
    )
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


@router.get("/api/audit-log")
async def audit_log_api(
    limit: int = Query(default=100, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    """Return bounded, sanitized audit events for administrators."""

    events = AuditLogService.list_recent(db, limit=limit)
    return JSONResponse(
        content={
            "events": [AuditLogService.serialize(event) for event in events],
        },
        headers={
            "Cache-Control": "no-store, max-age=0",
            "Pragma": "no-cache",
        },
    )
