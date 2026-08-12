"""
SentinelDNS Dashboard API.

Provides authenticated, read-only runtime statistics.

Security principles:

- Authentication required.
- No mutation endpoints.
- No raw DNS packets.
- No queried-domain history.
- No client addresses.
- No secrets or credentials.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from backend.security.dependencies import get_current_user
from database.models.user import User


router = APIRouter(
    prefix="/api/dashboard",
    tags=["Dashboard"],
)


@router.get(
    "/",
)
def get_dashboard(
    request: Request,
    current_user: User = Depends(
        get_current_user,
    ),
) -> dict:
    """
    Return authenticated dashboard runtime data.
    """

    # Explicitly reference the authenticated user so
    # authentication cannot accidentally become unused.
    _ = current_user

    service = getattr(
        request.app.state,
        "dashboard_service",
        None,
    )

    if service is None:
        return {
            "status": "unavailable",
        }

    return service.get_dashboard_data()