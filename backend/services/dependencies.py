"""
SentinelDNS Service Dependency Providers

Responsibilities:

- Provide database-backed service dependencies
- Create AuthenticationService instances
- Keep FastAPI dependency wiring centralized
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.orm import Session

from backend.services.authentication_service import (
    AuthenticationService,
)
from database.database import get_db


# ==========================================================
# AUTHENTICATION SERVICE
# ==========================================================

def get_auth_service(
    db: Session = Depends(get_db),
) -> AuthenticationService:
    """
    Return an AuthenticationService instance.

    FastAPI provides the database session through get_db().
    The service receives that session and creates the required
    repository dependencies internally.
    """

    return AuthenticationService(
        db,
    )