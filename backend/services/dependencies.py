"""
Service dependency providers.
"""

from sqlalchemy.orm import Session
from fastapi import Depends

from database.database import get_db
from backend.services.authentication_service import AuthenticationService


def get_auth_service(
    db: Session = Depends(get_db),
) -> AuthenticationService:
    """
    Return an AuthenticationService instance.
    """
    return AuthenticationService(db)