from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import jwt
import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from fastapi.responses import JSONResponse

from backend.security.dependencies import get_current_user
from backend.security.jwt import create_access_token
from backend.core.config import settings
from database.enums.user_role import UserRole
from database.models.user import User


@pytest.fixture
def client_and_db():
    from backend.security import dependencies
    from backend.exceptions.auth import AuthenticationRequiredError

    app = FastAPI()
    db = MagicMock()

    user = MagicMock(spec=User)
    user.username = "admin"
    user.is_active = True
    user.role = UserRole.ADMIN

    repository = MagicMock()
    repository.get_by_username.return_value = user

    original_repository = dependencies.UserRepository
    dependencies.UserRepository = MagicMock(return_value=repository)

    @app.exception_handler(AuthenticationRequiredError)
    async def authentication_required_handler(request, exc):
        return JSONResponse(
            status_code=401,
            content={"detail": "Authentication is required."},
        )

    app.dependency_overrides[dependencies.get_db] = lambda: db

    @app.get("/protected")
    def protected(current_user=Depends(get_current_user)):
        return {"username": current_user.username}

    try:
        yield TestClient(app), user
    finally:
        dependencies.UserRepository = original_repository
        app.dependency_overrides.clear()


@pytest.mark.parametrize(
    "purpose,mfa_completed",
    [
        ("totp_enrollment", False),
        ("unverified", False),
        ("authenticated", False),
    ],
)
def test_incomplete_mfa_token_is_rejected(
    client_and_db, purpose, mfa_completed
):
    client, _ = client_and_db

    token = create_access_token(
        "admin",
        purpose=purpose,
        mfa_completed=mfa_completed,
    )

    response = client.get(
        "/protected",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_authenticated_mfa_token_is_accepted(client_and_db):
    client, _ = client_and_db

    token = create_access_token(
        "admin",
        purpose="authenticated",
        mfa_completed=True,
    )

    response = client.get(
        "/protected",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json() == {"username": "admin"}


def test_token_without_mfa_claims_is_rejected(client_and_db):
    now = datetime.now(timezone.utc)

    token = jwt.encode(
        {
            "sub": "admin",
            "iat": now,
            "exp": now + timedelta(minutes=5),
        },
        settings.security.secret_key,
        algorithm=settings.security.algorithm,
    )

    client, _ = client_and_db

    response = client.get(
        "/protected",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401