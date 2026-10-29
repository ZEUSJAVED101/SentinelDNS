import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database.base import Base
from database.enums.user_role import UserRole
from database.models.user import User

from backend.exceptions.auth import (
    EmailAlreadyExistsError,
    InvalidCredentialsError,
    UserInactiveError,
    UsernameAlreadyExistsError,
)
from backend.schemas.user import UserCreate
from backend.security.jwt import decode_access_token
from backend.services.authentication_service import AuthenticationService


# ==========================================================
# Test Database
# ==========================================================

@pytest.fixture()
def db_session():
    """Create an isolated in-memory SQLite database for each test."""

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )

    TestingSessionLocal = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
    )

    Base.metadata.create_all(engine)
    session = TestingSessionLocal()

    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


@pytest.fixture()
def service(db_session):
    return AuthenticationService(db_session)


# ==========================================================
# Registration
# ==========================================================

def test_register_user(service):
    user = service.register(
        UserCreate(
            username="testuser",
            email="test@example.com",
            password="Password123!",
        )
    )

    assert user.username == "testuser"
    assert user.email == "test@example.com"
    assert user.is_active is True
    assert user.role == UserRole.USER


def test_duplicate_username_is_rejected(service):
    service.register(
        UserCreate(
            username="testuser",
            email="first@example.com",
            password="Password123!",
        )
    )

    with pytest.raises(UsernameAlreadyExistsError):
        service.register(
            UserCreate(
                username="testuser",
                email="second@example.com",
                password="Password123!",
            )
        )


def test_duplicate_email_is_rejected(service):
    service.register(
        UserCreate(
            username="firstuser",
            email="test@example.com",
            password="Password123!",
        )
    )

    with pytest.raises(EmailAlreadyExistsError):
        service.register(
            UserCreate(
                username="seconduser",
                email="test@example.com",
                password="Password123!",
            )
        )


# ==========================================================
# Authentication
# ==========================================================

def test_authenticate_valid_user(service, db_session):
    service.register(
        UserCreate(
            username="testuser",
            email="test@example.com",
            password="Password123!",
        )
    )

    user = (
        db_session.query(User)
        .filter(User.username == "testuser")
        .first()
    )
    assert user is not None

    # Only administrators may authenticate through the admin login.
    user.role = UserRole.ADMIN
    db_session.commit()

    token = service.authenticate(
        username="testuser",
        password="Password123!",
    )

    assert token.access_token
    assert token.token_type == "bearer"

    # Password verification must issue a restricted pending-MFA token,
    # not a fully authenticated session token.
    payload = decode_access_token(token.access_token)
    assert payload["sub"] == "testuser"
    assert payload["purpose"] == "totp_enrollment"
    assert payload["mfa_completed"] is False


def test_invalid_username_is_rejected(service):
    with pytest.raises(InvalidCredentialsError):
        service.authenticate(
            username="does-not-exist",
            password="Password123!",
        )


def test_invalid_password_is_rejected(service, db_session):
    service.register(
        UserCreate(
            username="testuser",
            email="test@example.com",
            password="Password123!",
        )
    )

    user = (
        db_session.query(User)
        .filter(User.username == "testuser")
        .first()
    )
    assert user is not None
    user.role = UserRole.ADMIN
    db_session.commit()

    with pytest.raises(InvalidCredentialsError):
        service.authenticate(
            username="testuser",
            password="WrongPassword123!",
        )


def test_inactive_user_is_rejected(service, db_session):
    service.register(
        UserCreate(
            username="inactiveuser",
            email="inactive@example.com",
            password="Password123!",
        )
    )

    user = (
        db_session.query(User)
        .filter(User.username == "inactiveuser")
        .first()
    )
    assert user is not None

    user.role = UserRole.ADMIN
    user.is_active = False
    db_session.commit()

    with pytest.raises(UserInactiveError):
        service.authenticate(
            username="inactiveuser",
            password="Password123!",
        )
