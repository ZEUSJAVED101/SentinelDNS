"""SentinelDNS authentication API."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from backend.exceptions.auth import PermissionDeniedError
from backend.schemas.auth import Token
from backend.schemas.totp import (
    TOTPEnrollResponse,
    TOTPStatusResponse,
    TOTPVerifyRequest,
)
from backend.schemas.user import UserResponse
from backend.security.dependencies import (
    AUTH_COOKIE_NAME,
    SERVER_SESSION_COOKIE_NAME,
    get_current_user,
)
from backend.security.totp import (
    build_provisioning_uri,
    build_qr_code_data_uri,
    decrypt_totp_secret,
    encrypt_totp_secret,
    generate_totp_secret,
    verify_totp_code,
)
from backend.services.audit_log_service import AuditLogService
from backend.services.authentication_service import AuthenticationService
from backend.services.dependencies import get_auth_service
from database.database import get_db
from database.enums.user_role import UserRole
from database.models.user import User

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


@router.post(
    "/login",
    response_model=Token,
)
def login(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    service: AuthenticationService = Depends(get_auth_service),
    db: Session = Depends(get_db),
) -> Token:
    """Authenticate an administrator and establish a browser session."""

    token = service.authenticate(
        username=form_data.username,
        password=form_data.password,
    )

    server_session_id = getattr(
        request.app.state,
        "server_session_id",
        None,
    )

    if not server_session_id:
        raise RuntimeError("SentinelDNS server session is unavailable.")

    response.set_cookie(
        key=AUTH_COOKIE_NAME,
        value=token.access_token,
        httponly=True,
        secure=False,
        samesite="strict",
        max_age=60 * 60,
        path="/",
    )

    response.set_cookie(
        key=SERVER_SESSION_COOKIE_NAME,
        value=server_session_id,
        httponly=True,
        secure=False,
        samesite="strict",
        max_age=60 * 60,
        path="/",
    )

    try:
        user = db.query(User).filter(User.username == form_data.username).first()
        if user is not None:
            AuditLogService.record(
                db,
                action="LOGIN",
                result="SUCCESS",
                actor=user,
                resource="authentication",
            )
    except Exception:
        # Audit logging must never break a successful login.
        db.rollback()

    return token


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
)
def logout(
    response: Response,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    """Clear the browser authentication cookies."""

    try:
        AuditLogService.record(
            db,
            action="LOGOUT",
            result="SUCCESS",
            actor=current_user,
            resource="authentication",
        )
    except Exception:
        db.rollback()

    response.delete_cookie(key=AUTH_COOKIE_NAME, path="/")
    response.delete_cookie(key=SERVER_SESSION_COOKIE_NAME, path="/")
    return response


@router.get(
    "/me",
    response_model=UserResponse,
)
def me(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """Return the authenticated administrator."""

    return UserResponse.model_validate(current_user)


@router.get(
    "/totp/status",
    response_model=TOTPStatusResponse,
)
def totp_status(
    current_user: User = Depends(get_current_user),
) -> TOTPStatusResponse:
    """Return TOTP enrollment state without exposing the secret."""

    return TOTPStatusResponse(
        enabled=current_user.totp_enabled,
        confirmed=current_user.totp_confirmed_at is not None,
    )


@router.post(
    "/totp/enroll",
    response_model=TOTPEnrollResponse,
)
def totp_enroll(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> TOTPEnrollResponse:
    """
    Start TOTP enrollment for the current administrator.

    The secret is returned only as part of the enrollment response.
    It is encrypted before being persisted and is never logged.
    """

    if current_user.role != UserRole.ADMIN:
        raise PermissionDeniedError()

    if current_user.totp_enabled:
        raise PermissionDeniedError("TOTP is already enrolled for this account.")

    secret = generate_totp_secret()

    current_user.totp_secret_encrypted = encrypt_totp_secret(secret)
    current_user.totp_enabled = False
    current_user.totp_confirmed_at = None

    db.commit()
    db.refresh(current_user)

    try:
        AuditLogService.record(
            db,
            action="TOTP_ENROLL_STARTED",
            result="SUCCESS",
            actor=current_user,
            resource="totp",
        )
    except Exception:
        db.rollback()
        # Enrollment already committed; audit failure must not expose the secret or break setup.

    provisioning_uri = build_provisioning_uri(
        secret,
        current_user.username,
    )

    return TOTPEnrollResponse(
        secret=secret,
        provisioning_uri=provisioning_uri,
        qr_code_data_uri=build_qr_code_data_uri(provisioning_uri),
    )


@router.post(
    "/totp/confirm",
    response_model=TOTPStatusResponse,
)
def totp_confirm(
    payload: TOTPVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> TOTPStatusResponse:
    """Confirm an authenticator code and activate TOTP for the account."""

    if current_user.role != UserRole.ADMIN:
        raise PermissionDeniedError()

    if current_user.totp_enabled:
        return TOTPStatusResponse(enabled=True, confirmed=True)

    if not current_user.totp_secret_encrypted:
        raise PermissionDeniedError("TOTP enrollment has not been started.")

    try:
        secret = decrypt_totp_secret(current_user.totp_secret_encrypted)
    except ValueError as exc:
        raise PermissionDeniedError("TOTP enrollment data is invalid.") from exc

    if not verify_totp_code(secret, payload.code):
        raise PermissionDeniedError("Invalid authenticator code.")

    current_user.totp_enabled = True
    current_user.totp_confirmed_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(current_user)

    try:
        AuditLogService.record(
            db,
            action="TOTP_ENROLL_CONFIRMED",
            result="SUCCESS",
            actor=current_user,
            resource="totp",
        )
    except Exception:
        db.rollback()

    return TOTPStatusResponse(enabled=True, confirmed=True)
