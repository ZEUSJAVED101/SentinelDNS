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
    get_totp_enrollment_user,
)
from backend.security.jwt import create_access_token
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


def _set_auth_cookie(
    response: Response,
    token: str,
) -> None:
    """Set the HTTP-only browser authentication cookie."""
    response.set_cookie(
        key=AUTH_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=False,
        samesite="strict",
        max_age=60 * 60,
        path="/",
    )


def _record_audit_safely(
    db: Session,
    *,
    action: str,
    actor: User,
    resource: str,
) -> None:
    """Record an audit event without breaking the authentication flow."""
    try:
        AuditLogService.record(
            db,
            action=action,
            result="SUCCESS",
            actor=actor,
            resource=resource,
        )
    except Exception:
        db.rollback()


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
    """Verify administrator credentials and establish a pending MFA session."""

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

    # This token is restricted until TOTP verification succeeds.
    _set_auth_cookie(response, token.access_token)

    response.set_cookie(
        key=SERVER_SESSION_COOKIE_NAME,
        value=server_session_id,
        httponly=True,
        secure=False,
        samesite="strict",
        max_age=60 * 60,
        path="/",
    )

    user = (
        db.query(User)
        .filter(User.username == form_data.username)
        .first()
    )

    if user is not None:
        _record_audit_safely(
            db,
            action="LOGIN_PASSWORD_VERIFIED",
            actor=user,
            resource="authentication",
        )

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

    _record_audit_safely(
        db,
        action="LOGOUT",
        actor=current_user,
        resource="authentication",
    )

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
    current_user: User = Depends(get_totp_enrollment_user),
    db: Session = Depends(get_db),
) -> TOTPEnrollResponse:
    """Start TOTP enrollment for an administrator who has not enabled it."""

    if current_user.role != UserRole.ADMIN:
        raise PermissionDeniedError()

    if current_user.totp_enabled:
        raise PermissionDeniedError(
            "TOTP is already enabled. Verify a current authenticator code."
        )

    secret = generate_totp_secret()

    current_user.totp_secret_encrypted = encrypt_totp_secret(secret)
    current_user.totp_enabled = False
    current_user.totp_confirmed_at = None

    db.commit()
    db.refresh(current_user)

    _record_audit_safely(
        db,
        action="TOTP_ENROLL_STARTED",
        actor=current_user,
        resource="totp",
    )

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
    response_model=Token,
)
def totp_confirm(
    payload: TOTPVerifyRequest,
    response: Response,
    current_user: User = Depends(get_totp_enrollment_user),
    db: Session = Depends(get_db),
) -> Token:
    """
    Verify a TOTP code and issue a fully authenticated session.

    For first-time enrollment, successful verification enables TOTP.
    For an existing enrollment, a valid current code is still required.
    """

    if current_user.role != UserRole.ADMIN:
        raise PermissionDeniedError()

    if not current_user.totp_secret_encrypted:
        raise PermissionDeniedError(
            "TOTP enrollment has not been started."
        )

    try:
        secret = decrypt_totp_secret(
            current_user.totp_secret_encrypted
        )
    except ValueError as exc:
        raise PermissionDeniedError(
            "TOTP enrollment data is invalid."
        ) from exc

    if not verify_totp_code(secret, payload.code):
        raise PermissionDeniedError(
            "Invalid authenticator code."
        )

    # Only first-time enrollment changes the enrollment state.
    if not current_user.totp_enabled:
        current_user.totp_enabled = True
        current_user.totp_confirmed_at = datetime.now(timezone.utc)

        db.commit()
        db.refresh(current_user)

        _record_audit_safely(
            db,
            action="TOTP_ENROLL_CONFIRMED",
            actor=current_user,
            resource="totp",
        )
    else:
        _record_audit_safely(
            db,
            action="TOTP_LOGIN_VERIFIED",
            actor=current_user,
            resource="authentication",
        )

    # Password and TOTP have now both been verified.
    authenticated_token = create_access_token(
        subject=current_user.username,
        purpose="authenticated",
        mfa_completed=True,
    )

    # Replace the pending MFA cookie with the authenticated token.
    _set_auth_cookie(response, authenticated_token)

    return Token(
        access_token=authenticated_token,
        token_type="bearer",
    )
