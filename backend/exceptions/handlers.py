"""
Global exception handlers.
"""

from __future__ import annotations

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from backend.exceptions.auth import (
    AuthenticationError,
    AuthenticationRequiredError,
    EmailAlreadyExistsError,
    InvalidCredentialsError,
    InvalidTokenError,
    PermissionDeniedError,
    UserInactiveError,
    UsernameAlreadyExistsError,
)


def _json_error(status_code: int, message: str) -> JSONResponse:
    """
    Create a standard JSON error response.
    """
    return JSONResponse(
        status_code=status_code,
        content={"detail": message},
    )


def register_exception_handlers(app: FastAPI) -> None:
    """
    Register all global exception handlers.
    """

    # ==========================================================
    # Registration Errors
    # ==========================================================

    @app.exception_handler(UsernameAlreadyExistsError)
    async def username_exists(
        request: Request,
        exc: UsernameAlreadyExistsError,
    ):
        return _json_error(
            status.HTTP_409_CONFLICT,
            str(exc),
        )

    @app.exception_handler(EmailAlreadyExistsError)
    async def email_exists(
        request: Request,
        exc: EmailAlreadyExistsError,
    ):
        return _json_error(
            status.HTTP_409_CONFLICT,
            str(exc),
        )

    # ==========================================================
    # Authentication Errors
    # ==========================================================

    @app.exception_handler(AuthenticationRequiredError)
    async def authentication_required(
        request: Request,
        exc: AuthenticationRequiredError,
    ):
        return _json_error(
            status.HTTP_401_UNAUTHORIZED,
            str(exc),
        )

    @app.exception_handler(InvalidCredentialsError)
    async def invalid_credentials(
        request: Request,
        exc: InvalidCredentialsError,
    ):
        return _json_error(
            status.HTTP_401_UNAUTHORIZED,
            str(exc),
        )

    @app.exception_handler(InvalidTokenError)
    async def invalid_token(
        request: Request,
        exc: InvalidTokenError,
    ):
        return _json_error(
            status.HTTP_401_UNAUTHORIZED,
            str(exc),
        )

    # ==========================================================
    # Authorization Errors
    # ==========================================================

    @app.exception_handler(PermissionDeniedError)
    async def permission_denied(
        request: Request,
        exc: PermissionDeniedError,
    ):
        return _json_error(
            status.HTTP_403_FORBIDDEN,
            str(exc),
        )

    @app.exception_handler(UserInactiveError)
    async def inactive_user(
        request: Request,
        exc: UserInactiveError,
    ):
        return _json_error(
            status.HTTP_403_FORBIDDEN,
            str(exc),
        )

    # ==========================================================
    # Fallback
    # ==========================================================

    @app.exception_handler(AuthenticationError)
    async def authentication_error(
        request: Request,
        exc: AuthenticationError,
    ):
        return _json_error(
            status.HTTP_401_UNAUTHORIZED,
            str(exc),
        )