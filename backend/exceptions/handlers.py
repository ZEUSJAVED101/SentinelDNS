"""
Global exception handlers.
"""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from backend.exceptions.auth import (
    AuthenticationError,
    EmailAlreadyExistsError,
    InvalidCredentialsError,
    InvalidTokenError,
    UserInactiveError,
    UsernameAlreadyExistsError,
)


def register_exception_handlers(app: FastAPI) -> None:
    """
    Register all global exception handlers.
    """

    @app.exception_handler(UsernameAlreadyExistsError)
    async def username_exists(
        request: Request,
        exc: UsernameAlreadyExistsError,
    ):
        return JSONResponse(
            status_code=409,
            content={"detail": str(exc)},
        )

    @app.exception_handler(EmailAlreadyExistsError)
    async def email_exists(
        request: Request,
        exc: EmailAlreadyExistsError,
    ):
        return JSONResponse(
            status_code=409,
            content={"detail": str(exc)},
        )

    @app.exception_handler(InvalidCredentialsError)
    async def invalid_credentials(
        request: Request,
        exc: InvalidCredentialsError,
    ):
        return JSONResponse(
            status_code=401,
            content={"detail": str(exc)},
        )

    @app.exception_handler(UserInactiveError)
    async def inactive(
        request: Request,
        exc: UserInactiveError,
    ):
        return JSONResponse(
            status_code=403,
            content={"detail": str(exc)},
        )

    @app.exception_handler(InvalidTokenError)
    async def invalid_token(
        request: Request,
        exc: InvalidTokenError,
    ):
        return JSONResponse(
            status_code=401,
            content={"detail": str(exc)},
        )

    @app.exception_handler(AuthenticationError)
    async def authentication_error(
        request: Request,
        exc: AuthenticationError,
    ):
        return JSONResponse(
            status_code=401,
            content={"detail": str(exc)},
        )