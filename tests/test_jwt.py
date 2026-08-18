import time

import jwt
import pytest

from backend.core.config import settings
from backend.exceptions.auth import InvalidTokenError
from backend.security.jwt import (
    create_access_token,
    decode_access_token,
)


def test_create_access_token_contains_subject():
    token = create_access_token(
        "testuser",
    )

    payload = decode_access_token(
        token,
    )

    assert payload["sub"] == "testuser"
    assert "iat" in payload
    assert "exp" in payload


def test_created_token_is_valid_jwt():
    token = create_access_token(
        "testuser",
    )

    payload = decode_access_token(
        token,
    )

    assert isinstance(
        payload,
        dict,
    )


def test_invalid_token_is_rejected():
    with pytest.raises(
        InvalidTokenError,
    ):
        decode_access_token(
            "this.is.not.a.valid.jwt",
        )


def test_tampered_token_is_rejected():
    token = create_access_token(
        "testuser",
    )

    parts = token.split(".")

    assert len(parts) == 3

    # Change the signature so validation must fail.
    parts[2] = "invalid-signature"

    tampered_token = ".".join(parts)

    with pytest.raises(
        InvalidTokenError,
    ):
        decode_access_token(
            tampered_token,
        )


def test_expired_token_is_rejected():
    now = int(time.time())

    payload = {
        "sub": "testuser",
        "iat": now - 120,
        "exp": now - 60,
    }

    expired_token = jwt.encode(
        payload,
        settings.security.secret_key,
        algorithm=settings.security.algorithm,
    )

    with pytest.raises(
        InvalidTokenError,
        match="Token has expired",
    ):
        decode_access_token(
            expired_token,
        )


def test_wrong_secret_is_rejected():
    payload = {
        "sub": "testuser",
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
    }

    token = jwt.encode(
        payload,
        "completely-wrong-secret-for-testing-only-32-bytes-minimum",
        algorithm=settings.security.algorithm,
    )

    with pytest.raises(
        InvalidTokenError,
    ):
        decode_access_token(
            token,
        )