"""Tests for SentinelDNS TOTP helpers."""

from backend.security.totp import (
    build_provisioning_uri,
    decrypt_totp_secret,
    encrypt_totp_secret,
    generate_totp_secret,
    verify_totp_code,
)

import pyotp


def test_totp_secret_round_trip_and_code_verification():
    secret = generate_totp_secret()
    encrypted = encrypt_totp_secret(secret)

    assert encrypted != secret
    assert decrypt_totp_secret(encrypted) == secret

    code = pyotp.TOTP(secret).now()
    assert verify_totp_code(secret, code) is True
    assert verify_totp_code(secret, "000000") is False


def test_totp_provisioning_uri_contains_expected_scheme_and_issuer():
    secret = generate_totp_secret()
    uri = build_provisioning_uri(secret, "admin")

    assert uri.startswith("otpauth://totp/")
    assert "SentinelDNS" in uri
    assert "admin" in uri
