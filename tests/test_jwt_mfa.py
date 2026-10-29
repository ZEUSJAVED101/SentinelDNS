"""Regression tests for explicit MFA state in SentinelDNS JWTs."""
from backend.security.jwt import create_access_token, decode_access_token


def test_authenticated_token_has_explicit_completed_mfa_claims():
    token = create_access_token(
        "admin",
        purpose="authenticated",
        mfa_completed=True,
    )
    payload = decode_access_token(token)

    assert payload["sub"] == "admin"
    assert payload["purpose"] == "authenticated"
    assert payload["mfa_completed"] is True


def test_pending_enrollment_token_is_not_a_full_session():
    token = create_access_token(
        "admin",
        purpose="totp_enrollment",
        mfa_completed=False,
        expires_minutes=10,
    )
    payload = decode_access_token(token)

    assert payload["purpose"] == "totp_enrollment"
    assert payload["mfa_completed"] is False


def test_default_token_is_not_marked_as_authenticated():
    token = create_access_token("admin")
    payload = decode_access_token(token)

    assert payload["purpose"] == "unverified"
    assert payload["mfa_completed"] is False
