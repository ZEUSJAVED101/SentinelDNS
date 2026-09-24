"""TOTP API schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class TOTPEnrollResponse(BaseModel):
    """Sensitive one-time enrollment information."""

    secret: str
    provisioning_uri: str
    qr_code_data_uri: str


class TOTPVerifyRequest(BaseModel):
    """Six-digit authenticator code."""

    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class TOTPStatusResponse(BaseModel):
    """Current TOTP enrollment state without exposing the secret."""

    enabled: bool
    confirmed: bool
