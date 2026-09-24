"""TOTP enrollment and verification helpers for SentinelDNS."""

from __future__ import annotations

import base64
import hashlib

import qrcode
from qrcode.image.svg import SvgPathImage

import pyotp
from cryptography.fernet import Fernet, InvalidToken

from backend.core.config import settings

_TOTP_ISSUER = "SentinelDNS"
_DERIVATION_CONTEXT = b"SentinelDNS TOTP secret encryption v1"


def _fernet() -> Fernet:
    """Create the Fernet key used to protect TOTP secrets at rest."""
    digest = hashlib.sha256(
        _DERIVATION_CONTEXT + settings.security.secret_key.encode("utf-8")
    ).digest()
    key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


def generate_totp_secret() -> str:
    """Generate a new random Base32 TOTP secret."""
    return pyotp.random_base32()


def encrypt_totp_secret(secret: str) -> str:
    """Encrypt a TOTP secret before database storage."""
    return _fernet().encrypt(secret.encode("utf-8")).decode("ascii")


def decrypt_totp_secret(encrypted_secret: str) -> str:
    """Decrypt a stored TOTP secret."""
    try:
        return _fernet().decrypt(encrypted_secret.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeDecodeError, ValueError) as exc:
        raise ValueError("Stored TOTP secret could not be decrypted.") from exc


def build_provisioning_uri(secret: str, username: str) -> str:
    """Build an otpauth URI compatible with authenticator applications."""
    return pyotp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name=_TOTP_ISSUER,
    )


def verify_totp_code(secret: str, code: str) -> bool:
    """Verify a six-digit TOTP code using the standard time window."""
    normalized = code.strip()
    if len(normalized) != 6 or not normalized.isdigit():
        return False
    return pyotp.TOTP(secret).verify(normalized, valid_window=1)


def build_qr_code_data_uri(provisioning_uri: str) -> str:
    """Build a local SVG QR-code data URI for the provisioning URI."""
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=6,
        border=2,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    image = qr.make_image(image_factory=SvgPathImage)
    svg = image.to_string().decode("utf-8")
    encoded = base64.b64encode(svg.encode("utf-8")).decode("ascii")
    return f"data:image/svg+xml;base64,{encoded}"
