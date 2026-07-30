"""
===============================================================================
File: auth.py

Project:
SentinelDNS

Purpose:
Authentication and authorization exceptions.

===============================================================================
"""

from __future__ import annotations

from backend.exceptions.base import SentinelDNSError


class AuthenticationError(SentinelDNSError):
    """
    Base exception for authentication-related errors.
    """

    default_message = "Authentication failed."


class InvalidCredentialsError(AuthenticationError):
    """
    Raised when supplied credentials are invalid.
    """

    default_message = "Invalid username or password."


class InvalidPasswordError(AuthenticationError):
    """
    Raised when a password fails validation rules.
    """

    default_message = "Password does not meet security requirements."


class InvalidTokenError(AuthenticationError):
    """
    Raised when a JWT or authentication token is invalid.
    """

    default_message = "Authentication token is invalid."


class UserInactiveError(AuthenticationError):
    """
    Raised when an inactive account attempts authentication.
    """

    default_message = "User account is inactive."


class AuthenticationRequiredError(AuthenticationError):
    """
    Raised when authentication is required.
    """

    default_message = "Authentication is required."