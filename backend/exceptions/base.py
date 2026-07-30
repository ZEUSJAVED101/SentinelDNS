"""
===============================================================================
File: base.py

Project:
SentinelDNS

Purpose:
Defines the base exception for all SentinelDNS-specific exceptions.

Responsibilities:
- Provide a common exception hierarchy.
- Allow centralized exception handling.
- Improve readability and maintainability.

===============================================================================
"""

from __future__ import annotations


class SentinelDNSError(Exception):
    """
    Base exception for all SentinelDNS application errors.
    """

    default_message = "An unexpected SentinelDNS error occurred."

    def __init__(self, message: str | None = None) -> None:
        self.message = message or self.default_message
        super().__init__(self.message)

    def __str__(self) -> str:
        return self.message