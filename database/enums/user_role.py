"""
User role definitions for SentinelDNS.
"""

from enum import Enum


class UserRole(str, Enum):
    """
    Supported application roles.
    """

    ADMIN = "ADMIN"
    USER = "USER"