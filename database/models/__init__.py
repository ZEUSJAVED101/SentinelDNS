"""
SentinelDNS Database Models
"""

from database.models.dhcp_lease import DHCPLease
from database.models.user import User

__all__ = [
    "DHCPLease",
    "User",
]