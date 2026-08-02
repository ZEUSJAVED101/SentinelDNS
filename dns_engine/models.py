"""
DNS Models

Responsibilities:
- DNS Query model
- DNS Cache model
- DNS Filter decision model
"""

from __future__ import annotations

from dataclasses import dataclass
from time import time


# ==========================================================
# DNS Query
# ==========================================================

@dataclass(slots=True)
class DNSQuery:
    """
    Parsed DNS query.
    """

    transaction_id: int

    flags: int

    questions: int

    answers: int

    authority: int

    additional: int

    domain: str

    query_type: int

    query_class: int


# ==========================================================
# DNS Cache
# ==========================================================

@dataclass(slots=True)
class DNSCacheEntry:
    """
    Cached DNS response.
    """

    response: bytes

    expires_at: float

    created_at: float

    hits: int = 0

    def expired(self) -> bool:
        """
        Returns True if the cache entry has expired.
        """

        return time() >= self.expires_at


# ==========================================================
# Filter Decision
# ==========================================================

@dataclass(slots=True)
class FilterDecision:
    """
    Result returned by a DNS filter.
    """

    allowed: bool

    reason: str = ""

    filter_name: str = ""