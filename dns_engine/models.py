"""
DNS Models

Responsibilities:
- DNS Query model
- DNS Cache model
- DNS Filter decision model
"""

from __future__ import annotations

from dataclasses import dataclass, field
from time import time


# ==========================================================
# DNS Query
# ==========================================================

@dataclass(slots=True, frozen=True)
class DNSQuery:
    """
    Parsed DNS query.

    This object is immutable after creation to prevent
    accidental modification while it moves through the
    DNS processing pipeline.
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

    created_at: float = field(default_factory=time)

    hits: int = 0

    def expired(self) -> bool:
        """
        Returns True if the cache entry has expired.
        """

        return time() >= self.expires_at

    def register_hit(self) -> None:
        """
        Increment cache hit counter.
        """

        self.hits += 1


# ==========================================================
# Filter Decision
# ==========================================================

@dataclass(slots=True, frozen=True)
class FilterDecision:
    """
    Result returned by a DNS filter.
    """

    allowed: bool

    reason: str = ""

    filter_name: str = ""