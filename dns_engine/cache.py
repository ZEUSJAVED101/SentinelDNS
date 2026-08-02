"""
DNS Cache

Responsibilities:
- Cache DNS responses
- Expire old entries
- Track cache statistics
"""

from __future__ import annotations

from time import time

from dns_engine.models import DNSCacheEntry, DNSQuery


class DNSCache:
    """
    In-memory DNS cache.
    """

    DEFAULT_TTL = 300

    def __init__(self) -> None:

        self._cache: dict[str, DNSCacheEntry] = {}

        self.hits = 0

        self.misses = 0

    def lookup(
        self,
        query: DNSQuery,
    ) -> bytes | None:
        """
        Lookup cached response.
        """

        entry = self._cache.get(query.domain)

        if entry is None:

            self.misses += 1

            return None

        if entry.expired():

            del self._cache[query.domain]

            self.misses += 1

            return None

        entry.hits += 1

        self.hits += 1

        return entry.response

    def store(
        self,
        query: DNSQuery,
        response: bytes,
    ) -> None:
        """
        Store DNS response.
        """

        self._cache[query.domain] = DNSCacheEntry(
            response=response,
            created_at=time(),
            expires_at=time() + self.DEFAULT_TTL,
        )

    @property
    def size(self) -> int:
        """
        Number of cached entries.
        """

        return len(self._cache)

    @property
    def hit_ratio(self) -> float:

        total = self.hits + self.misses

        if total == 0:

            return 0.0

        return self.hits / total