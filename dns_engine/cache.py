"""
DNS Cache

Responsibilities:
- Cache DNS responses
- Expire old entries
- Track cache statistics
- Prevent unlimited memory growth
"""

from __future__ import annotations

from collections import OrderedDict
from time import time

from dns_engine.models import DNSCacheEntry, DNSQuery


class DNSCache:
    """
    In-memory DNS cache with automatic eviction.
    """

    DEFAULT_TTL = 300

    MAX_CACHE_SIZE = 10000

    def __init__(self) -> None:
        self._cache: OrderedDict[
            str,
            DNSCacheEntry,
        ] = OrderedDict()

        self.hits = 0
        self.misses = 0

    def lookup(
        self,
        query: DNSQuery,
    ) -> bytes | None:
        """
        Lookup cached response.
        """

        entry = self._cache.get(
            query.domain,
        )

        if entry is None:
            self.misses += 1
            return None

        if entry.expired():
            del self._cache[query.domain]

            self.misses += 1

            return None

        entry.register_hit()

        self.hits += 1

        self._cache.move_to_end(
            query.domain,
        )

        return entry.response

    def store(
        self,
        query: DNSQuery,
        response: bytes,
    ) -> None:
        """
        Store DNS response.
        """

        if len(response) == 0:
            return

        now = time()

        self._cache[query.domain] = DNSCacheEntry(
            response=response,
            expires_at=now + self.DEFAULT_TTL,
        )

        self._cache.move_to_end(
            query.domain,
        )

        while (
            len(self._cache)
            > self.MAX_CACHE_SIZE
        ):
            self._cache.popitem(
                last=False,
            )

    def clear(self) -> None:
        """
        Clear the cache.
        """

        self._cache.clear()

        self.hits = 0
        self.misses = 0

    def remove_expired(self) -> int:
        """
        Remove expired cache entries.

        Returns
        -------
        int
            Number of removed entries.
        """

        removed = 0

        now = time()

        expired = [
            domain
            for domain, entry
            in self._cache.items()
            if entry.expires_at <= now
        ]

        for domain in expired:
            del self._cache[domain]
            removed += 1

        return removed

    @property
    def size(self) -> int:
        """
        Number of cached entries.
        """

        return len(self._cache)

    @property
    def hit_ratio(self) -> float:
        """
        Cache hit ratio.
        """

        total = self.hits + self.misses

        if total == 0:
            return 0.0

        return self.hits / total