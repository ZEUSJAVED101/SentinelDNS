"""
SentinelDNS DNS Query Audit Buffer.

Stores a bounded, in-memory view of recent DNS queries for the
authenticated management UI.

Security properties:
- No client address is stored.
- No raw DNS packet is stored.
- No authentication data is stored.
- Memory usage is bounded by MAX_ENTRIES.
- Returned records are immutable snapshots.
"""

from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass
from threading import RLock
from time import time
from typing import Literal


QueryStatus = Literal["ALLOWED", "BLOCKED", "ERROR"]
CacheStatus = Literal["HIT", "MISS", "NOT_USED"]
UpstreamStatus = Literal["SUCCESS", "FAILED", "NOT_USED"]


@dataclass(frozen=True, slots=True)
class DNSQueryLogEntry:
    """One sanitized DNS query audit record."""

    timestamp: float
    domain: str
    query_type: int
    query_class: int
    status: QueryStatus
    cache: CacheStatus
    upstream: UpstreamStatus
    rcode: int | None
    latency_ms: float

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-safe dictionary."""

        return asdict(self)


class DNSQueryLog:
    """
    Thread-safe, bounded DNS query audit buffer.

    The buffer is intentionally process-local and non-persistent.
    """

    DEFAULT_MAX_ENTRIES = 100

    def __init__(
        self,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ) -> None:
        if not isinstance(max_entries, int):
            raise TypeError("max_entries must be an integer.")

        if max_entries < 1:
            raise ValueError("max_entries must be greater than zero.")

        self._max_entries = max_entries
        self._entries: deque[DNSQueryLogEntry] = deque(
            maxlen=max_entries,
        )
        self._lock = RLock()

    @property
    def max_entries(self) -> int:
        """Maximum number of retained records."""

        return self._max_entries

    def record(
        self,
        *,
        domain: str,
        query_type: int,
        query_class: int,
        status: QueryStatus,
        cache: CacheStatus,
        upstream: UpstreamStatus,
        rcode: int | None,
        latency_ms: float,
        timestamp: float | None = None,
    ) -> None:
        """
        Add one sanitized query record.

        Invalid numeric values are rejected instead of being silently
        inserted into the audit stream.
        """

        if not isinstance(domain, str):
            raise TypeError("domain must be a string.")

        domain = domain.strip().lower().rstrip(".")

        if not domain:
            raise ValueError("domain must not be empty.")

        if len(domain) > 253:
            raise ValueError("domain exceeds the DNS maximum length.")

        if not isinstance(query_type, int):
            raise TypeError("query_type must be an integer.")

        if not 0 <= query_type <= 65535:
            raise ValueError("query_type is outside the valid DNS range.")

        if not isinstance(query_class, int):
            raise TypeError("query_class must be an integer.")

        if not 0 <= query_class <= 65535:
            raise ValueError("query_class is outside the valid DNS range.")

        if rcode is not None:
            if not isinstance(rcode, int):
                raise TypeError("rcode must be an integer or None.")

            if not 0 <= rcode <= 15:
                raise ValueError("rcode must be a DNS 4-bit value.")

        try:
            latency = float(latency_ms)
        except (TypeError, ValueError) as exc:
            raise ValueError("latency_ms must be numeric.") from exc

        if (
            latency < 0
            or latency != latency
            or latency in (float("inf"), float("-inf"))
        ):
            raise ValueError("latency_ms must be finite and non-negative.")

        event_time = time() if timestamp is None else float(timestamp)

        if (
            event_time != event_time
            or event_time in (float("inf"), float("-inf"))
        ):
            raise ValueError("timestamp must be finite.")

        entry = DNSQueryLogEntry(
            timestamp=event_time,
            domain=domain,
            query_type=query_type,
            query_class=query_class,
            status=status,
            cache=cache,
            upstream=upstream,
            rcode=rcode,
            latency_ms=round(latency, 3),
        )

        with self._lock:
            self._entries.append(entry)

    def recent(
        self,
        *,
        limit: int = 100,
    ) -> tuple[DNSQueryLogEntry, ...]:
        """
        Return the newest records first.

        The requested limit is clamped to the configured maximum.
        """

        if not isinstance(limit, int):
            raise TypeError("limit must be an integer.")

        limit = max(1, min(limit, self._max_entries))

        with self._lock:
            entries = tuple(self._entries)

        return tuple(reversed(entries[-limit:]))

    def as_dicts(
        self,
        *,
        limit: int = 100,
    ) -> list[dict[str, object]]:
        """Return recent entries as JSON-safe dictionaries."""

        return [
            entry.as_dict()
            for entry in self.recent(limit=limit)
        ]

    def clear(self) -> None:
        """Clear all retained audit records."""

        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


# One process-wide buffer is required so the DNS engine and the API
# observe the same recent query stream.
query_log = DNSQueryLog()
