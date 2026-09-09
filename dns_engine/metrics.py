"""
SentinelDNS DNS Metrics

Responsibilities:

- Track aggregate DNS runtime statistics
- Track DNS response codes
- Track cache hits and misses
- Track filtering decisions
- Track upstream success/failure
- Track bounded query latency statistics
- Track bounded security events
- Provide thread-safe read-only snapshots

Security principles:

- Never store queried domain names
- Never store client IP addresses
- Never store raw DNS packets
- Never store DNS response contents
- Keep time-series data bounded
- Expose snapshots instead of mutable internal state
- Security events contain only safe metadata
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any


# ==========================================================
# SECURITY EVENT
# ==========================================================


@dataclass(frozen=True)
class SecurityEvent:
    """
    Immutable security event.

    Security events deliberately contain no:

    - queried domain
    - client IP address
    - DNS packet contents
    - DNS response contents

    Only safe filtering metadata is retained.
    """

    timestamp: float
    event_type: str
    filter_name: str
    action: str
    reason: str


# ==========================================================
# METRICS SNAPSHOT
# ==========================================================


@dataclass(frozen=True)
class MetricsSnapshot:
    """
    Immutable aggregate DNS metrics snapshot.
    """

    total_queries: int
    allowed_queries: int
    blocked_queries: int

    cache_hits: int
    cache_misses: int

    upstream_success: int
    upstream_failures: int

    formerr: int
    nxdomain: int
    servfail: int
    noerror: int
    other_rcodes: int

    average_latency_ms: float
    max_latency_ms: float

    query_rate: float

    recent_queries: tuple[int, ...]
    recent_blocked: tuple[int, ...]

    security_events: tuple[SecurityEvent, ...]


# ==========================================================
# DNS METRICS
# ==========================================================


class DNSMetrics:
    """
    Thread-safe aggregate DNS metrics collector.

    The DNS engine runs in a background thread while the FastAPI
    dashboard reads metrics concurrently. Therefore all mutations
    and snapshots are protected by a lock.

    The collector deliberately stores only aggregate information
    and bounded security metadata.
    """

    HISTORY_SIZE = 60
    SECURITY_EVENT_HISTORY_SIZE = 100

    def __init__(self) -> None:
        """
        Initialize the metrics collector.
        """

        self._lock = threading.RLock()

        # ------------------------------------------------------
        # Aggregate counters
        # ------------------------------------------------------

        self._total_queries = 0

        self._allowed_queries = 0

        self._blocked_queries = 0

        self._cache_hits = 0

        self._cache_misses = 0

        self._upstream_success = 0

        self._upstream_failures = 0

        # ------------------------------------------------------
        # DNS response-code counters
        # ------------------------------------------------------

        self._formerr = 0

        self._nxdomain = 0

        self._servfail = 0

        self._noerror = 0

        self._other_rcodes = 0

        # ------------------------------------------------------
        # Latency
        # ------------------------------------------------------

        self._latency_total_ms = 0.0

        self._max_latency_ms = 0.0

        # ------------------------------------------------------
        # Bounded history
        #
        # Each entry represents one one-second bucket.
        #
        # [queries, blocked]
        # ------------------------------------------------------

        self._query_history: deque[int] = deque(
            maxlen=self.HISTORY_SIZE,
        )

        self._blocked_history: deque[int] = deque(
            maxlen=self.HISTORY_SIZE,
        )

        self._current_bucket_second = (
            int(time.monotonic())
        )

        self._current_bucket_queries = 0

        self._current_bucket_blocked = 0

        # ------------------------------------------------------
        # Security event history
        # ------------------------------------------------------

        self._security_events: deque[
            SecurityEvent
        ] = deque(
            maxlen=self.SECURITY_EVENT_HISTORY_SIZE,
        )

    # ==========================================================
    # INTERNAL HISTORY
    # ==========================================================

    def _rotate_bucket_locked(
        self,
        now_second: int,
    ) -> None:
        """
        Rotate one-second history buckets.

        Caller must hold self._lock.
        """

        if (
            now_second
            == self._current_bucket_second
        ):
            return

        elapsed = (
            now_second
            - self._current_bucket_second
        )

        # Prevent pathological memory/work amplification if
        # the process was suspended for a long period.
        elapsed = min(
            elapsed,
            self.HISTORY_SIZE,
        )

        for _ in range(elapsed):

            self._query_history.append(
                self._current_bucket_queries,
            )

            self._blocked_history.append(
                self._current_bucket_blocked,
            )

            self._current_bucket_queries = 0

            self._current_bucket_blocked = 0

        self._current_bucket_second = now_second

    # ==========================================================
    # QUERY
    # ==========================================================

    def record_query(
        self,
    ) -> None:
        """
        Record one DNS query.

        No domain name, client address or packet data is stored.
        """

        now_second = int(
            time.monotonic()
        )

        with self._lock:

            self._rotate_bucket_locked(
                now_second,
            )

            self._total_queries += 1

            self._current_bucket_queries += 1

    # ==========================================================
    # FILTERING
    # ==========================================================

    def record_allowed(
        self,
    ) -> None:
        """
        Record an allowed DNS query.
        """

        with self._lock:

            self._allowed_queries += 1

    def record_blocked(
        self,
    ) -> None:
        """
        Record a blocked DNS query.

        No blocked domain is stored.
        """

        now_second = int(
            time.monotonic()
        )

        with self._lock:

            self._rotate_bucket_locked(
                now_second,
            )

            self._blocked_queries += 1

            self._current_bucket_blocked += 1

    def record_security_event(
        self,
        filter_name: str,
        reason: str = "",
        action: str = "BLOCKED",
        event_type: str = "DNS_FILTER",
    ) -> None:
        """
        Record a bounded security event.

        Only safe metadata is retained.

        Domain names, client addresses, packets and DNS response
        contents are deliberately excluded.
        """

        if not isinstance(
            filter_name,
            str,
        ):
            filter_name = "Unknown"

        if not isinstance(
            reason,
            str,
        ):
            reason = ""

        if not isinstance(
            action,
            str,
        ):
            action = "BLOCKED"

        if not isinstance(
            event_type,
            str,
        ):
            event_type = "DNS_FILTER"

        filter_name = (
            filter_name.strip()
            or "Unknown"
        )

        reason = (
            reason.strip()
        )

        action = (
            action.strip()
            or "BLOCKED"
        )

        event_type = (
            event_type.strip()
            or "DNS_FILTER"
        )

        # Keep event metadata bounded even if a filter
        # accidentally supplies an excessively large value.
        filter_name = filter_name[:100]
        reason = reason[:200]
        action = action[:50]
        event_type = event_type[:100]

        event = SecurityEvent(
            timestamp=time.time(),
            event_type=event_type,
            filter_name=filter_name,
            action=action,
            reason=reason,
        )

        with self._lock:

            self._security_events.append(
                event,
            )

    # ==========================================================
    # CACHE
    # ==========================================================

    def record_cache_hit(
        self,
    ) -> None:
        """
        Record a cache hit.
        """

        with self._lock:

            self._cache_hits += 1

    def record_cache_miss(
        self,
    ) -> None:
        """
        Record a cache miss.
        """

        with self._lock:

            self._cache_misses += 1

    # ==========================================================
    # UPSTREAM
    # ==========================================================

    def record_upstream_success(
        self,
    ) -> None:
        """
        Record a successful upstream request.
        """

        with self._lock:

            self._upstream_success += 1

    def record_upstream_failure(
        self,
    ) -> None:
        """
        Record a failed upstream request.
        """

        with self._lock:

            self._upstream_failures += 1

    # ==========================================================
    # RESPONSE CODES
    # ==========================================================

    def record_rcode(
        self,
        rcode: int,
    ) -> None:
        """
        Record a DNS response code.

        Parameters
        ----------
        rcode:
            DNS response code from the DNS header.
        """

        if not isinstance(
            rcode,
            int,
        ):
            return

        # DNS RCODE is a 4-bit value in the basic DNS header.
        rcode &= 0x0F

        with self._lock:

            if rcode == 0:

                self._noerror += 1

            elif rcode == 1:

                self._formerr += 1

            elif rcode == 2:

                self._servfail += 1

            elif rcode == 3:

                self._nxdomain += 1

            else:

                self._other_rcodes += 1

    # ==========================================================
    # LATENCY
    # ==========================================================

    def record_latency(
        self,
        latency_ms: float,
    ) -> None:
        """
        Record query processing latency.

        Invalid, negative or non-finite values are ignored.
        """

        try:

            value = float(
                latency_ms
            )

        except (
            TypeError,
            ValueError,
        ):

            return

        if (
            value < 0
            or value != value
            or value == float("inf")
            or value == float("-inf")
        ):
            return

        with self._lock:

            self._latency_total_ms += value

            if value > self._max_latency_ms:

                self._max_latency_ms = value

    # ==========================================================
    # SNAPSHOT
    # ==========================================================

    def snapshot(
        self,
    ) -> MetricsSnapshot:
        """
        Return an immutable snapshot.

        The caller receives copies of all mutable history data.
        """

        now_second = int(
            time.monotonic()
        )

        with self._lock:

            self._rotate_bucket_locked(
                now_second,
            )

            total = self._total_queries

            if total > 0:

                average_latency = (
                    self._latency_total_ms
                    / total
                )

            else:

                average_latency = 0.0

            # --------------------------------------------------
            # Calculate recent query rate.
            #
            # History is one-second buckets.
            # --------------------------------------------------

            recent = list(
                self._query_history
            )

            recent.append(
                self._current_bucket_queries
            )

            window_seconds = max(
                1,
                len(recent),
            )

            query_rate = (
                sum(recent)
                / window_seconds
            )

            return MetricsSnapshot(
                total_queries=(
                    self._total_queries
                ),

                allowed_queries=(
                    self._allowed_queries
                ),

                blocked_queries=(
                    self._blocked_queries
                ),

                cache_hits=(
                    self._cache_hits
                ),

                cache_misses=(
                    self._cache_misses
                ),

                upstream_success=(
                    self._upstream_success
                ),

                upstream_failures=(
                    self._upstream_failures
                ),

                formerr=(
                    self._formerr
                ),

                nxdomain=(
                    self._nxdomain
                ),

                servfail=(
                    self._servfail
                ),

                noerror=(
                    self._noerror
                ),

                other_rcodes=(
                    self._other_rcodes
                ),

                average_latency_ms=round(
                    average_latency,
                    3,
                ),

                max_latency_ms=round(
                    self._max_latency_ms,
                    3,
                ),

                query_rate=round(
                    query_rate,
                    3,
                ),

                recent_queries=tuple(
                    recent[
                        -self.HISTORY_SIZE:
                    ]
                ),

                recent_blocked=tuple(
                    list(
                        self._blocked_history
                    )[
                        -self.HISTORY_SIZE:
                    ]
                    + [
                        self._current_bucket_blocked
                    ]
                ),

                security_events=tuple(
                    self._security_events
                ),
            )

    # ==========================================================
    # SECURITY EVENTS SNAPSHOT
    # ==========================================================

    def security_events(
        self,
    ) -> list[dict[str, Any]]:
        """
        Return a JSON-safe copy of recent security events.

        No mutable internal objects are exposed.
        """

        with self._lock:

            return [
                {
                    "timestamp": event.timestamp,
                    "event_type": event.event_type,
                    "filter_name": event.filter_name,
                    "action": event.action,
                    "reason": event.reason,
                }
                for event in self._security_events
            ]

    # ==========================================================
    # DICTIONARY SNAPSHOT
    # ==========================================================

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Return a JSON/template-safe metrics dictionary.
        """

        snapshot = self.snapshot()

        return {
            "total_queries": (
                snapshot.total_queries
            ),

            "allowed_queries": (
                snapshot.allowed_queries
            ),

            "blocked_queries": (
                snapshot.blocked_queries
            ),

            "cache_hits": (
                snapshot.cache_hits
            ),

            "cache_misses": (
                snapshot.cache_misses
            ),

            "upstream_success": (
                snapshot.upstream_success
            ),

            "upstream_failures": (
                snapshot.upstream_failures
            ),

            "formerr": (
                snapshot.formerr
            ),

            "nxdomain": (
                snapshot.nxdomain
            ),

            "servfail": (
                snapshot.servfail
            ),

            "noerror": (
                snapshot.noerror
            ),

            "other_rcodes": (
                snapshot.other_rcodes
            ),

            "average_latency_ms": (
                snapshot.average_latency_ms
            ),

            "max_latency_ms": (
                snapshot.max_latency_ms
            ),

            "query_rate": (
                snapshot.query_rate
            ),

            "recent_queries": list(
                snapshot.recent_queries
            ),

            "recent_blocked": list(
                snapshot.recent_blocked
            ),

            "security_events": (
                self.security_events()
            ),
        }

    # ==========================================================
    # RESET
    # ==========================================================

    def reset(
        self,
    ) -> None:
        """
        Reset runtime counters.

        This method is intentionally not exposed through the
        dashboard/API yet.
        """

        now_second = int(
            time.monotonic()
        )

        with self._lock:

            self._total_queries = 0

            self._allowed_queries = 0

            self._blocked_queries = 0

            self._cache_hits = 0

            self._cache_misses = 0

            self._upstream_success = 0

            self._upstream_failures = 0

            self._formerr = 0

            self._nxdomain = 0

            self._servfail = 0

            self._noerror = 0

            self._other_rcodes = 0

            self._latency_total_ms = 0.0

            self._max_latency_ms = 0.0

            self._query_history.clear()

            self._blocked_history.clear()

            self._security_events.clear()

            self._current_bucket_second = (
                now_second
            )

            self._current_bucket_queries = 0

            self._current_bucket_blocked = 0