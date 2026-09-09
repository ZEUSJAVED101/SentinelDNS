"""
SentinelDNS DNS Resolver

Responsibilities:

- Coordinate the DNS processing pipeline
- Parse and validate DNS queries
- Perform cache lookup
- Apply DNS filtering
- Forward allowed queries upstream
- Cache successful responses
- Record aggregate runtime metrics
- Record bounded security events
- Record bounded, sanitized recent-query audit data
- Support safe runtime upstream replacement

Security principles:

- Never expose raw DNS packets through metrics
- Never store client addresses
- Never store authentication data
- Query audit memory is strictly bounded
- Security event memory is strictly bounded
- Metrics and audit logging must never interrupt DNS resolution
- Fail-safe DNS response handling
- Failed upstream reconfiguration must not replace the active upstream
"""

from __future__ import annotations

import time
from threading import RLock

from dns_engine.cache import DNSCache
from dns_engine.filters.manager import FilterManager
from dns_engine.logger import DNSLogger
from dns_engine.metrics import DNSMetrics
from dns_engine.parser import DNSParser
from dns_engine.query_log import (
    CacheStatus,
    DNSQueryLog,
    QueryStatus,
    UpstreamStatus,
    query_log,
)
from dns_engine.response import DNSResponseBuilder
from dns_engine.upstream import DNSUpstream


class DNSResolver:
    """
    Main DNS resolver pipeline.

    Parse
        ↓
    Cache
        ↓
    Filter
        ↓
    Logger
        ↓
    Upstream
        ↓
    Cache Store
        ↓
    Response
    """

    def __init__(
        self,
        metrics: DNSMetrics | None = None,
    ) -> None:
        """
        Initialize the DNS resolver.
        """

        self.parser = DNSParser()

        self.cache = DNSCache()

        self.filter_manager = FilterManager()

        self.logger = DNSLogger()

        # --------------------------------------------------
        # Live upstream transport.
        #
        # The lock protects runtime replacement of the
        # upstream object while DNS queries are being served.
        # --------------------------------------------------

        self._upstream_lock = RLock()

        self.upstream = DNSUpstream()

        self.metrics = (
            metrics
            if metrics is not None
            else DNSMetrics()
        )

        # --------------------------------------------------
        # Shared bounded query audit buffer.
        # --------------------------------------------------

        self.query_log: DNSQueryLog = query_log

    # ======================================================
    # UPSTREAM RUNTIME CONFIGURATION
    # ======================================================

    def replace_upstream(
        self,
        upstream: DNSUpstream,
    ) -> None:
        """
        Replace the live upstream DNS transport.

        The new DNSUpstream must already be successfully
        constructed and validated before this method is
        called.

        If construction of a new upstream fails, this method
        is never reached and the current upstream remains
        active.

        The old upstream is closed after the new upstream has
        been installed.
        """

        if not isinstance(
            upstream,
            DNSUpstream,
        ):
            raise TypeError(
                "upstream must be a DNSUpstream instance."
            )

        with self._upstream_lock:

            old_upstream = self.upstream

            self.upstream = upstream

        if old_upstream is upstream:
            return

        try:

            old_upstream.close()

        except Exception:

            # Cleanup must never break DNS resolution.
            pass

    def upstream_info(
        self,
    ) -> dict[str, object]:
        """
        Return safe information about the active
        upstream transport.

        No credentials or authentication material is
        returned.
        """

        with self._upstream_lock:

            upstream = self.upstream

            try:

                return upstream.description()

            except Exception:

                return {
                    "transport": getattr(
                        upstream,
                        "transport",
                        "unknown",
                    ),
                }

    # ======================================================
    # RESPONSE CODE
    # ======================================================

    @staticmethod
    def _get_rcode(
        response: bytes,
    ) -> int | None:
        """
        Extract the DNS RCODE from a DNS response.

        Returns None when the response is too short.
        """

        try:

            if len(response) < 4:
                return None

            return response[3] & 0x0F

        except Exception:

            return None

    # ======================================================
    # METRICS
    # ======================================================

    def _record_response_metrics(
        self,
        response: bytes,
    ) -> None:
        """
        Record DNS response-code metrics.

        Metrics must never break DNS resolution.
        """

        try:

            rcode = self._get_rcode(
                response,
            )

            if rcode is None:
                return

            self.metrics.record_rcode(
                rcode,
            )

        except Exception:

            return

    def _record_latency(
        self,
        started_at: float,
    ) -> None:
        """
        Record query processing latency.
        """

        try:

            elapsed_ms = (
                time.perf_counter()
                - started_at
            ) * 1000.0

            self.metrics.record_latency(
                elapsed_ms,
            )

        except Exception:

            return

    # ======================================================
    # QUERY TYPE
    # ======================================================

    @staticmethod
    def _query_type(
        query,
    ) -> int:
        """
        Safely obtain the DNS query type.
        """

        value = getattr(
            query,
            "query_type",
            None,
        )

        if value is None:

            value = getattr(
                query,
                "qtype",
                None,
            )

        if value is None:

            value = getattr(
                query,
                "record_type",
                None,
            )

        if value is None:
            return 1

        try:

            return int(value)

        except (
            TypeError,
            ValueError,
        ):

            return 1

    # ======================================================
    # QUERY CLASS
    # ======================================================

    @staticmethod
    def _query_class(
        query,
    ) -> int:
        """
        Safely obtain the DNS query class.
        """

        value = getattr(
            query,
            "query_class",
            None,
        )

        if value is None:

            value = getattr(
                query,
                "qclass",
                None,
            )

        if value is None:
            return 1

        try:

            return int(value)

        except (
            TypeError,
            ValueError,
        ):

            return 1

    # ======================================================
    # QUERY AUDIT
    # ======================================================

    def _record_query_event(
        self,
        *,
        query,
        started_at: float,
        status: QueryStatus,
        cache: CacheStatus,
        upstream: UpstreamStatus,
        response: bytes | None = None,
    ) -> None:
        """
        Record one sanitized DNS query event.

        Audit failures are intentionally ignored because
        observability must never break DNS resolution.
        """

        try:

            latency_ms = (
                time.perf_counter()
                - started_at
            ) * 1000.0

            rcode = None

            if response:

                rcode = self._get_rcode(
                    response,
                )

            self.query_log.record(
                domain=query.domain,
                query_type=self._query_type(
                    query,
                ),
                query_class=self._query_class(
                    query,
                ),
                status=status,
                cache=cache,
                upstream=upstream,
                rcode=rcode,
                latency_ms=latency_ms,
            )

        except Exception:

            # Audit logging must never affect DNS.
            return

    # ======================================================
    # SECURITY EVENT
    # ======================================================

    def _record_security_event(
        self,
        *,
        filter_name: str | None,
        reason: str | None,
    ) -> None:
        """
        Record a safe security event.

        The metrics layer intentionally stores only:

        - event type
        - filter name
        - action
        - reason

        The queried domain, client address and raw DNS packet
        are NOT stored in the security event.

        Security event recording must never interrupt DNS.
        """

        try:

            safe_filter_name = (
                filter_name
                if isinstance(
                    filter_name,
                    str,
                )
                else "Unknown"
            )

            safe_reason = (
                reason
                if isinstance(
                    reason,
                    str,
                )
                else ""
            )

            self.metrics.record_security_event(
                filter_name=safe_filter_name,
                reason=safe_reason,
                action="BLOCKED",
                event_type="DNS_FILTER",
            )

        except Exception:

            return

    # ======================================================
    # RESOLVE
    # ======================================================

    def resolve(
        self,
        packet: bytes,
    ) -> bytes:
        """
        Process one DNS query.
        """

        started_at = time.perf_counter()

        # --------------------------------------------------
        # Aggregate query counter.
        # --------------------------------------------------

        try:

            self.metrics.record_query()

        except Exception:

            pass

        # ==================================================
        # PARSE
        # ==================================================

        try:

            query = self.parser.parse(
                packet,
            )

        except ValueError as exc:

            print(
                "\n========================================"
            )

            print(
                " SentinelDNS"
            )

            print(
                "========================================"
            )

            print(
                "Parser : FAILED"
            )

            print(
                f"Reason : {exc}"
            )

            print(
                "========================================\n"
            )

            response = DNSResponseBuilder.formerr(
                packet,
            )

            self._record_response_metrics(
                response,
            )

            self._record_latency(
                started_at,
            )

            return response

        # ==================================================
        # QUERY INFORMATION
        # ==================================================

        print(
            "\n========================================"
        )

        print(
            " SentinelDNS"
        )

        print(
            "========================================"
        )

        print(
            f"Domain : {query.domain}"
        )

        # ==================================================
        # CACHE LOOKUP
        # ==================================================

        cached = self.cache.lookup(
            query,
        )

        if cached is not None:

            print(
                "Cache : HIT"
            )

            print(
                "========================================\n"
            )

            try:

                self.metrics.record_cache_hit()

            except Exception:

                pass

            self._record_response_metrics(
                cached,
            )

            # --------------------------------------------------
            # Cache HIT.
            # --------------------------------------------------

            self._record_query_event(
                query=query,
                started_at=started_at,
                status="ALLOWED",
                cache="HIT",
                upstream="NOT_USED",
                response=cached,
            )

            self._record_latency(
                started_at,
            )

            return cached

        print(
            "Cache : MISS"
        )

        try:

            self.metrics.record_cache_miss()

        except Exception:

            pass

        # ==================================================
        # FILTER
        # ==================================================

        decision = self.filter_manager.evaluate(
            query,
        )

        if not decision.allowed:

            print(
                f"Filter : BLOCKED "
                f"({decision.filter_name})"
            )

            print(
                f"Reason : {decision.reason}"
            )

            print(
                "========================================\n"
            )

            try:

                self.metrics.record_blocked()

            except Exception:

                pass

            # --------------------------------------------------
            # Security event.
            #
            # This is connected to the real filter decision,
            # so the Security Events page can consume actual
            # DNS blocking activity.
            # --------------------------------------------------

            self._record_security_event(
                filter_name=decision.filter_name,
                reason=decision.reason,
            )

            response = DNSResponseBuilder.nxdomain(
                packet,
            )

            self._record_response_metrics(
                response,
            )

            # --------------------------------------------------
            # Blocked query.
            # --------------------------------------------------

            self._record_query_event(
                query=query,
                started_at=started_at,
                status="BLOCKED",
                cache="MISS",
                upstream="NOT_USED",
                response=response,
            )

            self._record_latency(
                started_at,
            )

            return response

        print(
            "Filter : ALLOWED"
        )

        try:

            self.metrics.record_allowed()

        except Exception:

            pass

        # ==================================================
        # LOGGER
        # ==================================================

        try:

            self.logger.log(
                query,
            )

        except Exception:

            # Logging must never break DNS.
            pass

        # ==================================================
        # UPSTREAM
        # ==================================================

        try:

            # --------------------------------------------------
            # Obtain a stable reference to the active upstream.
            #
            # The reference is captured while holding the lock.
            # This prevents a management operation from causing
            # an invalid intermediate reference.
            # --------------------------------------------------

            with self._upstream_lock:

                upstream = self.upstream

            response = upstream.query(
                packet,
            )

        except Exception as exc:

            print(
                "Upstream : FAILED"
            )

            print(
                f"Reason : {exc}"
            )

            print(
                "========================================\n"
            )

            try:

                self.metrics.record_upstream_failure()

            except Exception:

                pass

            response = DNSResponseBuilder.servfail(
                packet,
            )

            self._record_response_metrics(
                response,
            )

            # --------------------------------------------------
            # Upstream failure.
            # --------------------------------------------------

            self._record_query_event(
                query=query,
                started_at=started_at,
                status="ALLOWED",
                cache="MISS",
                upstream="FAILED",
                response=response,
            )

            self._record_latency(
                started_at,
            )

            return response

        # ==================================================
        # UPSTREAM SUCCESS
        # ==================================================

        try:

            self.metrics.record_upstream_success()

        except Exception:

            pass

        # ==================================================
        # RESPONSE METRICS
        # ==================================================

        self._record_response_metrics(
            response,
        )

        # ==================================================
        # CACHE
        # ==================================================

        try:

            self.cache.store(
                query,
                response,
            )

        except Exception:

            # Cache failure must never break DNS.
            pass

        print(
            "Upstream : SUCCESS"
        )

        print(
            "========================================\n"
        )

        # ==================================================
        # QUERY AUDIT
        # ==================================================

        self._record_query_event(
            query=query,
            started_at=started_at,
            status="ALLOWED",
            cache="MISS",
            upstream="SUCCESS",
            response=response,
        )

        # ==================================================
        # LATENCY
        # ==================================================

        self._record_latency(
            started_at,
        )

        return response