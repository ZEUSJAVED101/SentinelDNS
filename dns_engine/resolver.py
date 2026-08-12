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

Security principles:

- Never expose raw DNS packets through metrics
- Never store client addresses in metrics
- Never store queried domains in metrics
- Metrics must never interrupt DNS resolution
- Fail-safe DNS response handling
"""

from __future__ import annotations

import time

from dns_engine.cache import DNSCache
from dns_engine.filters.manager import FilterManager
from dns_engine.logger import DNSLogger
from dns_engine.metrics import DNSMetrics
from dns_engine.parser import DNSParser
from dns_engine.response import DNSResponseBuilder
from dns_engine.upstream import DNSUpstream


class DNSResolver:
    """
    Main DNS resolver pipeline.

    DNSMetrics is optional so the resolver remains easy to test
    and does not require dashboard infrastructure.
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

        self.upstream = DNSUpstream()

        self.metrics = (
            metrics
            if metrics is not None
            else DNSMetrics()
        )

    # ==========================================================
    # METRICS HELPERS
    # ==========================================================

    def _record_response_metrics(
        self,
        response: bytes,
    ) -> None:
        """
        Record DNS response metrics.

        Metrics are intentionally isolated from the DNS
        processing path. A metrics failure must never cause
        DNS resolution to fail.
        """

        try:

            if len(response) < 4:
                return

            rcode = response[3] & 0x0F

            self.metrics.record_rcode(
                rcode,
            )

        except Exception:
            # Observability must never break DNS resolution.
            return

    def _record_latency(
        self,
        started_at: float,
    ) -> None:
        """
        Record query processing latency.

        Metrics failures are intentionally ignored.
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
            # Never allow metrics to affect DNS.
            return

    # ==========================================================
    # RESOLVE
    # ==========================================================

    def resolve(
        self,
        packet: bytes,
    ) -> bytes:
        """
        Process a DNS query.

        The processing pipeline is:

        Parse
            ↓
        Cache
            ↓
        Filters
            ↓
        Logger
            ↓
        Upstream
            ↓
        Cache Store
            ↓
        Response
        """

        started_at = time.perf_counter()

        # ------------------------------------------------------
        # Record incoming query.
        #
        # No packet data is stored by DNSMetrics.
        # ------------------------------------------------------

        try:

            self.metrics.record_query()

        except Exception:
            # Metrics must never interrupt DNS processing.
            pass

        # ======================================================
        # PARSE DNS PACKET
        # ======================================================

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

        # ======================================================
        # QUERY INFORMATION
        # ======================================================

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

        # ======================================================
        # CACHE LOOKUP
        # ======================================================

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

        # ======================================================
        # FILTER PIPELINE
        # ======================================================

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

            response = DNSResponseBuilder.nxdomain(
                packet,
            )

            self._record_response_metrics(
                response,
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

        # ======================================================
        # LOG DNS QUERY
        # ======================================================

        self.logger.log(
            query,
        )

        # ======================================================
        # UPSTREAM RESOLUTION
        # ======================================================

        try:

            response = self.upstream.query(
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

            self._record_latency(
                started_at,
            )

            return response

        # ======================================================
        # UPSTREAM SUCCESS
        # ======================================================

        try:

            self.metrics.record_upstream_success()

        except Exception:
            pass

        # ======================================================
        # RESPONSE CODE METRICS
        # ======================================================

        self._record_response_metrics(
            response,
        )

        # ======================================================
        # CACHE SUCCESSFUL RESPONSE
        # ======================================================

        self.cache.store(
            query,
            response,
        )

        print(
            "Upstream : SUCCESS"
        )

        print(
            "========================================\n"
        )

        # ======================================================
        # LATENCY
        # ======================================================

        self._record_latency(
            started_at,
        )

        return response