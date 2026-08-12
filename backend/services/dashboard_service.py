"""
SentinelDNS Dashboard Service

Responsibilities:

- Collect safe runtime DNS information
- Expose DNS runtime metrics
- Expose cache statistics
- Expose DNS transport information
- Expose filter status
- Expose blocklist statistics

Security principles:

- Read-only service
- No raw DNS packets
- No queried-domain history
- No client addresses
- No credentials or secrets
- No mutable runtime objects exposed
"""

from __future__ import annotations

from typing import Any


class DashboardService:
    """
    Read-only service used by the SentinelDNS dashboard.

    The resolver must be the SAME DNSResolver instance used
    by the running DNS server.
    """

    def __init__(
        self,
        resolver=None,
    ) -> None:
        self.resolver = resolver

    # ==========================================================
    # DNS STATUS
    # ==========================================================

    def dns_status(
        self,
    ) -> dict[str, Any]:
        """
        Return DNS engine status.
        """

        if self.resolver is None:

            return {
                "available": False,
                "status": "unavailable",
            }

        return {
            "available": True,
            "status": "operational",
        }

    # ==========================================================
    # RUNTIME METRICS
    # ==========================================================

    def metrics(
        self,
    ) -> dict[str, Any]:
        """
        Return aggregate DNS runtime metrics.

        DNSMetrics deliberately stores only aggregate
        information and does not expose domains, client
        addresses, or raw DNS packets.
        """

        if self.resolver is None:

            return {
                "available": False,
                "total_queries": 0,
                "allowed_queries": 0,
                "blocked_queries": 0,
                "cache_hits": 0,
                "cache_misses": 0,
                "upstream_success": 0,
                "upstream_failures": 0,
                "formerr": 0,
                "nxdomain": 0,
                "servfail": 0,
                "noerror": 0,
                "other_rcodes": 0,
                "average_latency_ms": 0.0,
                "max_latency_ms": 0.0,
                "query_rate": 0.0,
                "recent_queries": [],
                "recent_blocked": [],
            }

        metrics = getattr(
            self.resolver,
            "metrics",
            None,
        )

        if metrics is None:

            return {
                "available": False,
                "total_queries": 0,
                "allowed_queries": 0,
                "blocked_queries": 0,
                "cache_hits": 0,
                "cache_misses": 0,
                "upstream_success": 0,
                "upstream_failures": 0,
                "formerr": 0,
                "nxdomain": 0,
                "servfail": 0,
                "noerror": 0,
                "other_rcodes": 0,
                "average_latency_ms": 0.0,
                "max_latency_ms": 0.0,
                "query_rate": 0.0,
                "recent_queries": [],
                "recent_blocked": [],
            }

        try:

            data = metrics.as_dict()

        except Exception:

            return {
                "available": False,
                "total_queries": 0,
                "allowed_queries": 0,
                "blocked_queries": 0,
                "cache_hits": 0,
                "cache_misses": 0,
                "upstream_success": 0,
                "upstream_failures": 0,
                "formerr": 0,
                "nxdomain": 0,
                "servfail": 0,
                "noerror": 0,
                "other_rcodes": 0,
                "average_latency_ms": 0.0,
                "max_latency_ms": 0.0,
                "query_rate": 0.0,
                "recent_queries": [],
                "recent_blocked": [],
            }

        # Defensive copy.

        result = dict(data)

        result["available"] = True

        # Ensure history values are JSON-safe lists.

        result["recent_queries"] = list(
            result.get(
                "recent_queries",
                [],
            )
        )

        result["recent_blocked"] = list(
            result.get(
                "recent_blocked",
                [],
            )
        )

        return result

    # ==========================================================
    # TRANSPORT
    # ==========================================================

    def transport(
        self,
    ) -> dict[str, Any]:
        """
        Return configured upstream transport information.

        Only non-secret configuration is exposed.
        """

        try:

            from backend.core.config import settings

            transport = (
                settings.dns.transport
                .strip()
                .lower()
            )

        except Exception:

            return {
                "transport": "unknown",
                "configured": False,
                "secure": False,
                "display_name": "Unknown",
            }

        result: dict[str, Any] = {
            "transport": transport,
            "configured": True,
            "secure": False,
            "display_name": transport.upper(),
        }

        if transport == "udp":

            servers = list(
                settings.dns.upstream.servers
            )

            result.update(
                {
                    "servers": servers,
                    "secure": False,
                    "display_name": "UDP",
                }
            )

        elif transport == "dot":

            result.update(
                {
                    "server": settings.dns.dot.server,
                    "port": settings.dns.dot.port,
                    "secure": True,
                    "tls_verification": (
                        settings.dns.dot.verify_tls
                    ),
                    "display_name": "DNS-over-TLS",
                }
            )

        elif transport == "doh":

            result.update(
                {
                    "provider": (
                        settings.dns.doh.provider
                    ),
                    "endpoint": (
                        settings.dns.doh.endpoint
                    ),
                    "secure": True,
                    "tls_verification": (
                        settings.dns.doh.verify_tls
                    ),
                    "http2": (
                        settings.dns.doh.http2
                    ),
                    "display_name": "DNS-over-HTTPS",
                }
            )

        return result

    # ==========================================================
    # CACHE
    # ==========================================================

    def cache(
        self,
    ) -> dict[str, Any]:
        """
        Return DNS cache statistics.
        """

        if self.resolver is None:

            return {
                "available": False,
                "size": 0,
                "hit_ratio": 0.0,
            }

        cache = getattr(
            self.resolver,
            "cache",
            None,
        )

        if cache is None:

            return {
                "available": False,
                "size": 0,
                "hit_ratio": 0.0,
            }

        # ------------------------------------------------------
        # DNSCache defines these as @property values.
        # Do NOT call them as functions.
        # ------------------------------------------------------

        try:

            size = int(
                cache.size
            )

        except Exception:

            size = 0

        try:

            hit_ratio = float(
                cache.hit_ratio
            )

        except Exception:

            hit_ratio = 0.0

        hit_ratio = max(
            0.0,
            min(
                1.0,
                hit_ratio,
            ),
        )

        return {
            "available": True,
            "size": max(
                0,
                size,
            ),
            "hit_ratio": hit_ratio,
        }

    # ==========================================================
    # FILTERS
    # ==========================================================

    def filters(
        self,
    ) -> list[dict[str, Any]]:
        """
        Return read-only information about active filters.
        """

        if self.resolver is None:
            return []

        manager = getattr(
            self.resolver,
            "filter_manager",
            None,
        )

        if manager is None:
            return []

        configured_filters = getattr(
            manager,
            "filters",
            [],
        )

        result: list[dict[str, Any]] = []

        for dns_filter in configured_filters:

            filter_name = (
                dns_filter.__class__.__name__
            )

            if filter_name.endswith(
                "Filter"
            ):

                filter_name = (
                    filter_name[:-6]
                )

            blocklist_size = None

            blocklist = getattr(
                dns_filter,
                "blocklist",
                None,
            )

            if blocklist is not None:

                try:

                    blocklist_size = int(
                        blocklist.size
                    )

                except Exception:

                    blocklist_size = None

            result.append(
                {
                    "name": filter_name,
                    "enabled": True,
                    "blocklist_size": (
                        blocklist_size
                    ),
                }
            )

        return result

    # ==========================================================
    # BLOCKLISTS
    # ==========================================================

    def blocklists(
        self,
    ) -> dict[str, int]:
        """
        Return aggregate blocklist information.
        """

        active_filters = self.filters()

        loaded_lists = 0
        total_domains = 0

        for dns_filter in active_filters:

            size = dns_filter.get(
                "blocklist_size"
            )

            if size is None:
                continue

            loaded_lists += 1

            total_domains += max(
                0,
                size,
            )

        return {
            "loaded_lists": loaded_lists,
            "total_domains": total_domains,
        }

    # ==========================================================
    # COMPLETE DASHBOARD
    # ==========================================================

    def get_dashboard_data(
        self,
    ) -> dict[str, Any]:
        """
        Return all dashboard-safe runtime information.
        """

        return {
            "dns": self.dns_status(),

            "metrics": self.metrics(),

            "transport": self.transport(),

            "cache": self.cache(),

            "filters": self.filters(),

            "blocklists": self.blocklists(),
        }