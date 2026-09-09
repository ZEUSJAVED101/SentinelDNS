"""
SentinelDNS Dashboard Service

Responsibilities:
- Collect safe runtime DNS information
- Expose DNS runtime metrics
- Expose persistent DNS query history
- Expose cache statistics
- Expose DNS transport information
- Expose filter status
- Expose blocklist statistics
- Expose security events

Security principles:
- Read-only service
- No raw DNS packets
- No client addresses
- No credentials or secrets
- Query history contains only sanitized DNS metadata
"""

from __future__ import annotations

from typing import Any

from dns_engine.query_log import query_log


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
        """

        if self.resolver is None:
            return self._empty_metrics()

        metrics = getattr(
            self.resolver,
            "metrics",
            None,
        )

        if metrics is None:
            return self._empty_metrics()

        try:
            data = metrics.as_dict()
        except Exception:
            return self._empty_metrics()

        if not isinstance(data, dict):
            data = {}

        result = dict(data)

        result["available"] = True

        try:
            recent_queries = query_log.as_dicts(
                limit=100,
            )
        except Exception:
            recent_queries = []

        result["recent_queries"] = (
            recent_queries
        )

        result["recent_blocked"] = [
            entry
            for entry in recent_queries
            if entry.get("status") == "BLOCKED"
        ]

        return result

    @staticmethod
    def _empty_metrics() -> dict[str, Any]:

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

    # ==========================================================
    # QUERY HISTORY
    # ==========================================================

    def query_history(
        self,
        limit: int = 100,
    ) -> list[dict[str, Any]]:

        try:
            entries = query_log.as_dicts(
                limit=limit,
            )
        except Exception:
            return []

        return [
            dict(entry)
            for entry in entries
        ]

    # ==========================================================
    # SECURITY EVENTS
    # ==========================================================

    def security_events(
        self,
    ) -> list[dict[str, Any]]:

        if self.resolver is None:
            return []

        metrics = getattr(
            self.resolver,
            "metrics",
            None,
        )

        if metrics is None:
            return []

        try:

            getter = getattr(
                metrics,
                "security_events",
                None,
            )

            if getter is None:
                return []

            events = getter()

        except Exception:
            return []

        if not isinstance(events, list):
            return []

        safe_events: list[
            dict[str, Any]
        ] = []

        for event in events:

            if not isinstance(event, dict):
                continue

            safe_events.append(
                {
                    "timestamp": event.get(
                        "timestamp",
                    ),
                    "event_type": event.get(
                        "event_type",
                    ),
                    "filter_name": event.get(
                        "filter_name",
                    ),
                    "action": event.get(
                        "action",
                    ),
                    "reason": event.get(
                        "reason",
                    ),
                }
            )

        return safe_events

    # ==========================================================
    # TRANSPORT
    # ==========================================================

    def transport(
        self,
    ) -> dict[str, Any]:
        """
        Return the LIVE upstream transport.

        IMPORTANT:
        This reads from resolver.upstream rather than
        config.yaml so the dashboard reflects runtime
        upstream replacement.
        """

        unknown = {
            "transport": "unknown",
            "configured": False,
            "secure": False,
            "display_name": "Unknown",
            "tls_verification": False,
        }

        if self.resolver is None:
            return unknown

        upstream = getattr(
            self.resolver,
            "upstream",
            None,
        )

        if upstream is None:
            return unknown

        try:

            transport = str(
                getattr(
                    upstream,
                    "transport",
                    "",
                )
            ).strip().lower()

        except Exception:

            return unknown

        if transport not in {
            "udp",
            "dot",
            "doh",
        }:
            return {
                "transport": transport or "unknown",
                "configured": False,
                "secure": False,
                "display_name": (
                    transport.upper()
                    if transport
                    else "Unknown"
                ),
                "tls_verification": False,
            }

        client = getattr(
            upstream,
            "client",
            None,
        )

        result: dict[str, Any] = {
            "transport": transport,
            "configured": True,
            "secure": transport in {
                "dot",
                "doh",
            },
            "display_name": transport.upper(),
            "tls_verification": False,
        }

        # ======================================================
        # UDP
        # ======================================================

        if transport == "udp":

            servers: list[str] = []

            server = getattr(
                client,
                "server",
                None,
            )

            if server:
                servers.append(
                    str(server)
                )

            if not servers:

                try:

                    from backend.core.config import (
                        settings,
                    )

                    servers = [
                        str(server)
                        for server
                        in settings.dns.upstream.servers
                    ]

                except Exception:

                    servers = []

            result.update(
                {
                    "servers": servers,
                    "secure": False,
                    "tls_verification": False,
                    "display_name": "UDP",
                }
            )

            return result

        # ======================================================
        # DNS-OVER-TLS
        # ======================================================

        if transport == "dot":

            server = getattr(
                client,
                "server",
                None,
            )

            port = getattr(
                client,
                "port",
                853,
            )

            verify_tls = getattr(
                client,
                "verify_tls",
                None,
            )

            if verify_tls is None:

                try:

                    from backend.core.config import (
                        settings,
                    )

                    verify_tls = (
                        settings.dns.dot.verify_tls
                    )

                except Exception:

                    verify_tls = True

            result.update(
                {
                    "server": (
                        str(server)
                        if server
                        else ""
                    ),
                    "port": int(port),
                    "secure": True,
                    "tls_verification": (
                        bool(verify_tls)
                    ),
                    "display_name": (
                        "DNS-over-TLS"
                    ),
                }
            )

            return result

        # ======================================================
        # DNS-OVER-HTTPS
        # ======================================================

        provider = getattr(
            client,
            "provider",
            None,
        )

        provider_name = getattr(
            provider,
            "name",
            None,
        )

        endpoint = getattr(
            provider,
            "endpoint",
            None,
        )

        http2 = getattr(
            client,
            "http2",
            None,
        )

        verify_tls = getattr(
            client,
            "verify_tls",
            None,
        )

        if provider_name is None:

            try:

                from backend.core.config import (
                    settings,
                )

                provider_name = (
                    settings.dns.doh.provider
                )

            except Exception:

                provider_name = "unknown"

        if endpoint is None:

            try:

                from backend.core.config import (
                    settings,
                )

                endpoint = (
                    settings.dns.doh.endpoint
                )

            except Exception:

                endpoint = ""

        if http2 is None:

            try:

                from backend.core.config import (
                    settings,
                )

                http2 = (
                    settings.dns.doh.http2
                )

            except Exception:

                http2 = True

        if verify_tls is None:

            try:

                from backend.core.config import (
                    settings,
                )

                verify_tls = (
                    settings.dns.doh.verify_tls
                )

            except Exception:

                verify_tls = True

        result.update(
            {
                "provider": str(
                    provider_name
                    or "unknown"
                ),
                "endpoint": str(
                    endpoint
                    or ""
                ),
                "secure": True,
                "tls_verification": (
                    bool(verify_tls)
                ),
                "http2": bool(http2),
                "display_name": (
                    "DNS-over-HTTPS"
                ),
            }
        )

        return result

    # ==========================================================
    # CACHE
    # ==========================================================

    def cache(
        self,
    ) -> dict[str, Any]:

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

        result: list[
            dict[str, Any]
        ] = []

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

            try:

                enabled = manager.is_enabled(
                    filter_name,
                )

            except (
                AttributeError,
                ValueError,
            ):

                enabled = False

            result.append(
                {
                    "name": filter_name,
                    "enabled": enabled,
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
        Return complete dashboard data.
        """

        return {
            "dns": self.dns_status(),
            "metrics": self.metrics(),
            "transport": self.transport(),
            "cache": self.cache(),
            "filters": self.filters(),
            "blocklists": self.blocklists(),
            "security_events": (
                self.security_events()
            ),
        }