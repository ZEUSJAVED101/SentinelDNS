"""
SentinelDNS Upstream DNS Resolver

Responsibilities:
- Forward DNS queries to upstream DNS servers
- Support UDP, DNS-over-TLS and DNS-over-HTTPS
- Allow safe runtime reconfiguration
- Validate upstream responses
- Close replaced clients cleanly
"""

from __future__ import annotations

from threading import RLock


class DNSUpstream:
    """
    Handles communication with upstream DNS servers.

    The transport configuration can be supplied explicitly so a
    running DNSResolver can safely replace its upstream transport
    without restarting the application.
    """

    MIN_DNS_PACKET_SIZE = 12

    def __init__(
        self,
        *,
        transport: str | None = None,
        udp_servers: list[str] | None = None,
        udp_timeout: float | None = None,
        udp_max_response_size: int | None = None,
        dot_server: str | None = None,
        dot_port: int | None = None,
        dot_timeout: float | None = None,
        dot_max_response_size: int | None = None,
        doh_provider: str | None = None,
        doh_endpoint: str | None = None,
        doh_timeout: float | None = None,
        doh_max_response_size: int | None = None,
    ) -> None:
        """
        Initialize an upstream DNS transport.

        If no explicit configuration is supplied, the current
        application configuration is used.
        """

        from backend.core.config import settings

        self._lock = RLock()

        if transport is None:
            transport = settings.dns.transport

        self.transport = (
            str(transport)
            .strip()
            .lower()
        )

        if self.transport not in {
            "udp",
            "dot",
            "doh",
        }:
            raise ValueError(
                f"Unsupported DNS transport: "
                f"{self.transport}"
            )

        self.client = None

        # ------------------------------------------------------
        # UDP
        # ------------------------------------------------------

        if self.transport == "udp":

            from dns_engine.udp.client import (
                UDPClient,
            )

            servers = (
                list(udp_servers)
                if udp_servers is not None
                else list(
                    settings.dns.upstream.servers
                )
            )

            if not servers:
                raise ValueError(
                    "At least one UDP upstream "
                    "server is required."
                )

            timeout = (
                settings.dns.upstream.timeout
                if udp_timeout is None
                else float(udp_timeout)
            )

            max_response_size = (
                settings.dns.upstream.max_response_size
                if udp_max_response_size is None
                else int(udp_max_response_size)
            )

            self.server = servers[0]

            self.client = UDPClient(
                server=self.server,
                port=53,
                timeout=timeout,
                max_response_size=max_response_size,
            )

        # ------------------------------------------------------
        # DNS-over-TLS
        # ------------------------------------------------------

        elif self.transport == "dot":

            from dns_engine.dot.client import (
                DoTClient,
            )

            server = (
                settings.dns.dot.server
                if dot_server is None
                else dot_server
            )

            port = (
                settings.dns.dot.port
                if dot_port is None
                else int(dot_port)
            )

            timeout = (
                settings.dns.dot.timeout
                if dot_timeout is None
                else float(dot_timeout)
            )

            max_response_size = (
                settings.dns.upstream.max_response_size
                if dot_max_response_size is None
                else int(dot_max_response_size)
            )

            self.server = server
            self.port = port

            self.client = DoTClient(
                server=server,
                port=port,
                timeout=timeout,
                max_response_size=max_response_size,
            )

        # ------------------------------------------------------
        # DNS-over-HTTPS
        # ------------------------------------------------------

        else:

            from dns_engine.doh.client import (
                DoHClient,
            )
            from dns_engine.doh.provider import (
                DoHProvider,
                create_custom_provider,
                get_provider,
            )

            provider_name = (
                settings.dns.doh.provider
                if doh_provider is None
                else str(doh_provider).strip().lower()
            )

            timeout = (
                settings.dns.doh.timeout
                if doh_timeout is None
                else float(doh_timeout)
            )

            max_response_size = (
                settings.dns.upstream.max_response_size
                if doh_max_response_size is None
                else int(doh_max_response_size)
            )

            if doh_endpoint:

                provider = create_custom_provider(
                    endpoint=doh_endpoint,
                    timeout=timeout,
                    max_response_size=max_response_size,
                )

            else:

                try:

                    provider = get_provider(
                        provider_name,
                    )

                    # Built-in providers are immutable.
                    # Rebuild with requested timeout/size.
                    provider = DoHProvider(
                        name=provider.name,
                        endpoint=provider.endpoint,
                        timeout=timeout,
                        max_response_size=max_response_size,
                    )

                except ValueError:

                    raise ValueError(
                        f"Unknown DoH provider: "
                        f"{provider_name}"
                    )

            provider.validate()

            self.provider = provider

            self.client = DoHClient(
                provider,
            )

    # ==========================================================
    # RESPONSE VALIDATION
    # ==========================================================

    def _validate_response(
        self,
        request: bytes,
        response: bytes,
    ) -> None:
        """
        Validate the upstream DNS response.
        """

        if len(response) < self.MIN_DNS_PACKET_SIZE:

            raise ValueError(
                "Received incomplete DNS response."
            )

        if request[:2] != response[:2]:

            raise ValueError(
                "DNS transaction ID mismatch."
            )

    # ==========================================================
    # QUERY
    # ==========================================================

    def query(
        self,
        packet: bytes,
    ) -> bytes:
        """
        Forward a DNS packet using the configured transport.
        """

        if (
            not packet
            or len(packet) < self.MIN_DNS_PACKET_SIZE
        ):
            raise ValueError(
                "Invalid DNS request packet."
            )

        with self._lock:

            client = self.client

            if client is None:

                raise RuntimeError(
                    "DNS upstream client is unavailable."
                )

            response = client.query(
                packet,
            )

        self._validate_response(
            packet,
            response,
        )

        return response

    # ==========================================================
    # CLOSE
    # ==========================================================

    def close(
        self,
    ) -> None:
        """
        Close the underlying upstream client if supported.
        """

        with self._lock:

            client = self.client

            if client is None:
                return

            close_method = getattr(
                client,
                "close",
                None,
            )

            if callable(close_method):

                try:
                    close_method()
                except Exception:
                    pass

    # ==========================================================
    # DESCRIPTION
    # ==========================================================

    def description(
        self,
    ) -> dict[str, object]:
        """
        Return safe information about the active upstream.
        """

        if self.transport == "udp":

            return {
                "transport": "udp",
                "server": getattr(
                    self,
                    "server",
                    None,
                ),
            }

        if self.transport == "dot":

            return {
                "transport": "dot",
                "server": getattr(
                    self,
                    "server",
                    None,
                ),
                "port": getattr(
                    self,
                    "port",
                    853,
                ),
            }

        provider = getattr(
            self,
            "provider",
            None,
        )

        if provider is None:

            return {
                "transport": "doh",
            }

        return {
            "transport": "doh",
            "provider": provider.name,
            "endpoint": provider.endpoint,
        }