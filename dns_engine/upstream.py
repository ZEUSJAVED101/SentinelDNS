"""
SentinelDNS Upstream DNS Resolver

Responsibilities:
- Forward DNS queries to upstream DNS servers
- Receive DNS responses
- Validate upstream responses
"""

from __future__ import annotations


class DNSUpstream:
    """
    Handles communication with upstream DNS servers.
    """

    MIN_DNS_PACKET_SIZE = 12

    def __init__(
        self,
    ) -> None:
        """
        Initialize the upstream DNS transport.
        """

        from backend.core.config import settings
        from dns_engine.udp.client import UDPClient
        from dns_engine.dot.client import DoTClient
        from dns_engine.doh.provider import get_provider
        from dns_engine.doh.client import DoHClient

        self.transport = settings.dns.transport.lower()

        if self.transport == "udp":

            self.client = UDPClient(
                server=settings.dns.upstream.servers[0],
                timeout=settings.dns.upstream.timeout,
                max_response_size=settings.dns.upstream.max_response_size,
            )

        elif self.transport == "dot":

            self.client = DoTClient(
                server=settings.dns.dot.server,
                port=settings.dns.dot.port,
                timeout=settings.dns.dot.timeout,
            )

        elif self.transport == "doh":

            provider = get_provider(
                settings.dns.doh.provider,
            )

            self.client = DoHClient(
                provider,
            )

        else:

            raise ValueError(
                f"Unsupported DNS transport: {self.transport}"
            )

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

        response = self.client.query(
            packet,
        )

        self._validate_response(
            packet,
            response,
        )

        return response