"""
SentinelDNS Upstream DNS Resolver

Responsibilities:
- Forward DNS queries to upstream DNS servers
- Receive DNS responses
- Validate upstream responses
"""

from __future__ import annotations

import socket


class DNSUpstream:
    """
    Handles communication with upstream DNS servers.
    """

    MIN_DNS_PACKET_SIZE = 12

    def __init__(
        self,
        server: str = "1.1.1.1",
        port: int = 53,
        timeout: float = 5.0,
    ) -> None:

        self.server = server
        self.port = port
        self.timeout = timeout

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

        #
        # Verify Transaction ID.
        #
        request_id = request[:2]

        response_id = response[:2]

        if request_id != response_id:

            raise ValueError(
                "DNS transaction ID mismatch."
            )

    def query(
        self,
        packet: bytes,
    ) -> bytes:
        """
        Forward a DNS packet upstream and return the response.
        """

        with socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        ) as sock:

            sock.settimeout(
                self.timeout,
            )

            sock.sendto(
                packet,
                (
                    self.server,
                    self.port,
                ),
            )

            response, _ = sock.recvfrom(
                4096,
            )

            self._validate_response(
                packet,
                response,
            )

            return response