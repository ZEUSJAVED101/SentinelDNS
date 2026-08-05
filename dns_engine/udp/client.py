"""
SentinelDNS UDP DNS Client

Responsibilities:
- Forward DNS queries over UDP
- Validate upstream responses
- Enforce secure network timeouts
- Prevent malformed DNS responses
"""

from __future__ import annotations

import socket


class UDPClient:
    """
    Secure UDP DNS client.
    """

    MIN_DNS_PACKET_SIZE = 12
    DEFAULT_BUFFER_SIZE = 4096

    def __init__(
        self,
        server: str,
        port: int = 53,
        timeout: float = 5.0,
        max_response_size: int = DEFAULT_BUFFER_SIZE,
    ) -> None:

        if not server:
            raise ValueError(
                "DNS server address cannot be empty."
            )

        if port <= 0 or port > 65535:
            raise ValueError(
                "Invalid DNS server port."
            )

        if timeout <= 0:
            raise ValueError(
                "Timeout must be greater than zero."
            )

        if max_response_size < self.MIN_DNS_PACKET_SIZE:
            raise ValueError(
                "Maximum response size is too small."
            )

        self.server = server
        self.port = port
        self.timeout = timeout
        self.max_response_size = max_response_size

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

        if len(response) > self.max_response_size:

            raise ValueError(
                "DNS response exceeds configured limit."
            )

        #
        # Verify Transaction ID
        #
        if request[:2] != response[:2]:

            raise ValueError(
                "DNS transaction ID mismatch."
            )

    def query(
        self,
        packet: bytes,
    ) -> bytes:
        """
        Send a DNS query using UDP.
        """

        if len(packet) < self.MIN_DNS_PACKET_SIZE:

            raise ValueError(
                "Invalid DNS request packet."
            )

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
                self.max_response_size,
            )

            self._validate_response(
                packet,
                response,
            )

            return response