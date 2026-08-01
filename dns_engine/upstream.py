"""
SentinelDNS Upstream DNS Resolver

Responsibilities:
- Forward DNS queries to upstream DNS servers
- Receive DNS responses
"""

from __future__ import annotations

import socket


class DNSUpstream:
    """
    Handles communication with upstream DNS servers.
    """

    def __init__(
        self,
        server: str = "1.1.1.1",
        port: int = 53,
        timeout: float = 5.0,
    ) -> None:

        self.server = server
        self.port = port
        self.timeout = timeout

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

            sock.settimeout(self.timeout)

            sock.sendto(
                packet,
                (
                    self.server,
                    self.port,
                ),
            )

            response, _ = sock.recvfrom(4096)

            return response