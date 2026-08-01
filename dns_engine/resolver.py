"""
DNS Resolver

Responsibilities:
- Coordinate DNS processing
- Forward DNS queries upstream
"""

from __future__ import annotations

from dns_engine.upstream import DNSUpstream


class DNSResolver:
    """
    DNS Resolver Pipeline.
    """

    def __init__(self) -> None:

        self.upstream = DNSUpstream()

    def resolve(
        self,
        query: bytes,
    ) -> bytes:
        """
        Resolve a DNS query by forwarding it upstream.
        """

        return self.upstream.query(query)