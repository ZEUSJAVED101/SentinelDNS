"""
DNS Resolver

Responsibilities:
- Parse incoming DNS queries
- Log query information
- Forward queries upstream
- Return DNS responses
"""

from __future__ import annotations

import logging

from dns_engine.parser import DNSParser
from dns_engine.upstream import DNSUpstream

LOGGER = logging.getLogger(__name__)


class DNSResolver:
    """
    Coordinates DNS query processing.
    """

    def __init__(self) -> None:
        self.parser = DNSParser()
        self.upstream = DNSUpstream()

    def resolve(self, query: bytes) -> bytes:
        """
        Resolve an incoming DNS query.
        """

        parsed = self.parser.parse(query)

        LOGGER.info(
            "DNS Query | Domain=%s Type=%d",
            parsed["domain"],
            parsed["query_type"],
        )

        print("\n========================================")
        print(" DNS QUERY RECEIVED")
        print("========================================")
        print(f"Domain      : {parsed['domain']}")
        print(f"Query Type  : {parsed['query_type']}")
        print("Forwarding  : 1.1.1.1")
        print("========================================")

        response = self.upstream.query(query)

        print("Response received successfully.\n")

        return response