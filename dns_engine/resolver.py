"""
DNS Resolver

Coordinates the DNS processing pipeline.
"""

from __future__ import annotations

from dns_engine.cache import DNSCache
from dns_engine.filters.manager import FilterManager
from dns_engine.logger import DNSLogger
from dns_engine.parser import DNSParser
from dns_engine.response import DNSResponseBuilder
from dns_engine.upstream import DNSUpstream


class DNSResolver:
    """
    Main DNS resolver pipeline.
    """

    def __init__(self) -> None:

        self.parser = DNSParser()

        self.cache = DNSCache()

        self.filter_manager = FilterManager()

        self.logger = DNSLogger()

        self.upstream = DNSUpstream()

    def resolve(
        self,
        packet: bytes,
    ) -> bytes:
        """
        Process a DNS query.
        """

        #
        # Parse DNS packet safely.
        #
        try:

            query = self.parser.parse(
                packet,
            )

        except ValueError as exc:

            print("\n========================================")
            print(" SentinelDNS")
            print("========================================")
            print("Parser : FAILED")
            print(f"Reason : {exc}")
            print("========================================\n")

            return DNSResponseBuilder.formerr(
                packet,
            )

        print("\n========================================")
        print(" SentinelDNS")
        print("========================================")
        print(f"Domain : {query.domain}")

        #
        # Cache lookup.
        #
        cached = self.cache.lookup(
            query,
        )

        if cached is not None:

            print("Cache : HIT")
            print("========================================\n")

            return cached

        print("Cache : MISS")

        #
        # Filter pipeline.
        #
        decision = self.filter_manager.evaluate(
            query,
        )

        if not decision.allowed:

            print(
                f"Filter : BLOCKED ({decision.filter_name})"
            )

            print(
                f"Reason : {decision.reason}"
            )

            print("========================================\n")

            return DNSResponseBuilder.nxdomain(
                packet,
            )

        print("Filter : ALLOWED")

        #
        # Log DNS query.
        #
        self.logger.log(
            query,
        )

        #
        # Forward to upstream resolver.
        #
        try:

            response = self.upstream.query(
                packet,
            )

        except ValueError as exc:

            print("Upstream : INVALID RESPONSE")
            print(f"Reason : {exc}")
            print("========================================\n")

            return DNSResponseBuilder.servfail(
                packet,
            )

        except TimeoutError:

            print("Upstream : TIMEOUT")
            print("========================================\n")

            return DNSResponseBuilder.servfail(
                packet,
            )

        except OSError as exc:

            print("Upstream : FAILED")
            print(f"Reason : {exc}")
            print("========================================\n")

            return DNSResponseBuilder.servfail(
                packet,
            )

        #
        # Cache only successful responses.
        #
        self.cache.store(
            query,
            response,
        )

        print("Upstream : SUCCESS")
        print("========================================\n")

        return response