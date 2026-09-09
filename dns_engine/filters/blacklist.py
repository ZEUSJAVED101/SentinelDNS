"""
SentinelDNS Blacklist Filter

Blocks domains listed in the configured blacklist.

The blacklist is loaded through BlocklistRegistry so that
the same BlocklistLoader instance can be reused and reloaded
by the management interface.
"""

from __future__ import annotations

from dns_engine.blocklist_registry import BlocklistRegistry
from dns_engine.filters.base import BaseFilter
from dns_engine.models import DNSQuery, FilterDecision


class BlacklistFilter(BaseFilter):
    """
    Blocks domains contained in the SentinelDNS blacklist.

    Default source:

        data/blocklists/test.txt
    """

    BLOCKLIST_FILENAME = "test.txt"

    def __init__(self) -> None:

        self.blocklist = BlocklistRegistry.get(
            self.BLOCKLIST_FILENAME,
        )

    def evaluate(
        self,
        query: DNSQuery,
    ) -> FilterDecision:
        """
        Evaluate a DNS query against the blacklist.

        Returns a blocking decision when the queried domain
        exists in the configured blacklist.
        """

        if not isinstance(
            query.domain,
            str,
        ):
            return FilterDecision(
                allowed=True,
            )

        domain = (
            query.domain
            .strip()
            .rstrip(".")
            .lower()
        )

        if not domain:

            return FilterDecision(
                allowed=True,
            )

        if self.blocklist.contains(
            domain,
        ):

            return FilterDecision(
                allowed=False,
                reason="Blacklisted domain",
                filter_name="Blacklist",
            )

        return FilterDecision(
            allowed=True,
        )