"""
SentinelDNS AdBlock Filter

Blocks domains contained in the SentinelDNS
advertising blocklist.
"""

from __future__ import annotations

from dns_engine.blocklist_registry import BlocklistRegistry
from dns_engine.filters.base import BaseFilter
from dns_engine.models import DNSQuery, FilterDecision


class AdBlockFilter(BaseFilter):
    """
    Advertisement blocking filter.
    """

    BLOCKLIST_FILENAME = "ads.txt"

    def __init__(self) -> None:

        self.blocklist = BlocklistRegistry.get(
            self.BLOCKLIST_FILENAME,
        )

    def evaluate(
        self,
        query: DNSQuery,
    ) -> FilterDecision:
        """
        Block domains present in ads.txt.
        """

        if self.blocklist.contains(
            query.domain,
        ):

            return FilterDecision(
                allowed=False,
                reason="Advertisement domain",
                filter_name="AdBlock",
            )

        return FilterDecision(
            allowed=True,
        )