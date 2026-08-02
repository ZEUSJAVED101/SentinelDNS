"""
Ad Block Filter

Blocks advertising domains.
"""

from __future__ import annotations

from dns_engine.blocklist import BlocklistLoader
from dns_engine.filters.base import BaseFilter
from dns_engine.models import DNSQuery, FilterDecision


class AdBlockFilter(BaseFilter):
    """
    Advertisement blocking filter.
    """

    def __init__(self) -> None:

        self.blocklist = BlocklistLoader(
            "ads.txt",
        )

    def evaluate(
        self,
        query: DNSQuery,
    ) -> FilterDecision:

        if self.blocklist.contains(query.domain):

            return FilterDecision(
                allowed=False,
                reason="Advertisement domain",
                filter_name="AdBlock",
            )

        return FilterDecision(
            allowed=True,
        )