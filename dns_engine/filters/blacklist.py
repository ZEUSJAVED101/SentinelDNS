"""
Blacklist Filter
"""

from __future__ import annotations

from dns_engine.filters.base import BaseFilter
from dns_engine.models import DNSQuery, FilterDecision


class BlacklistFilter(BaseFilter):
    """
    Blacklist filter.
    """

    def evaluate(
        self,
        query: DNSQuery,
    ) -> FilterDecision:

        return FilterDecision(
            allowed=True,
        )