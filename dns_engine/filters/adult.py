"""
Adult Content Filter
"""

from __future__ import annotations

from dns_engine.filters.base import BaseFilter
from dns_engine.models import DNSQuery, FilterDecision


class AdultFilter(BaseFilter):
    """
    Adult content filter.
    """

    def evaluate(
        self,
        query: DNSQuery,
    ) -> FilterDecision:

        return FilterDecision(
            allowed=True,
        )