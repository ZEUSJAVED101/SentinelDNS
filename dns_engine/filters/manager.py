"""
Filter Manager

Coordinates every DNS filter.
"""

from __future__ import annotations

from dns_engine.filters.adblock import AdBlockFilter
from dns_engine.filters.adult import AdultFilter
from dns_engine.filters.blacklist import BlacklistFilter
from dns_engine.filters.malware import MalwareFilter
from dns_engine.filters.schedule import ScheduleFilter
from dns_engine.filters.whitelist import WhitelistFilter
from dns_engine.models import DNSQuery, FilterDecision


class FilterManager:
    """
    Executes every enabled DNS filter.
    """

    def __init__(self) -> None:

        self.filters = [

            WhitelistFilter(),

            BlacklistFilter(),

            AdBlockFilter(),

            MalwareFilter(),

            AdultFilter(),

            ScheduleFilter(),

        ]

    def evaluate(
        self,
        query: DNSQuery,
    ) -> FilterDecision:

        for dns_filter in self.filters:

            decision = dns_filter.evaluate(query)

            if not decision.allowed:

                return decision

        return FilterDecision(
            allowed=True,
        )