"""
SentinelDNS Filter Manager

Responsibilities:
- Coordinate all DNS filters.
- Maintain enabled/disabled runtime state.
- Evaluate filters in deterministic order.
- Provide safe filter status information.
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
    Coordinates all SentinelDNS DNS filters.
    """

    DEFAULT_STATES = {
        "Whitelist": True,
        "Blacklist": True,
        "AdBlock": True,
        "Malware": True,
        "Adult": True,
        "Schedule": True,
    }

    def __init__(self) -> None:

        self.filters = [
            WhitelistFilter(),
            BlacklistFilter(),
            AdBlockFilter(),
            MalwareFilter(),
            AdultFilter(),
            ScheduleFilter(),
        ]

        self.enabled = dict(
            self.DEFAULT_STATES,
        )

    @staticmethod
    def _filter_name(
        dns_filter,
    ) -> str:
        """
        Return the public name of a filter.
        """

        name = (
            dns_filter.__class__.__name__
        )

        if name.endswith("Filter"):
            name = name[:-6]

        return name

    def evaluate(
        self,
        query: DNSQuery,
    ) -> FilterDecision:
        """
        Evaluate the query through every enabled filter.

        The first blocking decision immediately terminates
        evaluation.
        """

        for dns_filter in self.filters:

            name = self._filter_name(
                dns_filter,
            )

            if not self.enabled.get(
                name,
                False,
            ):
                continue

            decision = dns_filter.evaluate(
                query,
            )

            if not decision.allowed:
                return decision

        return FilterDecision(
            allowed=True,
        )

    def set_enabled(
        self,
        name: str,
        enabled: bool,
    ) -> None:
        """
        Enable or disable a registered filter.
        """

        valid_names = {
            self._filter_name(
                dns_filter,
            )
            for dns_filter in self.filters
        }

        if name not in valid_names:

            raise ValueError(
                f"Unknown DNS filter: {name}"
            )

        self.enabled[name] = bool(
            enabled,
        )

    def is_enabled(
        self,
        name: str,
    ) -> bool:
        """
        Return whether a filter is enabled.
        """

        valid_names = {
            self._filter_name(
                dns_filter,
            )
            for dns_filter in self.filters
        }

        if name not in valid_names:

            raise ValueError(
                f"Unknown DNS filter: {name}"
            )

        return bool(
            self.enabled.get(
                name,
                False,
            )
        )

    def status(
        self,
    ) -> list[dict[str, object]]:
        """
        Return safe filter status information.
        """

        result = []

        for dns_filter in self.filters:

            name = self._filter_name(
                dns_filter,
            )

            result.append(
                {
                    "name": name,
                    "enabled": self.is_enabled(
                        name,
                    ),
                    "available": True,
                }
            )

        return result