"""Runtime-safe custom DNS filter backed by a managed blocklist file."""
from __future__ import annotations
from dns_engine.blocklist_registry import BlocklistRegistry
from dns_engine.filters.base import BaseFilter
from dns_engine.models import DNSQuery, FilterDecision

class CustomBlocklistFilter(BaseFilter):
    def __init__(self, name: str, filename: str) -> None:
        self.name = name
        self.filename = filename
        self.blocklist = BlocklistRegistry.get(filename)

    def evaluate(self, query: DNSQuery) -> FilterDecision:
        domain = getattr(query, "domain", None)
        if not isinstance(domain, str) or not domain.strip():
            return FilterDecision(allowed=True)
        if self.blocklist.contains(domain):
            return FilterDecision(
                allowed=False,
                reason=f"Custom filter: {self.name}",
                filter_name=self.name,
            )
        return FilterDecision(allowed=True)
