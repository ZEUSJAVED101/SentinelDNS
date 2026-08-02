"""
Base DNS Filter

Every DNS filter must inherit from this class.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from dns_engine.models import DNSQuery, FilterDecision


class BaseFilter(ABC):
    """
    Abstract base class for DNS filters.
    """

    @abstractmethod
    def evaluate(
        self,
        query: DNSQuery,
    ) -> FilterDecision:
        """
        Evaluate the DNS query.

        Returns:
            FilterDecision
        """
        raise NotImplementedError