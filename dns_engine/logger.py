"""
DNS Logger

Responsibilities:
- Log DNS activity.
"""

from __future__ import annotations

import logging

from dns_engine.models import DNSQuery

LOGGER = logging.getLogger(__name__)


class DNSLogger:
    """
    DNS logging service.
    """

    def log(
        self,
        query: DNSQuery,
    ) -> None:

        LOGGER.info(
            "DNS Query | %s | Type=%d",
            query.domain,
            query.query_type,
        )