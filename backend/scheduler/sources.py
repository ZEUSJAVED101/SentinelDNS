"""
Official SentinelDNS Blocklist Sources.

This module contains every supported blocklist source.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class BlocklistSource:
    """
    Represents a downloadable blocklist.
    """

    name: str

    url: str

    filename: str

    description: str


class BlocklistSources:
    """
    Official blocklist registry.
    """

    STEVENBLACK = BlocklistSource(
        name="StevenBlack Hosts",
        url="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        filename="ads.txt",
        description="General advertising and tracking domains.",
    )

    OISD = BlocklistSource(
        name="OISD Small",
        url="https://small.oisd.nl/",
        filename="oisd.txt",
        description="Community-maintained advertisement and tracker blocklist.",
    )

    ADGUARD = BlocklistSource(
        name="AdGuard DNS Filter",
        url="https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
        filename="adguard.txt",
        description="Official AdGuard DNS blocklist.",
    )