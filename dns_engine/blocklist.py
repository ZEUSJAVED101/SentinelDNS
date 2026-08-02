"""
Generic Blocklist Loader

Responsibilities:
- Load any blocklist into memory
- Reload blocklists
- Check blocked domains
"""

from __future__ import annotations

from pathlib import Path


class BlocklistLoader:
    """
    Generic blocklist loader.
    """

    BLOCKLIST_DIRECTORY = Path("data/blocklists")

    def __init__(
        self,
        filename: str,
    ) -> None:

        self.filename = filename

        self._domains: set[str] = set()

        self.load()

    def load(self) -> None:
        """
        Load domains from the blocklist.
        """

        path = self.BLOCKLIST_DIRECTORY / self.filename

        self._domains.clear()

        if not path.exists():

            print(
                f"[Blocklist] WARNING: {path} not found."
            )

            return

        with path.open(
            "r",
            encoding="utf-8",
        ) as file:

            for line in file:

                domain = line.strip().lower()

                if not domain:
                    continue

                if domain.startswith("#"):
                    continue

                self._domains.add(domain)

        print(
            f"[Blocklist] {self.filename}: "
            f"{len(self._domains)} domains loaded."
        )

    def reload(self) -> None:
        """
        Reload the blocklist from disk.
        """

        print(
            f"[Blocklist] Reloading {self.filename}..."
        )

        self.load()

    def contains(
        self,
        domain: str,
    ) -> bool:
        """
        Returns True if the domain is blocked.
        """

        return domain.lower() in self._domains

    @property
    def size(
        self,
    ) -> int:
        """
        Number of blocked domains.
        """

        return len(self._domains)