"""
DNS Blocklist Loader

Responsibilities:

- Load DNS domains from blocklist files
- Support plain-domain lists
- Support hosts-file formatted lists
- Normalize domains
- Provide fast domain membership checks
"""

from __future__ import annotations

from pathlib import Path


class BlocklistLoader:
    """
    Generic blocklist loader.

    Supported formats:

        example.com

        0.0.0.0 example.com

        127.0.0.1 example.com

        :: example.com

        ::1 example.com

    Comments and blank lines are ignored.
    """

    BLOCKLIST_DIRECTORY = Path(
        "data/blocklists"
    )

    HOSTS_ADDRESSES = {
        "0.0.0.0",
        "127.0.0.1",
        "::",
        "::1",
    }

    def __init__(
        self,
        filename: str,
    ) -> None:

        self.filename = filename

        self._domains: set[str] = set()

        self.load()

    def load(
        self,
    ) -> None:
        """
        Load domains from the blocklist.

        Supports both plain-domain lists and
        hosts-file formatted lists.
        """

        path = (
            self.BLOCKLIST_DIRECTORY
            / self.filename
        )

        self._domains.clear()

        if not path.exists():

            print(
                f"[Blocklist] WARNING: "
                f"{path} not found."
            )

            return

        with path.open(
            "r",
            encoding="utf-8",
        ) as file:

            for line in file:

                line = line.strip().lower()

                #
                # Ignore blank lines.
                #
                if not line:
                    continue

                #
                # Ignore full-line comments.
                #
                if line.startswith("#"):
                    continue

                #
                # Remove inline comments.
                #
                line = line.split(
                    "#",
                    1,
                )[0].strip()

                if not line:
                    continue

                parts = line.split()

                if not parts:
                    continue

                #
                # Hosts-file format:
                #
                # 0.0.0.0 example.com
                # 127.0.0.1 example.com
                # :: example.com
                # ::1 example.com
                #
                if (
                    len(parts) >= 2
                    and parts[0]
                    in self.HOSTS_ADDRESSES
                ):

                    domains = parts[1:]

                else:

                    #
                    # Plain domain format.
                    #
                    domains = parts

                for domain in domains:

                    domain = (
                        domain
                        .strip()
                        .rstrip(".")
                        .lower()
                    )

                    if not domain:
                        continue

                    #
                    # Ignore accidental IP-only entries.
                    #
                    if domain in self.HOSTS_ADDRESSES:
                        continue

                    self._domains.add(
                        domain
                    )

        print(
            f"[Blocklist] {self.filename}: "
            f"{len(self._domains)} "
            f"domains loaded."
        )

    def reload(
        self,
    ) -> None:
        """
        Reload the blocklist from disk.
        """

        print(
            f"[Blocklist] Reloading "
            f"{self.filename}..."
        )

        self.load()

    def contains(
        self,
        domain: str,
    ) -> bool:
        """
        Return True if the domain is blocked.
        """

        if not isinstance(
            domain,
            str,
        ):
            return False

        normalized = (
            domain
            .strip()
            .lower()
            .rstrip(".")
        )

        if not normalized:
            return False

        return normalized in self._domains

    @property
    def size(
        self,
    ) -> int:
        """
        Return the number of blocked domains.
        """

        return len(
            self._domains
        )