"""
SentinelDNS Blocklist Updater

Responsibilities:
- Download blocklists
- Validate blocklists
- Save blocklists
- Reload blocklists
"""

from __future__ import annotations

from pathlib import Path

import requests

from backend.scheduler.sources import BlocklistSource


class BlocklistUpdater:
    """
    Downloads and updates DNS blocklists.
    """

    BLOCKLIST_DIRECTORY = Path("data/blocklists")

    def __init__(self) -> None:

        self.BLOCKLIST_DIRECTORY.mkdir(
            parents=True,
            exist_ok=True,
        )

    def download(
        self,
        source: BlocklistSource,
    ) -> str:
        """
        Download a blocklist.
        """

        print(
            f"Downloading: {source.name}"
        )

        response = requests.get(
            source.url,
            timeout=30,
        )

        response.raise_for_status()

        print("Download completed.")

        return response.text

    def validate(
        self,
        content: str,
    ) -> bool:
        """
        Validate blocklist.
        """

        if not content.strip():

            print("Validation failed.")

            return False

        print("Validation successful.")

        return True

    def save(
        self,
        source: BlocklistSource,
        content: str,
    ) -> Path:
        """
        Save blocklist.
        """

        path = (
            self.BLOCKLIST_DIRECTORY
            / source.filename
        )

        path.write_text(
            content,
            encoding="utf-8",
        )

        print(
            f"Saved: {path}"
        )

        return path

    def reload(self) -> None:
        """
        Reload blocklists.

        This will later notify the DNS engine.
        """

        print(
            "Reload requested."
        )

    def update(
        self,
        source: BlocklistSource,
    ) -> bool:
        """
        Complete update workflow.
        """

        try:

            content = self.download(
                source,
            )

            if not self.validate(
                content,
            ):

                return False

            self.save(
                source,
                content,
            )

            self.reload()

            print(
                f"{source.name} updated successfully."
            )

            return True

        except Exception as exc:

            print(exc)

            return False