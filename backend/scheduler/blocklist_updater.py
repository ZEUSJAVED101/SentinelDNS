"""
SentinelDNS Blocklist Updater

Responsibilities:
- Download blocklists
- Validate blocklists
- Save blocklists safely
- Reload blocklists
"""

from __future__ import annotations

import os
from pathlib import Path

import requests

from backend.scheduler.sources import BlocklistSource


class BlocklistUpdater:
    """
    Downloads and updates DNS blocklists.
    """

    BLOCKLIST_DIRECTORY = Path("data/blocklists")

    DOWNLOAD_TIMEOUT = 30

    MAX_BLOCKLIST_SIZE = 50 * 1024 * 1024  # 50 MB

    USER_AGENT = "SentinelDNS/1.0"

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
            timeout=self.DOWNLOAD_TIMEOUT,
            headers={
                "User-Agent": self.USER_AGENT,
            },
        )

        response.raise_for_status()

        content_length = response.headers.get(
            "Content-Length"
        )

        if content_length is not None:

            if int(content_length) > self.MAX_BLOCKLIST_SIZE:

                raise ValueError(
                    "Downloaded blocklist exceeds maximum allowed size."
                )

        print("Download completed.")

        return response.text

    def validate(
        self,
        content: str,
    ) -> bool:
        """
        Validate blocklist.
        """

        content = content.strip()

        if not content:

            print("Validation failed: empty blocklist.")

            return False

        lines = [
            line.strip()
            for line in content.splitlines()
            if line.strip()
            and not line.startswith("#")
        ]

        if not lines:

            print("Validation failed: no usable entries.")

            return False

        #
        # Reject obvious HTML error pages.
        #
        sample = content.lower()

        if (
            "<html" in sample
            or "<!doctype html" in sample
            or "<body" in sample
        ):

            print("Validation failed: HTML received.")

            return False

        print("Validation successful.")

        return True

    def save(
        self,
        source: BlocklistSource,
        content: str,
    ) -> Path:
        """
        Save blocklist using an atomic replacement.
        """

        path = (
            self.BLOCKLIST_DIRECTORY
            / source.filename
        )

        temp_path = path.with_suffix(
            path.suffix + ".tmp"
        )

        try:

            temp_path.write_text(
                content,
                encoding="utf-8",
            )

            os.replace(
                temp_path,
                path,
            )

        finally:

            if temp_path.exists():

                temp_path.unlink(
                    missing_ok=True,
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

        except requests.RequestException as exc:

            print(
                f"Download failed: {exc}"
            )

            return False

        except (OSError, ValueError) as exc:

            print(
                f"Update failed: {exc}"
            )

            return False