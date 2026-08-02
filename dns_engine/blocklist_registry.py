"""
Blocklist Registry

Responsibilities:
- Maintain shared BlocklistLoader instances.
"""

from __future__ import annotations

from dns_engine.blocklist import BlocklistLoader


class BlocklistRegistry:
    """
    Singleton registry for blocklists.
    """

    _loaders: dict[str, BlocklistLoader] = {}

    @classmethod
    def get(
        cls,
        filename: str,
    ) -> BlocklistLoader:
        """
        Return a shared BlocklistLoader instance.
        """

        if filename not in cls._loaders:

            cls._loaders[filename] = BlocklistLoader(
                filename,
            )

        return cls._loaders[filename]

    @classmethod
    def reload(
        cls,
        filename: str,
    ) -> None:
        """
        Reload a blocklist.
        """

        loader = cls.get(
            filename,
        )

        loader.reload()

    @classmethod
    def reload_all(
        cls,
    ) -> None:
        """
        Reload every loaded blocklist.
        """

        for loader in cls._loaders.values():

            loader.reload()