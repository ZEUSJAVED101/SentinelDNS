"""
Blocklist Registry

Responsibilities:
- Maintain shared BlocklistLoader instances.
- Provide access to loaded blocklists.
- Reload individual blocklists.
- Reload all loaded blocklists.
"""

from __future__ import annotations

from dns_engine.blocklist import BlocklistLoader


class BlocklistRegistry:
    """
    Shared registry for blocklist loaders.
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

            cls._loaders[filename] = (
                BlocklistLoader(
                    filename,
                )
            )

        return cls._loaders[filename]

    @classmethod
    def loaded(
        cls,
    ) -> dict[str, BlocklistLoader]:
        """
        Return all currently loaded blocklist loaders.

        A shallow copy is returned so callers cannot modify
        the registry dictionary directly.
        """

        return dict(
            cls._loaders,
        )

    @classmethod
    def reload(
        cls,
        filename: str,
    ) -> BlocklistLoader:
        """
        Reload one blocklist and return its loader.
        """

        loader = cls.get(
            filename,
        )

        loader.reload()

        return loader

    @classmethod
    def reload_all(
        cls,
    ) -> None:
        """
        Reload every currently loaded blocklist.
        """

        for loader in cls._loaders.values():

            loader.reload()