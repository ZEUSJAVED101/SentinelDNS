from typing import cast

from dns_engine.blocklist import BlocklistLoader
from dns_engine.blocklist_registry import BlocklistRegistry


def test_plain_domain_is_loaded(tmp_path):
    blocklist_file = tmp_path / "test.txt"

    blocklist_file.write_text(
        """
example.com
blocked.com
malware.test
""",
        encoding="utf-8",
    )

    original_directory = BlocklistLoader.BLOCKLIST_DIRECTORY

    try:
        BlocklistLoader.BLOCKLIST_DIRECTORY = tmp_path

        loader = BlocklistLoader("test.txt")

        assert loader.contains("example.com")
        assert loader.contains("blocked.com")
        assert loader.contains("malware.test")
        assert loader.size == 3

    finally:
        BlocklistLoader.BLOCKLIST_DIRECTORY = original_directory


def test_hosts_file_format_is_loaded(tmp_path):
    blocklist_file = tmp_path / "hosts.txt"

    blocklist_file.write_text(
        """
0.0.0.0 ads.example.com
127.0.0.1 tracker.example.com
:: malware.example.com
::1 bad.example.com
""",
        encoding="utf-8",
    )

    original_directory = BlocklistLoader.BLOCKLIST_DIRECTORY

    try:
        BlocklistLoader.BLOCKLIST_DIRECTORY = tmp_path

        loader = BlocklistLoader("hosts.txt")

        assert loader.contains("ads.example.com")
        assert loader.contains("tracker.example.com")
        assert loader.contains("malware.example.com")
        assert loader.contains("bad.example.com")
        assert loader.size == 4

    finally:
        BlocklistLoader.BLOCKLIST_DIRECTORY = original_directory


def test_comments_and_blank_lines_are_ignored(tmp_path):
    blocklist_file = tmp_path / "comments.txt"

    blocklist_file.write_text(
        """
# Full line comment

example.com

# Another comment
blocked.com # inline comment
""",
        encoding="utf-8",
    )

    original_directory = BlocklistLoader.BLOCKLIST_DIRECTORY

    try:
        BlocklistLoader.BLOCKLIST_DIRECTORY = tmp_path

        loader = BlocklistLoader("comments.txt")

        assert loader.contains("example.com")
        assert loader.contains("blocked.com")
        assert loader.size == 2

    finally:
        BlocklistLoader.BLOCKLIST_DIRECTORY = original_directory


def test_domains_are_normalized(tmp_path):
    blocklist_file = tmp_path / "normalize.txt"

    blocklist_file.write_text(
        """
Example.COM.
Blocked.COM
""",
        encoding="utf-8",
    )

    original_directory = BlocklistLoader.BLOCKLIST_DIRECTORY

    try:
        BlocklistLoader.BLOCKLIST_DIRECTORY = tmp_path

        loader = BlocklistLoader("normalize.txt")

        assert loader.contains("example.com")
        assert loader.contains("EXAMPLE.COM")
        assert loader.contains("example.com.")
        assert loader.contains("blocked.com")

    finally:
        BlocklistLoader.BLOCKLIST_DIRECTORY = original_directory


def test_unblocked_domain_returns_false(tmp_path):
    blocklist_file = tmp_path / "allowed.txt"

    blocklist_file.write_text(
        "blocked.com\n",
        encoding="utf-8",
    )

    original_directory = BlocklistLoader.BLOCKLIST_DIRECTORY

    try:
        BlocklistLoader.BLOCKLIST_DIRECTORY = tmp_path

        loader = BlocklistLoader("allowed.txt")

        assert loader.contains("allowed.com") is False
        assert loader.contains("example.com") is False

    finally:
        BlocklistLoader.BLOCKLIST_DIRECTORY = original_directory


def test_invalid_contains_input_returns_false(tmp_path):
    blocklist_file = tmp_path / "invalid.txt"

    blocklist_file.write_text(
        "example.com\n",
        encoding="utf-8",
    )

    original_directory = BlocklistLoader.BLOCKLIST_DIRECTORY

    try:
        BlocklistLoader.BLOCKLIST_DIRECTORY = tmp_path

        loader = BlocklistLoader("invalid.txt")

        # These intentionally pass invalid runtime types.
        # cast() only satisfies the static type checker.
        assert loader.contains(
            cast(str, None),
        ) is False

        assert loader.contains(
            cast(str, 123),
        ) is False

        assert loader.contains("") is False
        assert loader.contains("   ") is False

    finally:
        BlocklistLoader.BLOCKLIST_DIRECTORY = original_directory


def test_missing_blocklist_file_is_empty(tmp_path):
    original_directory = BlocklistLoader.BLOCKLIST_DIRECTORY

    try:
        BlocklistLoader.BLOCKLIST_DIRECTORY = tmp_path

        loader = BlocklistLoader(
            "does-not-exist.txt",
        )

        assert loader.size == 0
        assert loader.contains("example.com") is False

    finally:
        BlocklistLoader.BLOCKLIST_DIRECTORY = original_directory


def test_reload_updates_domains(tmp_path):
    blocklist_file = tmp_path / "reload.txt"

    blocklist_file.write_text(
        "first.com\n",
        encoding="utf-8",
    )

    original_directory = BlocklistLoader.BLOCKLIST_DIRECTORY

    try:
        BlocklistLoader.BLOCKLIST_DIRECTORY = tmp_path

        loader = BlocklistLoader("reload.txt")

        assert loader.contains("first.com")
        assert not loader.contains("second.com")

        blocklist_file.write_text(
            "second.com\n",
            encoding="utf-8",
        )

        loader.reload()

        assert not loader.contains("first.com")
        assert loader.contains("second.com")
        assert loader.size == 1

    finally:
        BlocklistLoader.BLOCKLIST_DIRECTORY = original_directory


def test_multiple_domains_on_hosts_line_are_loaded(tmp_path):
    blocklist_file = tmp_path / "multiple.txt"

    blocklist_file.write_text(
        "0.0.0.0 one.example.com "
        "two.example.com three.example.com\n",
        encoding="utf-8",
    )

    original_directory = BlocklistLoader.BLOCKLIST_DIRECTORY

    try:
        BlocklistLoader.BLOCKLIST_DIRECTORY = tmp_path

        loader = BlocklistLoader("multiple.txt")

        assert loader.contains("one.example.com")
        assert loader.contains("two.example.com")
        assert loader.contains("three.example.com")
        assert loader.size == 3

    finally:
        BlocklistLoader.BLOCKLIST_DIRECTORY = original_directory


def test_registry_returns_same_loader(tmp_path):
    blocklist_file = tmp_path / "registry.txt"

    blocklist_file.write_text(
        "example.com\n",
        encoding="utf-8",
    )

    original_directory = BlocklistLoader.BLOCKLIST_DIRECTORY
    original_loaders = BlocklistRegistry._loaders.copy()

    try:
        BlocklistLoader.BLOCKLIST_DIRECTORY = tmp_path

        BlocklistRegistry._loaders.clear()

        first = BlocklistRegistry.get(
            "registry.txt",
        )

        second = BlocklistRegistry.get(
            "registry.txt",
        )

        assert first is second
        assert first.contains("example.com")

    finally:
        BlocklistRegistry._loaders.clear()
        BlocklistRegistry._loaders.update(
            original_loaders,
        )

        BlocklistLoader.BLOCKLIST_DIRECTORY = original_directory


def test_registry_reload(tmp_path):
    blocklist_file = tmp_path / "registry_reload.txt"

    blocklist_file.write_text(
        "first.com\n",
        encoding="utf-8",
    )

    original_directory = BlocklistLoader.BLOCKLIST_DIRECTORY
    original_loaders = BlocklistRegistry._loaders.copy()

    try:
        BlocklistLoader.BLOCKLIST_DIRECTORY = tmp_path

        BlocklistRegistry._loaders.clear()

        loader = BlocklistRegistry.get(
            "registry_reload.txt",
        )

        assert loader.contains("first.com")

        blocklist_file.write_text(
            "second.com\n",
            encoding="utf-8",
        )

        BlocklistRegistry.reload(
            "registry_reload.txt",
        )

        assert not loader.contains("first.com")
        assert loader.contains("second.com")

    finally:
        BlocklistRegistry._loaders.clear()
        BlocklistRegistry._loaders.update(
            original_loaders,
        )

        BlocklistLoader.BLOCKLIST_DIRECTORY = original_directory