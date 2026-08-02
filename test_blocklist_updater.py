from backend.scheduler.blocklist_updater import BlocklistUpdater
from backend.scheduler.sources import BlocklistSources


def main() -> None:

    updater = BlocklistUpdater()

    updater.update(
        BlocklistSources.STEVENBLACK,
    )


if __name__ == "__main__":
    main()