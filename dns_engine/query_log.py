"""
SentinelDNS DNS Query Audit Log.

Provides:

- Bounded in-memory recent-query history
- Persistent 24-hour query history
- Automatic expiration of records older than 24 hours
- Persistence across application restarts
- Thread-safe access
- Sanitized DNS query records only

Security properties:

- No client address is stored.
- No raw DNS packet is stored.
- No authentication data is stored.
- Domain history is retained for a maximum of 24 hours.
- In-memory history remains bounded.
- Persistent history is automatically cleaned.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import RLock
from time import time
from typing import Literal


QueryStatus = Literal[
    "ALLOWED",
    "BLOCKED",
    "ERROR",
]

CacheStatus = Literal[
    "HIT",
    "MISS",
    "NOT_USED",
]

UpstreamStatus = Literal[
    "SUCCESS",
    "FAILED",
    "NOT_USED",
]


class DNSQueryLogEntry:
    """
    One sanitized DNS query audit record.
    """

    __slots__ = (
        "timestamp",
        "domain",
        "query_type",
        "query_class",
        "status",
        "cache",
        "upstream",
        "rcode",
        "latency_ms",
    )

    def __init__(
        self,
        *,
        timestamp: float,
        domain: str,
        query_type: int,
        query_class: int,
        status: QueryStatus,
        cache: CacheStatus,
        upstream: UpstreamStatus,
        rcode: int | None,
        latency_ms: float,
    ) -> None:

        self.timestamp = timestamp
        self.domain = domain
        self.query_type = query_type
        self.query_class = query_class
        self.status = status
        self.cache = cache
        self.upstream = upstream
        self.rcode = rcode
        self.latency_ms = latency_ms

    def as_dict(
        self,
    ) -> dict[str, object]:
        """
        Return a JSON-safe dictionary.
        """

        return {
            "timestamp": self.timestamp,
            "domain": self.domain,
            "query_type": self.query_type,
            "query_class": self.query_class,
            "status": self.status,
            "cache": self.cache,
            "upstream": self.upstream,
            "rcode": self.rcode,
            "latency_ms": self.latency_ms,
        }

    @classmethod
    def from_dict(
        cls,
        data: dict[str, object],
    ) -> "DNSQueryLogEntry":
        """
        Reconstruct an entry from persistent storage.
        """

        return cls(
            timestamp=float(
                data["timestamp"],
            ),
            domain=str(
                data["domain"],
            ),
            query_type=int(
                data["query_type"],
            ),
            query_class=int(
                data["query_class"],
            ),
            status=data["status"],
            cache=data["cache"],
            upstream=data["upstream"],
            rcode=(
                None
                if data.get("rcode") is None
                else int(data["rcode"])
            ),
            latency_ms=float(
                data["latency_ms"],
            ),
        )


class DNSQueryLog:
    """
    Thread-safe DNS query audit log.

    Recent entries are kept in memory for fast dashboard access.

    A persistent JSONL file stores query history for up to
    PERSISTENCE_SECONDS.

    Older records are automatically deleted.
    """

    DEFAULT_MAX_ENTRIES = 100

    PERSISTENCE_SECONDS = 24 * 60 * 60

    PROJECT_ROOT = Path(
        __file__
    ).resolve().parents[1]

    LOG_DIRECTORY = (
        PROJECT_ROOT
        / "data"
        / "logs"
    )

    LOG_FILE = (
        LOG_DIRECTORY
        / "dns_queries.jsonl"
    )

    def __init__(
        self,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ) -> None:

        if not isinstance(
            max_entries,
            int,
        ):
            raise TypeError(
                "max_entries must be an integer."
            )

        if max_entries < 1:
            raise ValueError(
                "max_entries must be greater than zero."
            )

        self._max_entries = max_entries

        self._entries: deque[
            DNSQueryLogEntry
        ] = deque(
            maxlen=max_entries,
        )

        self._lock = RLock()

        self._initialize_storage()

    # ==========================================================
    # STORAGE
    # ==========================================================

    def _initialize_storage(
        self,
    ) -> None:
        """
        Create the log directory and load valid
        non-expired records.
        """

        with self._lock:

            try:

                self.LOG_DIRECTORY.mkdir(
                    parents=True,
                    exist_ok=True,
                )

                self._cleanup_and_load()

            except Exception as exc:

                print(
                    "[QueryLog] WARNING: "
                    f"Unable to initialize persistent "
                    f"query log: {exc}"
                )

    def _cleanup_and_load(
        self,
    ) -> None:
        """
        Load persistent records and remove entries
        older than 24 hours.
        """

        if not self.LOG_FILE.exists():
            return

        now = time()

        valid_entries: list[
            DNSQueryLogEntry
        ] = []

        try:

            with self.LOG_FILE.open(
                "r",
                encoding="utf-8",
            ) as file:

                for line in file:

                    line = line.strip()

                    if not line:
                        continue

                    try:

                        data = json.loads(
                            line,
                        )

                        if not isinstance(
                            data,
                            dict,
                        ):
                            continue

                        timestamp = float(
                            data.get(
                                "timestamp",
                                0,
                            )
                        )

                        if (
                            timestamp <= 0
                            or now - timestamp
                            > self.PERSISTENCE_SECONDS
                        ):
                            continue

                        entry = (
                            DNSQueryLogEntry.from_dict(
                                data,
                            )
                        )

                        valid_entries.append(
                            entry
                        )

                    except (
                        ValueError,
                        TypeError,
                        KeyError,
                        json.JSONDecodeError,
                    ):
                        continue

            valid_entries.sort(
                key=lambda entry: entry.timestamp,
            )

            self._entries.clear()

            self._entries.extend(
                valid_entries[
                    -self._max_entries:
                ]
            )

            self._rewrite_file(
                valid_entries,
            )

            print(
                "[QueryLog] Loaded "
                f"{len(valid_entries)} "
                "query records from persistent log."
            )

        except OSError as exc:

            print(
                "[QueryLog] WARNING: "
                f"Unable to read query log: {exc}"
            )

    def _rewrite_file(
        self,
        entries: list[DNSQueryLogEntry],
    ) -> None:
        """
        Rewrite the persistent log atomically.
        """

        self.LOG_DIRECTORY.mkdir(
            parents=True,
            exist_ok=True,
        )

        fd, temporary_path = (
            tempfile.mkstemp(
                prefix="dns_queries_",
                suffix=".tmp",
                dir=self.LOG_DIRECTORY,
                text=True,
            )
        )

        try:

            with os.fdopen(
                fd,
                "w",
                encoding="utf-8",
            ) as file:

                for entry in entries:

                    file.write(
                        json.dumps(
                            entry.as_dict(),
                            separators=(
                                ",",
                                ":",
                            ),
                        )
                    )

                    file.write("\n")

                file.flush()

                os.fsync(
                    file.fileno(),
                )

            os.replace(
                temporary_path,
                self.LOG_FILE,
            )

        finally:

            if os.path.exists(
                temporary_path,
            ):

                try:
                    os.remove(
                        temporary_path,
                    )

                except OSError:
                    pass

    def _append_persistent(
        self,
        entry: DNSQueryLogEntry,
    ) -> None:
        """
        Append one entry to persistent storage.
        """

        self.LOG_DIRECTORY.mkdir(
            parents=True,
            exist_ok=True,
        )

        with self.LOG_FILE.open(
            "a",
            encoding="utf-8",
        ) as file:

            file.write(
                json.dumps(
                    entry.as_dict(),
                    separators=(
                        ",",
                        ":",
                    ),
                )
            )

            file.write("\n")

            file.flush()

    def _cleanup_expired(
        self,
        now: float,
    ) -> None:
        """
        Remove persistent records older than 24 hours.

        Cleanup is performed during writes so the file does
        not grow indefinitely.
        """

        if not self.LOG_FILE.exists():
            return

        valid_entries: list[
            DNSQueryLogEntry
        ] = []

        try:

            with self.LOG_FILE.open(
                "r",
                encoding="utf-8",
            ) as file:

                for line in file:

                    line = line.strip()

                    if not line:
                        continue

                    try:

                        data = json.loads(
                            line,
                        )

                        if not isinstance(
                            data,
                            dict,
                        ):
                            continue

                        timestamp = float(
                            data.get(
                                "timestamp",
                                0,
                            )
                        )

                        if (
                            timestamp <= 0
                            or now - timestamp
                            > self.PERSISTENCE_SECONDS
                        ):
                            continue

                        valid_entries.append(
                            DNSQueryLogEntry.from_dict(
                                data,
                            )
                        )

                    except (
                        ValueError,
                        TypeError,
                        KeyError,
                        json.JSONDecodeError,
                    ):
                        continue

            self._rewrite_file(
                valid_entries,
            )

        except OSError:
            return

    # ==========================================================
    # PROPERTIES
    # ==========================================================

    @property
    def max_entries(
        self,
    ) -> int:
        """
        Maximum number of in-memory records.
        """

        return self._max_entries

    # ==========================================================
    # RECORD
    # ==========================================================

    def record(
        self,
        *,
        domain: str,
        query_type: int,
        query_class: int,
        status: QueryStatus,
        cache: CacheStatus,
        upstream: UpstreamStatus,
        rcode: int | None,
        latency_ms: float,
        timestamp: float | None = None,
    ) -> None:
        """
        Add one sanitized DNS query record.

        The record is written both to memory and to the
        persistent 24-hour audit log.
        """

        if not isinstance(
            domain,
            str,
        ):
            raise TypeError(
                "domain must be a string."
            )

        domain = (
            domain
            .strip()
            .lower()
            .rstrip(".")
        )

        if not domain:
            raise ValueError(
                "domain must not be empty."
            )

        if len(domain) > 253:
            raise ValueError(
                "domain exceeds the DNS maximum length."
            )

        if not isinstance(
            query_type,
            int,
        ):
            raise TypeError(
                "query_type must be an integer."
            )

        if not 0 <= query_type <= 65535:
            raise ValueError(
                "query_type is outside the valid DNS range."
            )

        if not isinstance(
            query_class,
            int,
        ):
            raise TypeError(
                "query_class must be an integer."
            )

        if not 0 <= query_class <= 65535:
            raise ValueError(
                "query_class is outside the valid DNS range."
            )

        if rcode is not None:

            if not isinstance(
                rcode,
                int,
            ):
                raise TypeError(
                    "rcode must be an integer or None."
                )

            if not 0 <= rcode <= 15:
                raise ValueError(
                    "rcode must be a DNS 4-bit value."
                )

        try:

            latency = float(
                latency_ms,
            )

        except (
            TypeError,
            ValueError,
        ) as exc:

            raise ValueError(
                "latency_ms must be numeric."
            ) from exc

        if (
            latency < 0
            or latency != latency
            or latency in (
                float("inf"),
                float("-inf"),
            )
        ):
            raise ValueError(
                "latency_ms must be finite "
                "and non-negative."
            )

        event_time = (
            time()
            if timestamp is None
            else float(timestamp)
        )

        if (
            event_time != event_time
            or event_time in (
                float("inf"),
                float("-inf"),
            )
        ):
            raise ValueError(
                "timestamp must be finite."
            )

        entry = DNSQueryLogEntry(
            timestamp=event_time,
            domain=domain,
            query_type=query_type,
            query_class=query_class,
            status=status,
            cache=cache,
            upstream=upstream,
            rcode=rcode,
            latency_ms=round(
                latency,
                3,
            ),
        )

        with self._lock:

            self._entries.append(
                entry,
            )

            try:

                self._append_persistent(
                    entry,
                )

                self._cleanup_expired(
                    event_time,
                )

            except Exception as exc:

                # Persistent logging must never break DNS resolution.
                print(
                    "[QueryLog] WARNING: "
                    f"Persistent write failed: {exc}"
                )

    # ==========================================================
    # RECENT
    # ==========================================================

    def recent(
        self,
        *,
        limit: int = 100,
    ) -> tuple[DNSQueryLogEntry, ...]:
        """
        Return newest records first.
        """

        if not isinstance(
            limit,
            int,
        ):
            raise TypeError(
                "limit must be an integer."
            )

        limit = max(
            1,
            min(
                limit,
                self._max_entries,
            ),
        )

        with self._lock:

            entries = tuple(
                self._entries,
            )

        return tuple(
            reversed(
                entries[-limit:],
            )
        )

    # ==========================================================
    # DICTIONARY VIEW
    # ==========================================================

    def as_dicts(
        self,
        *,
        limit: int = 100,
    ) -> list[dict[str, object]]:
        """
        Return recent entries as JSON-safe dictionaries.
        """

        return [
            entry.as_dict()
            for entry in self.recent(
                limit=limit,
            )
        ]

    # ==========================================================
    # CLEAR
    # ==========================================================

    def clear(
        self,
    ) -> None:
        """
        Clear both the in-memory history and the persistent
        24-hour query log.
        """

        with self._lock:

            self._entries.clear()

            try:

                if self.LOG_FILE.exists():

                    self.LOG_FILE.unlink()

            except OSError as exc:

                print(
                    "[QueryLog] WARNING: "
                    f"Unable to clear persistent log: {exc}"
                )

    # ==========================================================
    # LENGTH
    # ==========================================================

    def __len__(
        self,
    ) -> int:

        with self._lock:

            return len(
                self._entries,
            )


# ==========================================================
# SHARED QUERY LOG
# ==========================================================

query_log = DNSQueryLog()