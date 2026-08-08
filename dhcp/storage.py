"""
SentinelDNS DHCP Lease Storage

Provides persistent storage for DHCP leases using the
existing SentinelDNS SQLAlchemy database layer.

Responsibilities:
- Save DHCP leases
- Retrieve leases by client ID
- Retrieve leases by IP address
- Update leases
- Delete leases
- Remove expired leases

This module does not:
- Parse DHCP packets
- Allocate IP addresses
- Handle DHCP sockets
- Implement DHCP protocol logic
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy import delete, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from database.database import SessionLocal
from database.models.dhcp_lease import DHCPLease


class DHCPStorageError(RuntimeError):
    """Raised when a DHCP storage operation fails."""


@dataclass(frozen=True)
class StoredLease:
    """
    Storage representation of a DHCP lease.
    """

    client_id: str
    ip_address: str

    lease_start: float
    lease_end: float

    hostname: str | None = None


class DHCPLeaseStorage:
    """
    Persistent DHCP lease storage.

    Uses the existing SentinelDNS SQLAlchemy database
    session factory rather than creating a separate
    database connection.
    """

    def __init__(
        self,
        session_factory: Callable[[], Session] = SessionLocal,
    ) -> None:

        self.session_factory = session_factory

    @staticmethod
    def _validate_client_id(
        client_id: str,
    ) -> str:
        """Validate a DHCP client identifier."""

        if not isinstance(
            client_id,
            str,
        ):
            raise DHCPStorageError(
                "Client ID must be a string."
            )

        client_id = client_id.strip()

        if not client_id:
            raise DHCPStorageError(
                "Client ID cannot be empty."
            )

        return client_id

    @staticmethod
    def _datetime_to_timestamp(
        value: datetime,
    ) -> float:
        """
        Convert a datetime into a Unix timestamp.
        """

        if value.tzinfo is None:

            value = value.replace(
                tzinfo=timezone.utc
            )

        return value.timestamp()

    @staticmethod
    def _timestamp_to_datetime(
        value: float,
    ) -> datetime:
        """
        Convert a Unix timestamp into a UTC datetime.
        """

        return datetime.fromtimestamp(
            value,
            tz=timezone.utc,
        )

    @classmethod
    def _to_stored_lease(
        cls,
        model: DHCPLease,
    ) -> StoredLease:
        """Convert an ORM model into a storage object."""

        return StoredLease(
            client_id=model.client_id,
            ip_address=model.ip_address,
            hostname=model.hostname,
            lease_start=cls._datetime_to_timestamp(
                model.lease_start
            ),
            lease_end=cls._datetime_to_timestamp(
                model.lease_end
            ),
        )

    @classmethod
    def _apply_lease(
        cls,
        model: DHCPLease,
        lease: StoredLease,
    ) -> None:
        """Copy storage data into an ORM model."""

        model.client_id = lease.client_id
        model.ip_address = lease.ip_address
        model.hostname = lease.hostname

        model.lease_start = (
            cls._timestamp_to_datetime(
                lease.lease_start
            )
        )

        model.lease_end = (
            cls._timestamp_to_datetime(
                lease.lease_end
            )
        )

    def save(
        self,
        lease: StoredLease,
    ) -> None:
        """
        Create or replace a DHCP lease.

        If a lease already exists for the client,
        it is updated.
        """

        if not isinstance(
            lease,
            StoredLease,
        ):
            raise DHCPStorageError(
                "lease must be a StoredLease instance."
            )

        client_id = self._validate_client_id(
            lease.client_id,
        )

        db = self.session_factory()

        try:

            existing = db.scalar(
                select(DHCPLease).where(
                    DHCPLease.client_id
                    == client_id
                )
            )

            if existing is None:

                existing = DHCPLease(
                    client_id=client_id,
                    ip_address=lease.ip_address,
                    hostname=lease.hostname,
                    lease_start=(
                        self._timestamp_to_datetime(
                            lease.lease_start
                        )
                    ),
                    lease_end=(
                        self._timestamp_to_datetime(
                            lease.lease_end
                        )
                    ),
                )

                db.add(existing)

            else:

                self._apply_lease(
                    existing,
                    lease,
                )

            db.commit()

        except SQLAlchemyError as exc:

            db.rollback()

            raise DHCPStorageError(
                "Failed to save DHCP lease."
            ) from exc

        finally:

            db.close()

    def get(
        self,
        client_id: str,
    ) -> StoredLease | None:
        """
        Retrieve a lease by client ID.
        """

        client_id = self._validate_client_id(
            client_id,
        )

        db = self.session_factory()

        try:

            model = db.scalar(
                select(DHCPLease).where(
                    DHCPLease.client_id
                    == client_id
                )
            )

            if model is None:
                return None

            return self._to_stored_lease(
                model
            )

        except SQLAlchemyError as exc:

            raise DHCPStorageError(
                "Failed to retrieve DHCP lease."
            ) from exc

        finally:

            db.close()

    def get_by_ip(
        self,
        ip_address: str,
    ) -> StoredLease | None:
        """
        Retrieve a lease by assigned IP address.
        """

        if not isinstance(
            ip_address,
            str,
        ):
            raise DHCPStorageError(
                "IP address must be a string."
            )

        ip_address = ip_address.strip()

        if not ip_address:
            raise DHCPStorageError(
                "IP address cannot be empty."
            )

        db = self.session_factory()

        try:

            model = db.scalar(
                select(DHCPLease).where(
                    DHCPLease.ip_address
                    == ip_address
                )
            )

            if model is None:
                return None

            return self._to_stored_lease(
                model
            )

        except SQLAlchemyError as exc:

            raise DHCPStorageError(
                "Failed to retrieve DHCP lease "
                "by IP address."
            ) from exc

        finally:

            db.close()

    def update(
        self,
        lease: StoredLease,
    ) -> None:
        """
        Update an existing DHCP lease.
        """

        if not isinstance(
            lease,
            StoredLease,
        ):
            raise DHCPStorageError(
                "lease must be a StoredLease instance."
            )

        client_id = self._validate_client_id(
            lease.client_id,
        )

        db = self.session_factory()

        try:

            model = db.scalar(
                select(DHCPLease).where(
                    DHCPLease.client_id
                    == client_id
                )
            )

            if model is None:

                raise DHCPStorageError(
                    f"No stored lease exists for "
                    f"client {client_id}."
                )

            self._apply_lease(
                model,
                lease,
            )

            db.commit()

        except DHCPStorageError:

            db.rollback()

            raise

        except SQLAlchemyError as exc:

            db.rollback()

            raise DHCPStorageError(
                "Failed to update DHCP lease."
            ) from exc

        finally:

            db.close()

    def delete(
        self,
        client_id: str,
    ) -> bool:
        """
        Delete a DHCP lease by client ID.

        Returns:
            True if a lease was deleted.
            False if no matching lease existed.
        """

        client_id = self._validate_client_id(
            client_id,
        )

        db = self.session_factory()

        try:

            model = db.scalar(
                select(DHCPLease).where(
                    DHCPLease.client_id
                    == client_id
                )
            )

            if model is None:
                return False

            db.delete(model)

            db.commit()

            return True

        except SQLAlchemyError as exc:

            db.rollback()

            raise DHCPStorageError(
                "Failed to delete DHCP lease."
            ) from exc

        finally:

            db.close()

    def delete_by_ip(
        self,
        ip_address: str,
    ) -> bool:
        """
        Delete a DHCP lease by IP address.
        """

        if not isinstance(
            ip_address,
            str,
        ):
            raise DHCPStorageError(
                "IP address must be a string."
            )

        db = self.session_factory()

        try:

            model = db.scalar(
                select(DHCPLease).where(
                    DHCPLease.ip_address
                    == ip_address
                )
            )

            if model is None:
                return False

            db.delete(model)

            db.commit()

            return True

        except SQLAlchemyError as exc:

            db.rollback()

            raise DHCPStorageError(
                "Failed to delete DHCP lease "
                "by IP address."
            ) from exc

        finally:

            db.close()

    def all(
        self,
    ) -> list[StoredLease]:
        """
        Return all stored DHCP leases.
        """

        db = self.session_factory()

        try:

            models = db.scalars(
                select(DHCPLease).order_by(
                    DHCPLease.ip_address
                )
            ).all()

            return [
                self._to_stored_lease(
                    model
                )
                for model in models
            ]

        except SQLAlchemyError as exc:

            raise DHCPStorageError(
                "Failed to retrieve DHCP leases."
            ) from exc

        finally:

            db.close()

    def count(self) -> int:
        """Return the number of stored leases."""

        db = self.session_factory()

        try:

            return len(
                db.scalars(
                    select(DHCPLease)
                ).all()
            )

        except SQLAlchemyError as exc:

            raise DHCPStorageError(
                "Failed to count DHCP leases."
            ) from exc

        finally:

            db.close()

def delete_expired(
    self,
    *,
    now: float | None = None,
) -> int:
    """
    Delete all DHCP leases whose expiration time has passed.

    Returns:
        Number of deleted leases.
    """

    if now is None:
        now = datetime.now(
            timezone.utc
        ).timestamp()

    expiry = self._timestamp_to_datetime(
        now
    )

    db = self.session_factory()

    try:

        expired_leases = db.scalars(
            select(DHCPLease).where(
                DHCPLease.lease_end <= expiry
            )
        ).all()

        deleted_count = len(
            expired_leases
        )

        for lease in expired_leases:
            db.delete(lease)

        db.commit()

        return deleted_count

    except SQLAlchemyError as exc:

        db.rollback()

        raise DHCPStorageError(
            "Failed to delete expired "
            "DHCP leases."
        ) from exc

    finally:

        db.close()
        """
        Delete all leases whose expiration time has passed.

        Returns:
            Number of deleted leases.
        """

        if now is None:
            now = datetime.now(
                timezone.utc
            ).timestamp()

        expiry = self._timestamp_to_datetime(
            now
        )

        db = self.session_factory()

        try:

            result = db.execute(
                delete(DHCPLease).where(
                    DHCPLease.lease_end
                    <= expiry
                )
            )

            db.commit()

            return result.rowcount or 0

        except SQLAlchemyError as exc:

            db.rollback()

            raise DHCPStorageError(
                "Failed to delete expired "
                "DHCP leases."
            ) from exc

        finally:

            db.close()

    def clear(self) -> None:
        """
        Delete all DHCP leases.

        Intended for controlled maintenance or testing.
        """

        db = self.session_factory()

        try:

            db.execute(
                delete(DHCPLease)
            )

            db.commit()

        except SQLAlchemyError as exc:

            db.rollback()

            raise DHCPStorageError(
                "Failed to clear DHCP leases."
            ) from exc

        finally:

            db.close()


__all__ = [
    "DHCPLeaseStorage",
    "DHCPStorageError",
    "StoredLease",
]