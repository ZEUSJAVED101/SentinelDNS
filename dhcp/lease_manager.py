"""
SentinelDNS DHCP Lease Manager

Responsibilities:
- Track DHCP leases
- Associate clients with IPv4 addresses
- Create leases
- Renew leases
- Release leases
- Expire leases
- Reuse valid existing leases
- Provide thread-safe lease inspection

This module does not:
- Parse DHCP packets
- Encode DHCP options
- Handle network sockets
- Persist leases to a database
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from threading import RLock


class DHCPLeaseError(ValueError):
    """Raised when a DHCP lease operation is invalid."""


class DHCPLeaseNotFoundError(DHCPLeaseError):
    """Raised when a requested lease does not exist."""


@dataclass
class DHCPLease:
    """
    Represents a single DHCP lease.
    """

    client_id: str
    ip_address: str

    lease_start: float
    lease_end: float

    hostname: str | None = None

    @property
    def expired(self) -> bool:
        """Return True when the lease has expired."""

        return time.time() >= self.lease_end

    @property
    def remaining_seconds(self) -> int:
        """Return the remaining lease duration."""

        remaining = self.lease_end - time.time()

        return max(
            0,
            int(remaining),
        )


class DHCPLeaseManager:
    """
    Manages DHCP leases using an in-memory store.

    The address pool is deliberately kept separate from
    lease management. The pool decides which addresses can
    be allocated; this class manages their client bindings.
    """

    def __init__(
        self,
        pool,
    ) -> None:

        if pool is None:
            raise DHCPLeaseError(
                "A DHCP address pool is required."
            )

        self.pool = pool

        self._leases_by_client: dict[
            str,
            DHCPLease,
        ] = {}

        self._leases_by_ip: dict[
            str,
            DHCPLease,
        ] = {}

        self._lock = RLock()

    @staticmethod
    def _validate_client_id(
        client_id: str,
    ) -> str:
        """Validate and normalize a client identifier."""

        if not isinstance(
            client_id,
            str,
        ):
            raise DHCPLeaseError(
                "Client ID must be a string."
            )

        client_id = client_id.strip()

        if not client_id:
            raise DHCPLeaseError(
                "Client ID cannot be empty."
            )

        return client_id

    @staticmethod
    def _validate_duration(
        lease_time: int,
    ) -> int:
        """Validate DHCP lease duration."""

        if not isinstance(
            lease_time,
            int,
        ):
            raise DHCPLeaseError(
                "Lease time must be an integer."
            )

        if lease_time <= 0:
            raise DHCPLeaseError(
                "Lease time must be greater than zero."
            )

        return lease_time

    def get_by_client(
        self,
        client_id: str,
    ) -> DHCPLease | None:
        """
        Return the active lease belonging to a client.

        Expired leases are cleaned up automatically.
        """

        client_id = self._validate_client_id(
            client_id,
        )

        with self._lock:

            lease = self._leases_by_client.get(
                client_id
            )

            if lease is None:
                return None

            if lease.expired:

                self._remove_lease(
                    lease
                )

                return None

            return lease

    def get_by_ip(
        self,
        ip_address: str,
    ) -> DHCPLease | None:
        """
        Return the active lease assigned to an IP address.
        """

        if not isinstance(
            ip_address,
            str,
        ):
            raise DHCPLeaseError(
                "IP address must be a string."
            )

        with self._lock:

            lease = self._leases_by_ip.get(
                ip_address
            )

            if lease is None:
                return None

            if lease.expired:

                self._remove_lease(
                    lease
                )

                return None

            return lease

    def create(
        self,
        client_id: str,
        lease_time: int,
        hostname: str | None = None,
    ) -> DHCPLease:
        """
        Allocate an address and create a new lease.

        If the client already has a valid lease, that lease
        is returned instead of allocating another address.
        """

        client_id = self._validate_client_id(
            client_id,
        )

        lease_time = self._validate_duration(
            lease_time,
        )

        with self._lock:

            existing = self.get_by_client(
                client_id
            )

            if existing is not None:

                return existing

            ip_address = self.pool.allocate()

            now = time.time()

            lease = DHCPLease(
                client_id=client_id,
                ip_address=ip_address,
                lease_start=now,
                lease_end=now + lease_time,
                hostname=hostname,
            )

            self._leases_by_client[
                client_id
            ] = lease

            self._leases_by_ip[
                ip_address
            ] = lease

            return lease

    def create_specific(
        self,
        client_id: str,
        ip_address: str,
        lease_time: int,
        hostname: str | None = None,
    ) -> DHCPLease:
        """
        Create a lease for a specifically requested IP address.

        This will be useful when handling DHCPREQUEST messages
        containing option 50 (Requested IP Address).
        """

        client_id = self._validate_client_id(
            client_id,
        )

        lease_time = self._validate_duration(
            lease_time,
        )

        with self._lock:

            existing = self.get_by_client(
                client_id
            )

            if existing is not None:

                if existing.ip_address == ip_address:

                    return self.renew(
                        client_id,
                        lease_time,
                    )

                self.release(
                    client_id
                )

            existing_ip = self.get_by_ip(
                ip_address
            )

            if existing_ip is not None:
                raise DHCPLeaseError(
                    f"IP address {ip_address} "
                    "is already leased."
                )

            allocated_ip = self.pool.allocate_specific(
                ip_address
            )

            now = time.time()

            lease = DHCPLease(
                client_id=client_id,
                ip_address=allocated_ip,
                lease_start=now,
                lease_end=now + lease_time,
                hostname=hostname,
            )

            self._leases_by_client[
                client_id
            ] = lease

            self._leases_by_ip[
                allocated_ip
            ] = lease

            return lease

    def renew(
        self,
        client_id: str,
        lease_time: int,
    ) -> DHCPLease:
        """
        Renew an existing client lease.
        """

        client_id = self._validate_client_id(
            client_id,
        )

        lease_time = self._validate_duration(
            lease_time,
        )

        with self._lock:

            lease = self._leases_by_client.get(
                client_id
            )

            if lease is None:
                raise DHCPLeaseNotFoundError(
                    f"No lease found for client "
                    f"{client_id}."
                )

            if lease.expired:

                self._remove_lease(
                    lease
                )

                raise DHCPLeaseNotFoundError(
                    f"Lease for client "
                    f"{client_id} has expired."
                )

            now = time.time()

            lease.lease_start = now

            lease.lease_end = (
                now + lease_time
            )

            return lease

    def release(
        self,
        client_id: str,
    ) -> bool:
        """
        Release the lease belonging to a client.

        Returns:
            True when a lease was released.
            False when no lease existed.
        """

        client_id = self._validate_client_id(
            client_id,
        )

        with self._lock:

            lease = self._leases_by_client.get(
                client_id
            )

            if lease is None:
                return False

            self._remove_lease(
                lease
            )

            return True

    def expire_leases(self) -> int:
        """
        Remove all expired leases.

        Returns:
            Number of leases removed.
        """

        expired: list[DHCPLease] = []

        with self._lock:

            for lease in list(
                self._leases_by_client.values()
            ):

                if lease.expired:
                    expired.append(
                        lease
                    )

            for lease in expired:

                self._remove_lease(
                    lease
                )

        return len(expired)

    def _remove_lease(
        self,
        lease: DHCPLease,
    ) -> None:
        """
        Remove a lease from the manager and return its
        IP address to the pool.
        """

        self._leases_by_client.pop(
            lease.client_id,
            None,
        )

        self._leases_by_ip.pop(
            lease.ip_address,
            None,
        )

        self.pool.release(
            lease.ip_address
        )

    def all_leases(
        self,
    ) -> list[DHCPLease]:
        """
        Return all currently active leases.
        """

        self.expire_leases()

        with self._lock:

            return list(
                self._leases_by_client.values()
            )

    def active_count(self) -> int:
        """Return the number of active leases."""

        self.expire_leases()

        with self._lock:
            return len(
                self._leases_by_client
            )

    def clear(self) -> None:
        """
        Release all active leases.

        Primarily useful during controlled shutdown
        and testing.
        """

        with self._lock:

            leases = list(
                self._leases_by_client.values()
            )

            for lease in leases:

                self._remove_lease(
                    lease
                )


__all__ = [
    "DHCPLease",
    "DHCPLeaseError",
    "DHCPLeaseManager",
    "DHCPLeaseNotFoundError",
]