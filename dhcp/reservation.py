"""
SentinelDNS DHCP Reservation Manager

Responsibilities:
- Manage static DHCP reservations
- Associate clients with fixed IPv4 addresses
- Normalize MAC addresses
- Prevent duplicate client reservations
- Prevent duplicate IP reservations
- Provide safe reservation lookup

This module does not:
- Allocate dynamic IP addresses
- Manage DHCP leases
- Parse DHCP packets
- Handle network sockets
- Access the database
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from threading import RLock


class DHCPReservationError(ValueError):
    """Raised when a DHCP reservation is invalid."""


@dataclass(frozen=True)
class DHCPReservation:
    """
    Represents a static DHCP reservation.

    A client identifier is normally a MAC address, but the
    manager intentionally accepts a generic client identifier
    so it can also support DHCP client identifiers later.
    """

    client_id: str
    ip_address: str
    hostname: str | None = None


class DHCPReservationManager:
    """
    Thread-safe manager for static DHCP reservations.
    """

    def __init__(self) -> None:

        self._by_client: dict[
            str,
            DHCPReservation,
        ] = {}

        self._by_ip: dict[
            str,
            DHCPReservation,
        ] = {}

        self._lock = RLock()

    @staticmethod
    def normalize_client_id(
        client_id: str,
    ) -> str:
        """
        Normalize a DHCP client identifier.

        MAC addresses are normalized to lowercase and use
        colon-separated notation.

        Examples:

            AA-BB-CC-DD-EE-FF
            aa:bb:cc:dd:ee:ff
            aabbccddeeff

        all become:

            aa:bb:cc:dd:ee:ff
        """

        if not isinstance(
            client_id,
            str,
        ):
            raise DHCPReservationError(
                "Client ID must be a string."
            )

        value = client_id.strip().lower()

        if not value:
            raise DHCPReservationError(
                "Client ID cannot be empty."
            )

        # Remove common MAC separators.
        compact = (
            value
            .replace(":", "")
            .replace("-", "")
            .replace(".", "")
        )

        # Standard six-byte MAC address.
        if len(compact) == 12:

            if all(
                character in "0123456789abcdef"
                for character in compact
            ):
                return ":".join(
                    compact[index:index + 2]
                    for index in range(
                        0,
                        12,
                        2,
                    )
                )

        # Non-MAC client identifiers are retained
        # in normalized lowercase form.
        return value

    @staticmethod
    def validate_ip(
        ip_address: str,
    ) -> str:
        """
        Validate and normalize an IPv4 address.
        """

        if not isinstance(
            ip_address,
            str,
        ):
            raise DHCPReservationError(
                "IP address must be a string."
            )

        value = ip_address.strip()

        try:

            return str(
                ipaddress.IPv4Address(
                    value
                )
            )

        except ValueError as exc:

            raise DHCPReservationError(
                f"Invalid IPv4 address: {ip_address}"
            ) from exc

    def add(
        self,
        client_id: str,
        ip_address: str,
        hostname: str | None = None,
    ) -> DHCPReservation:
        """
        Add a new static reservation.

        Raises:
            DHCPReservationError:
                If the client or IP is already reserved.
        """

        client_id = self.normalize_client_id(
            client_id
        )

        ip_address = self.validate_ip(
            ip_address
        )

        if hostname is not None:

            if not isinstance(
                hostname,
                str,
            ):
                raise DHCPReservationError(
                    "Hostname must be a string or None."
                )

            hostname = hostname.strip()

            if not hostname:
                hostname = None

        with self._lock:

            existing_client = self._by_client.get(
                client_id
            )

            if existing_client is not None:

                raise DHCPReservationError(
                    f"Client {client_id} already "
                    "has a reservation."
                )

            existing_ip = self._by_ip.get(
                ip_address
            )

            if existing_ip is not None:

                raise DHCPReservationError(
                    f"IP address {ip_address} is "
                    "already reserved."
                )

            reservation = DHCPReservation(
                client_id=client_id,
                ip_address=ip_address,
                hostname=hostname,
            )

            self._by_client[
                client_id
            ] = reservation

            self._by_ip[
                ip_address
            ] = reservation

            return reservation

    def update(
        self,
        client_id: str,
        ip_address: str,
        hostname: str | None = None,
    ) -> DHCPReservation:
        """
        Update an existing reservation.

        The client keeps the same identity, but its assigned
        IP address or hostname can be changed.
        """

        client_id = self.normalize_client_id(
            client_id
        )

        ip_address = self.validate_ip(
            ip_address
        )

        with self._lock:

            existing = self._by_client.get(
                client_id
            )

            if existing is None:

                raise DHCPReservationError(
                    f"No reservation exists for "
                    f"client {client_id}."
                )

            existing_ip = self._by_ip.get(
                ip_address
            )

            if (
                existing_ip is not None
                and existing_ip.client_id
                != client_id
            ):

                raise DHCPReservationError(
                    f"IP address {ip_address} is "
                    "already reserved by another client."
                )

            self._by_ip.pop(
                existing.ip_address,
                None,
            )

            reservation = DHCPReservation(
                client_id=client_id,
                ip_address=ip_address,
                hostname=hostname,
            )

            self._by_client[
                client_id
            ] = reservation

            self._by_ip[
                ip_address
            ] = reservation

            return reservation

    def get_by_client(
        self,
        client_id: str,
    ) -> DHCPReservation | None:
        """
        Find a reservation by client identifier.
        """

        client_id = self.normalize_client_id(
            client_id
        )

        with self._lock:

            return self._by_client.get(
                client_id
            )

    def get_by_ip(
        self,
        ip_address: str,
    ) -> DHCPReservation | None:
        """
        Find a reservation by IP address.
        """

        ip_address = self.validate_ip(
            ip_address
        )

        with self._lock:

            return self._by_ip.get(
                ip_address
            )

    def is_reserved(
        self,
        ip_address: str,
    ) -> bool:
        """
        Return True if an IP address has a reservation.
        """

        return (
            self.get_by_ip(ip_address)
            is not None
        )

    def remove_by_client(
        self,
        client_id: str,
    ) -> bool:
        """
        Remove a reservation by client identifier.

        Returns:
            True if removed.
            False if no reservation existed.
        """

        client_id = self.normalize_client_id(
            client_id
        )

        with self._lock:

            reservation = self._by_client.pop(
                client_id,
                None,
            )

            if reservation is None:
                return False

            self._by_ip.pop(
                reservation.ip_address,
                None,
            )

            return True

    def remove_by_ip(
        self,
        ip_address: str,
    ) -> bool:
        """
        Remove a reservation by IP address.

        Returns:
            True if removed.
            False if no reservation existed.
        """

        ip_address = self.validate_ip(
            ip_address
        )

        with self._lock:

            reservation = self._by_ip.pop(
                ip_address,
                None,
            )

            if reservation is None:
                return False

            self._by_client.pop(
                reservation.client_id,
                None,
            )

            return True

    def all(
        self,
    ) -> list[DHCPReservation]:
        """
        Return all configured reservations.
        """

        with self._lock:

            return list(
                self._by_client.values()
            )

    def count(
        self,
    ) -> int:
        """Return the number of reservations."""

        with self._lock:

            return len(
                self._by_client
            )

    def clear(
        self,
    ) -> None:
        """
        Remove all reservations.

        Intended for controlled maintenance or testing.
        """

        with self._lock:

            self._by_client.clear()
            self._by_ip.clear()


__all__ = [
    "DHCPReservation",
    "DHCPReservationError",
    "DHCPReservationManager",
]