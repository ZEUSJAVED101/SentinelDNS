"""
SentinelDNS DHCP Address Pool

Responsibilities:
- Validate an IPv4 address range
- Track available addresses
- Allocate addresses
- Release addresses
- Reserve addresses
- Detect pool exhaustion

This module does not:
- Manage DHCP leases
- Parse DHCP packets
- Handle network sockets
- Access the database
"""

from __future__ import annotations

import ipaddress
from threading import RLock


class DHCPPoolError(ValueError):
    """Raised when the DHCP address pool is invalid."""


class DHCPPoolExhaustedError(DHCPPoolError):
    """Raised when no address is available in the DHCP pool."""


class DHCPAddressPool:
    """
    Thread-safe IPv4 address pool.

    Addresses between start and end are inclusive.
    """

    def __init__(
        self,
        start: str,
        end: str,
    ) -> None:

        self.start = self._parse_ipv4(
            start,
            "start",
        )

        self.end = self._parse_ipv4(
            end,
            "end",
        )

        if int(self.start) > int(self.end):
            raise DHCPPoolError(
                "DHCP pool start address "
                "cannot be greater than the end address."
            )

        self._allocated: set[ipaddress.IPv4Address] = set()

        self._reserved: set[ipaddress.IPv4Address] = set()

        self._lock = RLock()

    @staticmethod
    def _parse_ipv4(
        address: str,
        field_name: str,
    ) -> ipaddress.IPv4Address:
        """Validate and convert an IPv4 address."""

        if not isinstance(address, str):
            raise DHCPPoolError(
                f"{field_name} address must be a string."
            )

        try:
            return ipaddress.IPv4Address(
                address.strip()
            )

        except ValueError as exc:

            raise DHCPPoolError(
                f"Invalid IPv4 {field_name} address: "
                f"{address}"
            ) from exc

    def contains(
        self,
        address: str,
    ) -> bool:
        """Return True if an address belongs to this pool."""

        ip = self._parse_ipv4(
            address,
            "address",
        )

        return (
            int(self.start)
            <= int(ip)
            <= int(self.end)
        )

    def reserve(
        self,
        address: str,
    ) -> None:
        """
        Reserve an address so that normal DHCP allocation
        cannot use it.
        """

        ip = self._parse_ipv4(
            address,
            "reservation",
        )

        if not self.contains(address):
            raise DHCPPoolError(
                f"Address {address} is outside "
                "the DHCP pool."
            )

        with self._lock:

            if ip in self._allocated:
                raise DHCPPoolError(
                    f"Address {address} is already allocated."
                )

            self._reserved.add(ip)

    def unreserve(
        self,
        address: str,
    ) -> None:
        """Remove an address from the reservation set."""

        ip = self._parse_ipv4(
            address,
            "reservation",
        )

        with self._lock:
            self._reserved.discard(ip)

    def is_reserved(
        self,
        address: str,
    ) -> bool:
        """Return True if an address is reserved."""

        ip = self._parse_ipv4(
            address,
            "address",
        )

        with self._lock:
            return ip in self._reserved

    def is_allocated(
        self,
        address: str,
    ) -> bool:
        """Return True if an address is currently allocated."""

        ip = self._parse_ipv4(
            address,
            "address",
        )

        with self._lock:
            return ip in self._allocated

    def allocate(
        self,
    ) -> str:
        """
        Allocate the first available address.

        Reserved and already allocated addresses are skipped.

        Raises:
            DHCPPoolExhaustedError:
                If no address is available.
        """

        with self._lock:

            current = int(self.start)

            end = int(self.end)

            while current <= end:

                address = ipaddress.IPv4Address(
                    current
                )

                if (
                    address not in self._allocated
                    and address not in self._reserved
                ):

                    self._allocated.add(
                        address
                    )

                    return str(address)

                current += 1

        raise DHCPPoolExhaustedError(
            "No available IPv4 address remains "
            "in the DHCP pool."
        )

    def allocate_specific(
        self,
        address: str,
    ) -> str:
        """
        Allocate a specific address when available.

        This will later be useful for DHCP lease renewal
        and requested-IP handling.
        """

        ip = self._parse_ipv4(
            address,
            "requested",
        )

        if not self.contains(address):
            raise DHCPPoolError(
                f"Address {address} is outside "
                "the DHCP pool."
            )

        with self._lock:

            if ip in self._reserved:
                raise DHCPPoolError(
                    f"Address {address} is reserved."
                )

            if ip in self._allocated:
                raise DHCPPoolError(
                    f"Address {address} is already allocated."
                )

            self._allocated.add(ip)

            return str(ip)

    def release(
        self,
        address: str,
    ) -> bool:
        """
        Release an allocated address.

        Returns:
            True if the address was allocated and released.
            False if it was not currently allocated.
        """

        ip = self._parse_ipv4(
            address,
            "address",
        )

        with self._lock:

            if ip not in self._allocated:
                return False

            self._allocated.remove(ip)

            return True

    def available_count(self) -> int:
        """Return the number of currently available addresses."""

        with self._lock:

            total = (
                int(self.end)
                - int(self.start)
                + 1
            )

            unavailable = (
                len(self._allocated)
                + len(self._reserved)
            )

            return max(
                0,
                total - unavailable,
            )

    def allocated_count(self) -> int:
        """Return the number of allocated addresses."""

        with self._lock:
            return len(
                self._allocated
            )

    def reserved_count(self) -> int:
        """Return the number of reserved addresses."""

        with self._lock:
            return len(
                self._reserved
            )

    def allocated_addresses(
        self,
    ) -> list[str]:
        """Return currently allocated addresses."""

        with self._lock:

            return [
                str(address)
                for address in sorted(
                    self._allocated,
                    key=int,
                )
            ]

    def reserved_addresses(
        self,
    ) -> list[str]:
        """Return currently reserved addresses."""

        with self._lock:

            return [
                str(address)
                for address in sorted(
                    self._reserved,
                    key=int,
                )
            ]

    def available_addresses(
        self,
    ) -> list[str]:
        """
        Return all currently available addresses.

        This method is intended primarily for diagnostics
        and testing.
        """

        with self._lock:

            addresses: list[str] = []

            current = int(self.start)

            end = int(self.end)

            while current <= end:

                address = ipaddress.IPv4Address(
                    current
                )

                if (
                    address not in self._allocated
                    and address not in self._reserved
                ):
                    addresses.append(
                        str(address)
                    )

                current += 1

            return addresses


__all__ = [
    "DHCPAddressPool",
    "DHCPPoolError",
    "DHCPPoolExhaustedError",
]