"""
SentinelDNS DHCP Packet Module

Responsibilities:
- Represent DHCP/BOOTP packets
- Parse raw DHCP packets
- Serialize DHCP packets
- Provide safe access to DHCP header fields
- Preserve DHCP options for higher-level processing

This module does not perform:
- IP allocation
- Lease management
- DHCP server logic
- Database operations
- Network socket handling
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field
from typing import ClassVar


class DHCPPacketError(ValueError):
    """Raised when a DHCP packet is invalid or malformed."""


@dataclass
class DHCPPacket:
    """
    Represents a DHCP/BOOTP packet.

    The fixed BOOTP/DHCP header is 236 bytes.
    A DHCP packet normally follows it with the
    DHCP magic cookie and DHCP options.
    """

    # DHCP/BOOTP fixed header fields
    op: int = 1
    htype: int = 1
    hlen: int = 6
    hops: int = 0

    xid: int = 0

    secs: int = 0
    flags: int = 0

    ciaddr: str = "0.0.0.0"
    yiaddr: str = "0.0.0.0"
    siaddr: str = "0.0.0.0"
    giaddr: str = "0.0.0.0"

    chaddr: bytes = b"\x00" * 16

    # BOOTP fields
    sname: bytes = b"\x00" * 64
    file: bytes = b"\x00" * 128

    # DHCP options are kept as raw option bytes.
    # options.py will parse/encode them later.
    options: bytes = b""

    MAGIC_COOKIE: ClassVar[bytes] = b"\x63\x82\x53\x63"
    HEADER_FORMAT: ClassVar[str] = "!BBBBIHH4s4s4s4s16s64s128s"
    HEADER_SIZE: ClassVar[int] = 236
    MIN_PACKET_SIZE: ClassVar[int] = 240

    def __post_init__(self) -> None:
        """Validate packet fields after initialization."""

        self._validate_byte_field(
            self.chaddr,
            16,
            "chaddr",
        )

        self._validate_byte_field(
            self.sname,
            64,
            "sname",
        )

        self._validate_byte_field(
            self.file,
            128,
            "file",
        )

        self._validate_ip(
            self.ciaddr,
            "ciaddr",
        )

        self._validate_ip(
            self.yiaddr,
            "yiaddr",
        )

        self._validate_ip(
            self.siaddr,
            "siaddr",
        )

        self._validate_ip(
            self.giaddr,
            "giaddr",
        )

        if not 0 <= self.op <= 255:
            raise DHCPPacketError(
                "Invalid DHCP op field."
            )

        if not 0 <= self.htype <= 255:
            raise DHCPPacketError(
                "Invalid DHCP hardware type."
            )

        if not 0 <= self.hlen <= 255:
            raise DHCPPacketError(
                "Invalid DHCP hardware address length."
            )

        if not 0 <= self.hops <= 255:
            raise DHCPPacketError(
                "Invalid DHCP hops field."
            )

        if not 0 <= self.xid <= 0xFFFFFFFF:
            raise DHCPPacketError(
                "Invalid DHCP transaction ID."
            )

        if not 0 <= self.secs <= 0xFFFF:
            raise DHCPPacketError(
                "Invalid DHCP seconds field."
            )

        if not 0 <= self.flags <= 0xFFFF:
            raise DHCPPacketError(
                "Invalid DHCP flags field."
            )

    @staticmethod
    def _validate_byte_field(
        value: bytes,
        expected_size: int,
        field_name: str,
    ) -> None:
        """Validate a fixed-size byte field."""

        if not isinstance(value, bytes):
            raise DHCPPacketError(
                f"{field_name} must be bytes."
            )

        if len(value) != expected_size:
            raise DHCPPacketError(
                f"{field_name} must contain "
                f"exactly {expected_size} bytes."
            )

    @staticmethod
    def _validate_ip(
        value: str,
        field_name: str,
    ) -> None:
        """Validate an IPv4 address."""

        try:
            ipaddress.IPv4Address(value)

        except ValueError as exc:

            raise DHCPPacketError(
                f"Invalid IPv4 address in {field_name}: "
                f"{value}"
            ) from exc

    @staticmethod
    def _ip_to_bytes(
        address: str,
    ) -> bytes:
        """Convert an IPv4 address to packed bytes."""

        try:
            return ipaddress.IPv4Address(
                address,
            ).packed

        except ValueError as exc:

            raise DHCPPacketError(
                f"Invalid IPv4 address: {address}"
            ) from exc

    @staticmethod
    def _bytes_to_ip(
        value: bytes,
    ) -> str:
        """Convert packed IPv4 bytes to a string."""

        try:
            return str(
                ipaddress.IPv4Address(
                    value,
                )
            )

        except ipaddress.AddressValueError as exc:

            raise DHCPPacketError(
                "Invalid IPv4 address field."
            ) from exc

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
    ) -> "DHCPPacket":
        """
        Parse a raw DHCP packet.

        Raises:
            DHCPPacketError:
                If the packet is malformed or too short.
        """

        if not isinstance(data, bytes):
            raise DHCPPacketError(
                "DHCP packet must be bytes."
            )

        if len(data) < cls.MIN_PACKET_SIZE:
            raise DHCPPacketError(
                "DHCP packet is too short."
            )

        try:

            (
                op,
                htype,
                hlen,
                hops,
                xid,
                secs,
                flags,
                ciaddr,
                yiaddr,
                siaddr,
                giaddr,
                chaddr,
                sname,
                file,
            ) = struct.unpack(
                cls.HEADER_FORMAT,
                data[:cls.HEADER_SIZE],
            )

        except struct.error as exc:

            raise DHCPPacketError(
                "Unable to unpack DHCP header."
            ) from exc

        cookie = data[
            cls.HEADER_SIZE:
            cls.HEADER_SIZE + 4
        ]

        if cookie != cls.MAGIC_COOKIE:
            raise DHCPPacketError(
                "Invalid or missing DHCP magic cookie."
            )

        options = data[
            cls.HEADER_SIZE + 4:
        ]

        return cls(
            op=op,
            htype=htype,
            hlen=hlen,
            hops=hops,
            xid=xid,
            secs=secs,
            flags=flags,
            ciaddr=cls._bytes_to_ip(
                ciaddr,
            ),
            yiaddr=cls._bytes_to_ip(
                yiaddr,
            ),
            siaddr=cls._bytes_to_ip(
                siaddr,
            ),
            giaddr=cls._bytes_to_ip(
                giaddr,
            ),
            chaddr=chaddr,
            sname=sname,
            file=file,
            options=options,
        )

    def to_bytes(
        self,
    ) -> bytes:
        """
        Serialize the DHCP packet to raw bytes.
        """

        header = struct.pack(
            self.HEADER_FORMAT,

            self.op,
            self.htype,
            self.hlen,
            self.hops,

            self.xid,

            self.secs,
            self.flags,

            self._ip_to_bytes(
                self.ciaddr,
            ),

            self._ip_to_bytes(
                self.yiaddr,
            ),

            self._ip_to_bytes(
                self.siaddr,
            ),

            self._ip_to_bytes(
                self.giaddr,
            ),

            self.chaddr,

            self.sname,

            self.file,
        )

        return (
            header
            + self.MAGIC_COOKIE
            + self.options
        )

    @property
    def client_mac(self) -> str:
        """
        Return the client hardware address
        in standard MAC notation.
        """

        mac = self.chaddr[
            :self.hlen
        ]

        return ":".join(
            f"{byte:02x}"
            for byte in mac
        )

    @property
    def broadcast(self) -> bool:
        """
        Return True when the DHCP broadcast flag is set.
        """

        return bool(
            self.flags & 0x8000
        )

    def copy(
        self,
        **changes,
    ) -> "DHCPPacket":
        """
        Create a copy of the packet with selected fields changed.
        """

        values = {
            "op": self.op,
            "htype": self.htype,
            "hlen": self.hlen,
            "hops": self.hops,
            "xid": self.xid,
            "secs": self.secs,
            "flags": self.flags,
            "ciaddr": self.ciaddr,
            "yiaddr": self.yiaddr,
            "siaddr": self.siaddr,
            "giaddr": self.giaddr,
            "chaddr": self.chaddr,
            "sname": self.sname,
            "file": self.file,
            "options": self.options,
        }

        values.update(changes)

        return DHCPPacket(
            **values,
        )


__all__ = [
    "DHCPPacket",
    "DHCPPacketError",
]