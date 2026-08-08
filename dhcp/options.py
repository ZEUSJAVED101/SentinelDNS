"""
SentinelDNS DHCP Options Module

Responsibilities:
- Parse DHCP options
- Encode DHCP options
- Provide named DHCP option constants
- Safely retrieve option values

This module does not:
- Allocate IP addresses
- Manage leases
- Handle sockets
- Run the DHCP server
"""

from __future__ import annotations

from dataclasses import dataclass


class DHCPOptionError(ValueError):
    """Raised when a DHCP option is malformed."""


class DHCPOptionCode:
    """Standard DHCP option codes used by SentinelDNS."""

    SUBNET_MASK = 1
    ROUTER = 3
    DNS_SERVER = 6
    HOSTNAME = 12
    DOMAIN_NAME = 15
    BROADCAST_ADDRESS = 28

    REQUESTED_IP = 50
    LEASE_TIME = 51

    MESSAGE_TYPE = 53
    SERVER_IDENTIFIER = 54

    PARAMETER_REQUEST_LIST = 55

    MESSAGE = 56

    MAX_MESSAGE_SIZE = 57

    RENEWAL_TIME = 58
    REBINDING_TIME = 59

    CLIENT_IDENTIFIER = 61

    END = 255


@dataclass(frozen=True)
class DHCPOption:
    """
    Represents a single DHCP option.
    """

    code: int
    value: bytes

    def __post_init__(self) -> None:
        if not 0 <= self.code <= 255:
            raise DHCPOptionError(
                "DHCP option code must be between 0 and 255."
            )

        if not isinstance(self.value, bytes):
            raise DHCPOptionError(
                "DHCP option value must be bytes."
            )

        if len(self.value) > 255:
            raise DHCPOptionError(
                "DHCP option value cannot exceed 255 bytes."
            )

    def to_bytes(self) -> bytes:
        """
        Encode the option using the DHCP TLV format.
        """

        return bytes(
            (
                self.code,
                len(self.value),
            )
        ) + self.value


def parse_options(
    data: bytes,
) -> list[DHCPOption]:
    """
    Parse a raw DHCP options field.

    PAD options are ignored.

    END terminates option parsing.

    Raises:
        DHCPOptionError:
            If an option is malformed.
    """

    if not isinstance(data, bytes):
        raise DHCPOptionError(
            "DHCP options must be bytes."
        )

    options: list[DHCPOption] = []

    offset = 0
    length = len(data)

    while offset < length:

        code = data[offset]

        offset += 1

        # PAD option.
        if code == 0:
            continue

        # END option.
        if code == DHCPOptionCode.END:
            break

        if offset >= length:
            raise DHCPOptionError(
                "DHCP option is missing its length field."
            )

        option_length = data[offset]

        offset += 1

        end = offset + option_length

        if end > length:
            raise DHCPOptionError(
                "DHCP option extends beyond packet boundary."
            )

        value = data[
            offset:end
        ]

        options.append(
            DHCPOption(
                code=code,
                value=value,
            )
        )

        offset = end

    return options


def encode_options(
    options: list[DHCPOption],
    *,
    add_end: bool = True,
) -> bytes:
    """
    Encode DHCP options into their wire representation.
    """

    if not isinstance(options, list):
        raise DHCPOptionError(
            "options must be a list."
        )

    encoded = bytearray()

    for option in options:

        if not isinstance(
            option,
            DHCPOption,
        ):
            raise DHCPOptionError(
                "All items must be DHCPOption objects."
            )

        encoded.extend(
            option.to_bytes()
        )

    if add_end:
        encoded.append(
            DHCPOptionCode.END
        )

    return bytes(encoded)


def get_option(
    options: list[DHCPOption],
    code: int,
) -> DHCPOption | None:
    """
    Return the first option matching the requested code.
    """

    for option in options:

        if option.code == code:
            return option

    return None


def get_option_value(
    options: list[DHCPOption],
    code: int,
) -> bytes | None:
    """
    Return the raw value of the requested option.
    """

    option = get_option(
        options,
        code,
    )

    if option is None:
        return None

    return option.value


def get_message_type(
    options: list[DHCPOption],
) -> int | None:
    """
    Return the DHCP message type.

    DHCP message type option (53) contains
    exactly one byte.
    """

    value = get_option_value(
        options,
        DHCPOptionCode.MESSAGE_TYPE,
    )

    if value is None:
        return None

    if len(value) != 1:
        raise DHCPOptionError(
            "Invalid DHCP message type option."
        )

    return value[0]


def make_message_type(
    message_type: int,
) -> DHCPOption:
    """
    Create a DHCP message type option.
    """

    if not 1 <= message_type <= 255:
        raise DHCPOptionError(
            "Invalid DHCP message type."
        )

    return DHCPOption(
        code=DHCPOptionCode.MESSAGE_TYPE,
        value=bytes((message_type,)),
    )


__all__ = [
    "DHCPOption",
    "DHCPOptionCode",
    "DHCPOptionError",
    "encode_options",
    "get_message_type",
    "get_option",
    "get_option_value",
    "make_message_type",
    "parse_options",
]