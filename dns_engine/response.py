"""
DNS Response Builder

Responsibilities:

- Build DNS responses
- Build NXDOMAIN responses
- Build FORMERR responses
- Build SERVFAIL responses
- Safely handle malformed DNS requests
"""

from __future__ import annotations

import struct

from dnslib import DNSRecord, RCODE
from dnslib.dns import DNSError


class DNSResponseBuilder:
    """
    Builds DNS response packets safely.
    """

    DNS_HEADER_SIZE = 12

    QR_MASK = 0x8000

    RCODE_MASK = 0x000F

    @staticmethod
    def _transaction_id(
        packet: bytes,
    ) -> int:
        """
        Extract the DNS transaction ID.

        If the packet is too short to contain a complete
        transaction ID, return zero.
        """

        if not isinstance(packet, bytes):
            return 0

        if len(packet) < 2:
            return 0

        return struct.unpack(
            "!H",
            packet[:2],
        )[0]

    @staticmethod
    def _minimal_error_response(
        packet: bytes,
        rcode: int,
    ) -> bytes:
        """
        Build a minimal DNS error response without parsing
        the complete request.

        This is used when the incoming packet is too malformed
        for dnslib to parse safely.
        """

        transaction_id = (
            DNSResponseBuilder._transaction_id(
                packet
            )
        )

        #
        # Set QR=1 and preserve the response code.
        #
        flags = (
            DNSResponseBuilder.QR_MASK
            | (rcode & DNSResponseBuilder.RCODE_MASK)
        )

        return struct.pack(
            "!HHHHHH",
            transaction_id,
            flags,
            0,
            0,
            0,
            0,
        )

    @staticmethod
    def _build_response(
        packet: bytes,
        rcode: int,
    ) -> bytes:
        """
        Build a DNS response with the specified response code.

        For a valid DNS request, the original question section
        is preserved through dnslib.

        For a malformed request that cannot be parsed, a minimal
        valid DNS error response is returned instead.
        """

        if not isinstance(packet, bytes):
            return DNSResponseBuilder._minimal_error_response(
                b"",
                rcode,
            )

        #
        # A packet shorter than the DNS header cannot be parsed.
        #
        if len(packet) < DNSResponseBuilder.DNS_HEADER_SIZE:
            return DNSResponseBuilder._minimal_error_response(
                packet,
                rcode,
            )

        try:

            request = DNSRecord.parse(
                packet
            )

            reply = request.reply()

            #
            # Ensure this is explicitly a response.
            #
            reply.header.qr = 1

            #
            # Set the requested DNS response code.
            #
            reply.header.rcode = rcode

            return bytes(
                reply.pack()
            )

        except (
            DNSError,
            BufferError,
            ValueError,
            IndexError,
        ):

            #
            # The request could not be parsed. Never allow the
            # error-response builder itself to crash the DNS
            # resolver.
            #
            return DNSResponseBuilder._minimal_error_response(
                packet,
                rcode,
            )

    @staticmethod
    def nxdomain(
        packet: bytes,
    ) -> bytes:
        """
        Build a valid NXDOMAIN response.
        """

        return DNSResponseBuilder._build_response(
            packet,
            RCODE.NXDOMAIN,
        )

    @staticmethod
    def formerr(
        packet: bytes,
    ) -> bytes:
        """
        Build a DNS Format Error response.

        This method is safe even when the incoming packet
        is severely malformed.
        """

        return DNSResponseBuilder._build_response(
            packet,
            RCODE.FORMERR,
        )

    @staticmethod
    def servfail(
        packet: bytes,
    ) -> bytes:
        """
        Build a DNS Server Failure response.

        This method is safe even when the incoming packet
        is severely malformed.
        """

        return DNSResponseBuilder._build_response(
            packet,
            RCODE.SERVFAIL,
        )