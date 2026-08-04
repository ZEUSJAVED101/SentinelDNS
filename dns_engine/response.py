"""
DNS Response Builder

Responsibilities:
- Build DNS responses
- Build NXDOMAIN responses
- Build FORMERR responses
- Build SERVFAIL responses
"""

from __future__ import annotations

from dnslib import DNSRecord, RCODE


class DNSResponseBuilder:
    """
    Builds DNS response packets.
    """

    @staticmethod
    def _build_response(
        packet: bytes,
        rcode: int,
    ) -> bytes:
        """
        Build a DNS response with the specified response code.
        """

        request = DNSRecord.parse(packet)

        reply = request.reply()

        reply.header.rcode = rcode

        return bytes(reply.pack())

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
        """

        return DNSResponseBuilder._build_response(
            packet,
            RCODE.SERVFAIL,
        )