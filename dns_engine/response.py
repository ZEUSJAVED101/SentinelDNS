"""
DNS Response Builder

Responsibilities:
- Build DNS responses
- Build NXDOMAIN responses
"""

from __future__ import annotations

from dnslib import DNSRecord, RCODE


class DNSResponseBuilder:
    """
    Builds DNS response packets.
    """

    @staticmethod
    def nxdomain(
        packet: bytes,
    ) -> bytes:
        """
        Build a valid NXDOMAIN response.
        """

        request = DNSRecord.parse(packet)

        reply = request.reply()

        reply.header.rcode = RCODE.NXDOMAIN

        return bytes(reply.pack())