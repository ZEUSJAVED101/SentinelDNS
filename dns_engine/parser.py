"""
DNS Packet Parser

Responsibilities:
- Parse DNS packet headers
- Extract queried domain
"""

from __future__ import annotations

import struct

from dns_engine.models import DNSQuery


class DNSParser:
    """
    Parses raw DNS packets.
    """

    def parse(
        self,
        packet: bytes,
    ) -> DNSQuery:
        """
        Parse a DNS query packet.
        """

        if len(packet) < 12:
            raise ValueError("Invalid DNS packet.")

        (
            transaction_id,
            flags,
            questions,
            answers,
            authority,
            additional,
        ) = struct.unpack(
            "!HHHHHH",
            packet[:12],
        )

        offset = 12

        labels = []

        while True:

            length = packet[offset]

            if length == 0:
                offset += 1
                break

            offset += 1

            labels.append(
                packet[offset : offset + length].decode("utf-8")
            )

            offset += length

        domain = ".".join(labels)

        query_type, query_class = struct.unpack(
            "!HH",
            packet[offset : offset + 4],
        )

        return DNSQuery(
            transaction_id=transaction_id,
            flags=flags,
            questions=questions,
            answers=answers,
            authority=authority,
            additional=additional,
            domain=domain,
            query_type=query_type,
            query_class=query_class,
        )