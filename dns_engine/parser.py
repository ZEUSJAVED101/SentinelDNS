"""
DNS Packet Parser

Responsibilities:
- Parse DNS packet headers
- Extract queried domain name
"""

from __future__ import annotations

import struct


class DNSParser:
    """
    Simple DNS packet parser.
    """

    def parse(self, packet: bytes) -> dict:
        """
        Parse a DNS query packet.

        Returns:
            Dictionary containing DNS header information and domain.
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
        ) = struct.unpack("!HHHHHH", packet[:12])

        offset = 12

        labels = []

        while True:

            length = packet[offset]

            if length == 0:
                offset += 1
                break

            offset += 1

            label = packet[offset : offset + length].decode("utf-8")

            labels.append(label)

            offset += length

        domain = ".".join(labels)

        query_type, query_class = struct.unpack(
            "!HH",
            packet[offset : offset + 4],
        )

        return {
            "transaction_id": transaction_id,
            "flags": flags,
            "questions": questions,
            "answers": answers,
            "authority": authority,
            "additional": additional,
            "domain": domain,
            "query_type": query_type,
            "query_class": query_class,
        }