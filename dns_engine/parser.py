"""
DNS Packet Parser

Responsibilities:
- Parse DNS packet headers
- Validate DNS packets
- Extract queried domain
- Defend against malformed packets
"""

from __future__ import annotations

import struct

from dns_engine.models import DNSQuery


class DNSParser:
    """
    Parses raw DNS query packets safely.

    This parser performs strict bounds checking before reading
    packet data to protect the DNS engine against malformed or
    intentionally crafted packets.
    """

    DNS_HEADER_SIZE = 12

    MAX_LABEL_LENGTH = 63

    MAX_DOMAIN_LENGTH = 255

    def _require_length(
        self,
        packet: bytes,
        offset: int,
        size: int,
    ) -> None:
        """
        Ensure that 'size' bytes can be read starting at 'offset'.
        """

        if offset < 0:

            raise ValueError(
                "Negative packet offset."
            )

        if offset + size > len(packet):

            raise ValueError(
                "Malformed DNS packet."
            )

    def _read_header(
        self,
        packet: bytes,
    ) -> tuple[int, int, int, int, int, int]:
        """
        Parse the DNS header.
        """

        if len(packet) < self.DNS_HEADER_SIZE:

            raise ValueError(
                "Incomplete DNS header."
            )

        return struct.unpack(
            "!HHHHHH",
            packet[: self.DNS_HEADER_SIZE],
        )

    def _read_domain(
        self,
        packet: bytes,
        offset: int,
    ) -> tuple[str, int]:
        """
        Parse the queried domain.

        Returns
        -------
        tuple[str, int]
            Parsed domain and the new packet offset.
        """

        labels: list[str] = []

        total_length = 0

        while True:

            self._require_length(
                packet,
                offset,
                1,
            )

            length = packet[offset]

            offset += 1

            if length == 0:

                break

            if length > self.MAX_LABEL_LENGTH:

                raise ValueError(
                    "DNS label exceeds 63 bytes."
                )

            self._require_length(
                packet,
                offset,
                length,
            )

            try:

                label = packet[
                    offset : offset + length
                ].decode(
                    "utf-8",
                )

            except UnicodeDecodeError as exc:

                raise ValueError(
                    "Invalid DNS label encoding."
                ) from exc

            labels.append(
                label,
            )

            total_length += length + 1

            if total_length > self.MAX_DOMAIN_LENGTH:

                raise ValueError(
                    "Domain exceeds 255 bytes."
                )

            offset += length

        return (
            ".".join(labels).lower(),
            offset,
        )
    def parse(
        self,
        packet: bytes,
    ) -> DNSQuery:
        """
        Safely parse a DNS query packet.

        Raises
        ------
        ValueError
            If the packet is malformed.
        """

        (
            transaction_id,
            flags,
            questions,
            answers,
            authority,
            additional,
        ) = self._read_header(
            packet,
        )

        #
        # SentinelDNS currently supports
        # exactly one DNS question.
        #
        if questions != 1:

            raise ValueError(
                f"Unsupported DNS question count: {questions}"
            )

        offset = self.DNS_HEADER_SIZE

        domain, offset = self._read_domain(
            packet,
            offset,
        )

        #
        # Read Query Type + Query Class
        #
        self._require_length(
            packet,
            offset,
            4,
        )

        (
            query_type,
            query_class,
        ) = struct.unpack(
            "!HH",
            packet[
                offset : offset + 4
            ],
        )

        #
        # Only Internet class is supported.
        #
        if query_class != 1:

            raise ValueError(
                "Unsupported DNS class."
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