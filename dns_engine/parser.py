"""
DNS Packet Parser

Responsibilities:

- Parse DNS packet headers
- Validate DNS packets
- Extract queried domain
- Support DNS name compression
- Defend against malformed packets
- Defend against compression-pointer loops
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

    MAX_POINTER_JUMPS = 32

    # DNS header flag masks.
    QR_MASK = 0x8000
    OPCODE_MASK = 0x7800
    Z_MASK = 0x0070

    # DNS opcode 0 = standard query.
    STANDARD_QUERY_OPCODE = 0

    # Internet DNS class.
    IN_CLASS = 1

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

        if size < 0:
            raise ValueError(
                "Negative packet size."
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

        Returns
        -------
        tuple[int, int, int, int, int, int]
            Transaction ID, flags, question count,
            answer count, authority count and additional count.
        """

        if not isinstance(packet, bytes):
            raise ValueError(
                "DNS packet must be bytes."
            )

        if len(packet) < self.DNS_HEADER_SIZE:
            raise ValueError(
                "Incomplete DNS header."
            )

        return struct.unpack(
            "!HHHHHH",
            packet[: self.DNS_HEADER_SIZE],
        )

    def _validate_header(
        self,
        flags: int,
        questions: int,
    ) -> None:
        """
        Validate DNS query header flags.
        """

        #
        # QR = 0 means this packet is a query.
        #
        if flags & self.QR_MASK:
            raise ValueError(
                "DNS packet is a response, not a query."
            )

        #
        # SentinelDNS currently supports only
        # standard DNS queries (opcode 0).
        #
        opcode = (
            flags & self.OPCODE_MASK
        ) >> 11

        if opcode != self.STANDARD_QUERY_OPCODE:
            raise ValueError(
                f"Unsupported DNS opcode: {opcode}"
            )

        #
        # Reserved Z bits must be zero.
        #
        if flags & self.Z_MASK:
            raise ValueError(
                "DNS reserved flag bits are set."
            )

        #
        # SentinelDNS currently supports exactly
        # one DNS question.
        #
        if questions != 1:
            raise ValueError(
                "Unsupported DNS question count: "
                f"{questions}"
            )

    def _decode_label(
        self,
        label_data: bytes,
    ) -> str:
        """
        Decode one DNS label.

        DNS labels are normally ASCII-compatible. UTF-8 is
        retained here to preserve the existing parser behavior.
        """

        try:
            return label_data.decode(
                "utf-8"
            )

        except UnicodeDecodeError as exc:
            raise ValueError(
                "Invalid DNS label encoding."
            ) from exc

    def _read_domain(
        self,
        packet: bytes,
        offset: int,
    ) -> tuple[str, int]:
        """
        Parse a DNS domain name.

        Supports normal DNS labels and DNS compression
        pointers.

        Returns
        -------
        tuple[str, int]
            Parsed domain and the packet offset immediately
            following the original encoded domain.

        Notes
        -----
        When a compression pointer is encountered, the parser
        follows the pointer to decode the remaining labels, but
        the returned packet offset remains immediately after
        the pointer in the original packet.
        """

        labels: list[str] = []

        original_offset = offset

        current_offset = offset

        jumped = False

        pointer_jumps = 0

        visited_offsets: set[int] = set()

        encoded_length = 0

        while True:

            self._require_length(
                packet,
                current_offset,
                1,
            )

            length = packet[current_offset]

            #
            # Normal DNS label.
            #
            if (length & 0xC0) == 0x00:

                current_offset += 1

                #
                # Zero-length label terminates
                # the domain name.
                #
                if length == 0:

                    if not jumped:
                        original_offset = current_offset

                    break

                if length > self.MAX_LABEL_LENGTH:
                    raise ValueError(
                        "DNS label exceeds 63 bytes."
                    )

                encoded_length += (
                    1 + length
                )

                if encoded_length > self.MAX_DOMAIN_LENGTH:
                    raise ValueError(
                        "Domain exceeds 255 bytes."
                    )

                self._require_length(
                    packet,
                    current_offset,
                    length,
                )

                label_data = packet[
                    current_offset :
                    current_offset + length
                ]

                label = self._decode_label(
                    label_data
                )

                labels.append(
                    label
                )

                current_offset += length

                continue

            #
            # DNS compression pointer.
            #
            if (length & 0xC0) == 0xC0:

                self._require_length(
                    packet,
                    current_offset,
                    2,
                )

                second_byte = packet[
                    current_offset + 1
                ]

                pointer = (
                    ((length & 0x3F) << 8)
                    | second_byte
                )

                #
                # Pointer must refer to an actual
                # position inside this packet.
                #
                if pointer >= len(packet):
                    raise ValueError(
                        "DNS compression pointer "
                        "is outside the packet."
                    )

                #
                # A pointer consumes exactly two bytes
                # in the original encoded name.
                #
                if not jumped:
                    original_offset = (
                        current_offset + 2
                    )

                pointer_jumps += 1

                if (
                    pointer_jumps
                    > self.MAX_POINTER_JUMPS
                ):
                    raise ValueError(
                        "Too many DNS compression "
                        "pointer jumps."
                    )

                #
                # Detect pointer loops.
                #
                if pointer in visited_offsets:
                    raise ValueError(
                        "DNS compression pointer loop."
                    )

                visited_offsets.add(
                    pointer
                )

                current_offset = pointer

                jumped = True

                continue

            #
            # 0x80-0xBF are reserved label encodings.
            #
            raise ValueError(
                "Invalid DNS label encoding."
            )

        domain = ".".join(
            labels
        ).lower()

        #
        # Empty QNAME is technically the root domain.
        #
        if not domain:
            domain = "."

        #
        # Final DNS wire-format name length check.
        #
        if encoded_length + 1 > self.MAX_DOMAIN_LENGTH:
            raise ValueError(
                "Domain exceeds 255 bytes."
            )

        return (
            domain,
            original_offset,
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
            If the packet is malformed or unsupported.
        """

        if not isinstance(packet, bytes):
            raise ValueError(
                "DNS packet must be bytes."
            )

        (
            transaction_id,
            flags,
            questions,
            answers,
            authority,
            additional,
        ) = self._read_header(
            packet
        )

        self._validate_header(
            flags,
            questions,
        )

        offset = self.DNS_HEADER_SIZE

        #
        # Parse QNAME.
        #
        domain, offset = self._read_domain(
            packet,
            offset,
        )

        #
        # Read QTYPE + QCLASS.
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
        if query_class != self.IN_CLASS:
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