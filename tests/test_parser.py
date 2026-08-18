import struct
from typing import cast

import pytest

from dns_engine.parser import DNSParser


def make_query(
    domain: str = "example.com",
    query_type: int = 1,
    query_class: int = 1,
    transaction_id: int = 0x1234,
    flags: int = 0x0100,
) -> bytes:
    """
    Build a minimal DNS query packet.
    """

    labels = domain.split(".")

    qname = b"".join(
        bytes([len(label)])
        + label.encode("ascii")
        for label in labels
    ) + b"\x00"

    header = struct.pack(
        "!HHHHHH",
        transaction_id,
        flags,
        1,
        0,
        0,
        0,
    )

    question = struct.pack(
        "!HH",
        query_type,
        query_class,
    )

    return header + qname + question


def test_parse_standard_query():
    parser = DNSParser()

    packet = make_query(
        domain="example.com",
        query_type=1,
        query_class=1,
    )

    query = parser.parse(packet)

    assert query.transaction_id == 0x1234
    assert query.domain == "example.com"
    assert query.query_type == 1
    assert query.query_class == 1
    assert query.questions == 1


def test_domain_is_normalized_to_lowercase():
    parser = DNSParser()

    packet = make_query(
        domain="Example.COM",
    )

    query = parser.parse(packet)

    assert query.domain == "example.com"


def test_parser_rejects_non_bytes():
    parser = DNSParser()

    with pytest.raises(
        ValueError,
        match="DNS packet must be bytes",
    ):
                parser.parse(
            cast(bytes, "not bytes"),
        )


def test_parser_rejects_incomplete_header():
    parser = DNSParser()

    with pytest.raises(
        ValueError,
        match="Incomplete DNS header",
    ):
        parser.parse(b"\x00" * 11)


def test_parser_rejects_response_packet():
    parser = DNSParser()

    packet = make_query(
        flags=0x8100,
    )

    with pytest.raises(
        ValueError,
        match="response, not a query",
    ):
        parser.parse(packet)


def test_parser_rejects_unsupported_opcode():
    parser = DNSParser()

    # Opcode 1 = inverse query.
    packet = make_query(
        flags=0x0900,
    )

    with pytest.raises(
        ValueError,
        match="Unsupported DNS opcode",
    ):
        parser.parse(packet)


def test_parser_rejects_reserved_z_bits():
    parser = DNSParser()

    packet = make_query(
        flags=0x0140,
    )

    with pytest.raises(
        ValueError,
        match="reserved flag bits",
    ):
        parser.parse(packet)


def test_parser_rejects_zero_questions():
    parser = DNSParser()

    header = struct.pack(
        "!HHHHHH",
        0x1234,
        0x0100,
        0,
        0,
        0,
        0,
    )

    with pytest.raises(
        ValueError,
        match="Unsupported DNS question count",
    ):
        parser.parse(header)


def test_parser_rejects_multiple_questions():
    parser = DNSParser()

    header = struct.pack(
        "!HHHHHH",
        0x1234,
        0x0100,
        2,
        0,
        0,
        0,
    )

    with pytest.raises(
        ValueError,
        match="Unsupported DNS question count",
    ):
        parser.parse(header)


def test_parser_rejects_unsupported_dns_class():
    parser = DNSParser()

    packet = make_query(
        query_class=3,
    )

    with pytest.raises(
        ValueError,
        match="Unsupported DNS class",
    ):
        parser.parse(packet)


def test_parser_rejects_truncated_domain():
    parser = DNSParser()

    header = struct.pack(
        "!HHHHHH",
        0x1234,
        0x0100,
        1,
        0,
        0,
        0,
    )

    # Label says 10 bytes are coming, but only 3 exist.
    malformed_qname = b"\x0aabc"

    packet = header + malformed_qname

    with pytest.raises(
        ValueError,
        match="Malformed DNS packet",
    ):
        parser.parse(packet)


def test_parser_rejects_invalid_label_encoding():
    parser = DNSParser()

    header = struct.pack(
        "!HHHHHH",
        0x1234,
        0x0100,
        1,
        0,
        0,
        0,
    )

    qname = (
        b"\x02"
        + b"\xff\xff"
        + b"\x00"
    )

    question = struct.pack(
        "!HH",
        1,
        1,
    )

    packet = header + qname + question

    with pytest.raises(
        ValueError,
        match="Invalid DNS label encoding",
    ):
        parser.parse(packet)


def test_parser_rejects_out_of_bounds_compression_pointer():
    parser = DNSParser()

    header = struct.pack(
        "!HHHHHH",
        0x1234,
        0x0100,
        1,
        0,
        0,
        0,
    )

    # Pointer to byte 200, which is outside this packet.
    qname = b"\xc0\xc8"

    question = struct.pack(
        "!HH",
        1,
        1,
    )

    packet = header + qname + question

    with pytest.raises(
        ValueError,
        match="outside the packet",
    ):
        parser.parse(packet)


def test_parser_rejects_compression_pointer_loop():
    parser = DNSParser()

    header = struct.pack(
        "!HHHHHH",
        0x1234,
        0x0100,
        1,
        0,
        0,
        0,
    )

    # Pointer points back to itself.
    qname = b"\xc0\x0c"

    question = struct.pack(
        "!HH",
        1,
        1,
    )

    packet = header + qname + question

    with pytest.raises(
        ValueError,
        match="compression pointer loop",
    ):
        parser.parse(packet)


def test_parser_supports_compression_pointer():
    parser = DNSParser()

    header = struct.pack(
        "!HHHHHH",
        0x4321,
        0x0100,
        1,
        0,
        0,
        0,
    )

    # Put the real domain at offset 12.
    base_name = (
        b"\x07example"
        b"\x03com"
        b"\x00"
    )

    # The question will use a compression pointer.
    # Offset 12 is the beginning of "example.com".
    compressed_name = b"\xc0\x0c"

    question = struct.pack(
        "!HH",
        1,
        1,
    )

    # The parser expects the QNAME immediately after
    # the 12-byte DNS header, so we need the actual
    # domain at another valid offset and point to it.
    #
    # Header = offsets 0-11
    # QNAME    = offsets 12-13
    # QTYPE    = offsets 14-15
    # QCLASS   = offsets 16-17
    # Base name starts at offset 18.

    base_offset = 18

    compressed_name = bytes([
        0xC0 | ((base_offset >> 8) & 0x3F),
        base_offset & 0xFF,
    ])

    packet = (
        header
        + compressed_name
        + question
        + base_name
    )

    query = parser.parse(packet)

    assert query.domain == "example.com"
    assert query.query_type == 1
    assert query.query_class == 1