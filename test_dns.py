"""
SentinelDNS DNS Test Client

Sends a raw DNS query to SentinelDNS and prints the response.
"""

from __future__ import annotations

import socket


def build_dns_query(domain: str) -> bytes:
    """
    Build a simple DNS A-record query.
    """

    transaction_id = b"\x12\x34"
    flags = b"\x01\x00"
    questions = b"\x00\x01"
    answers = b"\x00\x00"
    authority = b"\x00\x00"
    additional = b"\x00\x00"

    header = (
        transaction_id
        + flags
        + questions
        + answers
        + authority
        + additional
    )

    question = b""

    for label in domain.split("."):
        question += bytes([len(label)])
        question += label.encode()

    question += b"\x00"

    query_type = b"\x00\x01"      # A Record
    query_class = b"\x00\x01"     # Internet

    return header + question + query_type + query_class


def main() -> None:

    query = build_dns_query("doubleclick.net")

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
    )

    sock.settimeout(5)

    sock.sendto(
        query,
        (
            "127.0.0.1",
            5300,
        ),
    )

    response, _ = sock.recvfrom(4096)

    print("\n==============================")
    print("Response Received")
    print("==============================")
    print(f"Response Size : {len(response)} bytes")
    print(f"Transaction ID: {response[:2].hex()}")


if __name__ == "__main__":
    main()