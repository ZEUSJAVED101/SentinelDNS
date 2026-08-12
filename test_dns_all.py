import struct

from dns_engine.resolver import DNSResolver
from dns_engine.doh.client import DoHClient
from dns_engine.doh.provider import get_provider
from dns_engine.dot.client import DoTClient
from backend.core.config import settings


def make_query(
    transaction_id: int,
    domain: str = "example.com",
) -> bytes:

    header = struct.pack(
        "!HHHHHH",
        transaction_id,
        0x0100,
        1,
        0,
        0,
        0,
    )

    qname = b"".join(
        bytes([len(part)])
        + part.encode()
        for part in domain.split(".")
    ) + b"\x00"

    question = struct.pack(
        "!HH",
        1,
        1,
    )

    return header + qname + question


def rcode(response: bytes) -> int:
    return int.from_bytes(
        response[2:4],
        "big",
    ) & 0x0F


def check(name: str, condition: bool) -> None:

    print(
        f"{name:<28}"
        f"{'PASS' if condition else 'FAIL'}"
    )

    if not condition:
        raise AssertionError(
            f"{name} failed"
        )


print()
print("=" * 60)
print("        SENTINELDNS COMPLETE DNS TEST")
print("=" * 60)


# ==========================================================
# 1. Resolver initialization
# ==========================================================

resolver = DNSResolver()

check(
    "Resolver initialization",
    resolver is not None,
)

print()


# ==========================================================
# 2. Normal DNS resolution
# ==========================================================

print("[1] NORMAL DNS RESOLUTION")

packet = make_query(
    0x1001,
    "example.com",
)

response = resolver.resolve(
    packet,
)

print(
    "RCODE:",
    rcode(response),
)

check(
    "Normal DNS",
    rcode(response) == 0,
)

print()


# ==========================================================
# 3. Cache HIT
# ==========================================================

print("[2] CACHE HIT")

response2 = resolver.resolve(
    packet,
)

metrics = resolver.metrics.as_dict()

print(
    "CACHE HITS:",
    metrics["cache_hits"],
)

check(
    "Cache HIT",
    metrics["cache_hits"] >= 1,
)

check(
    "Cache response valid",
    rcode(response2) == 0,
)

print()


# ==========================================================
# 4. MALFORMED PACKET → FORMERR
# ==========================================================

print("[3] MALFORMED PACKET → FORMERR")

malformed = b"\x12\x34\x01"

response = resolver.resolve(
    malformed,
)

print(
    "RCODE:",
    rcode(response),
)

check(
    "FORMERR",
    rcode(response) == 1,
)

print()


# ==========================================================
# 5. ADVERTISEMENT BLOCKING → NXDOMAIN
# ==========================================================

print("[4] ADVERTISEMENT BLOCKING → NXDOMAIN")

blocked_domain = (
    "ad1.api.ero-advertising.com"
)

blocked_packet = make_query(
    0x1002,
    blocked_domain,
)

response = resolver.resolve(
    blocked_packet,
)

print(
    "DOMAIN:",
    blocked_domain,
)

print(
    "RCODE:",
    rcode(response),
)

check(
    "AdBlock NXDOMAIN",
    rcode(response) == 3,
)

print()


# ==========================================================
# 6. METRICS
# ==========================================================

print("[5] METRICS")

metrics = resolver.metrics.as_dict()

print(
    "TOTAL QUERIES:",
    metrics["total_queries"],
)

print(
    "ALLOWED:",
    metrics["allowed_queries"],
)

print(
    "BLOCKED:",
    metrics["blocked_queries"],
)

print(
    "CACHE HITS:",
    metrics["cache_hits"],
)

print(
    "CACHE MISSES:",
    metrics["cache_misses"],
)

print(
    "UPSTREAM SUCCESS:",
    metrics["upstream_success"],
)

print(
    "UPSTREAM FAILURES:",
    metrics["upstream_failures"],
)

print(
    "FORMERR:",
    metrics["formerr"],
)

print(
    "NXDOMAIN:",
    metrics["nxdomain"],
)

print(
    "SERVFAIL:",
    metrics["servfail"],
)

print(
    "NOERROR:",
    metrics["noerror"],
)

print(
    "AVERAGE LATENCY:",
    metrics["average_latency_ms"],
    "ms",
)

check(
    "Metrics collected",
    metrics["total_queries"] >= 4,
)

check(
    "Blocked metric",
    metrics["blocked_queries"] >= 1,
)

check(
    "FORMERR metric",
    metrics["formerr"] >= 1,
)

check(
    "NXDOMAIN metric",
    metrics["nxdomain"] >= 1,
)

print()


# ==========================================================
# 7. DoT integration
# ==========================================================

print("[6] DNS-OVER-TLS")

if settings.dns.dot.enabled:

    dot = DoTClient(
        server=settings.dns.dot.server,
        port=settings.dns.dot.port,
        timeout=settings.dns.dot.timeout,
    )

    dot_packet = make_query(
        0x2001,
        "example.com",
    )

    dot_response = dot.query(
        dot_packet,
    )

    print(
        "TRANSACTION ID:",
        hex(
            int.from_bytes(
                dot_response[:2],
                "big",
            )
        ),
    )

    print(
        "RCODE:",
        rcode(dot_response),
    )

    check(
        "DoT",
        (
            int.from_bytes(
                dot_response[:2],
                "big",
            )
            == 0x2001
            and rcode(dot_response) == 0
        ),
    )

else:

    print(
        "DoT disabled - SKIPPED"
    )

print()


# ==========================================================
# 8. DoH integration
# ==========================================================

print("[7] DNS-OVER-HTTPS")

if settings.dns.doh.enabled:

    provider = get_provider(
        settings.dns.doh.provider,
    )

    doh = DoHClient(
        provider,
    )

    doh_packet = make_query(
        0x3001,
        "example.com",
    )

    try:

        doh_response = doh.query(
            doh_packet,
        )

        print(
            "TRANSACTION ID:",
            hex(
                int.from_bytes(
                    doh_response[:2],
                    "big",
                )
            ),
        )

        print(
            "RCODE:",
            rcode(doh_response),
        )

        check(
            "DoH",
            (
                int.from_bytes(
                    doh_response[:2],
                    "big",
                )
                == 0x3001
                and rcode(doh_response) == 0
            ),
        )

    finally:

        doh.close()

else:

    print(
        "DoH disabled - SKIPPED"
    )

print()


# ==========================================================
# FINAL
# ==========================================================

print("=" * 60)
print("        SENTINELDNS TEST SUMMARY")
print("=" * 60)

print()
print("Normal DNS             PASS")
print("Cache HIT              PASS")
print("FORMERR                PASS")
print("AdBlock NXDOMAIN       PASS")
print("Metrics                PASS")

if settings.dns.dot.enabled:
    print("DoT                    PASS")

if settings.dns.doh.enabled:
    print("DoH                    PASS")

print()
print("# SENTINELDNS DNS ENGINE: ALL TESTS PASS")
print()