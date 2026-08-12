"""
SentinelDNS Cache Hit Test

Run:
    python test_cache_hit.py

Prerequisite:
    SentinelDNS must be running on 127.0.0.1:53.

This test sends the same DNS query twice.
Expected:
    1st query -> cache MISS
    2nd query -> cache HIT

It also reads /api/dashboard/ and verifies the cache counters.
"""

from __future__ import annotations

import json
import sys
import time
from urllib.request import Request, urlopen

import dns.message
import dns.query


DNS_SERVER = "127.0.0.1"
DNS_PORT = 53
DOMAIN = "example.com"
API_URL = "http://127.0.0.1:8000/api/dashboard/"


def dashboard() -> dict:
    request = Request(
        API_URL,
        headers={"Accept": "application/json"},
        method="GET",
    )

    with urlopen(request, timeout=5) as response:
        if response.status != 200:
            raise RuntimeError(
                f"Dashboard API returned HTTP {response.status}"
            )

        return json.loads(
            response.read().decode("utf-8")
        )


def query(domain: str) -> None:
    packet = dns.message.make_query(
        domain,
        "A",
    )

    response = dns.query.udp(
        packet,
        DNS_SERVER,
        port=DNS_PORT,
        timeout=5,
    )

    if response.rcode() != 0:
        raise RuntimeError(
            f"DNS query failed with RCODE "
            f"{response.rcode()}"
        )


def main() -> int:
    print("=" * 50)
    print(" SentinelDNS CACHE HIT TEST")
    print("=" * 50)
    print(f"DNS server : {DNS_SERVER}:{DNS_PORT}")
    print(f"Domain     : {DOMAIN}")
    print()

    try:
        before = dashboard()["metrics"]
    except Exception as exc:
        print(f"[FAIL] Dashboard API unavailable: {exc}")
        return 1

    before_hits = int(before.get("cache_hits", 0))
    before_misses = int(before.get("cache_misses", 0))

    print(
        f"Before: hits={before_hits}, "
        f"misses={before_misses}"
    )

    print()
    print("[1] Sending first query...")

    try:
        query(DOMAIN)
    except Exception as exc:
        print(f"[FAIL] First DNS query failed: {exc}")
        return 1

    time.sleep(0.2)

    print("[2] Sending identical query...")

    try:
        query(DOMAIN)
    except Exception as exc:
        print(f"[FAIL] Second DNS query failed: {exc}")
        return 1

    time.sleep(0.2)

    try:
        after = dashboard()["metrics"]
        cache = dashboard()["cache"]
    except Exception as exc:
        print(f"[FAIL] Could not read dashboard metrics: {exc}")
        return 1

    after_hits = int(after.get("cache_hits", 0))
    after_misses = int(after.get("cache_misses", 0))

    print()
    print(
        f"After : hits={after_hits}, "
        f"misses={after_misses}"
    )

    print()
    print("-" * 50)

    hit_delta = after_hits - before_hits
    miss_delta = after_misses - before_misses

    if hit_delta >= 1:
        print("[PASS] Cache HIT was recorded.")

    else:
        print("[FAIL] No cache HIT was recorded.")
        print()
        print("Dashboard response:")
        print(json.dumps(cache, indent=2))
        return 1

    if miss_delta >= 1:
        print("[PASS] Initial cache MISS was recorded.")
    else:
        print(
            "[WARN] No new MISS was recorded. "
            "The first query may already have been cached."
        )

    print()
    print(
        f"Cache size : {cache.get('size', 0)}"
    )
    print(
        f"Hit ratio  : {cache.get('hit_ratio', 0.0):.2%}"
    )

    print("-" * 50)
    print("CACHE TEST PASSED")
    print("-" * 50)

    return 0


if __name__ == "__main__":
    sys.exit(main())
