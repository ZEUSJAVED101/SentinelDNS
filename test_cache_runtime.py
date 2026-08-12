"""
SentinelDNS Cache Runtime Test

Run:
    python test_cache_runtime.py

This test uses two different domains to demonstrate:
    - first request is a MISS
    - repeated request is a HIT
    - different domain is a MISS

Requires:
    pip install dnspython
    SentinelDNS running on 127.0.0.1:53
    Dashboard API running on 127.0.0.1:8000
"""

from __future__ import annotations

import json
import sys
import time
from urllib.request import Request, urlopen

import dns.message
import dns.query


SERVER = "127.0.0.1"
PORT = 53
API = "http://127.0.0.1:8000/api/dashboard/"


def get_metrics() -> dict:
    request = Request(
        API,
        headers={"Accept": "application/json"},
    )

    with urlopen(request, timeout=5) as response:
        if response.status != 200:
            raise RuntimeError(
                f"API returned HTTP {response.status}"
            )

        return json.loads(
            response.read().decode("utf-8")
        )


def dns_query(domain: str) -> None:
    request = dns.message.make_query(
        domain,
        "A",
    )

    response = dns.query.udp(
        request,
        SERVER,
        port=PORT,
        timeout=5,
    )

    if response.rcode() != 0:
        raise RuntimeError(
            f"{domain}: DNS RCODE={response.rcode()}"
        )


def main() -> int:
    domains = [
        "example.com",
        "example.com",
        "google.com",
        "google.com",
    ]

    print("=" * 60)
    print(" SentinelDNS CACHE RUNTIME TEST")
    print("=" * 60)

    try:
        before = get_metrics()
    except Exception as exc:
        print(f"[FAIL] Cannot reach dashboard API: {exc}")
        return 1

    before_metrics = before["metrics"]

    initial_hits = int(
        before_metrics.get("cache_hits", 0)
    )

    initial_misses = int(
        before_metrics.get("cache_misses", 0)
    )

    print(
        f"Initial cache hits  : {initial_hits}"
    )
    print(
        f"Initial cache misses: {initial_misses}"
    )
    print()

    for number, domain in enumerate(domains, 1):
        print(
            f"[{number}/{len(domains)}] "
            f"Querying {domain}"
        )

        try:
            dns_query(domain)
        except Exception as exc:
            print(f"[FAIL] {exc}")
            return 1

        time.sleep(0.15)

    try:
        after = get_metrics()
    except Exception as exc:
        print(f"[FAIL] Cannot read dashboard API: {exc}")
        return 1

    metrics = after["metrics"]
    cache = after["cache"]

    final_hits = int(
        metrics.get("cache_hits", 0)
    )

    final_misses = int(
        metrics.get("cache_misses", 0)
    )

    hit_delta = final_hits - initial_hits
    miss_delta = final_misses - initial_misses

    print()
    print("-" * 60)
    print(f"New cache hits  : {hit_delta}")
    print(f"New cache misses: {miss_delta}")
    print(f"Cache size      : {cache.get('size', 0)}")
    print(
        f"Hit ratio       : "
        f"{float(cache.get('hit_ratio', 0.0)):.2%}"
    )
    print("-" * 60)

    if hit_delta < 2:
        print(
            "[FAIL] Expected at least 2 cache hits "
            "from repeated domains."
        )
        return 1

    if miss_delta < 2:
        print(
            "[WARN] Expected at least 2 misses "
            "for the first occurrence of each domain."
        )

    print()
    print("CACHE RUNTIME TEST PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
