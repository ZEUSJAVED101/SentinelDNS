from dns_engine.cache import DNSCache
from dns_engine.models import DNSQuery


def make_query(
    domain: str,
) -> DNSQuery:
    return DNSQuery(
        transaction_id=0x1234,
        flags=0x0100,
        questions=1,
        answers=0,
        authority=0,
        additional=0,
        domain=domain,
        query_type=1,
        query_class=1,
    )


def test_empty_cache_returns_miss():
    cache = DNSCache()

    query = make_query("example.com")

    result = cache.lookup(query)

    assert result is None
    assert cache.misses == 1
    assert cache.hits == 0
    assert cache.hit_ratio == 0.0


def test_store_and_lookup_returns_response():
    cache = DNSCache()

    query = make_query("example.com")
    response = b"dns-response"

    cache.store(
        query,
        response,
    )

    result = cache.lookup(query)

    assert result == response
    assert cache.hits == 1
    assert cache.misses == 0
    assert cache.hit_ratio == 1.0


def test_cache_hit_registers_entry_hit():
    cache = DNSCache()

    query = make_query("example.com")
    response = b"response"

    cache.store(
        query,
        response,
    )

    cache.lookup(query)
    cache.lookup(query)

    entry = cache._cache["example.com"]

    assert entry.hits == 2
    assert cache.hits == 2
    assert cache.misses == 0


def test_cache_miss_for_unknown_domain():
    cache = DNSCache()

    query = make_query("unknown.example")

    assert cache.lookup(query) is None
    assert cache.misses == 1


def test_empty_response_is_not_cached():
    cache = DNSCache()

    query = make_query("example.com")

    cache.store(
        query,
        b"",
    )

    assert cache.size == 0
    assert cache.lookup(query) is None
    assert cache.misses == 1


def test_cache_size():
    cache = DNSCache()

    query1 = make_query("one.example")
    query2 = make_query("two.example")

    cache.store(
        query1,
        b"one",
    )

    cache.store(
        query2,
        b"two",
    )

    assert cache.size == 2


def test_clear_resets_cache_and_statistics():
    cache = DNSCache()

    query = make_query("example.com")

    cache.store(
        query,
        b"response",
    )

    cache.lookup(query)

    assert cache.size == 1
    assert cache.hits == 1

    cache.clear()

    assert cache.size == 0
    assert cache.hits == 0
    assert cache.misses == 0
    assert cache.hit_ratio == 0.0


def test_expired_entry_is_treated_as_miss():
    cache = DNSCache()

    query = make_query("expired.example")

    cache.store(
        query,
        b"response",
    )

    # Force the cached entry to expire.
    cache._cache[
        "expired.example"
    ].expires_at = 0

    result = cache.lookup(query)

    assert result is None
    assert cache.misses == 1
    assert cache.hits == 0
    assert cache.size == 0


def test_remove_expired_entries():
    cache = DNSCache()

    query1 = make_query("expired.example")
    query2 = make_query("valid.example")

    cache.store(
        query1,
        b"expired",
    )

    cache.store(
        query2,
        b"valid",
    )

    cache._cache[
        "expired.example"
    ].expires_at = 0

    removed = cache.remove_expired()

    assert removed == 1
    assert cache.size == 1
    assert "expired.example" not in cache._cache
    assert "valid.example" in cache._cache


def test_hit_ratio_with_hits_and_misses():
    cache = DNSCache()

    cached_query = make_query(
        "cached.example",
    )

    missing_query = make_query(
        "missing.example",
    )

    cache.store(
        cached_query,
        b"response",
    )

    cache.lookup(cached_query)
    cache.lookup(cached_query)
    cache.lookup(missing_query)

    assert cache.hits == 2
    assert cache.misses == 1
    assert cache.hit_ratio == 2 / 3


def test_latest_access_moves_entry_to_end():
    cache = DNSCache()

    first = make_query(
        "first.example",
    )

    second = make_query(
        "second.example",
    )

    cache.store(
        first,
        b"first",
    )

    cache.store(
        second,
        b"second",
    )

    cache.lookup(first)

    keys = list(
        cache._cache.keys(),
    )

    assert keys == [
        "second.example",
        "first.example",
    ]


def test_cache_overwrites_existing_domain():
    cache = DNSCache()

    query = make_query(
        "example.com",
    )

    cache.store(
        query,
        b"old-response",
    )

    cache.store(
        query,
        b"new-response",
    )

    result = cache.lookup(query)

    assert result == b"new-response"
    assert cache.size == 1