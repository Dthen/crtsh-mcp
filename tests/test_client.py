"""Tests for the crt.sh API client: retries, caching, parsing, subdomains."""

import httpx
import pytest

import crtsh_mcp.client as client_mod
from crtsh_mcp.client import CrtshClient, CrtshError, extract_subdomains


def make_client(handler) -> CrtshClient:
    """Build a client backed by an httpx.MockTransport (no live network)."""
    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(base_url="https://crt.sh", transport=transport)
    return CrtshClient(client=http)


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    """Make retry backoff instantaneous so tests run fast."""

    async def _instant(_seconds):
        return None

    monkeypatch.setattr(client_mod.asyncio, "sleep", _instant)


SAMPLE = [
    {
        "issuer_ca_id": 413864,
        "issuer_name": "C=US, O=SSL Corporation, CN=Cloudflare TLS Issuing RSA CA 3",
        "common_name": "example.com",
        "name_value": "*.example.com\nexample.com",
        "id": 26787376238,
        "entry_timestamp": "2026-05-31T22:13:01.653",
        "not_before": "2026-05-31T21:39:00",
        "not_after": "2026-08-29T21:41:26",
        "serial_number": "27fd65644d90aa4763b6cfb53d6dcca3",
    }
]


# -- Successful search -----------------------------------------------------


async def test_search_returns_parsed_list():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=SAMPLE)

    client = make_client(handler)
    result = await client.search("example.com")
    assert result == SAMPLE
    assert result[0]["common_name"] == "example.com"


async def test_search_empty_result_is_valid():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[])

    client = make_client(handler)
    assert await client.search("no-such-domain-xyz.invalid") == []


# -- Retry behaviour -------------------------------------------------------


async def test_retry_on_502_then_success():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] <= 2:
            return httpx.Response(502, text="Bad Gateway")
        return httpx.Response(200, json=SAMPLE)

    client = make_client(handler)
    result = await client.search("example.com")
    assert result == SAMPLE
    assert calls["n"] == 3  # two 502s, then success


async def test_all_retries_failed_raises():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(502, text="Bad Gateway")

    client = make_client(handler)
    with pytest.raises(CrtshError, match="unavailable after"):
        await client.search("example.com")
    # MAX_RETRIES + 1 total attempts.
    assert calls["n"] == client_mod.MAX_RETRIES + 1


async def test_retry_on_timeout_then_success():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectTimeout("timed out")
        return httpx.Response(200, json=SAMPLE)

    client = make_client(handler)
    result = await client.search("example.com")
    assert result == SAMPLE
    assert calls["n"] == 2


async def test_non_retryable_status_raises_immediately():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(500, text="Internal Server Error")

    client = make_client(handler)
    with pytest.raises(CrtshError, match="HTTP 500"):
        await client.search("example.com")
    assert calls["n"] == 1  # no retries for a 500


async def test_retry_on_404_then_success():
    """crt.sh misuses 404 as a transient overload signal — retry it."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] <= 2:
            return httpx.Response(404, text="Not Found")
        return httpx.Response(200, json=SAMPLE)

    client = make_client(handler)
    result = await client.search("example.com")
    assert result == SAMPLE
    assert calls["n"] == 3  # two 404s, then success


async def test_404_cap_raises_after_two_retries():
    """404 retries are capped at 2 (3 total attempts), not retried forever."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(404, text="Not Found")

    client = make_client(handler)
    with pytest.raises(CrtshError, match="HTTP 404"):
        await client.search("example.com")
    assert calls["n"] == client_mod.MAX_404_RETRIES + 1  # 3 total attempts


async def test_400_not_retried():
    """Other 4xx (400) stay immediately fatal — guard against over-broadening."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(400, text="Bad Request")

    client = make_client(handler)
    with pytest.raises(CrtshError, match="HTTP 400"):
        await client.search("example.com")
    assert calls["n"] == 1  # no retries for a 400


# -- Caching ---------------------------------------------------------------


async def test_cache_hit_avoids_second_request():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=SAMPLE)

    client = make_client(handler)
    first = await client.search("example.com", cache_ttl=300)
    second = await client.search("example.com", cache_ttl=300)
    assert first == second == SAMPLE
    assert calls["n"] == 1  # second served from cache


async def test_cache_ttl_zero_bypasses_cache():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=SAMPLE)

    client = make_client(handler)
    await client.search("example.com", cache_ttl=0)
    await client.search("example.com", cache_ttl=0)
    assert calls["n"] == 2


async def test_cache_expiry_refetches(monkeypatch):
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=SAMPLE)

    fake_time = {"t": 1000.0}
    monkeypatch.setattr(client_mod.time, "monotonic", lambda: fake_time["t"])

    client = make_client(handler)
    await client.search("example.com", cache_ttl=60)
    fake_time["t"] += 61  # exceed TTL
    await client.search("example.com", cache_ttl=60)
    assert calls["n"] == 2


async def test_cache_is_bounded_evicts_oldest(monkeypatch):
    """Filling the cache past MAX_CACHE_SIZE evicts the oldest entries."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=SAMPLE)

    fake_time = {"t": 1000.0}
    monkeypatch.setattr(client_mod.time, "monotonic", lambda: fake_time["t"])

    client = make_client(handler)
    total = client_mod.MAX_CACHE_SIZE + 50
    for i in range(total):
        fake_time["t"] += 1.0  # strictly increasing timestamps
        await client.search(f"domain-{i}.example.com", cache_ttl=3600)

    # Cache never grows beyond the bound.
    assert len(client._cache) == client_mod.MAX_CACHE_SIZE
    # Oldest entries were evicted; newest retained.
    assert "/?q=domain-0.example.com&output=json" not in client._cache
    assert (
        f"/?q=domain-{total - 1}.example.com&output=json" in client._cache
    )


async def test_cache_returns_copies_not_references():
    """Mutating a returned result must not corrupt the cached data."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=SAMPLE)

    client = make_client(handler)
    first = await client.search("example.com", cache_ttl=300)
    # Mutate the returned data (both the list and the inner dict).
    first[0]["common_name"] = "MUTATED"
    first.append({"common_name": "INJECTED"})

    second = await client.search("example.com", cache_ttl=300)
    assert second == SAMPLE  # cache served unmutated data
    assert second[0]["common_name"] == "example.com"
    assert len(second) == 1


# -- Error body handling ---------------------------------------------------


async def test_unsupported_output_type_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<BR><BR>Unsupported output type: json")

    client = make_client(handler)
    with pytest.raises(CrtshError, match="HTML-only"):
        await client.search("28A4EB5CE222C5BF4368AF8A0D64C59BDDD3C4EA")


async def test_non_json_body_raises_clear_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>overloaded</html>")

    client = make_client(handler)
    with pytest.raises(CrtshError, match="non-JSON"):
        await client.search("example.com")


async def test_empty_query_raises_value_error():
    client = make_client(lambda r: httpx.Response(200, json=[]))
    with pytest.raises(ValueError):
        await client.search("   ")


# -- URL encoding ----------------------------------------------------------


async def test_wildcard_percent_is_url_encoded():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        # The raw target preserves percent-encoding.
        seen["raw"] = request.url.raw_path.decode()
        return httpx.Response(200, json=[])

    client = make_client(handler)
    await client.search("%.example.com")
    # "%" must be encoded as %25 so crt.sh receives the LIKE wildcard.
    assert "q=%25.example.com" in seen["raw"]
    assert "output=json" in seen["raw"]


async def test_exclude_expired_param_added():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["raw"] = request.url.raw_path.decode()
        return httpx.Response(200, json=[])

    client = make_client(handler)
    await client.search("%.example.com", exclude_expired=True)
    assert "exclude=expired" in seen["raw"]


# -- Subdomain extraction --------------------------------------------------


def test_extract_subdomains_dedupes_and_sorts():
    results = [
        {"name_value": "*.example.com\nexample.com"},
        {"name_value": "www.example.com\nexample.com"},
        {"name_value": "api.example.com"},
    ]
    subs = extract_subdomains(results)
    # Wildcard reduced to base domain; duplicates removed; sorted.
    assert subs == ["api.example.com", "example.com", "www.example.com"]


def test_extract_subdomains_handles_missing_and_blank():
    results = [
        {"name_value": ""},
        {"common_name": "no name_value field"},
        {"name_value": "a.com\n\n  \nb.com"},
    ]
    assert extract_subdomains(results) == ["a.com", "b.com"]
