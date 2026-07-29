"""Tests for the crt.sh MCP server tools."""

import httpx
import pytest

import crtsh_mcp.server as server_mod
from crtsh_mcp.client import CrtshError


def make_cert(cn: str, ts: str, name_value: str | None = None) -> dict:
    """Build a minimal certificate dict for testing."""
    return {
        "issuer_ca_id": 1,
        "issuer_name": "C=US, O=Test CA, CN=Test Issuer",
        "common_name": cn,
        "name_value": name_value if name_value is not None else cn,
        "id": 12345,
        "entry_timestamp": ts,
        "not_before": "2026-01-01T00:00:00",
        "not_after": "2026-12-31T00:00:00",
        "serial_number": "abc123",
    }


class FakeClient:
    """Stand-in for CrtshClient that records calls and returns canned data."""

    def __init__(self, results=None, error=None):
        self.results = results if results is not None else []
        self.error = error
        self.calls: list[str] = []
        self.aclose_called = False

    async def search(self, query, **kwargs):
        self.calls.append(query)
        if self.error is not None:
            raise self.error
        return self.results

    async def aclose(self):
        self.aclose_called = True


@pytest.fixture
def fake_client(monkeypatch):
    """Install a FakeClient on the server module and return it."""
    client = FakeClient()
    monkeypatch.setattr(server_mod, "_client", client)
    return client


# -- search_certificates ---------------------------------------------------


@pytest.mark.parametrize("raw", ["", "   "])
async def test_search_certificates_rejects_empty_query(fake_client, raw):
    result = await server_mod.search_certificates(raw)
    assert isinstance(result, str)
    assert result.startswith("Error:")
    assert "search query" in result
    # No garbage query should have been issued to the client.
    assert fake_client.calls == []


@pytest.mark.parametrize("bad_limit", [0, -1])
async def test_search_certificates_rejects_non_positive_limit(fake_client, bad_limit):
    fake_client.results = [make_cert("example.com", "2026-01-01T00:00:00")]
    result = await server_mod.search_certificates("example.com", limit=bad_limit)
    assert isinstance(result, str)
    assert result.startswith("Error:")
    assert "positive integer" in result
    assert fake_client.calls == []


async def test_search_certificates_truncates_to_limit(fake_client):
    fake_client.results = [make_cert(f"host{i}.example.com", "2026-01-01T00:00:00") for i in range(100)]
    result = await server_mod.search_certificates("example.com", limit=50)
    assert isinstance(result, dict)
    assert result["count"] == 50
    assert result["total_found"] == 100
    assert result["truncated"] is True
    assert len(result["certificates"]) == 50
    assert "note" in result


async def test_search_certificates_default_limit(fake_client):
    fake_client.results = [make_cert(f"host{i}.example.com", "2026-01-01T00:00:00") for i in range(80)]
    result = await server_mod.search_certificates("example.com")
    assert isinstance(result, dict)
    assert result["count"] == 50  # default limit
    assert result["total_found"] == 80
    assert result["truncated"] is True


async def test_search_certificates_fewer_than_limit(fake_client):
    fake_client.results = [make_cert("example.com", "2026-01-01T00:00:00")]
    result = await server_mod.search_certificates("example.com", limit=50)
    assert result["count"] == 1
    assert result["total_found"] == 1
    assert result["truncated"] is False
    assert "note" not in result


async def test_search_certificates_truncated_at_row_cap(fake_client):
    # 999 rows hits crt.sh's cap — must be flagged even if limit is huge.
    fake_client.results = [make_cert(f"h{i}.example.com", "2026-01-01T00:00:00") for i in range(999)]
    result = await server_mod.search_certificates("example.com", limit=1000)
    assert result["truncated"] is True
    assert result["total_found"] == 999
    assert "cap" in result["note"]


# -- discover_subdomains ---------------------------------------------------


async def test_discover_subdomains_returns_structured_dict(fake_client):
    fake_client.results = [
        make_cert("example.com", "2026-01-01T00:00:00", name_value="*.example.com\nexample.com"),
        make_cert("api.example.com", "2026-01-02T00:00:00", name_value="api.example.com"),
    ]
    result = await server_mod.discover_subdomains("example.com")
    assert isinstance(result, dict)
    assert result["domain"] == "example.com"
    assert result["subdomain_count"] == 2
    assert result["subdomains"] == ["api.example.com", "example.com"]
    assert result["truncated"] is False


async def test_discover_subdomains_builds_wildcard_query(fake_client):
    fake_client.results = []
    await server_mod.discover_subdomains("example.com")
    assert fake_client.calls == ["%.example.com"]


@pytest.mark.parametrize(
    "raw",
    ["*.example.com", "example.com.", "%.example.com", "  *.Example.COM.  "],
)
async def test_discover_subdomains_normalizes_input(fake_client, raw):
    fake_client.results = []
    result = await server_mod.discover_subdomains(raw)
    assert fake_client.calls == ["%.example.com"]
    assert result["domain"] == "example.com"


async def test_discover_subdomains_truncated_at_row_cap(fake_client):
    fake_client.results = [
        make_cert(f"h{i}.example.com", "2026-01-01T00:00:00", name_value=f"h{i}.example.com")
        for i in range(999)
    ]
    result = await server_mod.discover_subdomains("example.com")
    assert result["truncated"] is True


@pytest.mark.parametrize("raw", ["", "   ", "."])
async def test_discover_subdomains_rejects_degenerate_domain(fake_client, raw):
    fake_client.results = []
    result = await server_mod.discover_subdomains(raw)
    assert isinstance(result, str)
    assert result.startswith("Error:")
    assert "invalid domain" in result
    # No garbage query should have been issued to the client.
    assert fake_client.calls == []


@pytest.mark.parametrize("raw", ["", "   ", "."])
async def test_get_certificate_details_rejects_degenerate_domain(fake_client, raw):
    fake_client.results = []
    result = await server_mod.get_certificate_details(raw)
    assert isinstance(result, str)
    assert result.startswith("Error:")
    assert "invalid domain" in result
    assert fake_client.calls == []


# -- get_certificate_details -----------------------------------------------


async def test_get_certificate_details_sorts_descending(fake_client):
    fake_client.results = [
        make_cert("old.example.com", "2024-01-01T00:00:00"),
        make_cert("new.example.com", "2026-05-01T00:00:00"),
        make_cert("mid.example.com", "2025-06-01T00:00:00"),
    ]
    result = await server_mod.get_certificate_details("example.com")
    assert isinstance(result, dict)
    assert result["count"] == 3
    assert result["total_found"] == 3
    assert result["truncated"] is False
    timestamps = [c["entry_timestamp"] for c in result["certificates"]]
    assert timestamps == sorted(timestamps, reverse=True)
    assert result["certificates"][0]["common_name"] == "new.example.com"


async def test_get_certificate_details_limits_to_20(fake_client):
    fake_client.results = [make_cert(f"h{i}.example.com", f"2026-01-{i+1:02d}T00:00:00") for i in range(30)]
    result = await server_mod.get_certificate_details("example.com")
    assert result["count"] == 20
    assert len(result["certificates"]) == 20


async def test_get_certificate_details_truncated_flag_when_over_20(fake_client):
    fake_client.results = [make_cert(f"h{i}.example.com", f"2026-01-{i+1:02d}T00:00:00") for i in range(30)]
    result = await server_mod.get_certificate_details("example.com")
    assert result["truncated"] is True
    assert result["total_found"] == 30
    assert result["count"] == 20
    assert "note" in result


async def test_get_certificate_details_not_truncated_at_exactly_20(fake_client):
    fake_client.results = [make_cert(f"h{i}.example.com", f"2026-01-{i+1:02d}T00:00:00") for i in range(20)]
    result = await server_mod.get_certificate_details("example.com")
    assert result["truncated"] is False
    assert result["total_found"] == 20
    assert result["count"] == 20
    assert "note" not in result


async def test_get_certificate_details_does_not_mutate_cache(fake_client):
    # The client cache returns its list by reference; sorting must not reorder it.
    original = [
        make_cert("old.example.com", "2024-01-01T00:00:00"),
        make_cert("new.example.com", "2026-05-01T00:00:00"),
        make_cert("mid.example.com", "2025-06-01T00:00:00"),
    ]
    fake_client.results = original
    await server_mod.get_certificate_details("example.com")
    assert [c["common_name"] for c in original] == [
        "old.example.com",
        "new.example.com",
        "mid.example.com",
    ]


# -- error handling --------------------------------------------------------


async def test_search_certificates_crtsh_error_returns_string(monkeypatch):
    monkeypatch.setattr(server_mod, "_client", FakeClient(error=CrtshError("crt.sh overloaded")))
    result = await server_mod.search_certificates("example.com")
    assert isinstance(result, str)
    assert result.startswith("Error:")
    assert "overloaded" in result


async def test_search_certificates_http_error_returns_string(monkeypatch):
    monkeypatch.setattr(server_mod, "_client", FakeClient(error=httpx.ConnectError("boom")))
    result = await server_mod.search_certificates("example.com")
    assert isinstance(result, str)
    assert result.startswith("Error:")


async def test_discover_subdomains_error_returns_string(monkeypatch):
    monkeypatch.setattr(server_mod, "_client", FakeClient(error=CrtshError("down")))
    result = await server_mod.discover_subdomains("example.com")
    assert isinstance(result, str)
    assert result.startswith("Error:")


async def test_get_certificate_details_error_returns_string(monkeypatch):
    monkeypatch.setattr(server_mod, "_client", FakeClient(error=httpx.TimeoutException("slow")))
    result = await server_mod.get_certificate_details("example.com")
    assert isinstance(result, str)
    assert result.startswith("Error:")


# -- client shutdown -------------------------------------------------------


async def test_close_client_closes_underlying_client(fake_client):
    await server_mod.close_client()
    assert fake_client.aclose_called is True


async def test_lifespan_closes_client_on_shutdown(fake_client):
    async with server_mod._lifespan(server_mod.mcp):
        assert fake_client.aclose_called is False
    assert fake_client.aclose_called is True
