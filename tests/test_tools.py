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

    async def search(self, query, **kwargs):
        self.calls.append(query)
        if self.error is not None:
            raise self.error
        return self.results


@pytest.fixture
def fake_client(monkeypatch):
    """Install a FakeClient on the server module and return it."""
    client = FakeClient()
    monkeypatch.setattr(server_mod, "_client", client)
    return client


# -- search_certificates ---------------------------------------------------


async def test_search_certificates_truncates_to_limit(fake_client):
    fake_client.results = [make_cert(f"host{i}.example.com", "2026-01-01T00:00:00") for i in range(100)]
    result = await server_mod.search_certificates("example.com", limit=50)
    assert isinstance(result, list)
    assert len(result) == 50


async def test_search_certificates_default_limit(fake_client):
    fake_client.results = [make_cert(f"host{i}.example.com", "2026-01-01T00:00:00") for i in range(80)]
    result = await server_mod.search_certificates("example.com")
    assert isinstance(result, list)
    assert len(result) == 50  # default limit


async def test_search_certificates_fewer_than_limit(fake_client):
    fake_client.results = [make_cert("example.com", "2026-01-01T00:00:00")]
    result = await server_mod.search_certificates("example.com", limit=50)
    assert len(result) == 1


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


async def test_discover_subdomains_builds_wildcard_query(fake_client):
    fake_client.results = []
    await server_mod.discover_subdomains("example.com")
    assert fake_client.calls == ["%.example.com"]


# -- get_certificate_details -----------------------------------------------


async def test_get_certificate_details_sorts_descending(fake_client):
    fake_client.results = [
        make_cert("old.example.com", "2024-01-01T00:00:00"),
        make_cert("new.example.com", "2026-05-01T00:00:00"),
        make_cert("mid.example.com", "2025-06-01T00:00:00"),
    ]
    result = await server_mod.get_certificate_details("example.com")
    assert isinstance(result, list)
    timestamps = [c["entry_timestamp"] for c in result]
    assert timestamps == sorted(timestamps, reverse=True)
    assert result[0]["common_name"] == "new.example.com"


async def test_get_certificate_details_limits_to_20(fake_client):
    fake_client.results = [make_cert(f"h{i}.example.com", f"2026-01-{i+1:02d}T00:00:00") for i in range(30)]
    result = await server_mod.get_certificate_details("example.com")
    assert len(result) == 20


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
