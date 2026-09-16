"""Tests for the crt.sh MCP server tools — sync era port (T08).

Convention: every tool invocation goes through ``server_mod.handle_call(name,
arguments)`` (the dispatch the fleet ships; REFERENCE §5). ``handle_call``
returns the tool's raw dict/str result; wire encoding (compact-JSON text,
isError flag) is covered by test_stateless_era.py and
test_characterization_text.py and is deliberately NOT re-asserted here.

Port notes: the legacy suite was coroutine-based (24 defs / 35 collected,
calling ``@mcp.tool()`` functions). All async plumbing and httpx are gone; the two
lifespan/close_client tests were retired with the machinery they covered
(shared-handle teardown deleted by D5) and replaced by one absence-pin
(test_no_lingering_client_lifecycle). Net: 23 defs + 11 param expansions.
"""

import urllib.error

import pytest

import crtsh_mcp.server as server_mod
from crtsh_mcp.client import CrtshClient, CrtshError


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
    """Stand-in for CrtshClient that records calls and returns canned data.

    Sync and minimal: the real client's per-request urllib transport means
    there is no handle to close, so the legacy ``aclose`` stub is retired.
    """

    def __init__(self, results=None, error=None):
        self.results = results if results is not None else []
        self.error = error
        self.calls: list[str] = []

    def search(self, query, **kwargs):  # cache_ttl= / exclude_expired= keywords
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


@pytest.mark.parametrize("raw", ["", "   "])
def test_search_certificates_rejects_empty_query(fake_client, raw):
    result = server_mod.handle_call("search_certificates", {"query": raw})
    assert isinstance(result, str)
    assert result.startswith("Error:")
    assert "search query" in result
    # No garbage query should have been issued to the client.
    assert fake_client.calls == []


@pytest.mark.parametrize("raw", ["example.com\n", "  example.com  ", "\texample.com\r\n"])
def test_search_certificates_strips_query_before_client_call(fake_client, raw):
    fake_client.results = [make_cert("example.com", "2026-01-01T00:00:00")]
    result = server_mod.handle_call("search_certificates", {"query": raw, "limit": 2})
    assert isinstance(result, dict)
    # The client must receive the stripped query, not the raw whitespace-padded one.
    assert fake_client.calls == ["example.com"]


@pytest.mark.parametrize("bad_limit", [0, -1])
def test_search_certificates_rejects_non_positive_limit(fake_client, bad_limit):
    fake_client.results = [make_cert("example.com", "2026-01-01T00:00:00")]
    result = server_mod.handle_call("search_certificates", {"query": "example.com", "limit": bad_limit})
    assert isinstance(result, str)
    assert result.startswith("Error:")
    assert "positive integer" in result
    assert fake_client.calls == []


def test_search_certificates_truncates_to_limit(fake_client):
    fake_client.results = [make_cert(f"host{i}.example.com", "2026-01-01T00:00:00") for i in range(100)]
    result = server_mod.handle_call("search_certificates", {"query": "example.com", "limit": 50})
    assert isinstance(result, dict)
    assert result["count"] == 50
    assert result["total_found"] == 100
    assert result["truncated"] is True
    assert len(result["certificates"]) == 50
    assert "note" in result


def test_search_certificates_default_limit(fake_client):
    fake_client.results = [make_cert(f"host{i}.example.com", "2026-01-01T00:00:00") for i in range(80)]
    result = server_mod.handle_call("search_certificates", {"query": "example.com"})
    assert isinstance(result, dict)
    assert result["count"] == 50  # default limit
    assert result["total_found"] == 80
    assert result["truncated"] is True


def test_search_certificates_fewer_than_limit(fake_client):
    fake_client.results = [make_cert("example.com", "2026-01-01T00:00:00")]
    result = server_mod.handle_call("search_certificates", {"query": "example.com", "limit": 50})
    assert result["count"] == 1
    assert result["total_found"] == 1
    assert result["truncated"] is False
    assert "note" not in result


def test_search_certificates_truncated_at_row_cap(fake_client):
    # 999 rows hits crt.sh's cap — must be flagged even if limit is huge.
    fake_client.results = [make_cert(f"h{i}.example.com", "2026-01-01T00:00:00") for i in range(999)]
    result = server_mod.handle_call("search_certificates", {"query": "example.com", "limit": 1000})
    assert result["truncated"] is True
    assert result["total_found"] == 999
    assert "cap" in result["note"]


# -- discover_subdomains ---------------------------------------------------


def test_discover_subdomains_returns_structured_dict(fake_client):
    fake_client.results = [
        make_cert("example.com", "2026-01-01T00:00:00", name_value="*.example.com\nexample.com"),
        make_cert("api.example.com", "2026-01-02T00:00:00", name_value="api.example.com"),
    ]
    result = server_mod.handle_call("discover_subdomains", {"domain": "example.com"})
    assert isinstance(result, dict)
    assert result["domain"] == "example.com"
    assert result["subdomain_count"] == 2
    assert result["subdomains"] == ["api.example.com", "example.com"]
    assert result["truncated"] is False


def test_discover_subdomains_builds_wildcard_query(fake_client):
    fake_client.results = []
    server_mod.handle_call("discover_subdomains", {"domain": "example.com"})
    assert fake_client.calls == ["%.example.com"]


@pytest.mark.parametrize(
    "raw",
    ["*.example.com", "example.com.", "%.example.com", "  *.Example.COM.  "],
)
def test_discover_subdomains_normalizes_input(fake_client, raw):
    fake_client.results = []
    result = server_mod.handle_call("discover_subdomains", {"domain": raw})
    assert fake_client.calls == ["%.example.com"]
    assert result["domain"] == "example.com"


def test_discover_subdomains_truncated_at_row_cap(fake_client):
    fake_client.results = [
        make_cert(f"h{i}.example.com", "2026-01-01T00:00:00", name_value=f"h{i}.example.com")
        for i in range(999)
    ]
    result = server_mod.handle_call("discover_subdomains", {"domain": "example.com"})
    assert result["truncated"] is True


@pytest.mark.parametrize("raw", ["", "   ", "."])
def test_discover_subdomains_rejects_degenerate_domain(fake_client, raw):
    fake_client.results = []
    result = server_mod.handle_call("discover_subdomains", {"domain": raw})
    assert isinstance(result, str)
    assert result.startswith("Error:")
    assert "invalid domain" in result
    # No garbage query should have been issued to the client.
    assert fake_client.calls == []


@pytest.mark.parametrize("raw", ["", "   ", "."])
def test_get_certificate_details_rejects_degenerate_domain(fake_client, raw):
    fake_client.results = []
    result = server_mod.handle_call("get_certificate_details", {"domain": raw})
    assert isinstance(result, str)
    assert result.startswith("Error:")
    assert "invalid domain" in result
    assert fake_client.calls == []


# -- get_certificate_details -----------------------------------------------


def test_get_certificate_details_sorts_descending(fake_client):
    fake_client.results = [
        make_cert("old.example.com", "2024-01-01T00:00:00"),
        make_cert("new.example.com", "2026-05-01T00:00:00"),
        make_cert("mid.example.com", "2025-06-01T00:00:00"),
    ]
    result = server_mod.handle_call("get_certificate_details", {"domain": "example.com"})
    assert isinstance(result, dict)
    assert result["count"] == 3
    assert result["total_found"] == 3
    assert result["truncated"] is False
    timestamps = [c["entry_timestamp"] for c in result["certificates"]]
    assert timestamps == sorted(timestamps, reverse=True)
    assert result["certificates"][0]["common_name"] == "new.example.com"


def test_get_certificate_details_limits_to_20(fake_client):
    fake_client.results = [make_cert(f"h{i}.example.com", f"2026-01-{i+1:02d}T00:00:00") for i in range(30)]
    result = server_mod.handle_call("get_certificate_details", {"domain": "example.com"})
    assert result["count"] == 20
    assert len(result["certificates"]) == 20


def test_get_certificate_details_truncated_flag_when_over_20(fake_client):
    fake_client.results = [make_cert(f"h{i}.example.com", f"2026-01-{i+1:02d}T00:00:00") for i in range(30)]
    result = server_mod.handle_call("get_certificate_details", {"domain": "example.com"})
    assert result["truncated"] is True
    assert result["total_found"] == 30
    assert result["count"] == 20
    assert "note" in result


def test_get_certificate_details_not_truncated_at_exactly_20(fake_client):
    fake_client.results = [make_cert(f"h{i}.example.com", f"2026-01-{i+1:02d}T00:00:00") for i in range(20)]
    result = server_mod.handle_call("get_certificate_details", {"domain": "example.com"})
    assert result["truncated"] is False
    assert result["total_found"] == 20
    assert result["count"] == 20
    assert "note" not in result


def test_get_certificate_details_does_not_mutate_cache(fake_client):
    # The client hands out deep copies (T04 cache contract) and sorted() copies
    # anyway — the tool must never reorder the caller's source list.
    original = [
        make_cert("old.example.com", "2024-01-01T00:00:00"),
        make_cert("new.example.com", "2026-05-01T00:00:00"),
        make_cert("mid.example.com", "2025-06-01T00:00:00"),
    ]
    fake_client.results = original
    server_mod.handle_call("get_certificate_details", {"domain": "example.com"})
    assert [c["common_name"] for c in original] == [
        "old.example.com",
        "new.example.com",
        "mid.example.com",
    ]


# -- error handling --------------------------------------------------------
# Error classes below are what the post-seam (urllib) stack actually raises:
# legacy httpx.ConnectError/httpx.TimeoutException arrive as
# urllib.error.URLError wrapping the transport cause (R1 mapping).


def test_search_certificates_crtsh_error_returns_string(monkeypatch):
    monkeypatch.setattr(server_mod, "_client", FakeClient(error=CrtshError("crt.sh overloaded")))
    result = server_mod.handle_call("search_certificates", {"query": "example.com"})
    assert isinstance(result, str)
    assert result.startswith("Error:")
    assert "overloaded" in result


def test_search_certificates_http_error_returns_string(monkeypatch):
    # legacy: httpx.ConnectError("boom") -> post-seam arrival class URLError
    monkeypatch.setattr(
        server_mod, "_client", FakeClient(error=urllib.error.URLError(ConnectionError("boom")))
    )
    result = server_mod.handle_call("search_certificates", {"query": "example.com"})
    assert isinstance(result, str)
    assert result.startswith("Error:")
    assert "boom" in result


def test_discover_subdomains_error_returns_string(monkeypatch):
    monkeypatch.setattr(server_mod, "_client", FakeClient(error=CrtshError("down")))
    result = server_mod.handle_call("discover_subdomains", {"domain": "example.com"})
    assert isinstance(result, str)
    assert result.startswith("Error:")


def test_get_certificate_details_error_returns_string(monkeypatch):
    # legacy: httpx.TimeoutException("t") -> post-seam arrival class URLError
    # wrapping TimeoutError (R1: py3.11 socket.timeout folds into TimeoutError,
    # never a URLError subclass, until the seam converts it).
    monkeypatch.setattr(
        server_mod,
        "_client",
        FakeClient(error=urllib.error.URLError(TimeoutError("read timed out"))),
    )
    result = server_mod.handle_call("get_certificate_details", {"domain": "example.com"})
    assert isinstance(result, str)
    assert result.startswith("Error:")
    assert "read timed out" in result


# -- client lifecycle (absence pin) ----------------------------------------


def test_no_lingering_client_lifecycle():
    """D5: the shared-handle lifespan (server) and async-close surface (client)
    are deleted outright — sync urllib opens per-request. 2 legacy tests
    (close_client / lifespan) were retired with the machinery they covered;
    this pin is their replacement."""
    assert not hasattr(server_mod, "close_client")
    assert not hasattr(server_mod, "_lifespan")
    assert not hasattr(CrtshClient, "aclose")
    assert not hasattr(CrtshClient, "__aenter__")
