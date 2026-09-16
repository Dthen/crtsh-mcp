"""Tests for the crt.sh API client: retries, caching, parsing, subdomains."""

import http.client
import http.server
import json
import socket
import socketserver
import threading
import urllib.error
import urllib.request

import pytest

import crtsh_mcp.client as client_mod
from crtsh_mcp.client import (
    CrtshClient,
    CrtshError,
    extract_subdomains,
)


def make_client(handler) -> CrtshClient:
    """Build a client backed by a fake ``_raw_get`` seam (no live network).

    ``handler`` is a ``callable(path) -> (status, body)``; raising from it
    simulates a transport error at the seam.
    """
    client = CrtshClient()
    client._raw_get = handler  # inject the seam (instance attribute shadows method)
    return client


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    """Make retry backoff instantaneous so tests run fast."""
    monkeypatch.setattr(client_mod.time, "sleep", lambda _seconds: None)


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


def test_search_returns_parsed_list():
    def handler(path):
        return (200, json.dumps(SAMPLE))

    client = make_client(handler)
    result = client.search("example.com")
    assert result == SAMPLE
    assert result[0]["common_name"] == "example.com"


def test_search_empty_result_is_valid():
    def handler(path):
        return (200, json.dumps([]))

    client = make_client(handler)
    assert client.search("no-such-domain-xyz.invalid") == []


# -- Retry behaviour -------------------------------------------------------


def test_retry_on_502_then_success():
    calls = {"n": 0}

    def handler(path):
        calls["n"] += 1
        if calls["n"] <= 2:
            return (502, "Bad Gateway")
        return (200, json.dumps(SAMPLE))

    client = make_client(handler)
    result = client.search("example.com")
    assert result == SAMPLE
    assert calls["n"] == 3  # two 502s, then success


def test_all_retries_failed_raises():
    calls = {"n": 0}

    def handler(path):
        calls["n"] += 1
        return (502, "Bad Gateway")

    client = make_client(handler)
    with pytest.raises(CrtshError, match="unavailable after"):
        client.search("example.com")
    # MAX_RETRIES + 1 total attempts.
    assert calls["n"] == client_mod.MAX_RETRIES + 1


def test_retry_on_timeout_then_success():
    calls = {"n": 0}

    def handler(path):
        calls["n"] += 1
        if calls["n"] == 1:
            # What the seam raises for a socket timeout (R1 conversion).
            raise urllib.error.URLError(TimeoutError("timed out"))
        return (200, json.dumps(SAMPLE))

    client = make_client(handler)
    result = client.search("example.com")
    assert result == SAMPLE
    assert calls["n"] == 2


def test_non_retryable_status_raises_immediately():
    calls = {"n": 0}

    def handler(path):
        calls["n"] += 1
        return (500, "Internal Server Error")

    client = make_client(handler)
    with pytest.raises(CrtshError, match="HTTP 500"):
        client.search("example.com")
    assert calls["n"] == 1  # no retries for a 500


def test_retry_on_404_then_success():
    """crt.sh misuses 404 as a transient overload signal — retry it."""
    calls = {"n": 0}

    def handler(path):
        calls["n"] += 1
        if calls["n"] <= 2:
            return (404, "Not Found")
        return (200, json.dumps(SAMPLE))

    client = make_client(handler)
    result = client.search("example.com")
    assert result == SAMPLE
    assert calls["n"] == 3  # two 404s, then success


def test_404_cap_raises_after_two_retries():
    """404 retries are capped at 2 (3 total attempts), not retried forever."""
    calls = {"n": 0}

    def handler(path):
        calls["n"] += 1
        return (404, "Not Found")

    client = make_client(handler)
    with pytest.raises(CrtshError, match="HTTP 404"):
        client.search("example.com")
    assert calls["n"] == client_mod.MAX_404_RETRIES + 1  # 3 total attempts


def test_400_not_retried():
    """Other 4xx (400) stay immediately fatal — guard against over-broadening."""
    calls = {"n": 0}

    def handler(path):
        calls["n"] += 1
        return (400, "Bad Request")

    client = make_client(handler)
    with pytest.raises(CrtshError, match="HTTP 400"):
        client.search("example.com")
    assert calls["n"] == 1  # no retries for a 400


# -- Caching ---------------------------------------------------------------


def test_cache_hit_avoids_second_request():
    calls = {"n": 0}

    def handler(path):
        calls["n"] += 1
        return (200, json.dumps(SAMPLE))

    client = make_client(handler)
    first = client.search("example.com", cache_ttl=300)
    second = client.search("example.com", cache_ttl=300)
    assert first == second == SAMPLE
    assert calls["n"] == 1  # second served from cache


def test_cache_ttl_zero_bypasses_cache():
    calls = {"n": 0}

    def handler(path):
        calls["n"] += 1
        return (200, json.dumps(SAMPLE))

    client = make_client(handler)
    client.search("example.com", cache_ttl=0)
    client.search("example.com", cache_ttl=0)
    assert calls["n"] == 2


def test_cache_expiry_refetches(monkeypatch):
    calls = {"n": 0}

    def handler(path):
        calls["n"] += 1
        return (200, json.dumps(SAMPLE))

    fake_time = {"t": 1000.0}
    monkeypatch.setattr(client_mod.time, "monotonic", lambda: fake_time["t"])

    client = make_client(handler)
    client.search("example.com", cache_ttl=60)
    fake_time["t"] += 61  # exceed TTL
    client.search("example.com", cache_ttl=60)
    assert calls["n"] == 2


def test_cache_is_bounded_evicts_oldest(monkeypatch):
    """Filling the cache past MAX_CACHE_SIZE evicts the oldest entries."""
    def handler(path):
        return (200, json.dumps(SAMPLE))

    fake_time = {"t": 1000.0}
    monkeypatch.setattr(client_mod.time, "monotonic", lambda: fake_time["t"])

    client = make_client(handler)
    total = client_mod.MAX_CACHE_SIZE + 50
    for i in range(total):
        fake_time["t"] += 1.0  # strictly increasing timestamps
        client.search(f"domain-{i}.example.com", cache_ttl=3600)

    # Cache never grows beyond the bound.
    assert len(client._cache) == client_mod.MAX_CACHE_SIZE
    # Oldest entries were evicted; newest retained.
    assert "/?q=domain-0.example.com&output=json" not in client._cache
    assert (
        f"/?q=domain-{total - 1}.example.com&output=json" in client._cache
    )


def test_cache_returns_copies_not_references():
    """Mutating a returned result must not corrupt the cached data."""
    def handler(path):
        return (200, json.dumps(SAMPLE))

    client = make_client(handler)
    first = client.search("example.com", cache_ttl=300)
    # Mutate the returned data (both the list and the inner dict).
    first[0]["common_name"] = "MUTATED"
    first.append({"common_name": "INJECTED"})

    second = client.search("example.com", cache_ttl=300)
    assert second == SAMPLE  # cache served unmutated data
    assert second[0]["common_name"] == "example.com"
    assert len(second) == 1


# -- Error body handling ---------------------------------------------------


def test_unsupported_output_type_raises():
    def handler(path):
        return (200, "<BR><BR>Unsupported output type: json")

    client = make_client(handler)
    with pytest.raises(CrtshError, match="HTML-only"):
        client.search("28A4EB5CE222C5BF4368AF8A0D64C59BDDD3C4EA")


def test_non_json_body_raises_clear_error():
    def handler(path):
        return (200, "<html>overloaded</html>")

    client = make_client(handler)
    with pytest.raises(CrtshError, match="non-JSON"):
        client.search("example.com")


def test_empty_query_raises_value_error():
    client = make_client(lambda path: (200, json.dumps([])))
    with pytest.raises(ValueError):
        client.search("   ")


# -- URL encoding ----------------------------------------------------------


def test_wildcard_percent_is_url_encoded():
    seen = {}

    def handler(path):
        # The seam receives the already percent-encoded path.
        seen["raw"] = path
        return (200, json.dumps([]))

    client = make_client(handler)
    client.search("%.example.com")
    # "%" must be encoded as %25 so crt.sh receives the LIKE wildcard.
    assert "q=%25.example.com" in seen["raw"]
    assert "output=json" in seen["raw"]


def test_exclude_expired_param_added():
    seen = {}

    def handler(path):
        seen["raw"] = path
        return (200, json.dumps([]))

    client = make_client(handler)
    client.search("%.example.com", exclude_expired=True)
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


def test_extract_subdomains_filters_non_hostnames():
    """Cert CN/SAN strings with spaces, @, or bare * are not subdomains."""
    results = [
        {"name_value": "www.example.com\nmail.example.com"},
        {"name_value": "as207960 test intermediate - example.com"},
        {"name_value": "subjectname@example.com"},
        {"name_value": "*"},
        {"name_value": "*.example.com"},
    ]
    subs = extract_subdomains(results)
    assert subs == ["example.com", "mail.example.com", "www.example.com"]
    # No junk entries leaked through.
    for s in subs:
        assert " " not in s
        assert "@" not in s
        assert s != "*"


# -- Redirect contract (T02 headline gate) ---------------------------------


def test_canned_302_raises_and_is_never_followed(monkeypatch):
    # proves the _NoRedirect guard: urllib's DEFAULT would silently follow and
    # return the 200. Localhost socket-server form: canned 302 through the
    # REAL opener.
    seen = {"urls": []}
    real_open = urllib.request.OpenerDirector.open

    def spy(self, req, *a, **k):
        seen["urls"].append(req.full_url if hasattr(req, "full_url") else req)
        return real_open(self, req, *a, **k)

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", spy)

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/redirected"):     # must NEVER be reached
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"[]")
                return
            self.send_response(302)
            self.send_header("Location", "/redirected")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = socketserver.TCPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        c = CrtshClient(base_url=f"http://127.0.0.1:{port}")
        status, body = c._raw_get("/")               # seam returns the 3xx as a STATUS, never follows
        assert status == 302
        assert seen["urls"] == [f"http://127.0.0.1:{port}/"]  # exactly one request — no hop
        with pytest.raises(CrtshError, match="HTTP 302"):     # legacy parity: one attempt, friendly error
            c.search("example.com", cache_ttl=0)
    finally:
        srv.shutdown()
        srv.server_close()


# -- UA on the wire ---------------------------------------------------------


def test_raw_get_sets_user_agent_header(monkeypatch):
    """The Request built by _raw_get carries the pinned legacy UA."""
    captured = {}

    class _FakeResponse:
        status = 200

        def read(self):
            return b"[]"

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    class _FakeOpener:
        def open(self, req, timeout=None):
            captured["req"] = req
            return _FakeResponse()

    monkeypatch.setattr(client_mod, "_get_opener", lambda: _FakeOpener())
    client = CrtshClient()
    status, body = client._raw_get("/?q=example.com&output=json")
    assert status == 200
    req = captured["req"]
    # urllib capitalises header keys when storing them ("User-Agent" ->
    # "User-agent"); get_header applies the same normalisation.
    assert req.get_header("User-agent") == "crtsh-mcp/0.1.0"
    assert req.full_url == "https://crt.sh/?q=example.com&output=json"


# -- R1/R2 seam-semantics pins (T03) ----------------------------------------


def test_protocol_error_is_retried_intentional_deviation():
    """R2 fleet standard — legacy folded this to one-attempt error text;
    see seam mapping table.

    Tag-verified (pre-migration/20260914 client.py:219): the legacy retry
    tuple (TimeoutException, ConnectError, NetworkError) did NOT include
    RemoteProtocolError (a SIBLING branch under TransportError). Post-migration
    http.client.HTTPException enters the ladder on purpose — this test pins
    the intentional deviation, NOT a legacy-parity claim.
    """
    calls = {"n": 0}

    def handler(path):
        calls["n"] += 1
        if calls["n"] == 1:
            raise http.client.RemoteDisconnected("incomplete read")
        return (200, json.dumps(SAMPLE))

    client = make_client(handler)
    result = client.search("example.com")
    assert result == SAMPLE
    assert calls["n"] == 2  # the ladder retried a protocol error — R2 deviation


def test_protocol_error_parity_surface_after_exhaustion():
    """Friendly-text parity preserved across the ladder (never -32603).

    Every attempt hits the seam spy (cache_ttl=0 so the cache can't
    short-circuit), so the total attempt count pins that protocol errors feed
    the ladder — MAX_RETRIES + 1 attempts, not legacy's ONE — while the final
    surface stays a CrtshError whose text renders as `Error: …` in the tool
    handler (server-side rendering is T07's territory).
    """
    calls = {"n": 0}

    def handler(path):
        calls["n"] += 1
        raise http.client.BadStatusLine("")

    client = make_client(handler)
    with pytest.raises(CrtshError, match="unavailable after") as excinfo:
        client.search("example.com", cache_ttl=0)
    assert calls["n"] == client_mod.MAX_RETRIES + 1  # the ladder, not one attempt
    # Non-empty str(exc) = renders as `Error: <text>` friendly tool text.
    assert str(excinfo.value)


def test_timeout_conversion_is_caught_by_ladder(monkeypatch):
    """R1 pin — drives the REAL _raw_get so the except-order is exercised.

    A bare TimeoutError from inside urlopen must be converted to URLError at
    the seam (`except TimeoutError` sits BEFORE the ladder-class catch so
    str(exc) stays informative), then the ladder retries and attempt 2 wins.
    The opener is monkeypatched (not _raw_get) so the conversion code runs.
    """

    class _Resp:
        status = 200

        def read(self):
            return json.dumps(SAMPLE).encode()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    class _FlakyTimeoutOpener:
        def __init__(self):
            self.n = 0

        def open(self, req, timeout=None):
            self.n += 1
            if self.n == 1:
                raise TimeoutError("read timed out")
            return _Resp()

    client = CrtshClient()

    # The conversion itself: bare TimeoutError leaves the seam as URLError.
    monkeypatch.setattr(client_mod, "_get_opener", lambda: _FlakyTimeoutOpener())
    with pytest.raises(urllib.error.URLError) as excinfo:
        client._raw_get("/?q=example.com&output=json")
    assert isinstance(excinfo.value.reason, TimeoutError)

    # ...and the ladder retries it: attempt 2 returns 200 -> SAMPLE.
    opener = _FlakyTimeoutOpener()
    monkeypatch.setattr(client_mod, "_get_opener", lambda: opener)
    result = client.search("example.com", cache_ttl=0)
    assert result == SAMPLE
    assert opener.n == 2


def test_socket_timeout_is_timeout_error():
    """Documents why a naive `except URLError` leaks read timeouts: on this
    runtime (py3.11+) socket.timeout IS TimeoutError, NOT a URLError."""
    assert socket.timeout is TimeoutError
    assert not issubclass(TimeoutError, urllib.error.URLError)
