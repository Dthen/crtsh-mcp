"""Synchronous HTTP client for the crt.sh Certificate Transparency API.

crt.sh exposes a single JSON query endpoint (``?q=<identity>&output=json``)
with no authentication. The service is a free community resource that is
frequently overloaded, so this client retries transient failures (502/503,
timeouts, connection errors) with exponential backoff and caches responses
in-memory with a per-call TTL. Transport is stdlib urllib (zero runtime
deps).

Only identity (domain / org) searches support JSON output. Fingerprint,
serial-number, and crt.sh-ID lookups are HTML-only and will raise
``CrtshError`` ("Unsupported output type") if attempted through this client.
"""

from __future__ import annotations

import copy
import http.client
import json
import re
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import quote

BASE_URL = "https://crt.sh"

# Default request timeout (seconds). crt.sh is slow under load.
DEFAULT_TIMEOUT = 20.0

# Retry configuration for transient failures.
MAX_RETRIES = 3
BACKOFF_BASE = 1.0  # seconds; delays are 1s, 2s, 4s

# HTTP status codes that warrant a retry.
RETRYABLE_STATUS = {502, 503}

# crt.sh misuses HTTP 404 as a generic "I'm overloaded, go away" response under
# load rather than a genuine "not found" — a live QA test observed it return
# 404 twice for a perfectly valid query, then succeed on the third try. So we
# retry 404 too, but more conservatively than 502/503 (a 404 is more likely to
# be genuine, so it gets a lower cap). DO NOT "fix" this back to non-retryable
# without first re-checking live crt.sh behaviour under load.
MAX_404_RETRIES = 2

# Default cache TTL (seconds) for search results.
DEFAULT_CACHE_TTL = 300

# Maximum number of entries retained in the in-memory cache. When the cache
# exceeds this size after an insert, the oldest entries (by timestamp) are
# evicted so a long-running server cannot grow the cache without bound.
MAX_CACHE_SIZE = 256

# Extracted from the legacy httpx ctor literal (client.py:123) — bytes
# preserved; it says 0.1.0 while pyproject says 0.2.0. Do NOT "fix" the
# version drift here (card B.3: drift-fixing is out of scope).
_USER_AGENT = "crtsh-mcp/0.1.0"

# Transport errors the retry ladder catches. TimeoutError is already an
# OSError subclass (OSError ⊃ ConnectionResetError too), so the tuple's
# coverage is a superset of the R1 conversion tuple; the seam still wraps
# timeouts in URLError anyway so ``str(exc)`` stays informative.
_RETRYABLE_TRANSPORT_ERRORS: tuple[type, ...] = (
    urllib.error.URLError,
    OSError,
    http.client.HTTPException,
)


class CrtshError(Exception):
    """Raised when a crt.sh request ultimately fails or returns an error body."""


# parity guard: reproduces legacy httpx follow_redirects=False (VERIFIED from
# the tag — client.py never passed the flag; the httpx 0.28.1 default is
# False); urllib's default WOULD be the drift.
class _RedirectNotFollowed(urllib.error.HTTPError):
    """urllib would follow this redirect; legacy httpx (follow_redirects=False) did not."""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Opener handler that refuses to follow any 3xx.

    Raising from ``redirect_request`` covers 301/302/303/307/308 — they all
    route through this single choke point.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # single choke point
        raise _RedirectNotFollowed(req.full_url, code, msg, headers, fp)


def _build_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_NoRedirectHandler)


# Module-level singleton, created lazily: the opener is stateless (no
# connection pool to hold — the legacy httpx client handle is gone), so one
# shared instance is enough and nothing happens at import time.
_OPENER: urllib.request.OpenerDirector | None = None


def _get_opener() -> urllib.request.OpenerDirector:
    global _OPENER
    if _OPENER is None:
        _OPENER = _build_opener()
    return _OPENER


# A valid hostname: one or more dot-separated labels, each label starting and
# ending with an alphanumeric character, with hyphens allowed in the middle.
# Rejects spaces, @, and other special characters that appear in cert CN/SAN
# strings but are not valid hostnames (e.g. "subjectname@example.com",
# "as207960 test intermediate - example.com").
_HOSTNAME_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$"
)


def extract_subdomains(results: list[dict[str, Any]]) -> list[str]:
    """Extract a sorted list of unique subdomains from a search result set.

    Each result's ``name_value`` field is a newline-delimited list of all
    names the certificate covers (CN + SANs). Wildcard entries such as
    ``*.example.com`` are reduced to their base domain (``example.com``).
    Entries that are not valid hostnames (containing spaces, ``@``, or other
    special characters) are filtered out — these are cert CN/SAN strings,
    not subdomains.

    Args:
        results: A list of certificate dicts as returned by
            :meth:`CrtshClient.search`.

    Returns:
        A sorted list of unique valid domain names.
    """
    seen: set[str] = set()
    for entry in results:
        name_value = entry.get("name_value") or ""
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if not name:
                continue
            # Reduce wildcard entries to their base domain.
            if name.startswith("*."):
                name = name[2:]
            # Skip bare wildcards and anything that isn't a valid hostname.
            if not name or name == "*" or not _HOSTNAME_RE.match(name):
                continue
            seen.add(name)
    return sorted(seen)


class CrtshClient:
    """Sync wrapper around the crt.sh JSON search endpoint.

    Responses are cached in-memory keyed by the query string, with a
    per-call configurable TTL. The cache is a plain dict mapping
    ``cache_key -> (timestamp, data)``.
    """

    def __init__(
        self,
        base_url: str = BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.base_url = base_url
        self.timeout = timeout
        # cache_key -> (timestamp, data)
        self._cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}

    def clear_cache(self) -> None:
        self._cache.clear()

    def search(
        self,
        query: str,
        cache_ttl: int = DEFAULT_CACHE_TTL,
        exclude_expired: bool = False,
    ) -> list[dict[str, Any]]:
        """Search crt.sh for certificates matching an identity string.

        Args:
            query: A domain, wildcard (``%.example.com``), or organisation
                name. The ``%`` SQL LIKE wildcard is supported and will be
                URL-encoded automatically.
            cache_ttl: Seconds to cache this result. Pass ``0`` to bypass
                the cache entirely.
            exclude_expired: When True, append ``exclude=expired`` to drop
                expired certificates from the results.

        Returns:
            A list of certificate dicts. May be empty (``[]``) when no
            certificates match — this is distinct from a request failure.

        Raises:
            CrtshError: If all retries are exhausted, or crt.sh returns an
                error body (e.g. "Unsupported output type: json").
        """
        if not isinstance(query, str) or not query.strip():
            raise ValueError("query must be a non-empty string")

        # Build the query string. quote() with safe="" encodes "%" -> "%25"
        # which is exactly what crt.sh expects for the LIKE wildcard.
        params = f"q={quote(query, safe='')}&output=json"
        if exclude_expired:
            params += "&exclude=expired"
        path = f"/?{params}"

        cache_key = path
        now = time.monotonic()

        if cache_ttl > 0:
            cached = self._cache.get(cache_key)
            if cached is not None:
                ts, data = cached
                if now - ts < cache_ttl:
                    # Return a deep copy so callers cannot mutate the cached
                    # data (the cache stores the canonical list of dicts).
                    return copy.deepcopy(data)

        data = self._fetch_with_retries(path)

        if cache_ttl > 0:
            self._cache[cache_key] = (time.monotonic(), data)
            self._evict_if_needed()
        # Return a copy of freshly-fetched data too, for a consistent contract
        # (callers may mutate the result without affecting the cached copy).
        return copy.deepcopy(data)

    def _evict_if_needed(self) -> None:
        """Drop the oldest cache entries when the cache exceeds MAX_CACHE_SIZE."""
        if len(self._cache) <= MAX_CACHE_SIZE:
            return
        # Order keys by timestamp (oldest first) and remove the excess.
        ordered = sorted(self._cache, key=lambda k: self._cache[k][0])
        excess = len(self._cache) - MAX_CACHE_SIZE
        for key in ordered[:excess]:
            del self._cache[key]

    def _raw_get(self, path: str) -> tuple[int, str]:
        """Single-GET transport seam: returns ``(status, body_text)``.

        Error-mapping table (legacy httpx -> urllib; this is the R2
        fleet-standard seam contract — feeding protocol errors into the ladder
        is an intentional deviation, friendly-text parity is preserved):

        | legacy httpx raised here | old behaviour | new urllib condition | new behaviour |
        |---|---|---|---|
        | `httpx.TimeoutException` (incl. `ConnectTimeout`) | retried (tuple member) | `TimeoutError` / `socket.timeout` → wrapped `URLError` | retried (parity) |
        | `httpx.ConnectError` / `NetworkError` | retried | `URLError` (DNS/refused), `ConnectionError`, `OSError` | retried (parity) |
        | `httpx.RemoteProtocolError` (incomplete read, bad chunking) | **NOT retried** — escaped `_fetch_with_retries`, folded to `Error: …` by server handlers in ONE attempt | `http.client.HTTPException` (`IncompleteRead`, `BadStatusLine`, `RemoteDisconnected`→`ConnectionError`) | **fed into the retry ladder — R2 fleet standard, intentional deviation, friendly-text parity preserved** |
        | `httpx.TooManyRedirects` | n/a (never follows) | `_RedirectNotFollowed` → returned as a 3xx status | `CrtshError("crt.sh request failed with HTTP 3xx")` in ONE attempt (parity) |

        Deviation statement (facts re-verified from the tag at pin time, not
        from prose — `git show pre-migration/20260914`): Legacy (tag
        `pre-migration/20260914`, client.py:219) retried only
        `(httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError)`.
        `httpx.RemoteProtocolError` sits on a SIBLING branch (TransportError) —
        legacy did NOT feed it into the retry ladder; it escaped to the server
        handlers and was folded into friendly `Error: …` text in ONE attempt
        (server.py:110/141/184, httpx.HTTPError catch). Post-migration,
        protocol errors (`http.client.HTTPException`, incl.
        `RemoteDisconnected`/`IncompleteRead`/`BadStatusLine`) ARE fed into
        the ladder: this is the R2 fleet standard — a documented intentional
        deviation, with friendly-text parity preserved (ladder exhaustion
        still surfaces as `CrtshError` → `Error: …` tool text, never
        `-32603`). This is NOT "exactly as legacy" and must never be claimed
        as such.
        """
        url = self.base_url + path
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        try:
            with _get_opener().open(req, timeout=self.timeout) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:  # 4xx/5xx AND our _RedirectNotFollowed: real status
            return e.code, e.read().decode("utf-8", "replace")
        except TimeoutError as e:  # R1: py3.11 socket.timeout IS TimeoutError,
            raise urllib.error.URLError(e) from e  # NOT a URLError subclass — convert at the seam
        except (urllib.error.URLError, OSError, http.client.HTTPException):
            # Already ladder-classified members of _RETRYABLE_TRANSPORT_ERRORS
            # — see the mapping table above; propagate unchanged.
            raise

    def _fetch_with_retries(self, path: str) -> list[dict[str, Any]]:
        """GET ``path`` retrying transient failures with exponential backoff."""
        last_error: Exception | None = None
        not_found_retries = 0  # separate, lower cap for transient 404s

        for attempt in range(MAX_RETRIES + 1):
            if attempt > 0:
                delay = BACKOFF_BASE * (2 ** (attempt - 1))
                time.sleep(delay)
            try:
                status, text = self._raw_get(path)
            except _RETRYABLE_TRANSPORT_ERRORS as exc:
                # Protocol errors (http.client.HTTPException) land here too:
                # legacy (tag client.py:219) did NOT retry them — feeding them
                # into the ladder is the R2 fleet standard, a documented
                # intentional deviation with friendly-text parity preserved
                # (exhaustion surfaces as CrtshError → `Error: …` tool text,
                # never `-32603`). See the `_raw_get` mapping table.
                last_error = exc
                continue

            if status in RETRYABLE_STATUS:
                last_error = CrtshError(
                    f"crt.sh returned HTTP {status} (overloaded)"
                )
                continue

            # crt.sh misuses 404 as a transient "overloaded" signal under load
            # (see MAX_404_RETRIES above), so retry it — but with a lower cap
            # than 502/503 since a 404 is more likely to be genuine.
            if status == 404:
                not_found_retries += 1
                last_error = CrtshError(
                    "crt.sh returned HTTP 404 (possibly transient overload)"
                )
                if not_found_retries > MAX_404_RETRIES:
                    raise CrtshError(
                        "crt.sh request failed with HTTP 404"
                    )
                continue

            # Non-retryable status codes fail immediately.
            if status != 200:
                raise CrtshError(
                    f"crt.sh request failed with HTTP {status}"
                )

            return self._parse_body(status, text)

        raise CrtshError(
            f"crt.sh unavailable after {MAX_RETRIES + 1} attempts — "
            f"the service is likely overloaded, retry shortly. "
            f"Last error: {last_error}"
        )

    @staticmethod
    def _parse_body(status: int, text: str) -> list[dict[str, Any]]:
        """Parse a 200 response body into a list of certificate dicts.

        Detects the "Unsupported output type: json" error body that crt.sh
        returns (with HTTP 200) for fingerprint / serial / ID lookups.
        """
        text = text.strip()

        # crt.sh returns an HTML fragment for unsupported JSON lookups.
        if "Unsupported output type" in text:
            raise CrtshError(
                "crt.sh does not support JSON output for this lookup "
                "(fingerprint, serial, and ID lookups are HTML-only)"
            )

        if not text:
            return []

        try:
            data = json.loads(text)
        except ValueError as exc:
            raise CrtshError(
                "crt.sh returned a non-JSON response — the service may be "
                f"overloaded. Raw body start: {text[:120]!r}"
            ) from exc

        if not isinstance(data, list):
            raise CrtshError(
                f"Unexpected crt.sh response shape: expected a JSON array, "
                f"got {type(data).__name__}"
            )
        return data
