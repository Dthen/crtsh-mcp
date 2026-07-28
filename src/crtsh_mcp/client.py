"""Async HTTP client for the crt.sh Certificate Transparency API.

crt.sh exposes a single JSON query endpoint (``?q=<identity>&output=json``)
with no authentication. The service is a free community resource that is
frequently overloaded, so this client retries transient failures (502/503,
timeouts, connection errors) with exponential backoff and caches responses
in-memory with a per-call TTL.

Only identity (domain / org) searches support JSON output. Fingerprint,
serial-number, and crt.sh-ID lookups are HTML-only and will raise
``CrtshError`` ("Unsupported output type") if attempted through this client.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any
from urllib.parse import quote

import httpx

BASE_URL = "https://crt.sh"

# Default request timeout (seconds). crt.sh is slow under load.
DEFAULT_TIMEOUT = 20.0

# Retry configuration for transient failures.
MAX_RETRIES = 3
BACKOFF_BASE = 1.0  # seconds; delays are 1s, 2s, 4s

# HTTP status codes that warrant a retry.
RETRYABLE_STATUS = {502, 503}

# Default cache TTL (seconds) for search results.
DEFAULT_CACHE_TTL = 300


class CrtshError(Exception):
    """Raised when a crt.sh request ultimately fails or returns an error body."""


def extract_subdomains(results: list[dict[str, Any]]) -> list[str]:
    """Extract a sorted list of unique subdomains from a search result set.

    Each result's ``name_value`` field is a newline-delimited list of all
    names the certificate covers (CN + SANs). Wildcard entries such as
    ``*.example.com`` are reduced to their base domain (``example.com``).

    Args:
        results: A list of certificate dicts as returned by
            :meth:`CrtshClient.search`.

    Returns:
        A sorted list of unique domain names.
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
            if name:
                seen.add(name)
    return sorted(seen)


class CrtshClient:
    """Async wrapper around the crt.sh JSON search endpoint.

    Responses are cached in-memory keyed by the query string, with a
    per-call configurable TTL. The cache is a plain dict mapping
    ``cache_key -> (timestamp, data)``.
    """

    def __init__(
        self,
        base_url: str = BASE_URL,
        client: httpx.AsyncClient | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.base_url = base_url
        if client is not None:
            self._client = client
        else:
            self._client = httpx.AsyncClient(
                base_url=base_url,
                timeout=timeout,
                headers={"User-Agent": "crtsh-mcp/0.1.0"},
            )
        self._owns_client = client is None
        # cache_key -> (timestamp, data)
        self._cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}

    async def __aenter__(self) -> "CrtshClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    def clear_cache(self) -> None:
        self._cache.clear()

    async def search(
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
                    return data

        data = await self._fetch_with_retries(path)

        if cache_ttl > 0:
            self._cache[cache_key] = (time.monotonic(), data)
        return data

    async def _fetch_with_retries(self, path: str) -> list[dict[str, Any]]:
        """GET ``path`` retrying transient failures with exponential backoff."""
        last_error: Exception | None = None

        for attempt in range(MAX_RETRIES + 1):
            if attempt > 0:
                delay = BACKOFF_BASE * (2 ** (attempt - 1))
                await asyncio.sleep(delay)
            try:
                response = await self._client.get(path)
            except (httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError) as exc:
                last_error = exc
                continue

            if response.status_code in RETRYABLE_STATUS:
                last_error = CrtshError(
                    f"crt.sh returned HTTP {response.status_code} (overloaded)"
                )
                continue

            # Non-retryable status codes fail immediately.
            if response.status_code != 200:
                raise CrtshError(
                    f"crt.sh request failed with HTTP {response.status_code}"
                )

            return self._parse_response(response)

        raise CrtshError(
            f"crt.sh unavailable after {MAX_RETRIES + 1} attempts — "
            f"the service is likely overloaded, retry shortly. "
            f"Last error: {last_error}"
        )

    @staticmethod
    def _parse_response(response: httpx.Response) -> list[dict[str, Any]]:
        """Parse a 200 response body into a list of certificate dicts.

        Detects the "Unsupported output type: json" error body that crt.sh
        returns (with HTTP 200) for fingerprint / serial / ID lookups.
        """
        text = response.text.strip()

        # crt.sh returns an HTML fragment for unsupported JSON lookups.
        if "Unsupported output type" in text:
            raise CrtshError(
                "crt.sh does not support JSON output for this lookup "
                "(fingerprint, serial, and ID lookups are HTML-only)"
            )

        if not text:
            return []

        try:
            data = response.json()
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
