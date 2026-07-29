"""FastMCP server exposing crt.sh Certificate Transparency search as MCP tools."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

from crtsh_mcp.client import CrtshClient, CrtshError, extract_subdomains

# crt.sh caps query results at ~999 rows with no pagination. When a search
# returns this many rows the true result set is almost certainly larger, so we
# flag it as truncated rather than silently pretending the list is complete.
CRTSH_ROW_CAP = 999


@asynccontextmanager
async def _lifespan(app: FastMCP):
    """Manage the shared client's lifecycle: yield on startup, close on shutdown."""
    try:
        yield
    finally:
        await _client.aclose()


mcp = FastMCP(
    "crtsh",
    instructions=(
        "Certificate Transparency log search via crt.sh — discover SSL/TLS "
        "certs, subdomains, and cert history for any domain"
    ),
    lifespan=_lifespan,
)

# Single shared client instance (module-level).
_client = CrtshClient()


async def close_client() -> None:
    """Close the shared HTTP client. Called on server shutdown via the lifespan."""
    await _client.aclose()


def _normalize_domain(domain: str) -> str:
    """Normalize a user-supplied domain into a bare base domain.

    Strips a leading ``*.`` or ``%.`` wildcard prefix, a trailing ``.``,
    surrounding whitespace, and lowercases. So ``"*.Example.COM."`` becomes
    ``"example.com"``. This lets callers pass wildcards or FQDNs without
    producing a malformed ``%.`` query that silently returns zero results.
    """
    d = domain.strip().lower()
    for prefix in ("*.", "%.", "."):
        if d.startswith(prefix):
            d = d[len(prefix):]
            break
    return d.rstrip(".")


@mcp.tool()
async def search_certificates(query: str, limit: int = 50) -> dict[str, Any] | str:
    """Search Certificate Transparency logs for SSL/TLS certificates matching a domain or identity. Use % as wildcard (e.g. '%.example.com' for all subdomains). Returns certificate details including issuer, validity dates, and subject alternative names.

    Args:
        query: A domain, wildcard (``%.example.com``), or organisation name
            to search for in Certificate Transparency logs.
        limit: Maximum number of results to return (default 50). crt.sh can
            return up to 999 rows; results are truncated to this limit to
            avoid flooding the context window.

    Returns an object with ``count`` (number of certificates returned),
    ``total_found`` (rows crt.sh returned before truncation), ``truncated``
    (True when results were cut off — either by ``limit`` or by crt.sh's
    ~999-row cap), an optional ``note`` explaining the truncation, and
    ``certificates`` (the list of certificate dicts). Each certificate has
    issuer_name, common_name, name_value (SANs), id, entry_timestamp,
    not_before, not_after, and serial_number fields.
    """
    try:
        results = await _client.search(query)
        total_found = len(results)
        truncated = total_found > limit or total_found >= CRTSH_ROW_CAP
        certificates = results[:limit]
        out: dict[str, Any] = {
            "count": len(certificates),
            "total_found": total_found,
            "truncated": truncated,
            "certificates": certificates,
        }
        if truncated:
            if total_found >= CRTSH_ROW_CAP:
                out["note"] = (
                    f"crt.sh returned {total_found} rows, hitting its ~{CRTSH_ROW_CAP}-row "
                    "cap with no pagination — the true result set is likely larger. "
                    "Narrow the query (e.g. a more specific subdomain) for complete results."
                )
            else:
                out["note"] = (
                    f"{total_found} certificates matched but only the first {len(certificates)} "
                    f"were returned (limit={limit}). Raise 'limit' to see more."
                )
        return out
    except (CrtshError, httpx.HTTPError) as e:
        return f"Error: {e}"


@mcp.tool()
async def discover_subdomains(domain: str) -> dict[str, Any] | str:
    """Discover all known subdomains for a domain by searching Certificate Transparency logs. Returns a deduplicated, sorted list of subdomain names.

    Args:
        domain: The base domain to enumerate subdomains for (e.g. "example.com").
            Wildcard prefixes ("*.example.com", "%.example.com"), a trailing
            dot, and mixed case are all normalized automatically.

    Returns an object with the domain, the number of unique subdomains found,
    the sorted list of subdomain names, and a ``truncated`` flag (True when
    the underlying crt.sh search hit its ~999-row cap, meaning more subdomains
    likely exist than shown). Returns an ``Error:`` string for a degenerate
    domain that normalizes to empty (e.g. "", "   ", ".").
    """
    normalized = _normalize_domain(domain)
    if not normalized:
        return "Error: invalid domain"
    try:
        results = await _client.search(f"%.{normalized}")
        subdomains = extract_subdomains(results)
        return {
            "domain": normalized,
            "subdomain_count": len(subdomains),
            "subdomains": subdomains,
            "truncated": len(results) >= CRTSH_ROW_CAP,
        }
    except (CrtshError, httpx.HTTPError) as e:
        return f"Error: {e}"


@mcp.tool()
async def get_certificate_details(domain: str) -> dict[str, Any] | str:
    """Get detailed certificate information for a domain, including issuer, validity period, serial number, and all subject alternative names. Returns the most recent certificates first.

    Args:
        domain: The domain to look up certificate details for (e.g. "example.com").

    Returns an object with ``count`` (number of certificates returned, up to
    20), ``total_found`` (certificates crt.sh returned before truncation),
    ``truncated`` (True when more than 20 certificates exist and only the 20
    most recent were returned), an optional ``note`` explaining the truncation,
    and ``certificates`` (a list of up to 20 certificate dicts sorted by
    entry_timestamp descending, most recently logged first). Returns an
    ``Error:`` string for a degenerate domain that normalizes to empty.
    """
    normalized = _normalize_domain(domain)
    if not normalized:
        return "Error: invalid domain"
    try:
        results = await _client.search(normalized)
        total_found = len(results)
        # Sort a COPY — the client cache returns its list by reference, so
        # sorting in place would corrupt the cached data for other callers.
        certificates = sorted(
            results, key=lambda c: c.get("entry_timestamp") or "", reverse=True
        )[:20]
        truncated = total_found > 20
        out: dict[str, Any] = {
            "count": len(certificates),
            "total_found": total_found,
            "truncated": truncated,
            "certificates": certificates,
        }
        if truncated:
            out["note"] = (
                f"{total_found} certificates matched but only the 20 most recent "
                "were returned. Narrow the domain for a complete view."
            )
        return out
    except (CrtshError, httpx.HTTPError) as e:
        return f"Error: {e}"


def main() -> None:
    """Entry point for running the server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
