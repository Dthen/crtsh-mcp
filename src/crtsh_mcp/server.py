"""FastMCP server exposing crt.sh Certificate Transparency search as MCP tools."""

from __future__ import annotations

from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

from crtsh_mcp.client import CrtshClient, CrtshError, extract_subdomains

mcp = FastMCP(
    "crtsh",
    instructions=(
        "Certificate Transparency log search via crt.sh — discover SSL/TLS "
        "certs, subdomains, and cert history for any domain"
    ),
)

# Single shared client instance (module-level).
_client = CrtshClient()


@mcp.tool()
async def search_certificates(query: str, limit: int = 50) -> list[dict[str, Any]] | str:
    """Search Certificate Transparency logs for SSL/TLS certificates matching a domain or identity. Use % as wildcard (e.g. '%.example.com' for all subdomains). Returns certificate details including issuer, validity dates, and subject alternative names.

    Args:
        query: A domain, wildcard (``%.example.com``), or organisation name
            to search for in Certificate Transparency logs.
        limit: Maximum number of results to return (default 50). crt.sh can
            return up to 999 rows; results are truncated to this limit to
            avoid flooding the context window.

    Returns a list of certificate dicts, each with issuer_name, common_name,
    name_value (SANs), id, entry_timestamp, not_before, not_after, and
    serial_number fields.
    """
    try:
        results = await _client.search(query)
        return results[:limit]
    except (CrtshError, httpx.HTTPError) as e:
        return f"Error: {e}"


@mcp.tool()
async def discover_subdomains(domain: str) -> dict[str, Any] | str:
    """Discover all known subdomains for a domain by searching Certificate Transparency logs. Returns a deduplicated, sorted list of subdomain names.

    Args:
        domain: The base domain to enumerate subdomains for (e.g. "example.com").

    Returns an object with the domain, the number of unique subdomains found,
    and the sorted list of subdomain names.
    """
    try:
        results = await _client.search(f"%.{domain}")
        subdomains = extract_subdomains(results)
        return {
            "domain": domain,
            "subdomain_count": len(subdomains),
            "subdomains": subdomains,
        }
    except (CrtshError, httpx.HTTPError) as e:
        return f"Error: {e}"


@mcp.tool()
async def get_certificate_details(domain: str) -> list[dict[str, Any]] | str:
    """Get detailed certificate information for a domain, including issuer, validity period, serial number, and all subject alternative names. Returns the most recent certificates first.

    Args:
        domain: The domain to look up certificate details for (e.g. "example.com").

    Returns a list of up to 20 certificate dicts, sorted by entry_timestamp
    descending (most recently logged first).
    """
    try:
        results = await _client.search(domain)
        results.sort(key=lambda c: c.get("entry_timestamp") or "", reverse=True)
        return results[:20]
    except (CrtshError, httpx.HTTPError) as e:
        return f"Error: {e}"


def main() -> None:
    """Entry point for running the server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
