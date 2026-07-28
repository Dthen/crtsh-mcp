"""FastMCP server exposing crt.sh Certificate Transparency search as MCP tools."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "crtsh",
    instructions=(
        "Certificate Transparency log search via crt.sh — discover SSL/TLS "
        "certs, subdomains, and cert history for any domain"
    ),
)


def main() -> None:
    """Entry point for running the server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
