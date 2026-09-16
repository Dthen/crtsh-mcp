"""Smoke tests for the crt.sh MCP server module (era rewrite, T08).

Legacy smokes targeted the deleted fastmcp object (``server.mcp``); the
era-equivalent surface is the module constants SERVER_INFO / TOOLS (the
byte-freeze of the tool surface lives in test_stateless_era.py's golden
comparison — these are cheap import/shape smokes, 3 -> 3, no shrink).
"""


def test_module_imports():
    import crtsh_mcp.server  # noqa: F401


def test_server_info_name():
    from crtsh_mcp.server import SERVER_INFO

    assert SERVER_INFO["name"] == "crtsh"  # legacy mcp.name parity


def test_tools_surface_is_three():
    from crtsh_mcp.server import TOOLS

    assert [t["name"] for t in TOOLS] == [
        "search_certificates",
        "discover_subdomains",
        "get_certificate_details",
    ]
