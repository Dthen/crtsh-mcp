"""Smoke tests for the crt.sh MCP server skeleton."""


def test_import_mcp_instance():
    from crtsh_mcp.server import mcp

    assert mcp is not None


def test_server_name():
    from crtsh_mcp.server import mcp

    assert mcp.name == "crtsh"


def test_instructions_mention_crtsh():
    from crtsh_mcp.server import mcp

    assert "crt.sh" in mcp.instructions
    assert "Certificate Transparency" in mcp.instructions
