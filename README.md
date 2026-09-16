# crt.sh MCP Server

MCP server wrapping [crt.sh](https://crt.sh) — Certificate Transparency log search. Every SSL/TLS certificate ever publicly issued, searchable by domain, wildcard, or organisation.

## Tools

- **search_certificates(query, limit=50)** — Search CT logs for certificates matching a domain, wildcard (`%.example.com`), or organisation name. Returns an object with `count`, `total_found`, `truncated`, an optional `note`, and the `certificates` list (issuer, common name, SANs, validity dates, serial number).
- **discover_subdomains(domain)** — Enumerate all known subdomains for a domain from cert history. Input is normalized automatically (`*.example.com`, `%.example.com`, `example.com.`, and mixed case all work). Returns `{domain, subdomain_count, subdomains, truncated}`.
- **get_certificate_details(domain)** — Detailed certificate info for a domain, most recently logged first (up to 20).

## Features

- No API key required — crt.sh is free and unauthenticated
- Automatic retry with exponential backoff (crt.sh is frequently overloaded — 502s, 404s, and timeouts are retried)
- In-memory TTL cache (5 min) to avoid hammering the service
- Wildcard subdomain discovery with input normalization
- Result truncation with an explicit `truncated` flag — crt.sh caps queries at ~999 rows with no pagination, so the server tells you when results may be incomplete

## Install

```bash
cd crtsh-mcp
pip install -e .
```

## Configure (Hermes)

Add to your Hermes `config.yaml` under `mcp_servers`:

```yaml
mcp_servers:
  crtsh:
    command: /absolute/path/to/crtsh-mcp/.venv/bin/python3
    args: ["-m", "crtsh_mcp.server"]
```

The server is stdlib-only (zero runtime dependencies) and speaks the 2026-07-28
stateless era (`server/discover`; a legacy `initialize` answers `-32601`); retry/
backoff/TTL-cache/redirect semantics are documented in the `src/crtsh_mcp/client.py`
header. Set up the venv once:

```bash
cd crtsh-mcp
python3 -m venv .venv
.venv/bin/pip install -e .
```

Or for Claude Desktop / other MCP clients:

```json
{
  "mcpServers": {
    "crtsh": {
      "command": "python3",
      "args": ["-m", "crtsh_mcp.server"]
    }
  }
}
```

## Development

```bash
pip install -e ".[dev]"
python -m pytest
```

Run `python -m pytest` from the repo root — the suite covers both `tests/` and the
root-level `test_stateless_era.py` era suite.

## API Notes

- **Source:** https://crt.sh (`?q=<identity>&output=json`)
- **Auth:** None
- **Rate limits:** ~60 req/min per IP (unpublished)
- **Reliability:** Flaky — a free community resource that is often overloaded. Expect intermittent 502s, 404s, and timeouts; this server retries transient failures automatically with backoff (1s, 2s, 4s).
- **Result cap:** ~999 rows per query, no pagination. The `truncated` flag signals when this cap (or your `limit`) cut results off.
- **Wildcards:** `%` is the SQL LIKE wildcard (`%.example.com` matches all subdomains). Only identity/org searches support JSON output; fingerprint, serial, and crt.sh-ID lookups are HTML-only and unsupported here.

> **Note:** crt.sh is rate-limited and flaky. The server retries automatically, but if it reports the service as unavailable, wait a moment and try again.

## Migration note (2026-09-14, card B.3)

The server shed its MCP framework layer: it is now stdlib-only (zero runtime
dependencies) and speaks the stateless 2026-07-28 era; `pre-migration/20260914` is
the rollback anchor for the old code. The User-Agent in `client.py` remains the
legacy literal `crtsh-mcp/0.1.0`; pinned by tests.

## MIGRATION-NOTES (cutover hand-off — card B.3 / T10; NOT executed here)

```
server key: crtsh — config.yaml:970-975 today:
  command: .../mcp-venvs/crtsh-mcp/bin/python3 ; args: [-m, crtsh_mcp.server]
target after cutover (D.1 flips, ONE restart window; keep old venv until D.1b):
  command: /mnt/HC_Volume_105667182/kimbo/mcp-venvs/crtsh-mcp-v2/bin/python3
  args: [-m, crtsh_mcp.server] ; protocol: stateless
```
