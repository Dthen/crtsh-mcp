# crt.sh MCP Server

MCP server wrapping [crt.sh](https://crt.sh) — Certificate Transparency log search. Every SSL/TLS certificate ever publicly issued, searchable by domain, organisation, or fingerprint.

## Why

- Zero existing MCP coverage — lots of CLI tools and Python scripts, but nobody's wrapped it
- Genuinely useful OSINT/security tool: subdomain enumeration, discovering forgotten dev/staging servers, tracking org infrastructure changes, cert history forensics
- Dead simple API: `https://crt.sh/?q=example.com&output=json`

## API Notes

- **Auth:** None. Free. No key.
- **Rate limits:** ~60 req/min per IP (unpublished, confirmed via their Google Group)
- **Also exposes:** A public PostgreSQL interface for heavier queries
- **Output:** JSON array — issuer, dates, common names, serial numbers, fingerprint

## Rough Tool Ideas

- `search_certificates(domain)` — all certs for a domain (including wildcards)
- `search_by_org(organisation)` — certs by org name
- `get_certificate(id)` — full details for a specific cert
- `subdomain_discovery(domain)` — extract unique subdomains from cert history
- `cert_history(domain)` — timeline of cert issuance for a domain

## Status

⚠️ **Before proceeding:** This needs proper research and planning before any code is written. Use the `plan` skill for a thorough execution plan and `subagent-driven-development` for implementation. Research first, build second.

### Research TODO
- [ ] Confirm all API endpoints, parameters, and response shapes
- [ ] Test rate limits and error handling behaviour
- [ ] Investigate the PostgreSQL interface as an alternative
- [ ] Check pagination behaviour (known 999-result cap on some queries)
- [ ] Survey existing CLI tools for feature inspiration
- [ ] Decide: TypeScript or Python?
