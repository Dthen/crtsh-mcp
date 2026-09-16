#!/usr/bin/env python3
"""crt.sh Certificate Transparency search as a stateless 2026-07-28 era MCP server.

Stdlib-only newline-delimited JSON-RPC over stdio — REFERENCE §1–§7 copied
verbatim (migration card T07, PLAN D2/D3/D4/D5). Tool descriptions/schemas are
byte-frozen from golden/crtsh.tools.json with outputSchema/_meta stripped
(§4 trap: no outputSchema ⇒ no structuredContent requirement).
"""

import json, sys, urllib.error

if hasattr(sys.stdin, "reconfigure"):            # binary/undecodable bytes must not kill the loop
    sys.stdin.reconfigure(errors="replace")      # invalid UTF-8 → U+FFFD → lands in the json.loads except

from crtsh_mcp.client import CrtshClient, CrtshError, extract_subdomains

ERA_VERSION = "2026-07-28"
SERVER_INFO = {"name": "crtsh", "version": "0.3.0"}          # keep in sync with pyproject.toml [project] version (T00 note: legacy fastmcp self-reported 3.4.7 — not copied)
ERA_RESULT_FIELDS = {"resultType": "complete", "ttlMs": 0, "cacheScope": "private"}
RESULT_META = {"io.modelcontextprotocol/serverInfo": SERVER_INFO}     # spec-RECOMMENDED stamp, optional

# crt.sh caps query results at ~999 rows with no pagination. When a search
# returns this many rows the true result set is almost certainly larger, so we
# flag it as truncated rather than silently pretending the list is complete.
CRTSH_ROW_CAP = 999


def send(resp):
    sys.stdout.write(json.dumps(resp) + "\n")   # exactly one object per line
    sys.stdout.flush()                          # a buffered reply = a client timeout


def era_result(payload):
    """A result carrying the era-strict fields D3 mandates on every response."""
    out = dict(payload)
    out.update(ERA_RESULT_FIELDS)
    out["_meta"] = RESULT_META
    return out


# Single shared client instance (module-level). urllib opens per-request —
# nothing to hold, so the legacy shared-handle teardown (PLAN D5) is deleted
# outright; no replacement cleanup exists or is needed.
_client = CrtshClient()


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


def search_certificates(query: str, limit: int = 50) -> dict | str:
    # Tool logic copied from pre-migration/20260914; description/schema frozen
    # in TOOLS below (golden/crtsh.tools.json).
    query = query.strip()
    if not query:
        return "Error: please provide a search query"
    if limit < 1:
        return "Error: limit must be a positive integer"
    try:
        results = _client.search(query)
        total_found = len(results)
        truncated = total_found > limit or total_found >= CRTSH_ROW_CAP
        certificates = results[:limit]
        out: dict = {
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
    # parity: legacy caught (CrtshError, httpx.HTTPError); post-R1/R2 seam all transport
    # errors arrive as URLError/OSError/HTTPException-derived → ladder → CrtshError.
    # Friendly text preserved — the R2 deviation cannot leak a -32603 from here.
    # (URLError named explicitly for readers; HTTPError ⊂ URLError ⊂ OSError.)
    except (CrtshError, urllib.error.URLError, OSError) as e:
        return f"Error: {e}"


def discover_subdomains(domain: str) -> dict | str:
    normalized = _normalize_domain(domain)
    if not normalized:
        return "Error: invalid domain"
    try:
        results = _client.search(f"%.{normalized}")
        subdomains = extract_subdomains(results)
        return {
            "domain": normalized,
            "subdomain_count": len(subdomains),
            "subdomains": subdomains,
            "truncated": len(results) >= CRTSH_ROW_CAP,
        }
    except (CrtshError, urllib.error.URLError, OSError) as e:
        return f"Error: {e}"


def get_certificate_details(domain: str) -> dict | str:
    normalized = _normalize_domain(domain)
    if not normalized:
        return "Error: invalid domain"
    try:
        results = _client.search(normalized)
        total_found = len(results)
        # sorted() already returns a copy; the client ALSO hands out deep copies
        # (see test_cache_returns_copies_not_references) — belt-and-braces, not necessity.
        certificates = sorted(
            results, key=lambda c: c.get("entry_timestamp") or "", reverse=True
        )[:20]
        truncated = total_found > 20
        out: dict = {
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
    except (CrtshError, urllib.error.URLError, OSError) as e:
        return f"Error: {e}"


# TOOLS — D4 byte-freeze: 3 entries {name, description, inputSchema} extracted
# from golden/crtsh.tools.json with outputSchema and _meta stripped (§4 trap).
# The era suite's golden byte-identity test is the live proof.
TOOLS = [
    {
        "name": "search_certificates",
        "description": "Search Certificate Transparency logs for SSL/TLS certificates matching a domain or identity. Use % as wildcard (e.g. '%.example.com' for all subdomains). Returns certificate details including issuer, validity dates, and subject alternative names.",
        "inputSchema": {
            "additionalProperties": False,
            "properties": {
                "query": {"type": "string", "description": "A domain, wildcard (``%.example.com``), or organisation name\nto search for in Certificate Transparency logs."},
                "limit": {"default": 50, "type": "integer", "description": "Maximum number of results to return (default 50). crt.sh can\nreturn up to 999 rows; results are truncated to this limit to\navoid flooding the context window."}
            },
            "required": ["query"],
            "type": "object"
        },
    },
    {
        "name": "discover_subdomains",
        "description": "Discover all known subdomains for a domain by searching Certificate Transparency logs. Returns a deduplicated, sorted list of subdomain names.",
        "inputSchema": {
            "additionalProperties": False,
            "properties": {
                "domain": {"type": "string", "description": "The base domain to enumerate subdomains for (e.g. \"example.com\").\nWildcard prefixes (\"*.example.com\", \"%.example.com\"), a trailing\ndot, and mixed case are all normalized automatically."}
            },
            "required": ["domain"],
            "type": "object"
        },
    },
    {
        "name": "get_certificate_details",
        "description": "Get detailed certificate information for a domain, including issuer, validity period, serial number, and all subject alternative names. Returns the most recent certificates first.",
        "inputSchema": {
            "additionalProperties": False,
            "properties": {
                "domain": {"type": "string", "description": "The domain to look up certificate details for (e.g. \"example.com\")."}
            },
            "required": ["domain"],
            "type": "object"
        },
    },
]


def handle_call(name: str, args) -> dict | str:
    """Dispatch one tools/call (§5): bad arguments and unknown names return
    {"error": ...} dicts → the isError heuristic flips the flag; never crashes."""
    if not isinstance(args, dict):
        return {"error": "arguments must be an object"}
    try:
        if name == "search_certificates":
            query = args.get("query") or ""   # missing/None → "" → legacy "please provide a search query" guard fires
            if not isinstance(query, str):    # §5 fold: non-string args → error dict, never -32603
                return {"error": "query must be a string"}
            return search_certificates(query, args.get("limit", 50))
        if name == "discover_subdomains" or name == "get_certificate_details":
            domain = args.get("domain") or ""
            if not isinstance(domain, str):
                return {"error": "domain must be a string"}
            return discover_subdomains(domain) if name == "discover_subdomains" else get_certificate_details(domain)
    except (TypeError, ValueError, AttributeError) as e:
        # §5: bad-argument errors are result dicts (isError → LLM can self-correct),
        # never a -32603. AttributeError covers .strip() on non-str args that slip
        # past the isinstance gates (defensive belt for any future arg path).
        return {"error": str(e)}
    return {"error": f"Unknown tool: {name}"}


def main():
    for line in sys.stdin:                      # EOF on stdin ends the loop (see §7)
        line = line.strip()
        if not line: continue
        try: req = json.loads(line)
        except Exception: continue              # garbage lines: skip, NEVER die (§7)
        if not isinstance(req, dict): continue  # valid JSON, not an object ("5", null, [1,2]): skip, NEVER die (§7)
        rid = req.get("id")                     # str or int; absent ⇒ notification
        method = req.get("method")              # null/42/etc must not crash .startswith below
        if not isinstance(method, str): method = ""   # route as unknown-method
        if method == "server/discover":
            send({"jsonrpc": "2.0", "id": rid, "result": era_result({
                "supportedVersions": [ERA_VERSION],
                "capabilities": {"tools": {}}})})                    # §2
        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": rid, "result": era_result({"tools": TOOLS})})  # §4
        elif method == "tools/call":
            params = req.get("params")
            if not isinstance(params, dict) or not isinstance(params.get("name"), str):
                send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32602,
                    "message": "missing required param: params (with string 'name')"}})
                continue
            try:
                result = handle_call(params["name"], params.get("arguments", {}))
                is_err = isinstance(result, dict) and ("error" in result or "transport_error" in result)
                # REFERENCE §5 text-encoding rule (fastmcp-3.x migration; bytes captured in
                # golden/crtsh.characterization.json by T06): dict results serialize as compact,
                # non-ASCII-preserving JSON; str results pass through verbatim. Per §5's closing
                # note + R3 this is a pattern decision rule, not loop drift — never tagged.
                text = result if isinstance(result, str) else json.dumps(
                    result, separators=(",", ":"), ensure_ascii=False)
                payload: dict = {"content": [{"type": "text", "text": text}]}
                if is_err:
                    payload["isError"] = True
                send({"jsonrpc": "2.0", "id": rid, "result": era_result(payload)})
            except Exception as e:                       # dispatch-level only (shouldn't happen)
                send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32603, "message": str(e)}})
        elif method.startswith("notifications/"):
            pass                                         # §6: client notifications consumed silently
        elif method == "ping":
            send({"jsonrpc": "2.0", "id": rid, "result": {}})   # §6: keepalive → empty result
        else:
            # includes legacy `initialize` (D2) and every other unknown method, per JSON-RPC (§3)
            if rid is None and "id" not in req: continue   # no-id = notification: never respond
            send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601,
                "message": f"Method not found: {method}"}})


if __name__ == "__main__":
    main()
