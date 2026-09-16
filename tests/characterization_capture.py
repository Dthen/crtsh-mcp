"""Characterize the legacy fastmcp server's tool-text bytes (crtsh-mcp T06).

Run under the OLD venv (that is the point — this server dies at T07):

    /mnt/HC_Volume_105667182/kimbo/mcp-venvs/crtsh-mcp/bin/python3 \
        tests/characterization_capture.py

Writes ``golden/crtsh.characterization.json`` and exits 0.

Network-free by construction (crt.sh is NEVER contacted):
  * in-process cases monkeypatch ``server_mod._client.search`` with canned
    fakes before every call — nothing below the seam can reach the network;
  * wire cases drive a spawned legacy server whose ``CrtshClient.search`` is
    patched (class-level, before the server module imports) to a canned async
    fake, and the error-string wire case uses the short-circuit args
    ``{"query": "  "}`` which return before the client is touched at all.

DEAD ONCE T07 LANDS: the rewrite commit deletes this file — it patches the
async API T07 kills, and once the golden is captured the fixture governs.
"""

from __future__ import annotations

import asyncio
import json
import os
import select
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO, "src")
GOLDEN_PATH = os.path.join(REPO, "golden", "crtsh.characterization.json")

if SRC not in sys.path:
    sys.path.insert(0, SRC)

import crtsh_mcp.server as server_mod  # noqa: E402
from crtsh_mcp.client import CrtshError  # noqa: E402

# One canned cert dict copied verbatim from tests/test_client.py:39-51.
SAMPLE = [
    {
        "issuer_ca_id": 413864,
        "issuer_name": "C=US, O=SSL Corporation, CN=Cloudflare TLS Issuing RSA CA 3",
        "common_name": "example.com",
        "name_value": "*.example.com\nexample.com",
        "id": 26787376238,
        "entry_timestamp": "2026-05-31T22:13:01.653",
        "not_before": "2026-05-31T21:39:00",
        "not_after": "2026-08-29T21:41:26",
        "serial_number": "27fd65644d90aa4763b6cfb53d6dcca3",
    }
]

# The exact message shape client.py:334-338 raises after the ladder is spent.
BOOM_MSG = (
    "crt.sh unavailable after 4 attempts — the service is likely overloaded, "
    "retry shortly. Last error: timed out"
)


def canned_rows(n: int) -> list[dict]:
    """Deterministic n-row variant of SAMPLE (no timestamps from the clock)."""
    rows = []
    base = SAMPLE[0]
    for i in range(n):
        r = dict(base)
        r["id"] = base["id"] + i
        r["entry_timestamp"] = f"2026-06-{(i % 28) + 1:02d}T00:00:{i % 60:02d}.000"
        r["common_name"] = f"c{i}.example.com"
        rows.append(r)
    return rows


# Importable case table: (name, arguments, search-mode, queries search must see).
CASES = [
    {"name": "search_certificates", "arguments": {"query": "example.com"},
     "mode": "sample", "queries": ["example.com"]},
    {"name": "search_certificates", "arguments": {"query": "  "},
     "mode": "short", "queries": []},
    {"name": "search_certificates", "arguments": {"query": "example.com", "limit": 0},
     "mode": "short", "queries": []},
    {"name": "discover_subdomains", "arguments": {"domain": "example.com"},
     "mode": "sample", "queries": ["%.example.com"]},
    {"name": "discover_subdomains", "arguments": {"domain": "."},
     "mode": "short", "queries": []},
    {"name": "get_certificate_details", "arguments": {"domain": "example.com"},
     "mode": "sample", "queries": ["example.com"]},
    {"name": "get_certificate_details", "arguments": {"domain": "example.com"},
     "mode": "rows25", "queries": ["example.com"]},
    {"name": "search_certificates", "arguments": {"query": "example.com"},
     "mode": "boom", "queries": ["example.com"]},
]


def compact(value) -> str:
    """REFERENCE §5 fastmcp-3.x text encoding candidate for a tool return."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def install_search(mode: str, log: list):
    """Patch the shared client's search with a canned async fake (no network)."""
    if mode == "boom":
        async def boom(query, cache_ttl=300, exclude_expired=False):
            log.append(query)
            raise CrtshError(BOOM_MSG)
        server_mod._client.search = boom
    elif mode == "short":
        async def never(query, cache_ttl=300, exclude_expired=False):
            raise AssertionError("short-circuit case reached the client — not network-free!")
        server_mod._client.search = never
    else:
        rows = SAMPLE if mode == "sample" else canned_rows(25)

        async def fake(query, cache_ttl=300, exclude_expired=False):
            log.append(query)
            return [dict(r) for r in rows]
        server_mod._client.search = fake


async def run_in_process_cases() -> list[dict]:
    """The @mcp.tool() decorator returns the plain coroutine fn (verified in
    fastmcp 3.4.7), so we call the unwrapped functions directly."""
    out = []
    for case in CASES:
        log: list = []
        install_search(case["mode"], log)
        fn = getattr(server_mod, case["name"])
        result = await fn(**case["arguments"])
        assert log == case["queries"], (
            f"{case['name']}{case['arguments']}: search received {log!r}, "
            f"expected {case['queries']!r}")
        out.append({
            "name": case["name"],
            "arguments": case["arguments"],
            "search_mode": case["mode"],
            "search_queries": log,
            "return_repr": compact(result),
        })
    return out


# --- wire capture: spawn the legacy server exactly as production does --------

WRAPPER_TEMPLATE = """\
import sys
sys.path.insert(0, %(src)r)
import crtsh_mcp.client as c
ROWS = %(rows)s
async def _fake_search(self, query, cache_ttl=300, exclude_expired=False):
    return [dict(r) for r in ROWS]
async def _noop_aclose(self):
    pass
c.CrtshClient.search = _fake_search
c.CrtshClient.aclose = _noop_aclose  # T02 removed aclose; legacy lifespan still calls it
import crtsh_mcp.server as s
s.main()
"""


def _readline_deadline(f, sec):
    if not select.select([f], [], [], sec)[0]:
        return None
    return f.readline()


def _rpc(p, obj, timeout=15.0):
    p.stdin.write(json.dumps(obj) + "\n")
    p.stdin.flush()
    want = obj.get("id")
    if want is None:
        return None
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        assert remaining > 0, f"wire timeout waiting for id {want}"
        line = _readline_deadline(p.stdout, remaining)
        assert line, f"wire pipe closed / no reply for id {want}"
        msg = json.loads(line)
        if msg.get("id") == want:
            return msg


def run_wire_cases() -> dict:
    """T00 recipe over the real stdio wire: initialize -> notifications/initialized
    -> tools/call. The dict case is network-free via a canned seam patch in the
    spawn wrapper; the error case short-circuits before the client."""
    fd, wrapper = tempfile.mkstemp(prefix="t06_wire_", suffix=".py")
    with os.fdopen(fd, "w") as f:
        f.write(WRAPPER_TEMPLATE % {"src": SRC, "rows": repr(SAMPLE)})
    p = subprocess.Popen(
        [sys.executable, wrapper], cwd=REPO,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True,
    )
    try:
        _rpc(p, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "t06-capture", "version": "0"}}})
        _rpc(p, {"jsonrpc": "2.0", "method": "notifications/initialized"})  # no id, no reply

        dict_resp = _rpc(p, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
            "name": "search_certificates", "arguments": {"query": "example.com"}}})
        err_resp = _rpc(p, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "search_certificates", "arguments": {"query": "  "}}})

        def text_of(resp):
            result = resp["result"]
            assert result["content"][0]["type"] == "text"
            return result, result["content"][0]["text"]

        dict_result, dict_text = text_of(dict_resp)
        err_result, err_text = text_of(err_resp)
        return {
            "dict_case": dict_text,
            "error_string_case": err_text,
            "_detail": {
                "dict_case_isError": dict_result.get("isError"),
                "error_case_isError": err_result.get("isError"),
                "dict_case_has_structuredContent": "structuredContent" in dict_result,
                "path": ("spawned legacy stdio subprocess (wrapper patches "
                          "CrtshClient.search to canned SAMPLE + CrtshClient.aclose "
                          "to a no-op; zero crt.sh contact)"),
            },
        }
    finally:
        if p.poll() is None:
            p.kill()
            p.wait()
        os.unlink(wrapper)


def main() -> int:
    cases = asyncio.run(run_in_process_cases())
    wire = run_wire_cases()

    # Consistency gates for the contract itself (the whole point of T06):
    # dict text == §5-compact JSON of the in-process return; str text verbatim.
    assert wire["dict_case"] == cases[0]["return_repr"], (
        "wire dict text != compact encoding of in-process dict return:\n"
        f"{wire['dict_case']!r}\nvs\n{cases[0]['return_repr']!r}")
    assert wire["error_string_case"] == "Error: please provide a search query", (
        f"wire error text drifted: {wire['error_string_case']!r}")

    fixture = {
        "note": (
            "Captured from the legacy fastmcp 3.4.7 server BEFORE the T07 rewrite "
            "(D4 golden-before-edit). Fully network-free: in-process cases patched "
            "_client.search with canned fakes; the wire dict case spawned the server "
            "with CrtshClient.search patched to the canned SAMPLE (the tag-era async "
            "shape) and aclose stubbed (T02 drift), the error case short-circuits on "
            "blank query before the client. crt.sh was never contacted. §5 compact "
            "encoding (json.dumps(separators=(',',':'), ensure_ascii=False) for dicts, "
            "verbatim passthrough for strings) CONFIRMED on the wire for this server — "
            "no result-shape drift, so no R3 DEVIATION tag. T07 deletes "
            "tests/characterization_capture.py; this fixture governs."
        ),
        "cases": cases,
        "wire_text": {
            "dict_case": wire["dict_case"],
            "error_string_case": wire["error_string_case"],
        },
        "wire_detail": wire["_detail"],
    }
    with open(GOLDEN_PATH, "w", encoding="utf-8") as f:
        json.dump(fixture, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"wrote {GOLDEN_PATH}")
    print(f"cases: {len(cases)} | wire dict text bytes: {len(wire['dict_case'])}")
    print(f"wire error text: {wire['error_string_case']!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
