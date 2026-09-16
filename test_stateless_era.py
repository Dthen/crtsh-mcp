"""2026-07-28 era wire suite for crtsh-mcp (migration card T05, REFERENCE §1-§7).

Subprocess-driven, network-free: spawns the server exactly as the real Hermes
config does and drives newline-delimited JSON-RPC over its stdio pipes.
Committed RED against the legacy fastmcp server (TDD red = the spec exists in
history); goes GREEN at T07 after the stdlib rewrite. Tests 10/17 (ping,
EOF-exit) are verified-green against legacy and are NOT weakened.

Pure stdlib + subprocess — imports NOTHING from crtsh_mcp, so this file
collects error-free under the hermes venv (no fastmcp there) pre-T07.
"""

import json
import os
import select
import subprocess
import sys

# --- spawn constants: ONE seam; T09 flips PROD_PY to the v2 venv python ------
PROD_PY = "/mnt/HC_Volume_105667182/kimbo/mcp-venvs/crtsh-mcp-v2/bin/python3"  # flipped by T09 to the zero-dep v2 venv (D11: old venv kept as rollback anchor)
SERVER_CMD = [PROD_PY, "-m", "crtsh_mcp.server"]  # package server — mirrors the real config args exactly

REPO = os.path.dirname(os.path.abspath(__file__))
GOLDEN_PATH = os.path.join(REPO, "golden", "crtsh.tools.json")
TIMEOUT = 5.0  # per-read deadline; keeps a wedged legacy server far under the ~60 s budget


def spawn():
    """Start the server as its real config does: pipes in/out, stderr silenced."""
    return subprocess.Popen(
        SERVER_CMD, cwd=REPO,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True,
    )


def read_line_with_timeout(f, sec):
    """Fleet deadline helper (just-eat T03 / transitous T02 standard): bare
    readline is forbidden — a silent server must never wedge pytest.
    None == timeout."""
    if not select.select([f], [], [], sec)[0]:
        return None
    return f.readline()


def send_line(p, line):
    """Write one raw wire line + flush; a dead server's closed pipe is an assert."""
    try:
        p.stdin.write(line + "\n")
        p.stdin.flush()
    except (BrokenPipeError, ValueError):
        raise AssertionError("server closed its stdin mid-test (it died)")


def rpc(p, obj):
    """Send one JSON-RPC request, read exactly one reply via the deadline
    helper, parse it. A timeout / dead pipe reads as a test failure."""
    send_line(p, json.dumps(obj))
    line = read_line_with_timeout(p.stdout, TIMEOUT)
    assert line, f"no response within {TIMEOUT} s (method: {obj.get('method')})"
    return json.loads(line)


def cleanup(p):
    """Kill-in-finally hygiene: no orphans after a hang-fail."""
    if p.poll() is None:
        p.kill()
        p.wait()


def assert_era_triple(result):
    """REFERENCE §1: the D3 triple on every result object."""
    assert result["resultType"] == "complete"
    assert result["ttlMs"] == 0
    assert result["cacheScope"] == "private"


def canon(obj):
    """Canonical byte form for golden comparisons (key order/space proof)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# ---------------------------------------------------------------------------
# Era tests (12)
# ---------------------------------------------------------------------------

def test_discover_era_shape():
    p = spawn()
    try:
        resp = rpc(p, {"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {}})
        assert resp["id"] == 1
        result = resp["result"]  # §2: era server answers discover
        assert result["supportedVersions"] == ["2026-07-28"]
        assert "tools" in result["capabilities"]
        assert_era_triple(result)
    finally:
        cleanup(p)


def test_discover_paramless():
    p = spawn()
    try:
        resp = rpc(p, {"jsonrpc": "2.0", "id": 2, "method": "server/discover"})  # NO params key (§2: answer either way)
        assert resp["id"] == 2
        result = resp["result"]
        assert result["supportedVersions"] == ["2026-07-28"]
        assert "tools" in result["capabilities"]
        assert_era_triple(result)
    finally:
        cleanup(p)


def test_initialize_returns_32601_and_never_hangs_or_closes():
    p = spawn()
    try:
        init = rpc(p, {"jsonrpc": "2.0", "id": 3, "method": "initialize", "params": {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "era-suite", "version": "0"}}})  # §3: -32601, id echoed
        assert init["id"] == 3
        assert init["error"]["code"] == -32601
        resp = rpc(p, {"jsonrpc": "2.0", "id": 31, "method": "server/discover"})  # same pipes, no hang, no stdout close
        assert resp["id"] == 31
        assert resp["result"]["supportedVersions"] == ["2026-07-28"]
    finally:
        cleanup(p)


def test_notifications_initialized_swallowed():
    p = spawn()
    try:
        send_line(p, json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}))  # no id → no response (§6)
        resp = rpc(p, {"jsonrpc": "2.0", "id": 4, "method": "tools/list"})  # exactly one reply, THIS id (no phantom)
        assert resp["id"] == 4
    finally:
        cleanup(p)


def test_tools_list_triple_and_no_output_schema():
    p = spawn()
    try:
        resp = rpc(p, {"jsonrpc": "2.0", "id": 5, "method": "tools/list"})
        result = resp["result"]
        assert_era_triple(result)  # §4: ListToolsResult requires the full triple
        tools = result["tools"]
        assert len(tools) == 3
        for tool in tools:
            assert "outputSchema" not in tool  # §4 trap: structuredContent RuntimeError
    finally:
        cleanup(p)


def test_tools_list_golden_byte_identity():
    golden = json.load(open(GOLDEN_PATH))  # recipe 3: UNCONDITIONAL — no skipif, the golden is the tracked spec
    p = spawn()
    try:
        resp = rpc(p, {"jsonrpc": "2.0", "id": 6, "method": "tools/list"})
    finally:
        cleanup(p)
    by_name = {t["name"]: t for t in resp["result"]["tools"]}
    assert len(golden) == len(by_name) == 3
    for g in golden:
        g = {k: v for k, v in g.items() if k != "outputSchema"}  # golden HAS outputSchema ×3 — strip before diffing
        assert "outputSchema" not in g
        tool = by_name[g["name"]]
        for key in ("name", "description", "inputSchema"):
            assert canon(tool[key]) == canon(g[key]), f"{g['name']}.{key} drifted from golden"
        assert "outputSchema" not in tool  # none survives in the new listing


def test_tools_call_short_circuit_error_strings():
    p = spawn()
    try:
        resp = rpc(p, {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {
            "name": "search_certificates", "arguments": {"query": "  "}}})  # whitespace query: strips empty, no network (server.py:82-83)
        result = resp["result"]
        assert result["content"][0]["text"] == "Error: please provide a search query"
        assert_era_triple(result)
    finally:
        cleanup(p)


def test_tools_call_unknown_tool():
    p = spawn()
    try:
        resp = rpc(p, {"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {
            "name": "bogus", "arguments": {}}})
        result = resp["result"]  # §5: tool-level failures are RESULTS, not JSON-RPC errors
        text = result["content"][0]["text"]
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
        assert text.startswith("Error") or (isinstance(parsed, dict) and parsed.get("error") == "Unknown tool: bogus")
        assert_era_triple(result)
    finally:
        cleanup(p)


def test_tools_call_missing_params_is_32602():
    p = spawn()
    try:
        resp = rpc(p, {"jsonrpc": "2.0", "id": 9, "method": "tools/call"})  # no params at all (§5)
        assert resp["id"] == 9
        assert resp["error"]["code"] == -32602
    finally:
        cleanup(p)


def test_non_string_tool_args_fold_to_error_text_never_32603():
    # Carried-forward T08 caveat, absorbed by T10 (era-suite-owning task): wire-level
    # regression for REFERENCE §5's fold — a non-string tool argument must land as an
    # isError result dict (compact JSON text), never a -32603 and never a crash.
    # Network-free: every value short-circuits at the isinstance gates before any fetch.
    p = spawn()
    try:
        resp = rpc(p, {"jsonrpc": "2.0", "id": 16, "method": "tools/call", "params": {
            "name": "search_certificates", "arguments": {"query": 42}}})
        result = resp["result"]
        assert "error" not in resp and result["content"][0]["text"] == '{"error":"query must be a string"}'
        assert result.get("isError") is True
        assert_era_triple(result)
        resp2 = rpc(p, {"jsonrpc": "2.0", "id": 17, "method": "tools/call", "params": {
            "name": "get_certificate_details", "arguments": {"domain": ["x"]}}})
        result2 = resp2["result"]
        assert "error" not in resp2 and json.loads(result2["content"][0]["text"]) == {"error": "domain must be a string"}
        assert result2.get("isError") is True
        assert_era_triple(result2)
        resp3 = rpc(p, {"jsonrpc": "2.0", "id": 18, "method": "tools/call", "params": {
            "name": "discover_subdomains", "arguments": "not-an-object"}})
        result3 = resp3["result"]
        assert "error" not in resp3 and json.loads(result3["content"][0]["text"]) == {"error": "arguments must be an object"}
        assert result3.get("isError") is True
        assert_era_triple(result3)
        assert p.poll() is None  # server survives all three
    finally:
        cleanup(p)


def test_ping_answers_empty():
    p = spawn()
    try:
        resp = rpc(p, {"jsonrpc": "2.0", "id": 10, "method": "ping"})
        assert resp["id"] == 10
        assert resp["result"] == {}  # §6: keepalive ping → empty result
    finally:
        cleanup(p)


def test_unknown_method_32601():
    p = spawn()
    try:
        resp = rpc(p, {"jsonrpc": "2.0", "id": 11, "method": "resources/list"})
        assert resp["id"] == 11
        assert resp["error"]["code"] == -32601  # §3 catch-all: era-absent methods
    finally:
        cleanup(p)


def test_id_less_unknown_is_silent():
    p = spawn()
    try:
        send_line(p, json.dumps({"jsonrpc": "2.0", "method": "foo/bar"}))  # NO id → notification: never respond (§1/§3)
        resp = rpc(p, {"jsonrpc": "2.0", "id": 12, "method": "ping"})  # next reply must be the ping's id
        assert resp["id"] == 12
    finally:
        cleanup(p)


# ---------------------------------------------------------------------------
# Regression tests (5) — REFERENCE §7 server-killer guards
# ---------------------------------------------------------------------------

def test_garbage_lines_do_not_kill_the_server():
    p = spawn()
    try:
        send_line(p, "not json")  # §1 json.loads except: skip, never die
        resp = rpc(p, {"jsonrpc": "2.0", "id": 13, "method": "server/discover"})
        assert resp["id"] == 13
        assert resp["result"]["supportedVersions"] == ["2026-07-28"]
        assert p.poll() is None
    finally:
        cleanup(p)


def test_non_dict_json_lines_do_not_kill_the_server():
    p = spawn()
    try:
        for raw in ("5", "null", "[1,2]", '"str"'):  # §1 isinstance(req, dict) guard
            send_line(p, raw)
        resp = rpc(p, {"jsonrpc": "2.0", "id": 14, "method": "tools/list"})
        assert resp["id"] == 14  # id-correlated answer, not a phantom
        assert p.poll() is None
    finally:
        cleanup(p)


def test_null_method_does_not_crash():
    p = spawn()
    try:
        resp = rpc(p, {"jsonrpc": "2.0", "id": 15, "method": None})  # §1: non-string method → route unknown, don't crash
        assert resp["id"] == 15
        assert resp["error"]["code"] == -32601
    finally:
        cleanup(p)


def test_binary_garbage_line_does_not_kill_the_server():
    # REFERENCE §7 skeleton, copied verbatim (G→D→G→L, bytes-mode Popen,
    # stderr=DEVNULL, id-correlation, rc==0 on EOF, kill+wait in finally).
    # The two reads are wrapped in the fleet deadline helper — a timeout
    # wrapper, not a skeleton deviation (just-eat T03:86 precedent).
    discover_line = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "server/discover"})
    tools_list_line = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    p = subprocess.Popen(SERVER_CMD, cwd=REPO, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        p.stdin.write(b"\xff\xfe\x00garbage\n")                                    # G — pre-stream invalid UTF-8
        p.stdin.write(discover_line.encode() + b"\n"); p.stdin.flush()             # D
        line = read_line_with_timeout(p.stdout, TIMEOUT); assert line, "no response to discover (binary pre-garbage)"
        resp = json.loads(line)
        assert resp["id"] == 1 and resp["result"]["supportedVersions"] == ["2026-07-28"]
        p.stdin.write(b"\x00\xff\n")                                               # G — mid-stream garbage
        p.stdin.write(tools_list_line.encode() + b"\n"); p.stdin.flush()           # L
        line2 = read_line_with_timeout(p.stdout, TIMEOUT); assert line2, "no response to tools/list (binary mid-garbage)"
        resp2 = json.loads(line2)                                                  # id==2 proves no phantom response to G
        assert resp2["id"] == 2 and "result" in resp2
        assert p.poll() is None
        p.stdin.close(); assert p.wait(timeout=5) == 0                             # clean EOF exit
    finally:
        if p.poll() is None:
            p.kill(); p.wait()


def test_exit_on_stdin_eof_rc0():
    p = spawn()
    try:
        p.stdin.close()  # §7: exit ONLY on stdin EOF, rc 0, never sys.exit from a handler
        assert p.wait(timeout=5) == 0
    finally:
        cleanup(p)
