"""Byte-identity regression net: legacy tool-text bytes (crtsh-mcp T06 golden).

Loads ``golden/crtsh.characterization.json`` unconditionally and asserts that
the CURRENT server's in-process tool returns reproduce the recorded bytes.
Runs against the legacy fastmcp server NOW (old venv) and — post-T07 — drives
the new ``handle_call(name, args)`` unchanged; the tiny indirection below is
the whole difference between the two eras.

This pins the in-process return contract. The era *wire* bytes
(``content[0].text`` = §5-compact JSON for dicts, verbatim for strings) are
re-derived here from the fixture's own wire_text, which T06 captured off the
real stdio wire BEFORE the rewrite.

Network-free: every case patches ``server_mod._client.search`` with a canned
fake (short-circuit cases never touch the client). crt.sh is never contacted.
Pure stdlib + crtsh_mcp — no httpx, no fastmcp, no sleeps.
"""

import json
import os

import pytest

import crtsh_mcp.server as server_mod
from crtsh_mcp.client import CrtshError

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE_PATH = os.path.join(REPO, "golden", "crtsh.characterization.json")

with open(FIXTURE_PATH, encoding="utf-8") as _f:
    FIXTURE = json.load(_f)


def compact(value) -> str:
    """REFERENCE §5 fastmcp-3.x text encoding (captured, not assumed)."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _rows25(sample_row: dict) -> list[dict]:
    """Deterministic 25-row variant — byte-identical to the capture script's
    canned_rows(25) (the capture file dies at T07; this must survive)."""
    rows = []
    for i in range(25):
        r = dict(sample_row)
        r["id"] = sample_row["id"] + i
        r["entry_timestamp"] = f"2026-06-{(i % 28) + 1:02d}T00:00:{i % 60:02d}.000"
        r["common_name"] = f"c{i}.example.com"
        rows.append(r)
    return rows


# SAMPLE as the capture saw it, recovered from case 1's recorded return.
_SAMPLE_ROW = json.loads(FIXTURE["cases"][0]["return_repr"])["certificates"][0]


def _patch_search(mode: str, log: list) -> None:
    """Install a canned fake on the shared client (sync era post-T07 — the
    legacy async branch died with the fastmcp server)."""

    def _rows_for(mode):
        if mode == "sample":
            return [dict(_SAMPLE_ROW)]
        if mode == "rows25":
            return _rows25(_SAMPLE_ROW)
        raise AssertionError(f"unexpected canned mode {mode!r}")

    if mode == "boom":
        message = json.loads(
            next(c for c in FIXTURE["cases"] if c["search_mode"] == "boom")
            ["return_repr"]
        )[len("Error: "):]

        def behavior(query, *a, **k):
            log.append(query)
            raise CrtshError(message)
    elif mode == "short":
        def behavior(query, *a, **k):
            raise AssertionError("short-circuit case reached the client — not network-free!")
    else:
        def behavior(query, *a, **k):
            log.append(query)
            return _rows_for(mode)

    server_mod._client.search = behavior


def _invoke(name: str, arguments: dict):
    return server_mod.handle_call(name, arguments)


def test_fixture_shape():
    assert len(FIXTURE["cases"]) == 8
    assert set(FIXTURE["wire_text"]) == {"dict_case", "error_string_case"}


def _check_case(case: dict):
    log: list = []
    _patch_search(case["search_mode"], log)
    result = _invoke(case["name"], case["arguments"])
    assert log == case["search_queries"], (
        f"{case['name']}{case['arguments']}: search saw {log!r}, "
        f"expected {case['search_queries']!r}")
    # Byte-identity: the §5-compact encoding of the live return must equal the
    # recorded text bytes for BOTH dict and str returns (strs are JSON
    # strings in the fixture, matching the wire's verbatim-passthrough rule).
    assert compact(result) == case["return_repr"], (
        f"{case['name']}{case['arguments']} drifted:\n"
        f"live: {compact(result)!r}\n"
        f"golden: {case['return_repr']!r}")


@pytest.mark.parametrize("case", FIXTURE["cases"],
                         ids=[f"{i+1}-{c['name']}-{c['search_mode']}"
                              for i, c in enumerate(FIXTURE["cases"])])
def test_case_reproduces_recorded_bytes(case):
    _check_case(case)


def test_wire_dict_text_is_compact_encoding_of_inprocess_return():
    """§5 rule as captured for THIS server: content[0].text for a dict return
    == compact JSON of the in-process return — re-derived from the fixture's
    own bytes (the capture script asserted this on the live wire pre-T07)."""
    case1 = FIXTURE["cases"][0]
    assert FIXTURE["wire_text"]["dict_case"] == case1["return_repr"]
    # Encoding idempotence proof: compact bytes re-serialize to themselves.
    assert compact(json.loads(case1["return_repr"])) == case1["return_repr"]


def test_wire_error_string_text_is_verbatim():
    """str returns pass through verbatim with the 'Error: ' prefix intact."""
    assert FIXTURE["wire_text"]["error_string_case"] == "Error: please provide a search query"
    case2 = FIXTURE["cases"][1]
    assert json.loads(case2["return_repr"]) == FIXTURE["wire_text"]["error_string_case"]
