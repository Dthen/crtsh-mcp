"""Pin the legacy client constants as the byte-for-byte target of the 2.x port.

crt.sh is a slow/rate-limited API — the retry/cache/redirect machinery IS the
product. These asserts freeze timeout/retry semantics EXACTLY (card B.3) before
any port code lands, so the ported client has a machine-checkable target.

This file imports only `crtsh_mcp.client` (no httpx, no server), so it runs
under BOTH the legacy venv today and the post-port package later.
"""

import crtsh_mcp.client as c


def test_base_url():
    assert c.BASE_URL == "https://crt.sh"


def test_timeout():
    assert c.DEFAULT_TIMEOUT == 20.0


def test_max_retries():
    assert c.MAX_RETRIES == 3


def test_backoff_base():
    # delays 1s, 2s, 4s
    assert c.BACKOFF_BASE == 1.0


def test_retryable_status():
    assert c.RETRYABLE_STATUS == {502, 503}


def test_404_cap():
    assert c.MAX_404_RETRIES == 2


def test_cache_ttl():
    assert c.DEFAULT_CACHE_TTL == 300


def test_cache_cap():
    assert c.MAX_CACHE_SIZE == 256


def test_user_agent():
    # VERIFIED client.py:123 — literal says 0.1.0 while pyproject says
    # 0.2.0. Port keeps the BYTES; do not "fix" the version drift here.
    # T02 relocated the literal from the httpx ctor to module level
    # (_USER_AGENT); the pinned bytes are unchanged.
    assert c._USER_AGENT == "crtsh-mcp/0.1.0"
