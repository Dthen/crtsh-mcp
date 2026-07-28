# crt.sh API — Research Findings

> Research for building a crt.sh MCP server. All API tests run live via `curl --max-time 15` on 2026-07-28.
> **Note:** crt.sh is a free community service and is frequently slow / returns 502s under load. Several tests below required retries. Design for resilience.

---

## 1. API Endpoints

crt.sh has **no official REST API** — it's a web UI with a JSON output mode bolted on. Everything is query-string driven against a single endpoint.

### 1.1 Main search endpoint (JSON)

```
GET https://crt.sh/?q=<QUERY>&output=json
```

**Live test** — `https://crt.sh/?q=example.com&output=json` → HTTP 200, JSON array:

```json
[
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
    "result_count": 3
  }
]
```

### 1.2 Certificate detail (HTML only)

```
GET https://crt.sh/?id=<CRTSH_ID>
```

- **No JSON output** — returns an HTML page. Live test returned HTTP 200, ~25 KB HTML.
- Parsed fields available on the page: crt.sh ID, leaf/intermediate type, CT log entries (timestamp, entry #, log operator e.g. "Google", log URL e.g. `https://ct.googleapis.com/logs/us1/argon2026h2`), revocation status (CRL / CRLSet / disallowedcert.stl / OneCRL per provider), **SHA-256 fingerprint**, **SHA-1 fingerprint**, and the full PEM / `openssl x509 -text` dump.
- Example extracted: SHA-256 `28A4EB5CE222C5BF4368AF8A0D64C59BDDD3C4EA561B592F063ABAEE3A7C20EF`, SHA-1 `BBAF0CAAE3AFC4EAB1592ABE636A1F4B2A763A1B`.
- **MCP implication:** to get full cert details you must scrape HTML (or use the PostgreSQL interface). There is no `?id=X&output=json`.

### 1.3 Show-SQL endpoint (HTML)

```
GET https://crt.sh/?q=<QUERY>&showSQL=Y
```

Renders the page and appends the exact PostgreSQL query crt.sh generated (in a `<PRE>` block). Useful for reverse-engineering the schema. (Live test timed out / 502'd repeatedly — documented from web sources.)

### 1.4 Public PostgreSQL interface (see §5)

```
psql -h crt.sh -p 5432 -U guest -d certwatch
```

---

## 2. Query Parameters

The `q` parameter is a **free-text identity matcher**: it matches domain names, organization names, and (on the HTML interface) fingerprints / crt.sh IDs. The matching is done via a PostgreSQL full-text tsquery against certificate identities.

| Param | Values | Notes |
|-------|--------|-------|
| `q` | identity string | Domain, wildcard, org name, fingerprint, or crt.sh ID. Core search term. |
| `output` | `json` | Only `json` is supported. Any other value (e.g. `xml`) → error page. **Fingerprint/ID lookups reject `output=json`** (see §2.2). |
| `exclude` | `expired` | Drops expired certs. Live-tested: works with JSON. The Google Group also documents that crt.sh de-dupes precert/cert pairs keeping the lowest ID. |
| `type` | `precert` / `cert` | Filter to precertificates or final certificates. (Live test 502'd; documented from sources.) |
| `id` | crt.sh ID | Fetch single cert — **HTML only**, no JSON. |
| `serial` | hex serial | Serial-number lookup — **HTML only**. |
| `showSQL` | `Y` | Append generated SQL to HTML output. |

### 2.1 Wildcards (`%`)

- `%` is the SQL LIKE wildcard. `%.example.com` matches all subdomains of example.com.
- **Live test:** `https://crt.sh/?q=%25.example.com&output=json` (`%25` = URL-encoded `%`) → HTTP 200, **69 results**.
- Plain `example.com` (no wildcard) matches certs whose identity contains that string (returns the apex + wildcard certs).
- The Python lib `PaulSec/crt.sh` defaults to prepending `%.` when no `%` present — a good default for subdomain enumeration.

### 2.2 Lookups that do NOT support JSON

**Live test:** SHA-256 fingerprint lookup with `&output=json` returned:

```
<BR><BR>Unsupported output type: json
```

So **fingerprint, serial-number, and crt.sh-ID lookups are HTML-only**. JSON output works for identity (domain/org) searches. This is a critical constraint for MCP tool design — detail lookups need HTML scraping or PostgreSQL.

### 2.3 Organization search

`q` accepts org names, e.g. `?q=Cloudflare%2C+Inc.&output=json`. (Live test timed out under load — documented from the `Cyber-Guy1/domainCollector` tool which is built entirely around org-name queries.) Org matching is fuzzy/full-text, so results can be noisy.

---

## 3. Response Shape (JSON search)

Every element of the returned array has these fields:

| Field | Type | Description |
|-------|------|-------------|
| `issuer_ca_id` | integer | crt.sh internal ID of the issuing CA. |
| `issuer_name` | string | RFC 2253 DN of the issuer, e.g. `C=US, O=SSL Corporation, CN=...`. |
| `common_name` | string | The certificate's CN (subject commonName). |
| `name_value` | string | **Newline-delimited** (`\n`) list of all names the cert covers (CN + SANs). Split on `\n` to enumerate. Wildcards appear as `*.example.com`. |
| `id` | integer (int64) | crt.sh certificate ID — use with `?id=` for the detail page. |
| `entry_timestamp` | string (ISO 8601, ms) | When the cert was logged to CT, e.g. `2026-05-31T22:13:01.653`. |
| `not_before` | string (ISO 8601) | Cert validity start. |
| `not_after` | string (ISO 8601) | Cert validity end (expiry). |
| `serial_number` | string (hex) | Certificate serial number. |
| `result_count` | integer | **Dedup group size** — number of rows collapsed into this entry (precert + cert duplicates share a group). Not a total-results count. |

**Historical note:** older crt.sh JSON returned a slightly different shape (`min_cert_id`, `min_entry_timestamp` instead of `id`/`entry_timestamp`) — seen in the PaulSec lib docstring. Current API uses `id`/`entry_timestamp`. Older clients also had to repair malformed JSON (`}{` → `},{`); crt.sh fixed this (certwatch_db commit f4f46ea).

---

## 4. Rate Limits

- **Unofficial limit: ~60 requests/minute per IP** (confirmed via the crt.sh Google Group; not published in headers).
- **No auth, no API key.** Free.
- **Behaviour when exceeded / under load (observed live):**
  - **HTTP 502 Bad Gateway** from nginx (very common — seen on detail pages, serial lookups, org queries).
  - **HTTP 000 / connection timeout** — requests hang past the timeout with no response.
  - Intermittent: the same URL can 502 twice then 200 on the third try.
- **No rate-limit response headers** observed.
- **Mitigation strategy for the MCP server:**
  - Generous timeouts (15–30 s) + automatic retries with backoff (2–4 s).
  - Client-side request throttling / token bucket (~1 req/s sustained).
  - Response caching (see §9).
  - A realistic `User-Agent` header (some libs set a browser UA; default curl UA works but a descriptive one is polite).

---

## 5. Public PostgreSQL Interface

crt.sh exposes **read replicas** of its database directly over PostgreSQL. This is the most powerful access method and the only way to get clean structured detail data + bypass the 999-row cap.

### 5.1 Connection

```
psql -h crt.sh -p 5432 -U guest -d certwatch
# (no password required)
```

- `psql` was **not installed** in this environment, so the connection could not be tested live. Details below are from the official crt.sh Google Group announcement and the `crtsh/certwatch_db` GitHub repo.
- **Caveat (from PaulSec/crt.sh issue #8):** connections via `psycopg2` can fail with `long transactions not allowed` / `SSL connection has been closed unexpectedly`. The guest account is constrained — keep queries short and read-only. Set a statement timeout.

### 5.2 Key tables (from `crtsh/certwatch_db/sql/create_schema.sql`)

| Table | Purpose |
|-------|---------|
| `certificate` | All certs (partitioned by year: `certificate_2013andbefore` … `certificate_2030andbeyond`). Has `CERTIFICATE` (DER) + `ID`. |
| `ca` | Certificate authorities (`ID`, `NAME`). |
| `certificate_identity` | Maps certs to their identities (`CERTIFICATE_ID`, `ISSUER_CA_ID`, `NAME_VALUE`, `NAME_TYPE` e.g. `2.5.4.3` = commonName). The main search index. |
| `ct_log` / `ct_log_operator` / `ct_log_entry` | CT log metadata + per-cert log entries (partitioned by year). |
| `ca_certificate`, `ca_issuer` | CA hierarchy / AIA issuers. |
| `crl`, `crl_revoked` | CRL data + revoked serials. |
| `ocsp_responder` | OCSP responder info. |
| `lint_summary`, `lint_issue`, `lint_cert_issue` | Linting results (zlint). |
| `trust_context`, `trust_purpose`, `applicable_purpose`, `accepted_roots` | Browser trust/store context. |

### 5.3 Useful PL/pgSQL functions (`x509_*`, from libx509pq)

`x509_commonName(cert)`, `x509_notBefore(cert)`, `x509_notAfter(cert)`, `x509_serialNumber(cert)` (returns bytea → `encode(..., 'hex')`), `x509_subjectName`, `x509_issuerName`, `x509_extension`, `x509_altNames`, etc. These operate on the DER `CERTIFICATE` column.

### 5.4 Canonical query (the one crt.sh generates for `?q=%.github.com&exclude=expired`)

```sql
SELECT ci.ISSUER_CA_ID,
       ca.NAME ISSUER_NAME,
       ci.NAME_VALUE NAME_VALUE,
       min(c.ID) MIN_CERT_ID,
       min(ctle.ENTRY_TIMESTAMP) MIN_ENTRY_TIMESTAMP,
       x509_notBefore(c.CERTIFICATE) NOT_BEFORE,
       x509_notAfter(c.CERTIFICATE) NOT_AFTER
FROM ca, ct_log_entry ctle, certificate_identity ci, certificate c
WHERE ci.ISSUER_CA_ID = ca.ID
  AND c.ID = ctle.CERTIFICATE_ID
  AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower('%.github.com'))
  AND ci.CERTIFICATE_ID = c.ID
  AND x509_notAfter(c.CERTIFICATE) > statement_timestamp()   -- exclude=expired
GROUP BY c.ID, ci.ISSUER_CA_ID, ISSUER_NAME, NAME_VALUE
ORDER BY MIN_ENTRY_TIMESTAMP DESC, NAME_VALUE, ISSUER_NAME;
```

Note the `reverse(lower(...)) LIKE reverse(...)` trick — that's how suffix (subdomain) matching is indexed.

### 5.5 MCP implication

Two viable backends:
- **HTTP JSON** — simple, no deps, but capped at ~999 rows, no detail data, flaky.
- **PostgreSQL** — full power, structured detail, no row cap, but needs a PG driver (`pg`/`postgres` for Node, `psycopg`/`asyncpg` for Python), careful query timeouts, and is even more rate-sensitive.

Recommendation: **HTTP JSON as the primary path** (covers 90% of MCP use cases), with PostgreSQL as an optional advanced backend behind a config flag.

---

## 6. Pagination & the Result Cap

- **There is no pagination parameter** (no `page`, `offset`, or `limit` in the HTTP API).
- The web/JSON interface **caps results** — commonly reported as **999 rows** (the underlying SQL uses `LIMIT 10000` in some generated queries, but the UI/JSON layer truncates to ~999). Live broad-query tests were blocked by 502s so the exact cap couldn't be reconfirmed, but `result_count` on a small query (`%.example.com`) returned 12 rows with `result_count: 3` per group.
- **Workarounds:**
  1. **Narrow the query** — add subdomain prefixes (`%.api.example.com`), use `exclude=expired`, or `type=cert`.
  2. **PostgreSQL** — write your own query with `LIMIT`/`OFFSET` for true pagination.
  3. **Time-window chunking** via PostgreSQL (`x509_notBefore BETWEEN ...`).
- **MCP implication:** tools should accept an optional `limit` and always warn/truncate when results approach the cap. For `subdomain_discovery`, dedupe `name_value` client-side rather than trusting row count.

---

## 7. Error Handling

| Condition | Observed response |
|-----------|-------------------|
| Overload / rate limit | **HTTP 502 Bad Gateway** (nginx HTML body) — most common failure. |
| Slow backend | **Timeout / HTTP 000** — no response within window. |
| Fingerprint/serial/ID + `output=json` | HTTP 200 but body = `Unsupported output type: json` (HTML fragment). **Must detect this string.** |
| Invalid `output` value (e.g. `xml`) | 502 / error HTML. |
| Empty `q` | Timeout / no useful data. |
| Valid query | HTTP 200 + JSON array (may be empty `[]` for no matches). |

**MCP error-handling checklist:**
- Treat non-200 **and** bodies containing `Unsupported output type` / `<html` as errors.
- Validate JSON parse; on failure, surface a "crt.sh unavailable/overloaded — retry" message rather than crashing.
- Retry 502/timeout 2–3× with backoff before failing.
- Distinguish "no results" (valid `[]`) from "request failed".

---

## 8. Existing Tools & Libraries (feature inspiration)

| Project | Lang | Stars | Notes / features worth stealing |
|---------|------|-------|---------------------------------|
| **PaulSec/crt.sh** | Python | 153 | Unofficial API. `search(domain, wildcard=True, expired=True)`. Defaults to `%.` prefix + `exclude=expired`. Handles old malformed JSON. |
| **pycrtsh** (Te-k) | Python | — | Most complete. CLI `certsh domain <d>` and `certsh cert <id>`. **Uses PostgreSQL** for detail. Returns rich parsed cert: extensions (SANs, AIA, OCSP, CRL), subject/issuer, validity. Good model for a `get_certificate` tool. |
| **az7rb/crt.sh** | Shell | 297 | Subdomain enumeration focus — save/dedupe subdomains. |
| **crtfinder** (eslam3kl) | Python | 115 | Fast subdomain extraction, "up to N subdomains" output. |
| **domainCollector** (Cyber-Guy1) | Python | 102 | **Org-name → domains** discovery. Inspiration for `search_by_org`. |
| **famasoon/crtsh** | Go | 86 | Simple CLI result viewer. |
| **dsggregory/crt.sh** | Go | — | Queries domains, SHA1/SHA256 fingerprints, and Subject Key Identifiers. |
| **SubCerts** (0xJin) | Shell | 75 | CT-log subdomain tool. |

**Consensus feature set** across tools: domain search, wildcard subdomain enumeration, dedupe, expired-filtering, org search, cert-detail-by-id, fingerprint lookup. pycrtsh is the best architectural reference (HTTP for search + PG for detail).

---

## 9. MCP Server Design Considerations

### 9.1 Proposed tools

| Tool | Backend | Notes |
|------|---------|-------|
| `search_certificates(identity, wildcard?, include_expired?, limit?)` | HTTP JSON | Core. Default `wildcard=true` (prepend `%.`), `include_expired=false` (`exclude=expired`). |
| `subdomain_discovery(domain)` | HTTP JSON | Query `%.domain`, split `name_value` on `\n`, dedupe, strip `*.`, sort. Return unique subdomain list + count. |
| `cert_history(domain)` | HTTP JSON | Timeline grouped by `not_before`/issuer; show issuance cadence. |
| `search_by_org(organisation)` | HTTP JSON | `q=<org>`. Warn that org matching is fuzzy/noisy. |
| `get_certificate(id)` | **HTML scrape** or PG | Parse `?id=` HTML for fingerprints, SANs, CT logs, revocation, PEM. No JSON available. |
| `lookup_fingerprint(hash)` | HTML scrape / PG | SHA-1 or SHA-256. JSON unsupported. |

### 9.2 Response-size concerns (critical for MCP)

- A broad domain can return **hundreds of rows × ~10 fields** → tens of KB, and `name_value` can contain dozens of SANs per cert. This will blow up an LLM context window fast.
- **Mitigations:**
  - Default `limit` (e.g. 50) on every list tool; require explicit opt-in for more.
  - Return **summarized** rows by default (id, common_name, not_after, issuer CN only); offer a `full` flag.
  - For `subdomain_discovery`, return just the deduped name list (compact), not full cert objects.
  - Truncate `issuer_name` to the CN component in summaries.
  - Always include a `total_returned` + `truncated` flag so the model knows data was capped.

### 9.3 Caching

- crt.sh is slow and rate-limited → **cache aggressively**.
  - In-memory LRU keyed by full URL, TTL ~5–15 min (CT data is near-real-time but minutes-stale is fine for OSINT).
  - Cache detail-page scrapes longer (certs are immutable once logged → effectively cache forever by `id`).
- Caching also dedupes accidental repeat calls from the model.

### 9.4 Resilience

- Single shared HTTP client with: 20 s timeout, 3 retries w/ exponential backoff (2s→4s→8s), jitter, and a token-bucket throttle (~1 req/s).
- Set a descriptive `User-Agent` (e.g. `crtsh-mcp/<version>`).
- Surface 502/timeout as a clear "crt.sh is overloaded, retry shortly" tool error — don't retry forever.

### 9.5 Language choice

- **TypeScript** fits the MCP ecosystem best (official `@modelcontextprotocol/sdk`), and HTTP+HTML-scraping (`cheerio`) is trivial. PostgreSQL optional via `pg`.
- **Python** (`mcp` SDK + `httpx` + `BeautifulSoup`, optional `psycopg`) is equally viable and matches the reference libs (pycrtsh). Either works; TS has the edge for MCP-native tooling.

---

## 10. Quick-Reference Cheat Sheet

```bash
# Domain search (JSON) — the workhorse
curl --max-time 15 "https://crt.sh/?q=example.com&output=json"

# Subdomains (wildcard), exclude expired
curl --max-time 15 "https://crt.sh/?q=%25.example.com&output=json&exclude=expired"

# Single cert detail (HTML — scrape it)
curl --max-time 15 "https://crt.sh/?id=26787376238"

# See the SQL crt.sh generates
curl --max-time 15 "https://crt.sh/?q=example.com&showSQL=Y"

# PostgreSQL (full power, no row cap)
psql -h crt.sh -p 5432 -U guest -d certwatch
```

**Gotchas:** `output=json` only works for identity searches (not fingerprint/serial/ID). ~60 req/min/IP. Expect 502s — retry with backoff. Results capped ~999 rows, no pagination param. `name_value` is `\n`-delimited. `result_count` is a dedup-group size, not a total.
