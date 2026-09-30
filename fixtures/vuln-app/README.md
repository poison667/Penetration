# Vulnerable Test Fixture (test oracle)

A **deliberately vulnerable, loopback-only** web application used as the test
oracle for Meridian's engines. It exists so that true positives can be proven:
an engine that reports SQL injection here is *right*; one that reports it on a
clean page is wrong. Non-firing on non-vulnerable behavior is a true negative
and is never forced (decision D15).

**Loopback only — it binds 127.0.0.1 and is test infrastructure, never exposed.**

## Running

```bash
npm run fixture          # http://127.0.0.1:8081 + https://127.0.0.1:8082
```

Accounts: `admin` / `admin123!A` (admin role) · `alice` / `alice123!A` (user).

## Intentional vulnerabilities (all real, all detectable)

| Area | Flaw | Detected by |
|---|---|---|
| Search | Error-based SQL injection (`?q='`) | VAL-005 |
| Search | Reflected XSS (unsanitized echo) | VAL-001 |
| Search | Blind/time-based SQL injection — `SLEEP(n)` in input really delays the "DB" | VAL-006 |
| Search | HTTP parameter pollution — every duplicate `q` value is processed and reflected | VAL-025 |
| Search | Server-side includes — `<!--#exec cmd="…-->` in input is really executed | VAL-010 |
| Search | Template/expression injection — `{{7*7*7}}` is really evaluated server-side | VAL-013 |
| Search | Unbounded recursive parse — 16KB input really exhausts the stack (500 + RangeError) | VAL-015 |
| Home | DOM XSS sink in inline client code (`document.write(location.hash)`) | VAL-003 |
| Home/tools | Client-side-only validation (maxlength) not mirrored server-side | VAL-023 |
| Home | Left-over `api_key` in an HTML comment | CFG-014 |
| Home | Session-aware nav — pre-auth family sessions render authenticated state | ATH-012, SES-012 |
| Home | `mailto:` admin contact (address discovery for authorized enumeration tests) | ATH-002 |
| Comments | Stored XSS (persisted script) | VAL-002 |
| Login | Session cookie without HttpOnly/Secure; no rotation | SES family |
| Login | Verbose "wrong password" user enumeration | ATH-001 |
| Login | Password field capped at 8 chars | ATH-005 |
| Login | Remember-me control present | ATH-006 |
| Login | SSO (SAML) references | ATH-016 |
| Login | Blank-password service account (`service` / empty password) | ATH-003 |
| Login | Default credentials (`root` / `root`) | ATH-014 (intrusive) |
| Login | Any login upgrades all previously-issued sessions (session puzzling family) | SES-012 |
| /forgot-password | Reset-flow user enumeration (different responses per account) | ATH-002 |
| /forgot-password | Reset token disclosed in the response as a URL | ATH-008 |
| /profile | IDOR — sequential ids, no ownership check | AUT family |
| /profile | Session id also accepted from `?sid=` in the URL (+ links carry it) | SES-001 |
| Upload | Unrestricted file type/extension | UPL family |
| Headers | No CSP, missing security headers, information disclosure | CFG family |
| Headers | `X-Powered-By: FixtureCMS/2.3.1` version banner | CFG-015 |
| Cookies | `tracker_sid` with HttpOnly but no SameSite | SES-004 |
| TLS (8082) | Self-signed SHA-1 cert, 10-day validity, CN≠host | TLS-004/003/005/006 |
| TLS (8082) | Mixed content (http:// subresources on the https page) | TLS-008 |
| https pages | Session cookie without Secure flag, no HSTS | SES-002, CFG-008 |
| HTML | Missing alt attributes, link targets, page structure | A11Y/SEO families |
| /redirect, /goto | Open redirect (302 to arbitrary absolute URL) | VAL-020 |
| /goto | Location header built from raw input (header-injection surface) | VAL-017 |
| /file | Local file inclusion / path traversal (`?name=../../…/etc/passwd` really reads the file); linked as a form | VAL-021, AUT-001 |
| /include | Remote file inclusion — the server really fetches the URL and surfaces the fetch error | VAL-022 |
| /xml | XXE — external SYSTEM entities are really resolved (file read) | VAL-009 |
| /ping | OS command injection — the host param really reaches a shell | VAL-014 |
| /account | Malformed session state mishandled — garbage `sid` really throws (HTTP 500) | VAL-027 |
| /api/profile | Mass assignment — every submitted JSON field is persisted with no allowlist | VAL-026 |
| /index.html.bak | Stale backup file served as text/plain | CFG-005 |
| /error | Fatal error + stack trace page, linked from the nav | CFG-013 |
| /debug/vars | Exposed debug/diagnostic endpoint | CFG-016 |
| /_debug | Directory listing enabled | CFG-017 |
| /tools | noindex meta, positive tabindex, dangling aria-labelledby, table without `<th>`, `/file` form, `?id=` DOR links | SEO-006/REC-010, A11Y-007/009/010, AUT-001/006 |
| /js/app.js | `md5(password + "s4lt")`, ECB mode, `Math.random()` token, `ws://` WebSocket, `indexedDB.open('auth-tokens')`, service worker registration, hardcoded keys | CRP-002/003/004/005/007, H5-002/004/005/006 |
| /sw.js | Wide-scope service worker (fetch passthrough, no origin checks) | H5-004 |
| /Old_Deals.aspx | Legacy uppercase URL | SEO-013 |
| /products/gone | Broken internal link | SEO-011 |
| robots.txt | Declared sitemap points at an unreachable host | SEO-007 |
| /promo → /promo2 → /deals | Redirect chain, then slow (1.2s), 500KB+, uncompressed, 34-image, 4-blocking-script page; X-Robots-Tag noindex | PRF-001…007, REC-010 |
| TRACE | Cross-site tracing (verb echoes headers) | VAL-019 |
| Comment form | Unbounded payload acceptance | DOS-004 (intrusive) |

**Not present, and honestly not faked** (decision D15): LDAP / XPath / IMAP / NoSQL /
ORM injection require real backend services (directory server, mail server, MongoDB,
an ORM with error disclosure) — the checks (VAL-007/008/011/012/024) remain
signature-based capabilities without a local true-positive oracle. VAL-018 (request
smuggling) does not fire because Node's HTTP parser is strict about framing — a
correct true negative. VAL-004 (HTML injection) only fires when the script-capable
canary is handled but plain markup is not — this fixture reflects raw, so VAL-001
supersedes it. VAL-016 (format string) needs a C-style format sink; no honest Node
equivalent exists. TLS-002 (weak ciphers) cannot fire against Node/OpenSSL 3 (3DES/RC4
unavailable — a true negative). SES-011 (no rotation) conflicts with the sequential
token oracle (SES-010) — the fixture rotates token values, and the pre-auth-family
flaw is covered by SES-012 instead. DOS-003 (SQL wildcard degradation) does not fire
because the fixture's in-memory search does not degrade — a true negative. REC-009
(DNS intelligence) requires a domain-like asset; `localhost` is not one.

The fixture also exposes clean behaviors (valid robots.txt, some secure
headers on selected paths) so engines can be checked for false positives.

## In-process use

`startFixture({ httpPort, tlsPort })` is exported for the integration test
(`tests/integration-pipeline.test.js`), which runs the entire platform pipeline
against a live instance on an ephemeral port.
