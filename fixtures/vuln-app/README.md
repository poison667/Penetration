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
| Comments | Stored XSS (persisted script) | VAL-002 |
| Login | Session cookie without HttpOnly/Secure; no rotation | SES family |
| Login | Verbose "wrong password" user enumeration | ATH family |
| Notes | IDOR — sequential ids, no ownership check | AUT family |
| Upload | Unrestricted file type/extension | UPL family |
| Headers | No CSP, missing security headers, information disclosure | CFG family |
| TLS | Self-signed cert with weak properties (port 8082) | TLS family |
| HTML | Missing alt attributes, link targets, page structure | A11Y/SEO families |
| /redirect, /goto | Open redirect (302 to arbitrary absolute URL) | VAL-020 |
| /goto | Location header built from raw input (header-injection surface) | VAL-017 |
| /file | Local file inclusion / path traversal (`?name=../../…/etc/passwd` really reads the file) | VAL-021 |
| /include | Remote file inclusion — the server really fetches the URL and surfaces the fetch error | VAL-022 |
| /xml | XXE — external SYSTEM entities are really resolved (file read) | VAL-009 |
| /ping | OS command injection — the host param really reaches a shell | VAL-014 |
| /account | Malformed session state mishandled — garbage `sid` really throws (HTTP 500) | VAL-027 |
| /api/profile | Mass assignment — every submitted JSON field is persisted with no allowlist | VAL-026 |
| TRACE | Cross-site tracing (verb echoes headers) | VAL-019 |

**Not present, and honestly not faked** (decision D15): LDAP / XPath / IMAP / NoSQL /
ORM injection require real backend services (directory server, mail server, MongoDB,
an ORM with error disclosure) — the checks (VAL-007/008/011/012/024) remain
signature-based capabilities without a local true-positive oracle. VAL-018 (request
smuggling) does not fire because Node's HTTP parser is strict about framing — a
correct true negative. VAL-004 (HTML injection) only fires when the script-capable
canary is handled but plain markup is not — this fixture reflects raw, so VAL-001
supersedes it. VAL-016 (format string) needs a C-style format sink; no honest Node
equivalent exists.

The fixture also exposes clean behaviors (valid robots.txt, some secure
headers on selected paths) so engines can be checked for false positives.

## In-process use

`startFixture({ httpPort, tlsPort })` is exported for the integration test
(`tests/integration-pipeline.test.js`), which runs the entire platform pipeline
against a live instance on an ephemeral port.
