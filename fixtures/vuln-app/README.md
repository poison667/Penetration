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
| Comments | Stored XSS (persisted script) | VAL-002 |
| Login | Session cookie without HttpOnly/Secure; no rotation | SES family |
| Login | Verbose "wrong password" user enumeration | ATH family |
| Notes | IDOR — sequential ids, no ownership check | AUT family |
| Upload | Unrestricted file type/extension | UPL family |
| Headers | No CSP, missing security headers, information disclosure | CFG family |
| TLS | Self-signed cert with weak properties (port 8082) | TLS family |
| HTML | Missing alt attributes, link targets, page structure | A11Y/SEO families |
| Redirects | Open redirect (`?next=`) | VAL family |

The fixture also exposes clean behaviors (valid robots.txt, some secure
headers on selected paths) so engines can be checked for false positives.

## In-process use

`startFixture({ httpPort, tlsPort })` is exported for the integration test
(`tests/integration-pipeline.test.js`), which runs the entire platform pipeline
against a live instance on an ephemeral port.
