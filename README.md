# Meridian Platform

Multi-tenant platform for **website technical auditing, authorized security
assessment, SEO / performance / accessibility analysis, continuous monitoring,
data workbench, document intelligence, grounded AI analysis, workflow automation
and professional reporting** — with a React+TypeScript client and Windows/Linux
desktop distribution from one shared codebase.

Zero runtime dependencies on the backend (Node.js 20 built-ins only). The test
suite is the contract: **185 tests, 27 files, all passing**, including a full
end-to-end pipeline run against a deliberately-vulnerable in-process fixture.

## Quick start

```bash
npm install --prefix apps/client   # build-time only (client toolchain)
npm run seed:dev                   # demo tenant: real engine runs against the live fixture
npm start                          # API + worker + scheduler + UI on http://localhost:8080
npm run verify                     # FINAL GATE: suite → live docs → 13 live-instance checks
```

Demo accounts (seeded): `demo@meridian.local` / `Demo!Passw0rd` (owner) and
`staff@meridian.local` / `Staff!Passw0rd` (platform staff).
Test fixture (loopback only): `admin/admin123!A`, `alice/alice123!A`.

## Layout

| Path | Contents |
|---|---|
| `src/core` | util, validation, errors, taxonomy, expressions |
| `src/store` | custom WAL + snapshot JSON store with indexes |
| `src/app` | domain: db (tenant-scoped), catalog (31 services), billing ledger, files, notify, audit chain |
| `src/engines` | engine framework + 19 engines (8 web, 13 security) + 176 checks |
| `src/ai` | BM25 RAG, knowledge bases, grounded provider abstraction |
| `src/data` | workbench: profile, cleanse, dedup, transform, anomaly, CSV/XLSX |
| `src/docint` | text extraction (PDF text layer, plain text), document diff, OCR-honest fallback |
| `src/report` | PDF (custom writer), HTML, CSV, XLSX, JSON reports with sha256 integrity + history deltas |
| `src/automation` | cron, workflows (versioned), rules, webhooks |
| `src/queue`, `src/worker` | durable queue (lease/heartbeat), scheduler, runner, monitors |
| `src/api` | REST API + SSE, authn (scrypt, opaque tokens, TOTP MFA), RBAC, rate limits |
| `src/security` | crypto, net scope guards, rate limiters, secret scanning |
| `apps/client` | React+TypeScript SPA (web + desktop shared) |
| `apps/desktop` | Tauri 2 shell (Windows NSIS/MSI, Linux AppImage/deb/rpm via CI) |
| `fixtures/vuln-app` | deliberately vulnerable loopback application (test oracle) |
| `tests/` | 27 test files, 185 tests |
| `docs/` | ARCHITECTURE, DECISIONS, LIMITATIONS, VERIFICATION_AUDIT, TEST_REPORT, REQUIREMENTS_COVERAGE_MATRIX.csv |

## Documentation

- `docs/ARCHITECTURE.md` — topology, pipeline, finding model, storage
- `docs/DECISIONS.md` — D0–D23 decision register + conflict register C1–C6
- `docs/LIMITATIONS.md` — L-1..L-10 explicit known limitations
- `docs/VERIFICATION_AUDIT.md` — the final verification gate (`npm run verify`)
- `DEVELOPMENT.md` — setup, scripts, conventions, adding a security check
- `fixtures/vuln-app/README.md` — the test oracle and its intentional flaws
- `docs/screenshots/` — real-browser captures (login, dashboard light/dark, job & finding detail, marketplace, billing, data workbench)
- `docs/TEST_REPORT.md` — live-generated test report (`npm run report:tests`)
- `docs/REQUIREMENTS_COVERAGE_MATRIX.csv` — 19-column matrix, live-generated (`npm run gen:matrix`)

## Safety posture

Security engines run **only** against assets with verified authorization records
(scope domains, exclusions, ports, rate limits, safe-mode profiles). Private IPs are
refused unless explicitly authorized; destructive payloads are blocked at the
framework level; redirect/RFI canaries use the reserved `probe.meridian.invalid`
host. The platform reports only what it measured — every finding carries evidence,
facts are separated from inference, and AI answers cite their sources.
