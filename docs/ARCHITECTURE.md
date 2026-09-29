# Architecture — Meridian Platform

Meridian is a multi-tenant web-audit, security-assessment, monitoring, data-workbench and
reporting platform built as a **zero-runtime-dependency Node.js 20 ESM monorepo**, with a
React + TypeScript SPA (shared by web and desktop) and a Tauri 2 desktop shell for
Windows 10/11 and Linux.

## 1. Topology

```
┌────────────────────────┐        ┌──────────────────────────────┐
│ apps/client (React+TS) │  HTTP  │ src/api (REST :8080 + SSE)   │
│  web build → webroot/  │───────▶│  authn · router · routes     │
│  desktop: Tauri shell  │        └──────────┬───────────────────┘
└────────────────────────┘                   │
                                             ▼
        ┌────────────────────────────────────────────────────────┐
        │ src/worker: Scheduler · JobQueue · Runner · Monitors    │
        │   AutomationEngine (cron schedules · rules · webhooks)  │
        └───────┬───────────────────────────────┬────────────────┘
                │                               │
                ▼                               ▼
   ┌─────────────────────────┐    ┌──────────────────────────────┐
   │ src/engines             │    │ src/app (domain services)    │
   │  web/  (audit engines)  │    │  db · catalog · billing ·    │
   │  sec/  (security)       │    │  files · notify · audit      │
   │  lib/  (http·html·crawl)│    └──────────────────────────────┘
   │  checks.js (176 checks) │                 │
   └───────────┬─────────────┘                 ▼
               │                    ┌──────────────────────────────┐
               ▼                    │ src/store (custom WAL +      │
   ┌─────────────────────────┐      │ snapshot JSON store,         │
   │ fixtures/vuln-app       │      │ per-collection indexes)      │
   │ deliberately vulnerable │      └──────────────────────────────┘
   │ loopback test target    │
   └─────────────────────────┘
```

## 2. Execution pipeline (the real path)

`UI → POST /api/v1/requests → createServiceRequest (validation, pricing hold, enqueue) →
Scheduler claim (priority+FIFO, lease) → validateJob (authorization gate) →
buildContext (Fetcher, evidence/fact framework) → runEngine×N (real HTTP against the
authorized target) → analyzeFindings (dedup/merge) → qualityCheck (evidence+facts gate)
→ assignFids (MER-F-######) → persist findings+evidence → commit credits →
notifications → generateReport (5 formats, sha256, delta vs previous) → history`.

Job states: `REQUESTED → VALIDATING → QUEUED → RUNNING → ANALYZING → QUALITY_CHECK →
COMPLETED`, with `FAILED / CANCELLED / RETRYING / PARTIALLY_COMPLETED` paths (lease
expiry → reclaim → retry → FAILED at max attempts; engines that fail in a composite run
yield PARTIALLY_COMPLETED).

## 3. Finding model (FACT / INFERENCE / RECOMMENDATION)

Every finding carries: `fid`, `check_id`, `title`, `category`, `target`, `endpoint`,
`parameter`, `severity`, `confidence`, `cwe`, `owasp`, `facts[]` (directly observed),
`inference[]` (interpreted), `recommendation` (actionable fix), `evidence_ids[]`,
`reproduction`, `status`, `verification`, `provenance{engine, tool, kind:'measured'}`,
`detected_at/last_seen_at`. The framework **refuses** findings without evidence records,
and QC rejects findings whose evidence ids do not resolve. AI analysis is grounded: the
retrieval layer (BM25 over knowledge-base chunks) cites sources and the provider marks
answers `grounded=true/false` — it cannot originate measurements.

## 4. Authorization-first security testing

Security engines only run against assets with a declared+verified `authorization`
record: `scope_domains[]`, `exclusions[]`, ports, rate limits, `allow_private` (private
IPs are refused by default), and safe-mode profiles. The shared `ctx.fetch` enforces
exclusions, blocks destructive payload patterns outright, rate-limits per host, and the
redirect/RFI canary host `probe.meridian.invalid` (reserved `.invalid` TLD) proves
outbound fetches without touching third parties.

## 5. Storage

Custom write-ahead-log + snapshot store (`src/store`): append-only WAL, periodic
snapshots, torn-tail recovery, per-collection secondary indexes, tenant-scoped `Db`
wrapper (cross-tenant access throws; staff-only `byIdGlobal`). Billing is a ledger
(Σ amounts with per-tenant sequence numbers). Audit entries form a per-tenant
sha256 hash chain (`prev_hash`), verified by `verifyAuditChain`.

## 6. Reporting

`src/report`: zero-dependency PDF 1.4 writer (xref, auto-pagination), HTML, CSV, XLSX
(OOXML zip) and JSON renderers; executive summary, methodology, limitations, evidence
tables, historical deltas (added/resolved vs `previous_report_id`); integrity = content
hash computed pre-stamp then embedded in the rendered artifact (D23).

## 7. Clients

One SPA (`apps/client`, React+TypeScript, built with Vite into `webroot/`) serves the
web UI and is reused verbatim by the Tauri 2 desktop shell (`apps/desktop`) — one
codebase, Windows (NSIS/MSI) and Linux (AppImage/deb/rpm) installers built by CI (D4).

## 8. Requirements coverage

`npm run gen:matrix` → `docs/REQUIREMENTS_COVERAGE_MATRIX.csv` — 19 columns per
requirement with live-computed counts. `npm run report:tests` → `docs/TEST_REPORT.md`. The SPA subscribes to authenticated SSE (`/events`) for live job/finding/notification updates.
See DECISIONS.md for the decision register, LIMITATIONS.md for known limitations, and
VERIFICATION_AUDIT.md for the final verification gate.
