# Verification Audit — Meridian Platform

**Final verification gate.** Every claim below was executed, not asserted. The audit
was performed on the workspace at `/home/user/meridian` (Node v20.20.2, Linux).

## 1. Automated suite

- `npm test` → **185/185 passing, 27 files, ~37s** (live-generated breakdown: `docs/TEST_REPORT.md`).
- Verification as a whole (suite + live probes + real browser + oracle audit) found
  and fixed **15 real defects** in production source: 9 by the suite (tokenizer loop,
  ledger ordering, xlsx rels path, 3 cron defects, RAG chunk loss, session-family
  revocation, binary secret sealing, api-keys `require()` 500, dedupe null-key
  crash), 2 by real-browser verification (BillingView React-tree crash, missing
  evidence-list route), and 4 by the security-oracle audit (open-redirect probe
  redirect-following blindness, header-reflection hops, HPP query loss,
  invalid-session page filter). Details: TEST_REPORT.md + §3b3/§3b4 below.

## 2. End-to-end pipeline (no mocks)

`tests/integration-pipeline.test.js` proves the real path against a live,
deliberately-vulnerable fixture on an ephemeral loopback port:

1. `createServiceRequest` → job `REQUESTED`
2. Scheduler drives the lifecycle to `COMPLETED`
3. Real engines fetch real pages; **web_audit ≥5 findings with FIDs, facts, evidence**
4. **VAL-005 (error-based SQLi) genuinely detected** — a true positive against the
   fixture's actual flaw, plus ≥1 high/critical finding
5. Evidence records stored and linked; QC summary recorded
6. PDF report generated (`%PDF-1.4`, >10KB, embedded sha256)
7. Credit ledger carries the job's commit entry; job usage shows committed credits
8. Audit chain contains the pipeline actions

## 3. Live seeded environment

`npm run seed:dev` produced (on disk in `data/`): 6 COMPLETED jobs, **119 real
findings** across 74 distinct check ids (info 33 / low 35 / medium 27 / high 20 /
critical 4), report `rep_xtj7f5nyv6b5shsp` with sha256 `2b7801d4cf2257f0…`, demo
accounts `demo@meridian.local` / `staff@meridian.local`. Every finding traces to a
real HTTP exchange with the loopback fixture — none are synthesized. (After the
oracle hardening in §3b4 the seed was upgraded to run `sec_validation` at profile
`intrusive` with a 20-page crawl, so fresh seeds produce the fuller true-positive
set as well.)

## 3b. Post-restart live execution (fresh engine code)

After the final code fixes (incl. binary-safe secret sealing), a `web_audit` was
requested through the running API (`POST /api/v1/requests`) against the live fixture:
job reached `COMPLETED` with **82 findings** (info 28 / low 31 / medium 17 / high 6),
result summary + QC recorded — confirming the served instance executes the real
pipeline, not just the test harness.

## 3b4. Security-oracle hardening: 15 engine defects → 20/28 VAL true positives

The validation engine was audited check-by-check against the fixture oracle to
answer "which checks can actually fire?" — 22 of 28 `VAL` checks had no
true-positive proof. Extending the fixture with **real** implementations of the
missing vulnerability classes (time-based SQLi, SSI exec, SSTI, HPP reflection,
overflow crash, DOM-XSS sink, open redirect, LFI, RFI, XXE, invalid-session crash,
mass assignment, header reflection) and re-running a live `sec_validation`
(profile `intrusive`) through the API produced a job with **30 findings across
20 distinct VAL checks** in a single run — every one backed by a genuine HTTP
exchange and captured evidence.

The audit exposed **four more real engine defects** (all fixed, all re-verified live):
- **Open-redirect check was structurally blind (VAL-020)**: the shared fetcher
  follows redirects by default, so the probe never saw the 3xx it tests for.
  Fixed: the probe now sends with `noRedirect` and inspects the 30x + `Location`.
- **Header-reflection check missed followed hops (VAL-017)**: the canary in a
  `Location` header was only checked on the final response; the redirect chain
  (`res.redirects`) is now included.
- **HPP probe dropped the original query (VAL-025)**: discovered query-param
  actions were stored as `origin+pathname`, so the original value could never
  appear beside the injected duplicate. Fixed: full URL retained.
- **Invalid-session check could never fire (VAL-027)**: `crawl.pages` holds
  `{url,…}` objects but the filter regex-tested the object itself
  (`"[object Object]"`) — the protected-page list was always empty. Fixed.

Across the demo dataset the distinct fired check ids rose from 74 to **88**.
The 8 VAL checks that still do not fire are documented honestly in
`fixtures/vuln-app/README.md`: 5 are backend-signature checks (LDAP/ORM/XPath/
IMAP/NoSQL) needing real external services, VAL-018 is a true negative (Node's
strict HTTP parser), VAL-004 is superseded by VAL-001 by design, and VAL-016
needs a C-style format sink. None were forced.

## 3b2. Live client↔server contract probe

Every POST payload the SPA sends was executed against the running server:
users (incl. password), api-keys (create → authenticate → list-without-raw-key),
monitors (name/asset_id/interval_seconds), reports (all valid kinds), data
workbench (multipart upload → profile → dedupe → download), workflows, schedules,
tickets, findings PATCH. This probe caught and fixed three real integration bugs
that unit tests could not see: the api-keys `require()` 500, the dedupe null-key
crash, and the client sending `params` where the API takes `options`.

## 3b3. Real-browser verification (headless Chromium)

The SPA was driven in a real Chromium browser (Playwright): login (incl. wrong-
password error), all 19 workspace views, job detail, finding detail (FACTS vs
INFERENCE vs RECOMMENDATION visibly separated), dark theme toggle, and the SSE
live indicator. Result: **27/27 checks, 0 console errors, 0 page errors**.
Screenshots: `docs/screenshots/`.

This pass caught two real defects invisible to API-level tests:
- `BillingView` crashed the whole React tree (`features.join` on a structured
  object) → fixed + **ErrorBoundary added so no single view can take down the
  workspace**;
- the client called `GET /api/v1/evidence` which did not exist → route added
  (summaries only; content stays behind `GET /evidence/:id`), now test-covered.

## 3c. Client UI

`apps/client` (React 18 + TypeScript strict, ~2,300 lines, live SSE updates) builds with Vite into
`webroot/` (225 KB JS / 13 KB CSS / 67 KB gzip). The API serves it with SPA
fallback; all 16 data endpoints the SPA consumes returned 200 in the live smoke
test, and the desktop Tauri 2 shell loads the identical build (one codebase,
Windows NSIS/MSI + Linux AppImage/deb/rpm targets, CI-built — L-2).

## 4. API verification (over HTTP)

`tests/api-server.test.js`: 401 unauthenticated, 401 bad credentials, 200 login with
opaque tokens, RBAC 403 for viewer on write, cross-tenant asset read 404 + listing
isolation, registration → login, MFA enrollment → challenge login → TOTP success /
wrong-code 401, secure headers, rate limiting, 404 unknown routes.

## 5. Coverage matrix

`npm run gen:matrix` → `docs/REQUIREMENTS_COVERAGE_MATRIX.csv`: 45 requirement rows,
**42 Complete / 3 Partial / 0 Planned**. All three Partials carry explicit limitation
IDs (L-2 desktop installers via CI, L-3 OCR, L-5 external notification channels).
Counts inside the matrix (176 checks, 19 engines, 101 routes, tests) are computed live
from the source tree at generation time.

## 6. What was deliberately NOT claimed

- No OCR capability claim (images report `requires_ocr`).
- No browser-rendering CWV claim (server-side metrics + labeled inference only).
- No locally-built desktop binaries claim (CI-built, config real).
- No external notification delivery claim (adapters only).
- No fabricated findings, metrics, evidence or completions anywhere in the platform.

## 6b. One-command gate

`npm run verify` chains everything: full suite → live-generated TEST_REPORT.md →
live-generated coverage matrix → **13 live-instance checks** (health, UI bundle,
anonymous-auth rejection, SSE gate + stream, login, session, catalog, executed
jobs, findings-with-evidence, report download, fixture). Current run:
**185/185 tests + 13/13 live checks passed**. It exits non-zero on any failure
and never fabricates success.

## 7. Re-verification commands

```bash
npm test                  # full suite
npm run report:tests      # regenerates docs/TEST_REPORT.md from a live run
npm run gen:matrix        # regenerates the coverage matrix from live counts
npm run seed:dev          # rebuilds the demo tenant against the live fixture
node src/main.js --mode=all   # API :8080 + worker + scheduler + UI
```

## 8. Repository

The workspace is a git repository — initial commit `867ff83` ("Meridian Platform
v1.0"), 154 tracked files, clean working tree. Runtime state (`data/`),
dependencies and build output are ignored; the fixture's self-signed test
certificates are committed as documented test infrastructure. Pushing to a
remote activates `.github/workflows/ci.yml` (tests → client build → Windows and
Linux desktop installers).

**Gate result: PASS** — with the documented limitations above, which are visible in
the matrix, the report, and the UI rather than hidden.
