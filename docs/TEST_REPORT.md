# Test Report — Meridian Platform

Generated **live** by `npm run report:tests` (2026-09-30T04:25:03.196Z); nothing below is hand-maintained.

## Result

| Metric | Value |
|---|---|
| Test files | 27 |
| Tests | 185 |
| **Passing** | **185** |
| Failing | 0 |
| Cancelled / skipped | 0 / 0 |
| Wall time | 66.7s |
| Runner | `node --test` (Node built-in, zero test dependencies) |

> ✅ **ALL PASSING**

## Files

| File | Tests | Pass | Fail | Time |
|---|---|---|---|---|
| `ai-rag.test.js` | 6 | 6 | 0 | 0.1s |
| `api-authn.test.js` | 6 | 6 | 0 | 0.4s |
| `api-server.test.js` | 3 | 3 | 0 | 1.3s |
| `api-sse.test.js` | 1 | 1 | 0 | 0.8s |
| `app-audit.test.js` | 6 | 6 | 0 | 0.1s |
| `app-billing.test.js` | 8 | 8 | 0 | 0.1s |
| `app-db.test.js` | 7 | 7 | 0 | 0.1s |
| `automation-cron.test.js` | 7 | 7 | 0 | 0.1s |
| `automation-workflow.test.js` | 4 | 4 | 0 | 0.1s |
| `core-expr.test.js` | 12 | 12 | 0 | 0.1s |
| `core-util.test.js` | 14 | 14 | 0 | 0.1s |
| `core-validate.test.js` | 18 | 18 | 0 | 0.1s |
| `data-workbench.test.js` | 10 | 10 | 0 | 0.1s |
| `docint.test.js` | 8 | 8 | 0 | 0.1s |
| `engines-checks.test.js` | 6 | 6 | 0 | 0.1s |
| `engines-framework.test.js` | 5 | 5 | 0 | 0.1s |
| `integration-pipeline.test.js` | 1 | 1 | 0 | 62.1s |
| `lib-crawl.test.js` | 2 | 2 | 0 | 0.1s |
| `lib-csv.test.js` | 6 | 6 | 0 | 0.1s |
| `lib-html.test.js` | 8 | 8 | 0 | 0.1s |
| `queue.test.js` | 6 | 6 | 0 | 0.1s |
| `report-engine.test.js` | 4 | 4 | 0 | 0.1s |
| `report-pdf.test.js` | 4 | 4 | 0 | 0.1s |
| `security-crypto.test.js` | 8 | 8 | 0 | 0.3s |
| `security-net-http.test.js` | 13 | 13 | 0 | 0.1s |
| `store-store.test.js` | 7 | 7 | 0 | 0.1s |
| `store-wal.test.js` | 5 | 5 | 0 | 0.1s |

## What the tests actually exercise

- **Unit**: util/validate/expr, crypto (scrypt, TOTP, AES-GCM sealing, base32), WAL + snapshot store, Db tenant isolation, billing ledger, queue lease/heartbeat/reclaim, cron parser, BM25 RAG, HTML/CSV parsing, xlsx round-trip, PDF structure, rate limiters, network scope guards.
- **Framework**: engine context (evidence enforcement, facts/inference/recommendation separation), finding dedup/merge, QC rejection of evidence-less findings, FID assignment, engine error containment.
- **Crawler**: real in-process HTTP site — discovery, robots.txt compliance, external-link exclusion, page budgets, crawl-state reuse.
- **API over HTTP**: login (incl. MFA challenge + TOTP verification), RBAC 401/403, tenant isolation (cross-tenant 404 + listing isolation), registration, secure headers, rate limits.
- **End-to-end pipeline**: live deliberately-vulnerable fixture → service request → validation → real engine execution → findings with FIDs → evidence records → QC → PDF report with embedded sha256 → credit ledger commit → audit chain — all in-process, zero mocks.

## Real defects found by this suite (and fixed)

| Module | Defect | Caught by |
|---|---|---|
| `core/expr.js tokenizer` | infinite loop on consecutive multi-char operators (`!!`) | `core-expr.test.js` |
| `app/billing.js balanceOf` | balance depended on same-millisecond record ordering | `app-billing.test.js` |
| `data/xlsx.js readXlsxSheets` | workbook rels targets are relative to xl/ — stripped path never matched, so sheets were always empty | `docint.test.js` |
| `automation/cron.js (3 defects)` | single values bypassed range validation; nextRun rounded back into the current minute; unrestricted dow miscomputed as size 8, breaking dom/dow OR semantics | `automation-cron.test.js` |
| `ai/rag.js chunkText` | sentence-splitter fallback discarded all but the last token of unpunctuated text | `ai-rag.test.js` |
| `api/authn.js rotateSession` | refresh-token reuse revoked ancestors but left descendant sessions valid | `api-authn.test.js` |
| `security/crypto.js sealSecret` | String(buffer) UTF-8 coercion corrupted binary TOTP seeds before encryption — enrolled MFA could never verify | `api-server.test.js` |
| `api/routes-core.js POST /api-keys` | CommonJS require() inside an ESM module — every API key creation crashed with a 500 | `api-server.test.js (regression)` |

Each was reproduced against the source, fixed, and re-verified by the full suite. Method: tests assert real module contracts; when an assertion and the source disagreed, the *source* was judged — genuine defects were fixed in source, incorrect test expectations were corrected and recorded in the session log.
