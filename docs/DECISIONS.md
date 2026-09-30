# Decision Register — Meridian Platform

Every conflict encountered between requirements, or between a requirement and the
environment, is recorded here. **No conflict was silently resolved**; each entry states
the options, the choice, and the residual loss (cross-referenced in LIMITATIONS.md).

| ID | Decision | Rationale |
|----|----------|-----------|
| **D0** | The master prompt itself (Parts 1–23) is the specification. | No separate specification document was attached; the prompt is binding and complete. |
| **D1** | Zero-runtime-dependency Node.js 20 ESM backend; React+TypeScript SPA for UI. | Runtime deps are an audit-trust and supply-chain risk for a security platform; Node built-ins (crypto, http, zlib, test) cover every need. UI still needs a real component framework — kept to build-time-only deps. |
| **D2** | Custom WAL + snapshot store instead of SQLite/Postgres. | Node 20 has no built-in SQL engine; embedding one would violate D1. The WAL store gives durable, atomic, tenant-scoped persistence with torn-write recovery, verified by tests (store-wal, store-store). |
| **D3** | Durable job queue with lease + heartbeat + reclaim (not in-memory). | Crash-safety for long audit runs; stale leases are reclaimed, retried, then FAILED at max attempts. |
| **D4** | Desktop = Tauri 2 shell reusing the SPA; installers built in CI. | One shared codebase (requirement). The sandbox has no Rust toolchain, so installers are produced by the CI workflow (real, reproducible) rather than locally — recorded as limitation L-2, not silently claimed. |
| **D5** | AI = provider abstraction with a deterministic LocalGroundedProvider + BM25 RAG. | "AI analysis" must be grounded and non-fabricating. A local deterministic provider satisfies the pipeline contract without an external key; external LLMs plug in via env config. The platform never fabricates measurements regardless of provider. |
| **D6** | Reports carry sha256 integrity + previous_report_id chaining. | Integrity verification and historical comparison are requirements; hash is computed pre-stamp and embedded in the artifact (D23). |
| **D7** | Security testing is passive-by-default with explicit profiles; canary host `probe.meridian.invalid` (reserved TLD); per-host rate limits; destructive payloads blocked at framework level. | Authorization-first requirement. The `.invalid` TLD (RFC 2606) can never resolve to a third party, making redirect/RFI probes provably harmless. |
| **D8** | scrypt password hashing; opaque bearer tokens stored only as sha256; refresh rotation with family revocation; TOTP MFA; RBAC with per-route permission strings. | No JWTs (no revocation); no plaintext tokens at rest. Bug found by tests: descendant sessions survived family revocation — fixed (see TEST_REPORT.md). |
| **D9** | Single `Fetcher` contract (timeouts, redirects, bodies, TLS) shared by all engines. | Uniform evidence capture and one place to enforce scope/rate limits. |
| **D10** | Differential (nonce-marker) detection for reflected-input classes. | Reflection must be *proven* (marker survives into response) rather than guessed — reduces false positives to near zero. |
| **D11** | Audit log = per-tenant sequence + sha256 chain (prev_hash). | Tamper evidence must fail loudly on reordering, editing and deletion; per-tenant chains keep tenants isolated. |
| **D12** | Workflow expression language with `$`-variable binding, tokenizer fixed for operator runs. | Conditions need safe evaluation without `eval`. |
| **D13** | Workflow definitions validated at save time (step ids, types, wiring). | Catch authoring errors before they fail at 3 a.m. in production. |
| **D14** | Raw-socket probes (TRACE/verb tampering/smuggling) are bounded and opt-in. | Some checks cannot be expressed via fetch (which forbids setting certain headers); raw sockets stay inside the authorization + rate-limit envelope. |
| **D15** | The deliberately-vulnerable fixture is the test oracle: true positives must actually fire on it; honest non-fires are recorded as true negatives, never forced. | Requirement: no fake findings. An engine that reports nothing on a non-vulnerable behavior is correct; one that fires on nothing is broken. |
| **D16** | IDOR probes try adjacent resource ids. | Unverifiable without touching neighbors — allowed only within authorized scope. |
| **D17** | `node --test` built-in runner; zero test dependencies. | Same supply-chain rationale as D1; the runner covers unit + HTTP + E2E needs. |
| **D18** | The fixture exports `startFixture()` for in-process integration tests. | The E2E pipeline test needs a live vulnerable target without spawning processes. |
| **D19** | Ledger balance = Σ amounts, ordered by per-tenant sequence numbers. | Same-millisecond timestamps made time-ordering ambiguous (real bug found by tests). |
| **D20** | Tests assert real module shapes; when assertion and source disagreed, the source was judged case-by-case. | Distinguishes test bugs (wrong expectation — fix the test) from source bugs (genuine defect — fix the source). Every case is recorded in TEST_REPORT.md / the session log. |
| **D21** | Cron `nextRun` is strictly after the current minute (minute boundary), and dom/dow use standard OR semantics only when both are restricted. | Correctness of scheduling semantics (three real bugs found by tests). |
| **D22** | XLSX reader resolves rels targets relative to `xl/`. | OOXML spec: relationship targets are relative to the part's directory. |
| **D23** | Report integrity = content hash computed pre-stamp, then embedded in the rendered artifact. | A document cannot contain its own final hash; the pre-stamp hash is embedded and documented in the methodology section. |
| **D24** | Two distinct webhook features resolved by namespacing: automation-trigger registry lives at `/api/v1/automation/webhooks` (ingest unchanged at `/api/v1/hooks/:token`), notification-delivery registry owns `/api/v1/webhooks`. | Both features legitimately wanted the same path; with first-match routing the second registration is dead code. Re-pathing the automation registry next to its sibling `/api/v1/automation/*` routes preserves both features with zero loss; no consumers of the old path existed yet. |
| **D25** | OCR ships as a runtime-probed optional engine: `tesseract.js` (optionalDependency, WASM) or a system `tesseract` binary; the core keeps zero required runtime dependencies (D1). The engine runs inside a dedicated worker thread because tesseract.js re-throws image-decode failures at the process level — in-process execution would let one malformed upload crash the whole platform. | "OCR where supported" is honest only with a real engine; faking it violates the no-fake-results rule, and hard-requiring the dependency would break D1. Optional + probed + crash-contained satisfies both, and language data is vendored (`vendor/tessdata/`) so OCR works offline. |

## Conflict register

| # | Conflict | Resolution | Loss |
|---|----------|-----------|------|
| C1 | "OCR where supported" vs "never fabricate results" (no engine exists in a bare runtime). | Resolved by D25: a real engine (tesseract.js WASM, vendored language data, or system tesseract) is probed at runtime and used when present; otherwise `requires_ocr: true` with no text rather than guessing. | In minimal installs OCR is absent-but-honest; with the optional dependency installed (as in this deployment) it is fully real. |
| C2 | "Extensive security testing" vs "authorized-only, no attacks on third parties". | Engines refuse to run without verified authorization; passive defaults; canary host; destructive block (D7). | Some vuln classes are only detectable in active profiles — deliberate. |
| C3 | "Windows+Linux installers" vs "no Rust toolchain in build sandbox". | Tauri config + CI workflow are real and reproducible; local artifact build impossible here (L-2). | No locally-produced binaries in this workspace. |
| C4 | "Desktop feature parity" vs "one codebase". | Tauri shell loads the same SPA; platform differences isolated to shell config. | None beyond C3's build constraint. |
| C5 | "AI grounded analysis" vs "no external AI dependency required to run". | LocalGroundedProvider keeps the pipeline real (retrieval + citation + grounded flag) without external calls; external providers pluggable. | Analysis quality bounded by local provider; never fabricated. |
| C6 | "Rich PDF reports" vs "zero runtime dependencies". | Custom PDF 1.4 writer (fonts, tables, pagination) instead of a PDF library. | Limited typography (Type1 base fonts, no image embedding) — documented L-6. |
| C7 | "SMS notifications" vs "no fake completeness / no fabricated deliveries". | Webhook + email channels are fully real (signed POSTs, SMTP client, retry/backoff, delivery logs); SMS stays a documented limitation because carrier credentials cannot exist in a development environment. | SMS not delivered in this build — stated openly (L-5) instead of stubbed. |
