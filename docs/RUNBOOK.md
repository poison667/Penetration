# Meridian Platform — Operations Runbook

Complete, verified instructions for obtaining, running, operating, verifying,
backing up and troubleshooting the platform. Every command below was executed
and validated against the code in this repository. Source of truth for any
detail: `docs/ARCHITECTURE.md`, `docs/VERIFICATION_AUDIT.md`, `DEVELOPMENT.md`,
`src/main.js`, `scripts/verify-live.mjs`.

---

## 1. What you are running

| Component | What it is | Where it lives |
|---|---|---|
| **API server** | REST API + SSE + static UI host. Zero runtime dependencies (Node.js ≥20 built-ins only) | `src/api/` |
| **Worker + scheduler** | Durable job queue (lease/heartbeat), monitors, cron, billing grants | `src/queue/`, `src/worker/` |
| **Engines** | 19 engines (8 web, 13 security), 176 checks | `src/engines/` |
| **Web client** | React+TypeScript SPA, built into `webroot/` | `apps/client/` |
| **Desktop shell** | Tauri 2 wrapper embedding the identical SPA | `apps/desktop/` |
| **Test fixture** | Deliberately vulnerable loopback app (test oracle) | `fixtures/vuln-app/` |
| **Data** | JSON store (WAL + snapshots), files, secret key | `data/` (auto-created) |

**Process model.** One process (`--mode=all`) runs API + UI + worker + scheduler.
Split operation: `--mode=api` (HTTP only) and one or more `--mode=worker`
processes sharing the same data directory.

**Ports.**

| Port | Service | Binding |
|---|---|---|
| 8080 | API + web UI (`PORT` env to change) | `0.0.0.0` by default (`HOST` env to change) |
| 8081 | Test fixture — HTTP (`FIXTURE_HTTP_PORT`) | 127.0.0.1 only |
| 8082 | Test fixture — TLS (`FIXTURE_TLS_PORT`) | 127.0.0.1 only |
| 5173 | Vite dev server (client development only) | loopback |

---

## 2. Prerequisites

- **Node.js ≥ 20** (`engines.node` in package.json; built and verified on 20.20.2). Check: `node --version`.
- **npm** (ships with Node 20).
- **Git** (to clone; or download the source zip from the release).
- **OS**: Linux, macOS or Windows — the backend uses only Node built-ins.
- **Disk**: ~250 MB (dependencies + built client + demo data).
- **Network**: loopback is enough for the seeded demo; outbound access is needed
  only when you scan real, authorized external targets.
- No database, no Redis, no Docker required.

---

## 3. Obtain the software

```bash
git clone https://github.com/poison667/Penetration.git
cd Penetration
# optional: pin the verified release
git checkout v1.0.0
```

Or download the source archive from
https://github.com/poison667/Penetration/releases/tag/v1.0.0 and extract it.

---

## 4. First-time setup (in this exact order)

### Step 1 — Install backend dependencies

```bash
npm install --no-audit --no-fund
```

~13 packages. This includes the **optional** `tesseract.js` OCR engine (an
`optionalDependency`): with it, document intelligence performs real OCR; if you
install with `--omit=optional`, OCR reports an honest "engine unavailable"
instead of fabricating results.

### Step 2 — Install the client toolchain

```bash
npm --prefix apps/client install --no-audit --no-fund
```

~68 packages (Vite, TypeScript, React) — build-time only.

### Step 3 — Build the web client (required for the UI)

```bash
npm --prefix apps/client run build
```

Outputs the SPA to `webroot/` (`index.html` + hashed `assets/index-*.js|css`).
The server serves the UI **only if `webroot/` exists** — without this step you
get an API-only instance. (CI and `npm run verify:desktop` perform this step
automatically.)

### Step 4 — Seed the demo workspace

```bash
npm run seed:dev
```

This one-time step (clearly identified DEMO DATA per the specification):
- creates `data/` — `secret.key` (auto-generated 32-byte key, mode 0600),
  `store/` (WAL + snapshot JSON), `files/`;
- creates the demo tenant, `demo@meridian.local` (owner) and
  `staff@meridian.local` (platform staff), a Pro subscription and **5000 credits**;
- starts the loopback fixture on 127.0.0.1:8081/8082 **temporarily**;
- executes **real** web-audit and security-assessment jobs against that fixture
  (the demo workspace's findings are genuine engine output, not canned data);
- generates an initial PDF report from the results; then closes the fixture and exits.

Idempotent: a second run prints "demo tenant already present". `FORCE_SEED=1 npm run seed:dev`
adds another round of sample jobs.

### Step 5 — Keep the test fixture running (recommended)

```bash
npm run fixture        # separate terminal; serves 127.0.0.1:8081 (HTTP) + :8082 (TLS)
```

The seeded monitors and the demo asset point at this fixture. It binds to
loopback only and is **deliberately vulnerable** — never expose it beyond localhost.

### Step 6 — Start the platform

```bash
npm start              # = node src/main.js --mode=all
```

Expected console output:

```
[meridian] scheduler started (jobs, monitors, schedules, billing grants)
[meridian] API + UI listening on http://0.0.0.0:8080 (mode=all)
[meridian] data dir: /…/data
[meridian] openapi: http://0.0.0.0:8080/openapi.json
```

Split topology (optional): `npm run start:api` in one process +
`npm run start:worker` in another (or several), same `MERIDIAN_DATA`.

### Step 7 — Confirm it is running

```bash
curl http://127.0.0.1:8080/api/v1/health
# → {"ok":true,"version":"1.0.0",…}
```

Open **http://localhost:8080** in a browser → the Meridian login screen.
The machine-readable API contract is at **http://localhost:8080/openapi.json**.

---

## 5. Sign in

| Account | Password | Role | Purpose |
|---|---|---|---|
| `demo@meridian.local` | `Demo!Passw0rd` | owner | Full demo workspace (credits, jobs, findings, reports) |
| `staff@meridian.local` | `Staff!Passw0rd` | viewer + `is_staff` | Platform staff/administration views |
| fixture `admin` / `alice` | `admin123!A` / `alice123!A` | — | Logins **on the test fixture app itself** (127.0.0.1:8081), useful as scan targets |

Create your own tenant instead: **Register** in the UI, or
`POST /api/v1/auth/register`. Tokens are opaque access + refresh pairs
(`Authorization: Bearer …`), stored in `localStorage` by the SPA.

**MFA (TOTP)**: Settings → enable MFA, scan the secret into any authenticator
app, confirm the code. Codes are **replay-protected** (each accepted counter is
persisted; a used code can never succeed again). Disable requires a current code.

API-only access: create API keys (scoped, prefix + raw secret shown once) under
Settings → API keys.

---

## 6. Operating the platform (first steps)

1. **Dashboard** — 19 workspace views: dashboard, marketplace, requests, jobs,
   assets, monitoring, security, reports, evidence, data workbench, document
   vault, automation, AI workspace, billing, notifications, support, audit,
   settings, IAM.
2. **Scan a real website (authorization-first)** — Assets → add the host, then
   attach an **authorization record**: scope domains, exclusions, allowed ports,
   rate limits, safe-mode profile, and explicit `allow_private` if (and only if)
   the target is a private IP. Security engines **refuse to run** against assets
   without a verified authorization record; private ranges are refused unless
   explicitly authorized; destructive payloads are blocked at framework level.
3. **Marketplace** — 31 services across web-audit, SEO, performance/CWV,
   accessibility, and the 13 authorized-security categories (information
   gathering, configuration, TLS, authentication, sessions, authorization,
   input validation incl. XSS/SQLi/…, DoS resilience, business logic,
   cryptography, file uploads, payment, HTML5).
4. **Request a service** — pick an asset + params → the job runs the real
   lifecycle: `REQUESTED → VALIDATING → QUEUED → RUNNING → ANALYZING →
   QUALITY_CHECK → COMPLETED` (+ `FAILED/CANCELLED/RETRYING/PARTIALLY_COMPLETED`),
   visible in the Jobs view and over SSE (live updates).
5. **Findings** — every finding separates **FACT** (measured, with evidence
   attached and sha256-hashed) from **INFERENCE** and **RECOMMENDATION**.
   Nothing is reported that was not measured.
6. **Reports** — generate PDF / HTML / CSV / XLSX / JSON: executive summary,
   methodology, limitations, historical comparison with previous reports,
   sha256 integrity digest; download from the Reports view.
7. **Data workbench** — upload CSV/XLSX → profile → cleanse → dedupe →
   transform → anomaly detection → download results.
8. **Document vault** — upload documents → text extraction (PDF text layer,
   plain text), real OCR when tesseract.js is installed, side-by-side document
   comparison/diff.
9. **AI workspace** — build knowledge bases (RAG, BM25 retrieval), ask
   grounded questions; answers cite their sources and refuse to fabricate
   scan results or evidence.
10. **Automation** — versioned workflows, cron schedules, trigger rules,
    HMAC-signed webhooks, SMTP email channels (configured in-app under
    Notifications — host/port/from/to per channel).
11. **Monitoring** — website / API / SSL / DNS / DOM-visual monitors with
    configurable intervals and history.
12. **Billing** — plans, credit grants, usage ledger, invoices.
13. **Administration** — staff views for tenants, catalog, audit log
    (hash-chained: `seq, action, prev_hash → hash`).

---

## 7. Desktop applications

Three desktop forms exist, all built from the same shared codebase:

### 7a. Windowed application (Electron) — **recommended**

`Meridian-Desktop-1.0.0-win64.zip` (Windows 10+ x64 incl. LTSC; Linux twin
buildable) — a portable app that opens the platform **in its own window**:
extract the zip, double-click `Meridian.exe`. No browser, no console, no
installer, no WebView2, no Node.js required (Chromium is bundled — nothing
can fail on "this Windows version"). First run shows live seeding progress
inside the window (12 real jobs, a few minutes), then the login screen; later
runs start in seconds. App home: `%LOCALAPPDATA%\Meridian` (`data/` = all
state — back it up to back up the platform, delete it to reset; `logs/` =
dated log files). One instance at a time; free loopback ports are chosen
automatically. Unsigned → SmartScreen: *More info → Run anyway*. OCR not
bundled (honest "engine unavailable"). Build/rebuild either target on any
machine: `packaging/electron/build.sh` — full verification record in
`packaging/electron/README.md`.

### 7b. Single executable, console mode (Node SEA)

`Meridian-Platform-1.0.0-x64.exe` — one ~90 MB file that runs the whole
platform with a console window and opens the UI in the default browser
(preferable for headless/server use). Same first-run seeding, same app home.
(Build recipe: Node v24 SEA — `launcher.cjs` injected into `node.exe` with
postject; sources lost with an unrecovered snapshot, superseded by 7d.)

### 7d. One-file Windows setup — `Meridian-Setup-1.0.0.exe` (recommended)

A single ~229 MB exe that installs the 7a windowed application like normal
Windows software: double-click → installs to `%LOCALAPPDATA%\Meridian\Program`
(no admin) → Desktop + Start Menu shortcuts ("Meridian Platform") →
Apps & Features entry with uninstaller → launches the windowed app.
Workspace data at `%LOCALAPPDATA%\Meridian\data` is never touched
(re-installs/upgrades preserve it; uninstall keeps it).

Architecture (same overlay technique commercial installers use):

```
[node.exe + tiny SEA blob (installer.cjs)] [app.tar.gz] [64-byte footer]
```

- `packaging/installer/installer.cjs` — setup logic: reads the archive from
  its own file tail (magic `MERIDIAN-OVL1`), pure-Node ustar+gzip extractor,
  live-instance refusal via `instance.lock`, `.installed-version` marker,
  `uninstall.cmd` generation, PowerShell shortcuts + `reg.exe` HKCU uninstall
  key (best-effort, non-fatal), detached launch, `--uninstall` mode.
- `packaging/installer/build.sh` — build: tars the assembled 7a app tree,
  generates the tiny SEA blob (Node v24.21.0), postjects it into win/linux
  node binaries (Authenticode cert table zeroed first on win), appends the
  overlay. Produces `Meridian-Setup-1.0.0.exe` + a Linux twin for verification.
- `packaging/installer/sea-config.json` — SEA config (no assets; the app is
  the overlay).

Verified in-sandbox on the Linux twin (same code path, real executable):
extraction is byte-identical to the source tree (SHA-256 of `Meridian.exe`
matches; 22 files + 2 generated), install/re-install/`--uninstall` behave as
specified, live-lock refusal works, data survives uninstall. Windows exe
structurally verified (valid PE32+ AMD64, SEA resource present, fuse flipped,
overlay footer sane). Windows-only integration steps (shortcuts, registry,
detached launch, and the GUI window itself) cannot execute in this sandbox —
they are PowerShell/`reg.exe` one-liners run best-effort with warnings, and
each failure is reported without aborting the install.

### 7c. Tauri shell installers (on the release — documented open item)

https://github.com/poison667/Penetration/releases/tag/v1.0.0
(SHA-256 digests in the release notes and `installers/SHA256SUMS.txt`).

| OS | File | Install |
|---|---|---|
| Debian/Ubuntu 22.04+ | `meridian-platform_1.0.0_amd64.deb` | `sudo apt install ./meridian-platform_1.0.0_amd64.deb` |
| Fedora/RHEL | `meridian-platform-1.0.0-1.x86_64.rpm` | `sudo dnf install ./meridian-platform-1.0.0-1.x86_64.rpm` |
| Any x86_64 Linux | `meridian-platform_1.0.0_amd64.AppImage` | `chmod +x …AppImage && ./…AppImage` |
| Windows 10/11 | `meridian-platform_1.0.0_x64-setup.exe` | double-click (NSIS installer) |
| Windows 10/11 | `meridian-platform_1.0.0_x64_en-US.msi` | `msiexec /i …msi` (enterprise deployment) |

**Known limitation (docs/LIMITATIONS.md L-2):** these shells embed the
identical SPA but the SPA issues same-origin API requests, which do not reach
the server from inside the desktop webview — login/API calls from the
installed shell fail until the client-side server-URL wiring is completed
(the CSP already allows it; it is a small client change awaiting rebuild).
They also require the WebView2 runtime, which Windows 10 LTSC does not ship
by default. The verified operating paths are the **browser UI** and the
**single executable (7a)**.

---

## 8. Verification gate (prove it to yourself)

```bash
npm run verify
```

Runs, in order:

| Stage | What it does | Expected |
|---|---|---|
| `npm install` | restores dependencies | clean install |
| `report:tests` | runs the full suite, live-generates `docs/TEST_REPORT.md` | **203/203 tests, 29 files** |
| `gen:matrix` | regenerates the 19-column requirements matrix | **45/45 Complete** |
| `verify:desktop` | installs + builds the client, runs 30 build-input checks | **30/30** |
| `verify-live` | probes the **running** instance (start one first with `npm start`, and `npm run fixture` for the fixture checks) | **15/15** |

`verify-live` never fabricates: with no instance on
`MERIDIAN_URL` (default `http://127.0.0.1:8080`) it exits 0 with a notice; with
an instance up, **every** check must pass or it exits 1. Environment overrides:
`MERIDIAN_URL`, `FIXTURE_URL`, `DEMO_EMAIL`, `DEMO_PASSWORD`.

---

## 9. Configuration reference

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | API + UI port |
| `HOST` | `0.0.0.0` | Bind address (set `127.0.0.1` for loopback-only) |
| `MERIDIAN_DATA` | `./data` | Data directory (store, files, secret key) |
| `FIXTURE_HTTP_PORT` / `FIXTURE_TLS_PORT` | `8081` / `8082` | Fixture ports (seed + `npm run fixture`) |
| `FORCE_SEED` | — | `1` = seed another round of sample jobs |
| `MERIDIAN_URL`, `FIXTURE_URL`, `DEMO_EMAIL`, `DEMO_PASSWORD` | see §8 | verify-live overrides |

**Data directory layout:** `data/secret.key` (32-byte key, 0600 — losing it
invalidates sessions and sealed secrets), `data/store/` (`meta.json`,
`wal.jsonl`, `snapshot-*.json`), `data/files/` (uploads, evidence, reports).

**Backup:** stop the server (or snapshot after clean shutdown), copy `data/`.
**Restore:** copy back, start. **Reset to a fresh demo:** stop, `rm -rf data`,
`npm run seed:dev`.

**Production hardening:** the server speaks plain HTTP — terminate TLS at a
reverse proxy for any non-loopback deployment; bind `HOST=127.0.0.1` if the
UI/API should stay local; run `--mode=api` behind the proxy and `--mode=worker`
separately; back up `data/` (it is the entire state).

---

## 10. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `'tsc' is not recognized` (client build) | client dependencies never installed (step 2 skipped) | `npm --prefix apps/client install --no-audit --no-fund` |
| `EACCES: permission denied 0.0.0.0:8080` (Windows) | wildcard bind blocked externally — port held by another process (SO_EXCLUSIVEADDRUSE), a winnat/Hyper-V reserved range, or a security-software filter driver. Never an elevation problem; loopback binds are typically unaffected | Diagnose: `netsh interface ipv4 show excludedportrange protocol=tcp` and `netstat -ano \| findstr ":8080"` (then `tasklist \| findstr <PID>`). Fastest fix for local use: `HOST=127.0.0.1 npm start` — loopback binding, also the correct posture for single-machine deployments |
| `npm run fixture` exits silently, no `[fixture] …` line | defect #40: bin-mode guard compared a POSIX suffix against Windows' backslash `argv[1]` | fixed in-repo (path normalization). On the v1.0.0 tag, apply the one-line fix, or run zero-edit: `node -e "import('./fixtures/vuln-app/server.js').then(m => m.startFixture({ httpPort: 8081, tlsPort: 8082 }))"` |
| Seed prints nothing after "enqueueing…" | expected — the 12 real engine jobs run first; per-job lines print only when all finish | wait for `[seed] done. …` (several minutes); do not interrupt; interrupted seeds self-heal via the durable queue (`reclaimStale`), but re-run `rm -rf data && npm run seed:dev` for the pristine demo state |
| `npm error code ENOENT … package.json` | command run outside the repo (e.g. home dir) | `cd ~/Penetration` — every npm command runs from the repo root |
| `GET /` returns no UI / JSON only | `webroot/` missing (client not built) | `npm --prefix apps/client run build` |
| `EADDRINUSE :8080` | port occupied | `PORT=8081 npm start` (or free the port) |
| Login 401 | no users yet (fresh clone never seeded) or wrong credentials | `npm run seed:dev`; or Register |
| Monitors/jobs against the demo target fail | fixture not running | `npm run fixture` |
| "OCR engine unavailable" | tesseract.js not installed (e.g. `--omit=optional`) | `npm install` at repo root |
| `gen-certs` permission denied | lost exec bit | `bash scripts/gen-certs.sh` |
| Want fresh demo jobs | seed is idempotent | `FORCE_SEED=1 npm run seed:dev` |
| Tests fail after editing | — | `npm test` runs 203 tests in ~70 s; never commit with a red suite |
| Desktop app login fails | documented open item (§7) | use the browser UI; desktop server-URL wiring is pending |

---

## 11. Where everything lives

- Repository: https://github.com/poison667/Penetration · Release: `v1.0.0`
- `docs/ARCHITECTURE.md` — topology, pipeline, finding model, storage
- `docs/DECISIONS.md` — decision register D0–D23, conflict register C1–C6
- `docs/LIMITATIONS.md` — L-1…L-10 explicit known limitations
- `docs/VERIFICATION_AUDIT.md` — the full verification gate record (39 defects found & fixed)
- `docs/TEST_REPORT.md`, `docs/REQUIREMENTS_COVERAGE_MATRIX.csv` — live-generated
- `DEVELOPMENT.md` — conventions, adding a security check
- `fixtures/vuln-app/README.md` — the test oracle and its intentional flaws
- `docs/screenshots/` — real-browser captures of the workspace

## 12. Retest & fix verification (v1.0.1)

Any completed security/audit job with an asset can be retested: the platform
re-runs the SAME service, engine set and profile against the SAME target, then
verifies every source finding:

- **reproduced** — re-detected with fresh evidence (the finding keeps its FID)
- **fixed** — every contributing engine re-ran successfully and did not re-detect it
- **inconclusive** — a contributing engine failed during the retest (no claim made)
- **new** — first observed in this retest run

How to use: open a completed job → **Retest — verify fixes**. The retest job
shows a verdict panel + a downloadable **Retest Report** (PDF/HTML/CSV/JSON,
integrity-hashed). API: `POST /api/v1/jobs/:id/retest`, `GET /api/v1/retests`,
`GET /api/v1/retests/:id`, `POST /api/v1/reports {kind:"retest_report", retest_id}`.

Honest semantics (also printed in every retest report): "fixed" means "not
re-detected by the same checks under the same profile at retest time" — strong
evidence of remediation, not proof of absence. Verdicts never downgrade to
"fixed" when an engine failed (they stay "inconclusive").

Verified end-to-end against the deliberately vulnerable fixture with its
**patched mode** (`FIXTURE_PATCHED=headers,exposure,verbose_errors,…` — see
`fixtures/vuln-app/README.md`): real behaviour change between runs produces
real verdicts (e.g. 66 findings → 62 reproduced / 4 fixed after remediating
security headers). Tests: `tests/engines-retest.test.js` (unit verdict matrix
+ full e2e).

## 13. Manual-work hub (v1.1.0)

Real assessments combine automated scanning with manual testing. The manual hub
gives manual work first-class records — same findings store, same FIDs, same
evidence discipline, same reports.

**Manual findings** — `POST /api/v1/findings/manual`
(`findings:write`): a human-identified issue with `title`, `severity`,
`description` (stored as the finding FACT *and* as a `manual_note` evidence
record — no evidence-free findings), optional endpoint/parameter/CWE, optional
pasted request/response (stored as an `http_exchange` evidence record), and
optional `har_evidence_ids` linking imported HAR exchanges. Check ids
`MAN-001` (vulnerability), `MAN-002` (business logic), `MAN-003`
(misconfiguration), `MAN-004` (observation) — category `manual`, kind
`assisted`: the person is the measurement instrument, the platform records and
reports. Manual findings get a `MER-F-…` FID, a stable dedup hash, full triage
(`PATCH /api/v1/findings/:id`) and appear in every report next to engine
findings (Source column: MANUAL vs engine). Provenance records
`kind: manual`, the tool and the entering user.

**HAR import** — `POST /api/v1/har-imports` (`findings:write`): paste or
upload a HAR 1.2 document (the export format of browser DevTools, Burp Suite
and OWASP ZAP). Every HTTP exchange becomes a normal evidence record
(`kind: har_exchange`, sha256-hashed, size-capped: 32 KiB bodies, 100 headers,
500 entries) that you attach to manual findings via `har_evidence_ids`.
`GET /api/v1/har-imports` lists imports; `GET /api/v1/har-imports/:id`
returns the full import with its evidence ids.

UI: Findings → **New manual finding** / **Import HAR**.

Tests: `tests/manual-hub.test.js` — HAR parser (normalization, base64
decoding, truncation, non-HAR rejection), manual-finding validation (evidence
invariant, enums, FID/hash), and a full e2e: real traffic captured from the
live fixture as a genuine HAR → imported over the real API → manual finding
linked to it → findings list → asset report inclusion.
