# Development Guide — Meridian Platform

How to set up, run, test and verify the platform. For architecture see
`docs/ARCHITECTURE.md`; for decisions `docs/DECISIONS.md`; for what is NOT
implemented `docs/LIMITATIONS.md`.

## Requirements

- **Node.js ≥ 20** (backend has zero runtime dependencies — built-ins only)
- npm ≥ 10 (client build toolchain only; the server never needs it)

## Quick start

```bash
npm install --prefix apps/client   # client toolchain (build-time only)
npm run seed:dev                   # demo tenant + fixture, real engine runs
npm start                          # API :8080 + worker + scheduler + UI
```

Open http://localhost:8080 — sign in with `demo@meridian.local` / `Demo!Passw0rd`
(owner) or `staff@meridian.local` / `Staff!Passw0rd` (platform staff).

## Scripts

| Command | What it does |
|---|---|
| `npm test` | full suite — **185 tests, 27 files, zero test dependencies** |
| `npm run report:tests` | runs the suite and writes `docs/TEST_REPORT.md` from live TAP |
| `npm run gen:matrix` | writes `docs/REQUIREMENTS_COVERAGE_MATRIX.csv` (19 cols, live counts) |
| `npm run verify` | **final gate**: suite → test report → matrix → live-instance checks |
| `npm start` | API + UI + worker + scheduler (`--mode=all`) |
| `npm run start:api` / `start:worker` | split-process operation |
| `npm run seed:dev` | rebuild demo tenant (runs real jobs against the fixture) |
| `npm run fixture` | the vulnerable test target on :8081/:8082 (loopback only) |
| `npm --prefix apps/client run build` | build the SPA into `webroot/` |
| `npm run gen:icons` | favicon/logo SVGs + desktop PNG icons (dependency-free) |
| `npm run gen:certs` | regenerate the fixture's TLS certificates |

## Ports & processes

| Port | Process |
|---|---|
| 8080 | API + UI (`node src/main.js`) |
| 8081 / 8082 | fixture HTTP / TLS (test target) |
| 5173 | client dev server (proxies /api and /events to :8080) |

## Layout orientation

- `src/` — the platform (see README table). Engine framework: `src/engines/`.
- `apps/client` — React+TS SPA, shared by web and the Tauri desktop shell.
- `apps/desktop` — Tauri 2 config; installers built by CI (L-2).
- `fixtures/vuln-app` — the deliberately vulnerable test oracle.
- `tests/` — `node --test` files; integration test runs the whole pipeline.
- `data/` — runtime state (WAL store, files, secret key). **Never commit.**

## Conventions that keep the zero-dependency promise

1. Backend imports use the `#alias/*` subpath imports defined in `package.json`
   (`#core/*`, `#engines`, `#api/*`, …). Aliases map to `.js` files — **omit the
   `.js` extension in aliased imports, keep it in relative ones.**
2. No `require()` anywhere — ESM only (a stray one caused a real 500; there is
   a regression test).
3. New checks must be registered in `src/engines/checks.js` with CWE/OWASP,
   wired into an engine, and exercised against the fixture. The engine-wiring
   test fails on unwired checks.
4. New routes must be tenant-scoped (`Db` layer enforces it) and guarded by
   `requireAuth([permission])`.
5. Findings without evidence are refused by the framework; QC rejects findings
   whose evidence ids don't resolve. Never report what wasn't measured.

## Adding a security check (end to end)

1. Add the check to `src/engines/checks.js` (id `XXX-###`, title, category,
   severity, CWE, remediation).
2. Implement the probe in the matching engine in `src/engines/sec/`, reporting
   via `ctx.report('XXX-###', { facts, inference, evidence: [ctx.evidenceFrom(...)] })`.
3. Prove a true positive on the fixture (add the flaw to
   `fixtures/vuln-app/server.js` if the class isn't represented) and a true
   negative on clean behavior.
4. `npm run verify` must stay green, then regenerate the matrix.

## Verification gate (before claiming anything works)

```bash
npm run verify
```

runs the suite, regenerates both live documents, and — if an instance is up on
:8080 — probes health, UI, auth enforcement, SSE, catalog, jobs, findings,
report download and the fixture. It prints PASS/FAIL per check and exits
non-zero on any failure. It never fabricates success.

## Repository & CI

`.gitignore` keeps runtime state (`data/`), dependencies and build output out.
On push, `.github/workflows/ci.yml` runs the test job, builds the client, and
builds Windows (NSIS/MSI) and Linux (AppImage/deb/rpm) installers from the
shared codebase. Initialize with:

```bash
git init && git add -A && git commit -m "Meridian Platform v1.0"
```
