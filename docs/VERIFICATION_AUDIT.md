# Verification Audit — Meridian Platform

**Final verification gate.** Every claim below was executed, not asserted. The audit
was performed on the workspace at `/home/user/meridian` (Node v20.20.2, Linux).

## 1. Automated suite

- `npm test` → **203/203 passing, 29 files, ~70s** (live-generated breakdown: `docs/TEST_REPORT.md`).
- Verification as a whole (suite + live probes + real browser + oracle audits) found
  and fixed **39 real defects** in production source: 9 by the suite (tokenizer loop,
  ledger ordering, xlsx rels path, 3 cron defects, RAG chunk loss, session-family
  revocation, binary secret sealing, api-keys `require()` 500, dedupe null-key
  crash), 2 by real-browser verification (BillingView React-tree crash, missing
  evidence-list route), 4 by the validation-oracle audit (§3b4), 8 by the
  full-catalog oracle audit (§3b5), 4 by the notification-delivery audit (§3b6),
  4 by the OCR audit (§3b7), 2 by the desktop build-input verification (§3b8),
  and 4 by the TOTP/MFA verification pass (§3b9). §3b10 then produced the real
  Linux installers locally (5 build-environment gaps found and closed), and the
  FIRST CI run on a fresh clone caught 2 more (§3b10 end): the unanchored
  `data/` ignore that swallowed the `src/data/` engine layer, and a
  CRLF-fragile multi-line check that failed only on windows runners. Details: TEST_REPORT.md + §3b3–§3b10 below.

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

## 3b5. Full-catalog oracle audit: 164/176 checks proven as true positives

The same audit was then extended to **every** check family (all 176 checks across
19 engines), not just validation. The live demo environment was extended with two
additional authorized assets — the fixture's HTTPS endpoint
(`https://localhost:8082`, deliberately weak self-signed SHA-1 certificate with
10-day validity) and its marketing redirect chain (`/promo → /promo2 → /deals`,
a slow, 500KB, uncompressed, 34-image page) — so TLS, HTTPS-only and
performance checks have genuine targets. The fixture gained 30+ additional real
flaws (see `fixtures/vuln-app/README.md`), and every engine was re-run live
through the API. Result: **164 of 176 checks fire as true positives** across the
demo dataset; whole families (PRF 9/9, A11Y 12/12, CRP 7/7, H5 6/6, BIZ 5/5,
PAY 5/5, UPL 10/10, AUT 6/6, CFG 16/17, ATH 15/16, SES 13/14, TLS 8/9) are now
proven against real HTTP exchanges with captured evidence.

This round exposed **eight more real engine defects** (all fixed, all re-verified live):
- **TLS engine skipped http assets entirely** (`if (start.protocol === 'http:') return`)
  even when the authorization record declared an in-scope HTTPS port — TLS-001…006/008
  were unreachable for every http:// asset. Fixed: the engine now probes the declared
  ports (only those — no port scanning) and runs the full analysis on the TLS endpoint.
- **TLS-004 was dead via a wrong field name**: the cert summary read `cert.sig_alg`,
  which does not exist in any Node version (Node 20 doesn't expose the signature
  algorithm at all). Fixed with a real minimal DER parser that extracts the
  signature-algorithm OID from the certificate bytes.
- **CFG-015 (banner disclosure) was never implemented by any engine** — a catalog
  check with no code behind it. Implemented in the headers engine.
- **ATH-002/008 (reset-flow enumeration/token-in-URL) could not fire as written**:
  the "plausible address" was a fixed generic address no real application treats
  specially. Fixed: the probe now harvests addresses actually discovered on the
  site (mailto links, page text).
- **AUT-001 (path traversal) was starved by its candidate ranking**: the field-name
  regex matched `username` (ends with "name") and `xml_document` (contains "doc"),
  so the first-5 probe budget was consumed before the actual `/file` parameter was
  reached. Fixed: candidates are now ranked (exact keyword names first).
- **ATH-014 and DOS-004 were unreachable**: both are gated on the `intrusive`
  profile, but the catalog did not offer that profile for their services. Fixed.
- **PRF-006 (caching) skipped when the first referenced asset was unreachable**
  (e.g. a dead CDN link first in the DOM) — now iterates candidates.
- **H5-004's wide-scope heuristic missed the standard service-worker passthrough
  idiom** `fetch(event.request)` — now recognized.

The remaining 12 non-firing checks are honest and documented in the fixture
README: 5 backend-signature VAL checks (LDAP/ORM/XPath/IMAP/NoSQL), VAL-004
(superseded), VAL-016 (C-style sink), VAL-018 + TLS-002 + DOS-003 (true
negatives on a Node target), SES-011 (deliberate trade-off — would conflict
with the SES-010 sequential-token oracle; the equivalent flaw is proven by
SES-012), and REC-009 (needs a domain-like asset, not `localhost`).

## 3b6. External notification delivery audit: webhooks + email proven live

R-2.15 (external notification channels) was closed with a real delivery stack:
`notify()` now fans every notification out to a persisted outbox
(`notify_deliveries`), and the scheduler tick flushes it — webhooks as
HMAC-SHA256-signed POSTs (`x-meridian-signature: sha256=HMAC(secret,
`${'{timestamp}'}.${'{body}'})`), email as a real RFC-5321 SMTP client
(EHLO → MAIL FROM → RCPT TO → DATA → QUIT) against the configured relay.
Retries use 15/60/300s backoff (max 3 attempts) and every attempt is visible in
the deliveries log. Verified three ways: **unit/integration tests** (loopback HTTP
receiver asserting the signature byte-for-byte; loopback SMTP server asserting
envelope + body; clock-injected retry/backoff tests — `tests/notify-delivery.test.js`,
8 tests), **API-surface tests** (anon 401, RBAC 403, SSRF guard on private URLs,
secret shown exactly once and stripped everywhere, audit trail —
`tests/api-server.test.js`), and **live check #14** in `scripts/verify-live.mjs`,
which spins an ephemeral receiver, registers a webhook through the real API,
triggers a test delivery, and asserts the received POST's HMAC signature against
the creation-time secret.

This round exposed **four more real defects** (all fixed, all re-verified):
- **Event filters never matched their own prefix syntax** — the matcher tested
  `startsWith(e + '.')`, so a filter of `job.` became `job..` and matched nothing
  (exact matches still worked, hiding the bug).
- **The webhook event header was a hardcoded constant** (`x-meridian-event:
  notification`) instead of the notification type — receivers could not filter by
  event. Found by live check #14: the delivery succeeded, the signature verified,
  but the event header carried no information.
- **Route shadowing**: the new delivery-webhook routes registered the same paths
  (`/api/v1/webhooks`) as the older automation-trigger webhook registry; with
  first-match routing the new routes were unreachable dead code. Resolved by
  re-pathing the automation registry to `/api/v1/automation/webhooks` (decision
  D24) — both features fully preserved.
- **The API rate limiter was module-global**: separate server instances (exactly
  what tests create, and what multi-process deployments run) shared login buckets,
  cross-contaminating throttling. Now scoped per server instance.

SMS delivery is deliberately not stubbed: carrier credentials are external
deployment configuration (limitation L-5).

## 3b7. OCR audit: real engine, proven live, crash-contained

R-2.8 ("OCR where supported") was closed with a real engine instead of a stub.
`extractTextAsync` routes images through a runtime-probed OCR provider:
`tesseract.js` (optional WASM dependency, language data vendored in
`vendor/tessdata/` for offline operation) or a system `tesseract` binary; when
neither exists the platform reports `requires_ocr` honestly and extracts
nothing. Verified four ways: unit tests on a committed sample image
(`tests/fixtures/ocr-sample.png`, deterministically regenerable via
`scripts/gen-ocr-fixture.mjs` — the engine reads exactly "MERIDIAN OCR 4217",
confidence 80, reproducible across runs), API-surface tests (multipart upload →
inline extraction → RBAC), an engine-crash containment test (undecodable bytes
must not kill the process), and **live check #15** (upload + extract through
the running API). The document vault UI gained an Extract action; the
`doc_extract` service runs OCR through the same code path in the job pipeline.

This round exposed **four more real defects** (fixed):
- **tesseract.js crashes the host process on undecodable images** — its worker
  'error' handler re-throws via `process.nextTick`, so a malformed upload would
  take down the API server (a denial-of-service from user input). The engine now
  runs in a dedicated worker thread: a decode crash kills only the thread and
  the failure is reported honestly. A test proves recovery (valid OCR succeeds
  after a crash).
- **a persistent engine thread kept processes alive at exit even after
  `Worker#unref()`** (verified on Node 20: a worker thread with a live message
  listener blocks process exit). First attempt (persistent thread + unref) hung
  the whole test suite invisibly; the engine now uses a disposable per-job
  thread that is terminated as soon as its result or crash is observed — no
  handles outlive the call.
- **the test-report generator silently swallowed killed test processes**: a file
  that timed out produced no TAP summary, contributed zero tests, and the report
  still read green while the suite had actually hung (the first verify run
  "passed" 190/190 in 666s with one file killed). The generator now fails loudly
  on any file without a TAP summary.
- **`POST /api/v1/requests` required `asset_id` unconditionally**, making every
  asset-less service (documents, data workbench, AI) unrequestable through the
  API even though `createServiceRequest` explicitly exempts them. `asset_id` is
  now optional; the per-service requirement is enforced server-side.

## 3b8. Desktop build-input verification: installers made CI-safe

The desktop requirement (R-3.11) cannot produce binaries in this sandbox (no
Rust toolchain, no system WebKitGTK — D4/L-2), so the remaining risk was CI
discovering a broken build only after spending runner minutes. A new gate step,
`npm run verify:desktop` (30 checks), verifies every build input statically:
tauri.conf.json structure and identifiers, bundle targets for all five installer
formats, icon existence/dimensions AND byte-identity with the deterministic
generator, a valid `.ico`, the shared-SPA invariant (the desktop bundle embeds
the same `webroot/` the web deployment serves, rebuilt by `beforeBuildCommand`),
the shell crate wiring, and the CI workflow itself (both OS legs, system deps,
explicit per-OS `--bundles`, artifact globs for all five formats).

Its first run caught **two real defects** (both fixed, gate green):
- **no `.ico` icon existed** — Tauri's Windows bundlers (NSIS/MSI) require one;
  the `windows-latest` CI leg would have failed at bundle time. A zero-
  dependency ICO writer (PNG-compressed 16/32/48/256 entries) was added to
  `scripts/gen-icons.js` and `icon.ico` is now listed in the bundle config.
- **`frontendDist` was `"../../webroot"`** — Tauri resolves it relative to
  `tauri.conf.json` (in `src-tauri/`), so it pointed at the nonexistent
  `apps/webroot`; the desktop bundle would have embedded nothing. Fixed to
  `../../../webroot` (verified semantics against upstream Tauri documentation
  and issue reports), and the check now pins the resolution rule.

The CI workflow was hardened in the same pass: per-OS `--bundles` instead of
`--target all`, `npm run verify:desktop` runs before `tauri-action` on both
legs, and the test job installs dependencies so CI exercises the real OCR
engine (previously it ran in honest-absence mode) with the vendored offline
language data. R-3.11 remains Partial — installers are CI-produced — but every
input the CI build consumes is now verified by the same gate that tests the
platform.

## 3b9. TOTP replay protection + MFA test determinism

While hardening the desktop gate (§3b8), a full-gate run failed intermittently
in the MFA login test. Chasing it exposed a chain of four real defects:

- **`verifyTotp` documented replay protection that did not exist.** Its comment
  promised "consumes codes to prevent replay"; nothing consumed anything — an
  intercepted TOTP code stayed valid for its whole ±90s acceptance window.
  Implemented for real: `verifyTotp` now returns the matched counter and rejects
  counters at/below a caller-supplied `lastCounter`, persisted on the user
  record at all three verification sites (login, enable, disable). A used code
  can never succeed again; unit + API tests assert the replay rejection.
- **A stale-spread write clobbered the counter** moments after it was persisted:
  the login route wrote `mfa_last_counter`, then overwrote the user record from
  the pre-MFA `user` object for `last_login_at`, silently dropping the new field.
  Caught immediately by the new replay assertion (the "fixed" code replayed
  successfully, 100% reproducible). The route now performs one merged write.
- **The MFA test computed its next-window code as `Date.now() + 31s`** — which
  lands TWO steps ahead (outside the ±1 acceptance window) whenever the test
  runs in the last second of a 30s step (~3% of runs, measured). Replaced with
  step-boundary-aligned math that is exactly +1 at any wall-clock offset.
- **Failing tests hung the whole file**: `server.close()` sat inside `try`, so
  any assertion failure leaked the listener and the process had to be killed —
  surfacing as "file killed" instead of "test failed" (the report generator
  from §3b7 then correctly flagged it, but the real failure was obscured).
  All api-server tests now close their servers in `finally`.

Verified stable: the full api-server file 8/8 clean and the MFA test 15/15
clean across repeated runs spanning multiple 30-second step boundaries.

## 3b10. Real Linux installers built and verified locally (R-3.11 closed)

The single remaining PARTIAL requirement (R-3.11 — actual installer binaries)
was closed by building the installers **for real, in this workspace**, with no
root access, using a user-space WebKitGTK sysroot.

**Build (one codebase, one command, exit 0):** `cd apps/desktop && npx
@tauri-apps/cli@2 build --bundles deb,rpm,appimage` under rustc 1.98.1 /
tauri-cli 2.12.0, with a 146-package Debian trixie apt closure (`--no-install-
recommends`: libwebkit2gtk-4.1-dev 2.52.6, gtk+ 3.24.49, librsvg, patchelf)
extracted via `dpkg-deb -x` into `~/gtkroot` and wired up via `PKG_CONFIG_PATH`
(.pc files rewritten to absolute paths), `LD_LIBRARY_PATH`, and `PATH`. Output:
`Finished 3 bundles at:` **Meridian Platform_1.0.0_amd64.deb (2.80 MiB) ·
Meridian Platform-1.0.0-1.x86_64.rpm (2.80 MiB) · Meridian Platform_1.0.0_
amd64.AppImage (96.89 MiB)** — copied with SHA-256 checksums to
`/home/user/installers/` (recipe + transcript: `installers/BUILD_INFO.md`).

**Five build-environment gaps found and closed** (none were product-code
defects; each initially failed the build loudly — no silent degradation):

1. **Static-archive shadowing broke the final link.** The sysroot's
   `libdbus-1.a` (from the -dev closure) shadowed the system shared libdbus,
   and the static archive references `sd_listen_fds`/`sd_is_socket`
   (libsystemd) → `rust-lld: undefined symbol`. Fix: sysroot `.so` symlinks to
   the system shared libs for every `.a`-only shadow (11 libs, notably
   `libdbus-1.so` → system 3.38.3). After that the entire ~450-crate tree
   linked clean.
2. **`mksquashfs` missing** (headless image, no squashfs-tools) — linuxdeploy's
   appimage plugin needs it. The tauri CLI swallows linuxdeploy's stderr at
   default log level, so this was located by re-running tauri's exact
   linuxdeploy invocation manually (`--verbosity 0`). Fix: user-space
   `squashfs-tools` extracted into the sysroot and put on PATH.
3. **The AppImage needed `APPIMAGE_EXTRACT_AND_RUN=1`** (no FUSE in the
   sandbox) — inherited through the bundler to linuxdeploy and its plugins.
4. **tauri's embedded `linuxdeploy-plugin-gtk.sh` searches SYSTEM paths** for
   GTK modules (`/usr/lib/x86_64-linux-gnu/gtk-3.0` — absent on this headless
   image). It honors two overrides, both now used: `LD_GTK_LIBRARY_PATH`
   → sysroot libdir (module trees: gtk-3.0, gio/modules, typelibs), and
   `PKG_CONFIG_PATH` (all `--variable` lookups resolve to sysroot paths).
5. **Module-cache tools are fatal-if-missing** (`set -e` + unconditional
   `sed` on the cache files): `gtk-query-immodules-3.0`,
   `gdk-pixbuf-query-loaders`, `gio-querymodules` were fetched into the
   sysroot (libgtk-3-0 / libgdk-pixbuf-2.0-0 / libglib2.0-bin) and exposed on
   PATH, so the AppImage ships **real generated** `immodules.cache`
   (gtk+ 3.24.49) and `loaders.cache` (incl. the librsvg SVG loader).

**Verification of the artifacts (structural — the sandbox has no display, so
the GUI was not launched; see L-2):**

- **DEB** — `dpkg-deb -I`: `meridian-platform` 1.0.0 amd64, `Depends:
  libwebkit2gtk-4.1-0, libgtk-3-0`; `dpkg-deb -c`: `/usr/bin/meridian-desktop`
  (11,062,648 B), hicolor icons 32/128/256/256@2, desktop entry.
- **RPM** — `rpm2cpio | cpio -it`: binary + desktop entry + all 4 icon sizes.
- **AppImage** — `--appimage-extract`: AppRun, AppRun.wrapped,
  `apprun-hooks/linuxdeploy-plugin-gtk.sh`, .desktop, .DirIcon, binary, **196
  bundled shared libs**, real immodules/loaders caches. `ldd` against the
  extracted tree: **143 dependencies resolve inside the AppImage**; the only
  external is `libasound.so.2`, which is on **linuxdeploy's embedded
  system-lib exclusion list** (upstream policy: ALSA is base-system on
  desktops; the deb/rpm pull it transitively via the distro webkit package).
- **ELF** — `file`: 64-bit x86-64 **PIE**; `objdump -p`: DT_NEEDED =
  libwebkit2gtk-4.1.so.0, libgtk-3.so.0, libsoup-3.0.so.0,
  libjavascriptcoregtk-4.1.so.0, gio/glib/gobject/gdk/cairo/pixbuf/dbus (…).
- **Shared-SPA invariant holds in the shipped binary**: `strings` finds
  `assets/index-CHJYQdlS.js` + `assets/index-BAjiAVxf.css` — the deterministic
  vite hashes identical to the committed `webroot/` (§3b8), i.e. the desktop
  installers embed the exact SPA the web client serves.

Windows .exe (NSIS) / .msi (WiX) remain CI-built per the committed workflow
(no Windows runner or wine locally — D4 addendum, L-2). GUI install/run
testing on a real Linux desktop remains an open item, recorded in L-2.

**Rebuild record (same session).** The first verified build's AppImage file
(SHA-256 `1b91cc08c600b453…`) was dropped by the build sandbox's
workspace-snapshot size cap after verification; everything was rebuilt from
the same sources and the same surviving deb set + recipe (one re-download:
the `libwebkit2gtk-4.1-0` runtime deb, also dropped by the cap). The rebuild
reproduced the identical verification profile — 196 bundled libs, 143
in-image dependency resolutions, only the deliberate linuxdeploy alsa
exclusion external, SPA assets embedded, DEB/RPM metadata unchanged — with
new hashes recorded in `installers/SHA256SUMS.txt` (byte differences are
packaging timestamps, not content). Both build logs are in the workspace
history; artifacts republished with the GitHub v1.0.0 release.

**Windows cross-compile attempt (made, and honestly resource-blocked).** A
serious local attempt to also produce the NSIS .exe was made with
`cargo-xwin` 0.23.1 (rustc target `x86_64-pc-windows-msvc`, xwin-downloaded
MSVC CRT + Windows SDK, clang-cl 19.1.7 + LLVM tools in the user-space
sysroot). The full Windows dependency tree resolved and compiled for ~10
minutes, then rustc was **killed by the OOM killer (SIGKILL) while compiling
the `windows` 0.62.2 crate** — its metadata pass exceeds what the sandbox's
2 GB RAM can hold even with `CARGO_BUILD_JOBS=1`. This is a hard resource
ceiling of this workspace, not a toolchain gap: the recipe is recorded here
so it can be re-run unchanged on any machine with ≥4 GB RAM, and the
committed CI workflow (windows-latest runner) builds the same NSIS/MSI
targets with the same one shared codebase. No Windows binary exists locally;
none is claimed.


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
live-generated coverage matrix → client build + **30 desktop build-input checks**
→ **15 live-instance checks** (health, UI bundle, anonymous-auth rejection, SSE
gate + stream, login, session, catalog, executed jobs, findings-with-evidence,
report download, signed webhook delivery, live OCR through the API, fixture). It
exits non-zero on any failure and never fabricates success.

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

**Published (final state).** The repository is published at
github.com/poison667/Penetration; the CI workflow runs green on both
windows-latest and ubuntu-22.04 for the fixed commits (7896316, d1920b0):
the test suite passes 203/203 **on a fresh clone**, all 30 desktop
build-input checks pass **including on Windows** (after the CRLF fix), and
the CI `build-desktop` job produced the **Windows NSIS .exe + WiX .msi**
from the same shared codebase. Together with the locally-built and verified
Linux installers, all five are attached to the **v1.0.0 release** with
SHA-256 digests (installers/SHA256SUMS.txt + release notes). Two real
defects were found by that first CI run and fixed in commit 7896316:

- **#38 — unanchored `data/` gitignore pattern swallowed the data-workbench
  engine layer** (`src/data/`, 7 modules incl. `xlsx.js` imported by the
  report engine): the files existed in the build workspace, so every local
  gate passed, but fresh clones (CI) failed with `ERR_MODULE_NOT_FOUND`.
  Fixed by anchoring the pattern to `/data/` (runtime tenant state stays
  ignored) and committing the missing modules.
- **#39 — a CRLF-fragile multi-line regex in verify-desktop.mjs** (JS `.` does
  not match `\r`): passed on Linux checkouts, failed 29/30 on windows-latest
  where git autocrlf converts to CRLF. Fixed with `\r?`-tolerant matching and
  a `.gitattributes` LF pin for the whole repo.
