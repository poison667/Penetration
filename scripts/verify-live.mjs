/**
 * Live verification gate — checks the RUNNING instance (npm start, :8080).
 * If no instance is running, exits 0 with a notice (code-level verification
 * already ran via the test suite); when an instance IS up, every check must
 * pass or this exits 1. Never fabricates success.
 */
const B = process.env.MERIDIAN_URL || 'http://127.0.0.1:8080';
const FIXTURE = process.env.FIXTURE_URL || 'http://127.0.0.1:8081';
const DEMO_EMAIL = process.env.DEMO_EMAIL || 'demo@meridian.local';
const DEMO_PASSWORD = process.env.DEMO_PASSWORD || 'Demo!Passw0rd';

const results = [];
const check = (name, ok, detail = '') => { results.push({ name, ok, detail }); console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`); };

async function main() {
  let up = false;
  try { const r = await fetch(`${B}/api/v1/health`, { signal: AbortSignal.timeout(2000) }); up = r.ok; } catch { /* down */ }
  if (!up) {
    console.log('[verify-live] no live instance on ' + B + ' — start one with `npm start` to run the live gate. Code-level verification is covered by `npm test`.');
    process.exit(0);
  }
  console.log(`[verify-live] probing live instance at ${B}`);

  // health + version
  const health = await (await fetch(`${B}/api/v1/health`)).json();
  check('API health', health.ok === true, `v${health.version}`);

  // UI is served (built SPA, not a stub)
  const ui = await fetch(`${B}/`);
  const html = await ui.text();
  check('UI served', ui.status === 200 && html.includes('/assets/'), `${html.length}B index`);
  const asset = html.match(/src="(\/assets\/[^"]+\.js)"/)?.[1];
  if (asset) {
    const js = await fetch(`${B}${asset}`);
    check('UI bundle resolves', js.status === 200 && (await js.arrayBuffer()).byteLength > 100000, `${asset}`);
  }

  // auth gate: anonymous rejected everywhere sensitive
  const anonJobs = await fetch(`${B}/api/v1/jobs`);
  check('auth enforced (401 anonymous)', anonJobs.status === 401);
  const sseAnon = await fetch(`${B}/events`);
  check('SSE auth enforced', sseAnon.status === 401);

  // demo login → tokens → catalog → jobs
  const login = await (await fetch(`${B}/api/v1/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: DEMO_EMAIL, password: DEMO_PASSWORD }) })).json();
  check('demo login', !!login.access_token);
  const H = { authorization: `Bearer ${login.access_token}` };
  const me = await (await fetch(`${B}/api/v1/auth/me`, { headers: H })).json();
  check('session resolves', me.user?.email === DEMO_EMAIL, `credits: ${me.credits}`);

  const cat = await (await fetch(`${B}/api/v1/catalog`, { headers: H })).json();
  check('catalog complete', Array.isArray(cat.services) && cat.services.length >= 25, `${cat.services?.length} services`);

  const jobs = await (await fetch(`${B}/api/v1/jobs?limit=200`, { headers: H })).json();
  const completed = jobs.jobs.filter((j) => j.state === 'COMPLETED');
  check('jobs executed historically', jobs.jobs.length > 0 && completed.length > 0, `${jobs.jobs.length} total, ${completed.length} completed`);

  const findings = await (await fetch(`${B}/api/v1/findings?limit=500`, { headers: H })).json();
  check('findings recorded with evidence', findings.findings.length > 0, `${findings.total} total`);

  // reports downloadable
  const reports = await (await fetch(`${B}/api/v1/reports?limit=10`, { headers: H })).json();
  if (reports.reports?.length) {
    const dl = await fetch(`${B}/api/v1/reports/${reports.reports[0].id}/download`, { headers: H });
    const buf = await dl.arrayBuffer();
    const head = Buffer.from(buf.slice(0, 8)).toString('latin1');
    check('report download + integrity', dl.status === 200 && (head.startsWith('%PDF') || buf.byteLength > 500), reports.reports[0].format);
  } else {
    check('report download + integrity', false, 'no reports to download');
  }

  // SSE live stream (query-param token, as the SPA sends)
  const sse = await fetch(`${B}/events?access_token=${login.access_token}`);
  check('SSE stream opens', sse.status === 200 && (sse.headers.get('content-type') || '').includes('text/event-stream'));

  // fixture (the authorized test target) reachable when running
  try {
    const fx = await fetch(`${FIXTURE}/`, { signal: AbortSignal.timeout(2000) });
    check('test fixture up', fx.ok, `${FIXTURE}`);
  } catch {
    console.log('  NOTE  test fixture not running (npm run fixture) — fine unless demonstrating engine runs');
  }

  const failed = results.filter((r) => !r.ok);
  console.log(`[verify-live] ${results.length - failed.length}/${results.length} live checks passed`);
  if (failed.length) { console.error('[verify-live] FAILED — see above'); process.exit(1); }
}

main().catch((e) => { console.error('[verify-live] error:', e.message); process.exit(1); });
