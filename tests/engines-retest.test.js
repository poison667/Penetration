import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Db } from '#app/db';
import { openStore } from '#store/store';
import { FileStore } from '#app/files';
import { Scheduler } from '#worker/scheduler';
import { createServiceRequest, createRetestRequest } from '#worker/runner';
import { generateRetestReport } from '#report/engine';
import { linkRetestFindings, applyRetestVerdicts } from '../src/engines/retest.js';
import { startFixture } from '../fixtures/vuln-app/server.js';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * RETEST / FIX-VERIFICATION TESTS
 *
 * Unit: verdict matrix (reproduced / fixed / inconclusive / new), FID
 * inheritance, source-finding updates.
 *
 * End-to-end: real fixture (loopback) → real engines → retest after REAL
 * remediation (fixture patched mode) → verdicts must reflect the behaviour
 * change: header/exposure findings flip to fixed, the rest reproduce.
 * No mocks: the fixture genuinely changes behaviour between the two runs.
 */

function seededDb(dir) {
  const store = openStore(dir);
  const db = new Db(store);
  const files = new FileStore(join(dir, 'files'), store);
  const tenant = db.insert('tenants', { name: 'Retest Tenant (test data)', status: 'active', created_at: new Date().toISOString() });
  db.insert('users', { tenant_id: tenant.id, email: 'rt@meridian.local', name: 'RT', role: 'owner', status: 'active', password_hash: 'x', mfa_enabled: false });
  db.insert('subscriptions', { tenant_id: tenant.id, plan_key: 'pro', status: 'active' });
  return { db, files, tenant };
}

test('unit: verdict matrix — reproduced / fixed / inconclusive / new + FID inheritance', () => {
  const dir = mkdtempSync(join(tmpdir(), 'meridian-rt-unit-'));
  try {
    const { db, tenant } = seededDb(dir);
    const asset = db.insert('assets', {
      tenant_id: tenant.id, identifier: 'http://unit.test', kind: 'web_host', title: 'unit',
      authorization: { status: 'verified', scope_domains: ['unit.test'], authorized_by: 'test', exclusions: [], ports: [], allow_private: true },
      status: 'active', created_at: new Date().toISOString(),
    });
    const now = new Date().toISOString();
    // source job with 3 findings: A (will reproduce), B (will be fixed), C (engine will fail → inconclusive)
    const srcJob = db.insert('jobs', { tenant_id: tenant.id, service_key: 'sec_config', asset_id: asset.id, params: {}, state: 'COMPLETED', finished_at: now });
    const mk = (h, engine, sev) => ({
      id: 'f_' + h, tenant_id: tenant.id, job_id: srcJob.id, asset_id: asset.id, fid: 'MER-F-' + h,
      check_id: 'X-' + h, title: 't' + h, severity: sev, status: 'open', verification: 'not_retested',
      hash: h, endpoint: '/e', parameter: null, detected_at: now, last_seen_at: now,
      provenance: { engine, engines: [engine], service_key: 'sec_config', job_id: srcJob.id, kind: 'measured' },
      facts: ['x'], evidence_ids: ['ev_x'],
    });
    const A = mk('hashA', 'sec_config', 'medium');
    const B = mk('hashB', 'sec_config', 'high');
    const C = mk('hashC', 'sec_crypto', 'low');
    for (const f of [A, B, C]) db.store.put('findings', f);

    // retest job: re-detects A (+ one new finding D), misses B, engine sec_crypto failed
    const rtJob = db.insert('jobs', {
      tenant_id: tenant.id, service_key: 'sec_config', asset_id: asset.id, params: {}, state: 'COMPLETED',
      finished_at: now, meta: { retest_of: srcJob.id },
      result_summary: { engines: [{ key: 'sec_config', ok: true, ms: 1 }, { key: 'sec_crypto', ok: false, ms: 1, error: 'x' }] },
    });
    const A2 = { ...A, id: 'f_A2', job_id: rtJob.id, detected_at: now, last_seen_at: now, evidence_ids: ['ev_a2'] };
    const D = { ...mk('hashD', 'sec_config', 'info'), id: 'f_D', job_id: rtJob.id, fid: 'MER-F-000004' };
    // linkRetestFindings: A2 inherits A's fid
    linkRetestFindings(db, rtJob, [A2, D]);
    assert.equal(A2.fid, 'MER-F-hashA', 're-detected finding must inherit the source FID');
    assert.equal(A2.verification, 'reproduced');
    assert.equal(D.verification, 'not_retested');
    db.store.put('findings', A2);
    db.store.put('findings', D);

    const run = applyRetestVerdicts(db, rtJob);
    assert.deepEqual(run.verdicts, { reproduced: 1, fixed: 1, inconclusive: 1, new: 1 });

    const updated = (id) => db.store.byId('findings', id);
    assert.equal(updated('f_hashA').verification, 'reproduced');
    assert.equal(updated('f_hashA').status, 'open');
    assert.equal(updated('f_hashA').reproduced_finding_id, 'f_A2');
    assert.equal(updated('f_hashB').verification, 'fixed');
    assert.equal(updated('f_hashB').status, 'fixed');
    assert.ok(updated('f_hashB').fixed_at);
    assert.equal(updated('f_hashC').verification, 'inconclusive');
    assert.equal(updated('f_hashC').status, 'open', 'inconclusive must NOT claim fixed');
    const itemD = run.items.find((i) => i.verdict === 'new');
    assert.equal(itemD.fid, 'MER-F-000004');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('e2e: real fixture → real engines → remediation → retest verdicts + report', async () => {
  delete process.env.FIXTURE_PATCHED;
  const fixture = await startFixture({ httpPort: 0, tlsPort: 0 });
  const port = fixture[0].address().port;
  const base = `http://127.0.0.1:${port}`;

  const dir = mkdtempSync(join(tmpdir(), 'meridian-rt-e2e-'));
  try {
    const { db, files, tenant } = seededDb(dir);
    const { grantCredits } = await import('#app/billing');
    grantCredits(db, tenant.id, 100000, 'test', 'rt grant');
    const asset = db.insert('assets', {
      tenant_id: tenant.id, identifier: base, kind: 'web_host', title: 'Fixture (retest test)',
      authorization: { status: 'verified', scope_domains: ['127.0.0.1'], authorized_by: 'test', exclusions: [], ports: [port], allow_private: true },
      status: 'active', created_at: new Date().toISOString(),
    });

    // ---- run 1: sec_config against the vulnerable fixture ----
    const { job: src } = createServiceRequest({ db, tenantId: tenant.id, serviceKey: 'web_audit', assetId: asset.id, params: { max_pages: 3 }, userId: null });
    const scheduler = new Scheduler({ db, files, requestService: (o) => createServiceRequest({ db, ...o }).job, generateReport: () => ({}), intervalMs: 2500 });
    let srcFinal = null;
    for (let i = 0; i < 80 && !srcFinal; i++) {
      await scheduler.tick();
      const cur = db.byIdGlobal('jobs', src.id);
      if (['COMPLETED', 'PARTIALLY_COMPLETED', 'FAILED'].includes(cur.state)) srcFinal = cur;
    }
    assert.ok(srcFinal, 'source job never finished');
    assert.equal(srcFinal.state, 'COMPLETED');
    const srcFindings = db.store.find('findings', (f) => f.job_id === src.id);
    assert.ok(srcFindings.length >= 3, `expected real findings, got ${srcFindings.length}`);

    // guard: retest of a non-completed job is refused
    const failedJob = db.insert('jobs', { tenant_id: tenant.id, service_key: 'sec_config', asset_id: asset.id, params: {}, state: 'FAILED' });
    assert.throws(() => createRetestRequest({ db, tenantId: tenant.id, sourceJob: failedJob }), /completed/);

    // ---- remediate the fixture (SAME instance, same port) ----
    process.env.FIXTURE_PATCHED = 'headers,exposure,verbose_errors';

    // ---- run 2: retest through the real runner ----
    const { job: rt } = createRetestRequest({ db, tenantId: tenant.id, sourceJob: srcFinal });
    assert.equal(rt.state, 'REQUESTED');
    assert.equal(rt.meta.retest_of, srcFinal.id);
    let rtFinal = null;
    for (let i = 0; i < 80 && !rtFinal; i++) {
      await scheduler.tick();
      const cur = db.byIdGlobal('jobs', rt.id);
      if (['COMPLETED', 'PARTIALLY_COMPLETED', 'FAILED'].includes(cur.state)) rtFinal = cur;
    }
    assert.ok(rtFinal, 'retest job never finished');
    assert.equal(rtFinal.state, 'COMPLETED');

    const runs = db.store.find('retest_runs', (r) => r.retest_job_id === rt.id);
    assert.equal(runs.length, 1);
    const run = runs[0];
    const v = run.verdicts;

    // REAL behaviour change → real verdicts: some fixed, most reproduced
    assert.ok(v.fixed >= 2, `expected fixed findings after remediation, got ${JSON.stringify(v)}`);
    assert.ok(v.reproduced >= 3, `expected reproduced findings, got ${JSON.stringify(v)}`);
    assert.equal(v.inconclusive, 0, `no engine should fail on the healthy fixture: ${JSON.stringify(v)}`);

    // header findings specifically must be fixed (headers were added)
    const headerChecks = run.items.filter((i) => ['CFG-006', 'CFG-007', 'CFG-008', 'CFG-009', 'CFG-010'].includes(i.check_id));
    assert.ok(headerChecks.length >= 3, `expected header findings in the source run: ${headerChecks.length}`);
    for (const h of headerChecks) {
      assert.equal(h.verdict, 'fixed', `header check ${h.check_id} must be fixed after remediation`);
    }

    // source findings carry the verdicts
    const fixedSrc = db.store.find('findings', (f) => f.job_id === src.id && f.verification === 'fixed');
    assert.equal(fixedSrc.length, v.fixed);
    for (const f of fixedSrc) { assert.equal(f.status, 'fixed'); assert.ok(f.fixed_at); assert.ok(f.verified_by_job_id); }
    const reprSrc = db.store.find('findings', (f) => f.job_id === src.id && f.verification === 'reproduced');
    assert.equal(reprSrc.length, v.reproduced);

    // re-detected findings inherit FIDs
    const rtFindings = db.store.find('findings', (f) => f.job_id === rt.id && f.verification === 'reproduced');
    for (const f of rtFindings) assert.match(f.fid, /^MER-F-\d{6}$/);

    // retest job summary exposes verdicts
    assert.equal(rtFinal.result_summary.retest.verdicts.fixed, v.fixed);
    assert.equal(rtFinal.result_summary.retest.source_job_id, srcFinal.id);

    // ---- retest report (pdf + json + csv) ----
    for (const format of ['pdf', 'json', 'csv']) {
      const { report, content } = generateRetestReport(db, files, { tenantId: tenant.id, run, format });
      assert.ok(report.sha256 && report.sha256.length === 64);
      assert.ok(content.length > 100);
      assert.equal(report.kind, 'retest_report');
      assert.equal(report.retest_run_id, run.id);
      if (format === 'pdf') assert.equal(content.subarray(0, 4).toString(), '%PDF');
    }
  } finally {
    delete process.env.FIXTURE_PATCHED;
    for (const s of fixture) await new Promise((r) => s.close(r));
    rmSync(dir, { recursive: true, force: true });
  }
});
