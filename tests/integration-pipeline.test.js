import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Db } from '#app/db';
import { openStore } from '#store/store';
import { FileStore } from '#app/files';
import { Scheduler } from '#worker/scheduler';
import { createServiceRequest } from '#worker/runner';
import { generateReport } from '#report/engine';
import { startFixture } from '../fixtures/vuln-app/server.js';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * END-TO-END PIPELINE TEST
 * Real fixture (loopback) → real engines → real findings → QC → FIDs → evidence → report.
 * No mocks: the deliberately-vulnerable fixture genuinely exhibits the detected flaws.
 */

test('full pipeline: request → validate → execute → findings → evidence → report', async () => {
  const fixture = await startFixture({ httpPort: 0, tlsPort: 0 }); // ephemeral ports
  const port = fixture[0].address().port;
  const base = `http://127.0.0.1:${port}`;

  const dir = mkdtempSync(join(tmpdir(), 'meridian-e2e-'));
  try {
    const store = openStore(dir);
    const db = new Db(store);
    const files = new FileStore(join(dir, 'files'), store);

    // tenant + authorized asset (the fixture is loopback-only test infrastructure)
    const tenant = db.insert('tenants', { name: 'E2E Tenant (test data)', status: 'active', created_at: new Date().toISOString() });
    const owner = db.insert('users', { tenant_id: tenant.id, email: 'e2e@meridian.local', name: 'E2E', role: 'owner', status: 'active', password_hash: 'x', mfa_enabled: false });
    const asset = db.insert('assets', {
      tenant_id: tenant.id, identifier: base, kind: 'web_host', title: 'Fixture',
      authorization: { status: 'verified', scope_domains: ['127.0.0.1'], authorized_by: 'test', exclusions: [], ports: [], allow_private: true },
      status: 'active', created_at: new Date().toISOString(),
    });
    db.insert('subscriptions', { tenant_id: tenant.id, plan_key: 'pro', status: 'active' });
    const { grantCredits } = await import('#app/billing');
    grantCredits(db, tenant.id, 100000, 'test', 'e2e grant');

    // request a real service
    const { job } = createServiceRequest({ db, tenantId: tenant.id, serviceKey: 'web_audit', assetId: asset.id, params: { max_pages: 4 }, userId: owner.id });
    assert.equal(job.state, 'REQUESTED');

    // drive the real scheduler until the job reaches a terminal state
    const scheduler = new Scheduler({ db, files, requestService: (o) => createServiceRequest({ db, ...o }).job, generateReport: (o) => generateReport(db, files, o), intervalMs: 2500 });
    let final = null;
    for (let i = 0; i < 60 && !final; i++) {
      await scheduler.tick();
      const cur = db.byIdGlobal('jobs', job.id);
      if (['COMPLETED', 'PARTIALLY_COMPLETED', 'FAILED'].includes(cur.state)) final = cur;
    }
    assert.ok(final, 'job never reached a terminal state');
    assert.equal(final.state, 'COMPLETED');
    assert.ok(final.result_summary?.findings_count >= 5, `expected real findings, got ${JSON.stringify(final.result_summary)}`);

    // lifecycle trace: REQUESTED → VALIDATING → QUEUED → RUNNING → … → COMPLETED
    const states = db.store.find('job_events', (e) => e.job_id === job.id).map((e) => e.state ?? e.to);
    if (states.length) {
      assert.equal(states[0], 'REQUESTED');
      assert.equal(states[states.length - 1], 'COMPLETED');
    }

    // findings: structured, FIDed, with facts and evidence links
    const findings = db.store.find('findings', (f) => f.job_id === job.id);
    assert.ok(findings.length >= 5);
    for (const f of findings.slice(0, 10)) {
      assert.match(f.fid, /^MER-F-\d{6}$/);
      assert.ok(f.check_id && f.severity && f.title);
      assert.ok(Array.isArray(f.facts) && f.facts.length >= 1, `finding ${f.fid} lacks facts`);
      assert.ok(f.detected_at || f.created_at, `finding ${f.fid} lacks a detection timestamp`);
      assert.ok(['open', 'remediated', 'false_positive', 'accepted_risk', 'retest_pending'].includes(f.status));
    }
    // at least one finding must link stored evidence
    const evidence = db.store.find('evidence', (e) => e.job_id === job.id);
    assert.ok(evidence.length >= 1, 'expected captured evidence records');

    // QC + engines metrics recorded
    assert.ok(final.result_summary || final.qc, 'expected a result summary from QC');

    // generate a real report and verify integrity
    const { report, content } = generateReport(db, files, { tenantId: tenant.id, job: final, kind: 'service_report', format: 'pdf' });
    assert.equal(report.findings_count, findings.length);
    assert.match(report.sha256, /^[0-9a-f]{64}$/);
    assert.equal(content.slice(0, 8).toString('latin1'), '%PDF-1.4');
    const stored = files.read(tenant.id, report.file_id);
    assert.ok(stored.length > 10000);

    // credits were actually committed for the run (ledger carries a commit entry)
    const ledger = db.store.find('credit_ledger', (l) => l.tenant_id === tenant.id && l.job_id === job.id);
    assert.ok(ledger.some((l) => l.source === 'job_commit' || l.entry_type === 'commit'), `expected a commit entry, got ${JSON.stringify(ledger.map((l) => l.entry_type))}`);
    assert.ok(final.usage?.credits_committed > 0, 'expected credits_committed in job usage');

    // a security job also works end-to-end (the fixture is genuinely vulnerable)
    const { job: secJob } = createServiceRequest({ db, tenantId: tenant.id, serviceKey: 'sec_validation', assetId: asset.id, params: { profile: 'standard', max_pages: 6 }, userId: owner.id });
    let secFinal = null;
    for (let i = 0; i < 80 && !secFinal; i++) {
      await scheduler.tick();
      const cur = db.byIdGlobal('jobs', secJob.id);
      if (['COMPLETED', 'PARTIALLY_COMPLETED', 'FAILED'].includes(cur.state)) secFinal = cur;
    }
    assert.equal(secFinal.state, 'COMPLETED');
    const secFindings = db.store.find('findings', (f) => f.job_id === secJob.id);
    const sevs = new Set(secFindings.map((f) => f.severity));
    assert.ok(secFindings.length >= 3, `expected security findings, got ${secFindings.length}`);
    assert.ok(sevs.has('critical') || sevs.has('high'), 'expected at least one high/critical real security finding');
    const sqli = secFindings.find((f) => f.check_id === 'VAL-005');
    assert.ok(sqli, 'expected the error-based SQLi (VAL-005) to be genuinely detected on the fixture');

    // TLS engine against the fixture's HTTPS endpoint (weak self-signed cert):
    // hostname mismatch (TLS-005) + trust problem (TLS-006) + SHA-1 signature (TLS-004) must be detected
    const tlsPort = fixture[1]?.address()?.port;
    if (tlsPort) {
      const tlsAsset = db.insert('assets', {
        tenant_id: tenant.id, identifier: `https://127.0.0.1:${tlsPort}`, kind: 'web_host', title: 'Fixture TLS',
        authorization: { status: 'verified', scope_domains: ['127.0.0.1'], authorized_by: 'test', exclusions: [], ports: [tlsPort], allow_private: true, authorized_at: new Date().toISOString() },
        status: 'active', created_at: new Date().toISOString(),
      });
      const { job: tlsJob } = createServiceRequest({ db, tenantId: tenant.id, serviceKey: 'sec_transmission', assetId: tlsAsset.id, params: {}, userId: owner.id });
      let tlsFinal = null;
      for (let i = 0; i < 80 && !tlsFinal; i++) {
        await scheduler.tick();
        const cur = db.byIdGlobal('jobs', tlsJob.id);
        if (['COMPLETED', 'PARTIALLY_COMPLETED', 'FAILED'].includes(cur.state)) tlsFinal = cur;
      }
      assert.equal(tlsFinal.state, 'COMPLETED');
      const tlsFindings = db.store.find('findings', (f) => f.job_id === tlsJob.id);
      const tlsChecks = new Set(tlsFindings.map((f) => f.check_id));
      assert.ok(tlsChecks.has('TLS-005'), 'expected cert hostname mismatch (TLS-005) on the fixture cert');
      assert.ok(tlsChecks.has('TLS-006'), 'expected self-signed trust problem (TLS-006)');
      assert.ok(tlsChecks.has('TLS-004'), 'expected SHA-1 signature detection (TLS-004) via DER parsing');
    }

    // authorization engine: the /file form must be probed for traversal despite
    // unrelated fields like "username" competing for the probe budget (AUT-001 regression)
    {
      const { job: authzJob } = createServiceRequest({ db, tenantId: tenant.id, serviceKey: 'sec_authz', assetId: asset.id, params: { profile: 'standard', max_pages: 14, test_username: 'admin', test_password: 'admin123!A' }, userId: owner.id });
      let authzFinal = null;
      for (let i = 0; i < 80 && !authzFinal; i++) {
        await scheduler.tick();
        const cur = db.byIdGlobal('jobs', authzJob.id);
        if (['COMPLETED', 'PARTIALLY_COMPLETED', 'FAILED'].includes(cur.state)) authzFinal = cur;
      }
      assert.equal(authzFinal.state, 'COMPLETED');
      const authzFindings = db.store.find('findings', (f) => f.job_id === authzJob.id);
      const aut1 = authzFindings.find((f) => f.check_id === 'AUT-001');
      assert.ok(aut1, 'expected the /file traversal (AUT-001) to be genuinely detected');
    }

    // audit trail covers the pipeline actions
    const audit = db.store.find('audit', (a) => a.tenant_id === tenant.id);
    assert.ok(audit.length >= 2, 'expected audit entries for the pipeline run');

    for (const s of fixture) s.close();
    store.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}, { timeout: 180_000 });
