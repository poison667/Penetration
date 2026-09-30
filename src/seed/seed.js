#!/usr/bin/env node
/**
 * Development/demo seed — CLEARLY IDENTIFIED TEST DATA (specification Part 19).
 * What this seeds:
 *  - one demo tenant + owner user + platform staff user (marked DEMO DATA)
 *  - the loopback fixture asset with an authorization record
 *  - monitors, one automation rule, one schedule
 *  - REAL service jobs (web audit + security assessment) which the worker
 *    genuinely executes against the fixture at seed time — findings in the
 *    demo workspace are produced by real engine runs, not fixtures.
 */
import fs from 'node:fs';
import path from 'node:path';
import { openStore } from '#store/store';
import { Db } from '#app/db';
import { FileStore } from '#app/files';
import { loadOrCreateSecretKey, hashPassword } from '#sec/crypto';
import { grantCredits } from '#app/billing';
import { createServiceRequest } from '#worker/runner';
import { startFixture } from '../../fixtures/vuln-app/server.js';
import { Scheduler } from '#worker/scheduler';
import { AutomationEngine } from '#auto/engine';
import { generateReport } from '#report/engine';
import { recordAudit } from '#app/audit';

const dataDir = path.resolve(process.env.MERIDIAN_DATA || './data');
fs.mkdirSync(dataDir, { recursive: true });
loadOrCreateSecretKey(dataDir, fs);
const store = openStore(path.join(dataDir, 'store'), { sync: true });
const db = new Db(store);
const files = new FileStore(dataDir, store);

const existing = db.store.findOne('tenants', (t) => t.slug === 'meridian-demo');
if (existing && !process.env.FORCE_SEED) {
  console.log('[seed] demo tenant already present — nothing to do (set FORCE_SEED=1 to add sample jobs)');
  process.exit(0);
}

console.log('[seed] === DEVELOPMENT / DEMO DATA (clearly identified test data) ===');

// 1. start the loopback fixture target (must be running for seeded jobs)
const servers = await startFixture({ httpPort: Number(process.env.FIXTURE_HTTP_PORT || 8081), tlsPort: null });
console.log('[seed] fixture target started on 127.0.0.1:8081 (DELIBERATELY VULNERABLE, loopback only)');

// 2. tenant + users
const tenant = db.insert('tenants', { name: 'Meridian Demo (DEMO DATA)', slug: 'meridian-demo', status: 'active', plan: 'pro', created_at: new Date().toISOString() });
const owner = db.insert('users', { tenant_id: tenant.id, email: 'demo@meridian.local', name: 'Demo Owner', role: 'owner', status: 'active', password_hash: hashPassword('Demo!Passw0rd'), mfa_enabled: false, is_staff: false });
const staff = db.insert('users', { tenant_id: tenant.id, email: 'staff@meridian.local', name: 'Platform Staff', role: 'viewer', status: 'active', password_hash: hashPassword('Staff!Passw0rd'), mfa_enabled: false, is_staff: true });
db.insert('subscriptions', { tenant_id: tenant.id, plan_key: 'pro', status: 'active', current_period_start: new Date().toISOString(), current_period_end: null });
grantCredits(db, tenant.id, 5000, 'demo_grant', 'DEMO DATA: initial credit grant');

// 3. fixture asset with authorization record (private loopback target — gated)
const asset = db.insert('assets', {
  tenant_id: tenant.id, identifier: 'localhost', kind: 'web_host', title: 'Fixture Store (demo target)', port: 8081,
  authorization: {
    status: 'verified', scope_domains: ['localhost', '127.0.0.1'], authorized_by: 'Demo Owner (self-hosted test target)',
    authorization_evidence: 'DEMO DATA: loopback fixture owned by this workspace; see fixtures/vuln-app/server.js',
    exclusions: [], ports: [8081, 8082], allow_private: true, authorized_at: new Date().toISOString(),
  },
  status: 'active', created_at: new Date().toISOString(),
});

// 4. monitors (real checks run by scheduler)
db.insert('monitors', { tenant_id: tenant.id, name: 'Fixture homepage HTTP', type: 'http', asset_id: asset.id, url: 'http://127.0.0.1:8081/', interval_seconds: 120, config: {}, enabled: true, last_status: null, last_run_at: null, next_run_at: new Date().toISOString(), created_at: new Date().toISOString() });
db.insert('monitors', { tenant_id: tenant.id, name: 'Fixture content change', type: 'content_hash', asset_id: asset.id, url: 'http://127.0.0.1:8081/', interval_seconds: 120, config: {}, enabled: true, last_status: null, last_run_at: null, next_run_at: new Date().toISOString(), created_at: new Date().toISOString() });

// 5. automation: notify + report on job completion
db.insert('rules', {
  tenant_id: tenant.id, name: 'Notify on completed jobs', enabled: true, last_fired_at: null, created_at: new Date().toISOString(),
  trigger: { type: 'job_completed', config: {} }, conditions: '$.event.findings_count > 0',
  actions: [{ type: 'notify', title: 'Job completed with findings', body: 'Check the findings workspace for details.' }],
});
db.insert('schedules', {
  tenant_id: tenant.id, name: 'Weekly fixture audit', cron: '0 6 * * 1', rule_id: null, workflow_id: null,
  enabled: false, next_run_at: null, last_run_at: null, created_at: new Date().toISOString(),
});

recordAudit(store, { tenantId: tenant.id, actorType: 'system', actorId: null, action: 'demo.seeded', resource: 'tenant', resourceId: tenant.id, detail: { note: 'DEMO DATA seed' } });

// 6. REAL initial jobs — executed by a real scheduler pass at seed time
const automation = new AutomationEngine({ db, files, requestService: (o) => createServiceRequest({ db, ...o }).job, generateReport: (o) => generateReport(db, files, o) });
const scheduler = new Scheduler({ db, files, automation, requestService: (o) => createServiceRequest({ db, ...o }).job, generateReport: (o) => generateReport(db, files, o), intervalMs: 2500 });

console.log('[seed] enqueueing real web_audit + security_full jobs against the fixture (real engine execution — this takes a moment)...');
createServiceRequest({ db, tenantId: tenant.id, serviceKey: 'web_audit', assetId: asset.id, params: { max_pages: 5 }, userId: owner.id });
createServiceRequest({ db, tenantId: tenant.id, serviceKey: 'sec_validation', assetId: asset.id, params: { profile: 'intrusive', max_pages: 20, test_username: 'admin', test_password: 'admin123!A' }, userId: owner.id });
createServiceRequest({ db, tenantId: tenant.id, serviceKey: 'sec_auth', assetId: asset.id, params: { profile: 'safe', test_username: 'admin', test_password: 'admin123!A' }, userId: owner.id });
createServiceRequest({ db, tenantId: tenant.id, serviceKey: 'sec_session', assetId: asset.id, params: { test_username: 'admin', test_password: 'admin123!A' }, userId: owner.id });
createServiceRequest({ db, tenantId: tenant.id, serviceKey: 'sec_authz', assetId: asset.id, params: { profile: 'standard', test_username: 'admin', test_password: 'admin123!A' }, userId: owner.id });
createServiceRequest({ db, tenantId: tenant.id, serviceKey: 'sec_upload', assetId: asset.id, params: { profile: 'intrusive' }, userId: owner.id });

let processed = 0;
for (let i = 0; i < 300 && processed < 6; i++) {
  await scheduler.tick();
  processed = db.store.count('jobs', (j) => ['COMPLETED', 'PARTIALLY_COMPLETED', 'FAILED'].includes(j.state));
}
const jobs = db.store.find('jobs', (j) => j.tenant_id === tenant.id);
for (const j of jobs) {
  console.log(`[seed] job ${j.service_key}: ${j.state} — ${j.result_summary?.findings_count ?? 0} findings${j.error ? ' (error: ' + j.error.slice(0, 120) + ')' : ''}`);
}
const findings = db.store.find('findings', (f) => f.tenant_id === tenant.id);
console.log(`[seed] total real findings captured: ${findings.length} (by severity: ${JSON.stringify(findings.reduce((a, f) => { a[f.severity] = (a[f.severity] || 0) + 1; return a; }, {}))})`);

// initial report from real data
const job = jobs.find((j) => j.service_key === 'web_audit' && j.state === 'COMPLETED') || jobs[0];
const { report } = generateReport(db, files, { tenantId: tenant.id, job: db.byIdGlobal('jobs', job.id), kind: 'service_report', format: 'pdf', createdBy: 'seed' });
console.log(`[seed] generated initial PDF report ${report.id} (${report.findings_count} findings, sha256 ${report.sha256.slice(0, 16)}…)`);

store.snapshot();
console.log('[seed] done. Demo login: demo@meridian.local / Demo!Passw0rd  (staff: staff@meridian.local / Staff!Passw0rd)');
for (const s of servers) s.close();
store.close();
process.exit(0);
