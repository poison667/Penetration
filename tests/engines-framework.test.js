import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildContext, runEngine, analyzeFindings, qualityCheck, assignFids } from '#engines';
import { Db } from '#app/db';
import { openStore } from '#store/store';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const tmp = () => mkdtempSync(join(tmpdir(), 'meridian-engfw-'));
const mkCtx = () => buildContext({
  db: null, job: { tenant_id: 't1', id: 'job_fw' }, asset: null,
  service: { key: 'web_audit', profiles: ['safe'] }, params: {},
});

test('ctx.report enforces evidence and structures facts/inference/recommendation', () => {
  const ctx = mkCtx();
  const ev = ctx.evidenceRaw('http_exchange', { status: 200, body: 'x' }, 'probe');
  const f = ctx.report('VAL-005', { target: 'https://t.example', endpoint: '/search', parameter: 'q', facts: ['database error reflected in response'], evidence: [ev], severity: 'high' });
  assert.equal(f.check_id, 'VAL-005');
  assert.match(f.cwe, /^CWE-\d+$/, 'vulnerability checks carry a CWE id');
  assert.deepEqual(f.facts, ['database error reflected in response']);
  assert.deepEqual(f.inference, [], 'inference defaults to empty when only facts are observed');
  assert.ok(f.recommendation, 'fallback remediation from catalogue');
  assert.deepEqual(f.evidence_ids, [ev.id]);
  assert.equal(f.status, 'open');
  // no evidence → hard error (framework-level QC gate)
  assert.throws(() => ctx.report('VAL-006', { facts: ['x'] }), /evidence/);
});

test('analyzeFindings dedups by check|target|endpoint|parameter, upholds severity, unions evidence', () => {
  const ctx = mkCtx();
  const ev1 = ctx.evidenceRaw('k', { n: 1 }, 'one');
  const ev2 = ctx.evidenceRaw('k', { n: 2 }, 'two');
  const base = { target: 'https://t.example', endpoint: '/a', parameter: 'q', category: 'val' };
  ctx.findings.push(ctx.report('VAL-001', { ...base, severity: 'low', facts: ['f1'], evidence: [ev1] }));
  ctx.findings.push(ctx.report('VAL-001', { ...base, severity: 'high', confidence: 'confirmed', facts: ['f2'], evidence: [ev2] }));
  ctx.findings.push(ctx.report('VAL-002', { ...base, endpoint: '/b', facts: ['f3'], evidence: [ev1] }));
  const merged = analyzeFindings(ctx);
  assert.equal(merged.length, 2);
  const dedup = merged.find((f) => f.check_id === 'VAL-001');
  assert.equal(dedup.severity, 'high');
  assert.equal(dedup.confidence, 'confirmed');
  assert.equal(dedup.evidence_ids.length, 2);
  assert.deepEqual([...dedup.facts].sort(), ['f1', 'f2']);
});

test('qualityCheck rejects findings with orphan evidence or no facts', () => {
  const ctx = mkCtx();
  const ev = ctx.evidenceRaw('k', { n: 1 }, 'ok');
  ctx.findings.push({ id: 'f_ok', check_id: 'VAL-001', title: 'ok', facts: ['observed'], evidence_ids: [ev.id] });
  ctx.findings.push({ id: 'f_orphan', check_id: 'VAL-002', title: 'orphan', facts: ['observed'], evidence_ids: ['ev_missing'] });
  ctx.findings.push({ id: 'f_nofacts', check_id: 'VAL-003', title: 'nofacts', facts: [], evidence_ids: [ev.id] });
  const qc = qualityCheck(ctx);
  assert.equal(qc.findings_accepted, 1);
  assert.equal(qc.findings_rejected, 2);
  assert.deepEqual(qc.rejected.map((r) => r.reason).sort(), ['missing_fact_statements', 'missing_or_orphan_evidence']);
  assert.equal(ctx.findings.length, 1); // rejected ones removed pre-persist
});

test('runEngine contains engine errors and records failure result', async () => {
  const ctx = mkCtx();
  const failing = { key: 'test_engine', run: async () => { throw new Error('boom'); } };
  const res = await runEngine(ctx, failing);
  assert.equal(res.ok, false);
  assert.ok(/boom/.test(res.error));
  assert.equal(ctx.engineResults[0].key, 'test_engine');
  const ok = await runEngine(ctx, { key: 'noop_engine', run: async () => {} });
  assert.equal(ok.ok, true);
});

test('assignFids issues strictly sequential per-tenant ids', () => {
  const dir = tmp();
  try {
    const store = openStore(dir);
    const db = new Db(store);
    const batch1 = [{ id: 'a' }, { id: 'b' }];
    assignFids(db, 't1', batch1);
    assert.deepEqual(batch1.map((f) => f.fid), ['MER-F-000001', 'MER-F-000002']);
    const batch2 = [{ id: 'c' }];
    assignFids(db, 't1', batch2);
    assert.equal(batch2[0].fid, 'MER-F-000003');
    // other tenant has an independent counter
    const batch3 = [{ id: 'd' }];
    assignFids(db, 't2', batch3);
    assert.equal(batch3[0].fid, 'MER-F-000001');
    store.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
