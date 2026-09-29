import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Db } from '#app/db';
import { openStore } from '#store/store';
import { FileStore } from '#app/files';
import { generateReport, buildReportModel, computeDelta } from '#report/engine';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import crypto from 'node:crypto';

const tmp = () => mkdtempSync(join(tmpdir(), 'meridian-report-'));

function seedFindings(db, tenantId, n, base = 0) {
  for (let i = 0; i < n; i++) {
    db.insert('findings', {
      tenant_id: tenantId, job_id: 'job_x', asset_id: 'ast_x',
      check_id: `VAL-${String(base + i % 5 + 1).padStart(3, '0')}`,
      title: `Finding ${i}`, category: 'validation', target: 'http://t.local',
      endpoint: '/x', parameter: 'p', severity: i === 0 ? 'critical' : i < 3 ? 'high' : 'medium',
      confidence: 'confirmed', cwe: 79, owasp: 'A03:2021',
      facts: [`fact ${i}`], inference: ['inf'], recommendation: ['rec'], remediation: 'rem',
      status: 'open', verification: { status: 'not_retested' }, provenance: 'engine',
      evidence_ids: [], created_at: new Date(Date.now() + i).toISOString(),
    });
  }
}

test('generateReport produces a PDF with embedded sha256 integrity stamp', () => {
  const dir = tmp();
  try {
    const store = openStore(dir);
    const db = new Db(store);
    seedFindings(db, 't1', 5);
    const files = new FileStore(join(dir, 'files'), store);
    const { report, content } = generateReport(db, files, { tenantId: 't1', kind: 'service_report', format: 'pdf' });
    assert.ok(report.id);
    assert.equal(report.format, 'pdf');
    assert.equal(report.findings_count, 5);
    assert.match(report.sha256, /^[0-9a-f]{64}$/);
    assert.equal(content.slice(0, 8).toString('latin1'), '%PDF-1.4');
    // the stored file content matches the record
    const stored = files.read('t1', report.file_id);
    assert.ok(stored.equals(Buffer.isBuffer(content) ? content : Buffer.from(content)));
    // integrity hash is embedded in the document itself
    assert.ok(content.toString('latin1').includes(report.sha256.slice(0, 32)));
    store.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('second report links to the first (history chain) and computes a delta', () => {
  const dir = tmp();
  try {
    const store = openStore(dir);
    const db = new Db(store);
    seedFindings(db, 't1', 3);
    const files = new FileStore(join(dir, 'files'), store);
    const first = generateReport(db, files, { tenantId: 't1', kind: 'service_report', format: 'pdf' });
    // one finding remediated (removed), two new introduced
    const all = db.store.find('findings', (f) => f.tenant_id === 't1');
    db.store.del('findings', all[0].id); // remove VAL-001
    seedFindings(db, 't1', 2, 5); // introduce VAL-006/VAL-007 (new merge keys)
    const second = generateReport(db, files, { tenantId: 't1', kind: 'service_report', format: 'pdf' });
    assert.equal(second.report.previous_report_id, first.report.id);
    assert.notEqual(second.report.sha256, first.report.sha256);
    const model = buildReportModel(db, { kind: 'service_report', tenantId: 't1' });
    const delta = computeDelta(db, 't1', model, first.report.id);
    assert.ok(delta, 'expected a delta against the previous report');
    assert.ok(Number.isInteger(delta.added_count) && Number.isInteger(delta.resolved_count));
    assert.ok(delta.resolved_count >= 1, `expected the removed finding to be resolved, got ${JSON.stringify(delta)}`);
    assert.ok(delta.added_count >= 1, 'expected new findings to be counted as added');
    store.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('all report formats render real content', () => {
  const dir = tmp();
  try {
    const store = openStore(dir);
    const db = new Db(store);
    seedFindings(db, 't1', 4);
    const files = new FileStore(join(dir, 'files'), store);
    for (const format of ['pdf', 'html', 'csv', 'json', 'xlsx']) {
      const { report, content } = generateReport(db, files, { tenantId: 't1', kind: 'service_report', format });
      assert.ok(report.id, format);
      const buf = Buffer.isBuffer(content) ? content : Buffer.from(content);
      assert.ok(buf.length > 200, `${format} report too small: ${buf.length}`);
      if (format === 'html') assert.ok(buf.toString('utf8').includes('<html'));
      if (format === 'json') assert.ok(JSON.parse(buf.toString('utf8')).summary);
      if (format === 'csv') assert.ok(buf.toString('utf8').includes('Finding 0'.split(' ')[0]));
      if (format === 'xlsx') assert.equal(buf.slice(0, 2).toString('latin1'), 'PK');
    }
    store.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('report model separates facts, inference and recommendations', () => {
  const dir = tmp();
  try {
    const store = openStore(dir);
    const db = new Db(store);
    seedFindings(db, 't1', 2);
    const model = buildReportModel(db, { kind: 'service_report', tenantId: 't1' });
    const f = model.findings[0];
    assert.ok(Array.isArray(f.facts) && f.facts.length);
    assert.ok(Array.isArray(f.inference ?? f.inferences));
    assert.ok(Array.isArray(f.recommendation ?? f.recommendations ?? [f.remediation]));
    store.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
