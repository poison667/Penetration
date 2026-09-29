import { test } from 'node:test';
import assert from 'node:assert/strict';
import { profile, inferType } from '#data/profile';
import { cleanse } from '#data/cleanse';
import { dedupe } from '#data/dedup';
import { transform } from '#data/transform';
import { detectAnomalies } from '#data/anomaly';

test('inferType distinguishes numeric, boolean and string columns', () => {
  assert.equal(inferType(['1', '2', '3']), 'integer');
  assert.equal(inferType(['1.5', '2.5']), 'float');
  assert.equal(inferType(['true', 'false']), 'boolean');
  assert.equal(inferType(['a', 'b', 'c']), 'string');
  assert.equal(inferType(['1', 'x']), 'string');
});

test('profile reports row/column counts and per-column stats', () => {
  const rows = [
    { id: '1', name: 'alice', age: '34' },
    { id: '2', name: 'bob', age: 'not-a-number' },
    { id: '3', name: 'alice', age: '' },
  ];
  const p = profile(rows);
  assert.equal(p.rows, 3);
  assert.equal(p.columns, 3); // column count
  const nameCol = p.column_stats.name;
  assert.equal(nameCol.distinct, 2);
  assert.equal(nameCol.nulls, 0);
  assert.ok(p.column_stats.age);
});

test('cleanse applies rules and records a change log', () => {
  const rows = [{ a: '  x  ', b: '' }, { a: 'y', b: null }];
  const rules = [
    { column: '*', rule: 'trim' },
    { column: 'b', rule: 'fill_null', params: { value: 'N/A' } },
  ];
  const res = cleanse(rows, rules);
  assert.deepEqual(res.rows, [{ a: 'x', b: 'N/A' }, { a: 'y', b: 'N/A' }]);
  assert.ok(res.changes.length >= 2);
  const change = res.changes[0];
  assert.ok('before' in change && 'after' in change && change.rule === 'trim');
});

test('dedupe exact mode collapses identical keys and reports duplicates', () => {
  const rows = [
    { email: 'a@x.co', n: 1 },
    { email: 'b@x.co', n: 2 },
    { email: 'a@x.co', n: 3 },
    { email: 'c@x.co', n: 4 },
  ];
  const res = dedupe(rows, ['email'], { mode: 'exact' });
  assert.equal(res.rows.length, 3);
  assert.equal(res.stats.duplicates_found, 1);
  assert.equal(res.duplicates[0].duplicate_index, 2);
});

test('dedupe fuzzy mode catches near-duplicate keys within threshold', () => {
  const rows = [
    { name: 'Jon Smyth', v: 1 },
    { name: 'John Smith', v: 2 },
    { name: 'Completely Different Person', v: 3 },
  ];
  const res = dedupe(rows, ['name'], { mode: 'fuzzy', threshold: 3 });
  assert.equal(res.rows.length, 2); // Jon/John merged, Different kept
});

test('transform ops: filter, rename, derive, cast, sort, limit — with lineage', () => {
  const rows = [
    { id: '1', age: '34', salary: '54000' },
    { id: '2', age: '29', salary: '48000' },
    { id: '3', age: '45', salary: '90000' },
  ];
  const res = transform(rows, [
    { op: 'filter', expr: '$.age > 30' },
    { op: 'cast', column: 'salary', type: 'number' },
    { op: 'derive', column: 'salary_k', expr: '$.salary / 1000' },
    { op: 'rename', from: 'id', to: 'user_id' },
    { op: 'sort', column: 'salary', dir: 'desc' },
    { op: 'limit', count: 1 },
  ]);
  assert.equal(res.rows.length, 1);
  assert.equal(res.rows[0].user_id, '3');
  assert.equal(res.rows[0].salary_k, 90);
  assert.equal(res.lineage.length, 6);
  assert.equal(res.lineage[0].rows_before, 3);
  assert.equal(res.lineage[0].rows_after, 2);
});

test('transform rejects unknown ops loudly', () => {
  assert.throws(() => transform([{ a: 1 }], [{ op: 'explode' }]), /unknown transform op/);
});

test('detectAnomalies flags statistical outliers via MAD and IQR', () => {
  const rows = Array.from({ length: 12 }, (_, i) => ({ v: 10 + i }));
  rows.push({ v: 999 }); // obvious outlier
  const res = detectAnomalies(rows);
  assert.equal(res.anomalies.length, 1);
  assert.equal(res.anomalies[0].row_index, 12);
  const methods = res.anomalies[0].reasons.map((r) => r.method);
  assert.ok(methods.includes('mad') || methods.includes('iqr'));
});

test('detectAnomalies stays quiet on uniform data', () => {
  const rows = Array.from({ length: 20 }, () => ({ v: 42 }));
  const res = detectAnomalies(rows);
  assert.equal(res.anomalies.length, 0);
});


test('dedupe accepts null and comma-string key columns (regression: null crashed)', () => {
  const rows = [
    { email: 'a@x.co', name: 'Alice', score: 1 },
    { email: 'a@x.co', name: 'Alice', score: 1 },
    { email: 'b@x.co', name: 'Bob', score: 2 },
  ];
  // null (the API route passes this when no key_columns option is set)
  const byNull = dedupe(rows, null);
  assert.equal(byNull.rows.length, 2, 'null keys → derive from row shape');
  // comma string (what the UI sends from a text input)
  const byString = dedupe(rows, 'email, name');
  assert.equal(byString.rows.length, 2);
  // array still works
  const byArray = dedupe(rows, ['email']);
  assert.equal(byArray.rows.length, 2);
});
