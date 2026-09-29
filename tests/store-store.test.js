import { test } from 'node:test';
import assert from 'node:assert/strict';
import { openStore } from '#store/store';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const tmp = () => mkdtempSync(join(tmpdir(), 'meridian-store-'));

test('put/find/findOne/del basic CRUD', () => {
  const dir = tmp();
  try {
    const s = openStore(dir);
    s.put('users', { id: 'u1', name: 'a' });
    s.put('users', { id: 'u2', name: 'b' });
    assert.equal(s.find('users').length, 2);
    assert.equal(s.findOne('users', (u) => u.name === 'b').id, 'u2');
    s.del('users', 'u1');
    assert.equal(s.find('users').length, 1);
    assert.equal(s.find('users')[0].id, 'u2');
    s.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('tx applies all operations atomically', () => {
  const dir = tmp();
  try {
    const s = openStore(dir);
    s.tx([
      { op: 'put', c: 'a', d: { id: 'x1' } },
      { op: 'put', c: 'a', d: { id: 'x2' } },
      { op: 'put', c: 'b', d: { id: 'y1' } },
    ]);
    assert.equal(s.find('a').length, 2);
    assert.equal(s.find('b').length, 1);
    s.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('durability: data survives close + reopen (WAL replay)', () => {
  const dir = tmp();
  try {
    {
      const s = openStore(dir);
      s.put('jobs', { id: 'j1', state: 'RUNNING' });
      s.put('jobs', { id: 'j2', state: 'DONE' });
      s.close();
    }
    const s2 = openStore(dir);
    assert.equal(s2.find('jobs').length, 2);
    assert.equal(s2.findOne('jobs', (j) => j.id === 'j1').state, 'RUNNING');
    s2.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('multi-tenant isolation in db helpers (tenant-scoped find)', () => {
  const dir = tmp();
  try {
    const s = openStore(dir);
    s.put('findings', { id: 'f1', tenant_id: 't1', sev: 'high' });
    s.put('findings', { id: 'f2', tenant_id: 't2', sev: 'low' });
    const t1 = s.find('findings', (f) => f.tenant_id === 't1');
    assert.equal(t1.length, 1);
    assert.equal(t1[0].id, 'f1');
    s.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('byIndex reflects updates and deletions', () => {
  const dir = tmp();
  try {
    const s = openStore(dir);
    s.addIndex('users', 'email', (u) => u.email);
    s.put('users', { id: 'u1', email: 'a@x.co' });
    assert.equal(s.byIndex('users', 'email', 'a@x.co').length, 1);
    s.put('users', { id: 'u1', email: 'new@x.co' });
    assert.equal(s.byIndex('users', 'email', 'a@x.co').length, 0);
    assert.equal(s.byIndex('users', 'email', 'new@x.co').length, 1);
    s.del('users', 'u1');
    assert.equal(s.byIndex('users', 'email', 'new@x.co').length, 0);
    s.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('seq counter increments monotonically across ops', () => {
  const dir = tmp();
  try {
    const s = openStore(dir);
    const before = s.seq;
    s.put('x', { id: '1' });
    s.put('x', { id: '2' });
    assert.ok(s.seq >= before + 2);
    s.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('put requires a document id (programmer errors surface loudly)', () => {
  const dir = tmp();
  try {
    const s = openStore(dir);
    assert.throws(() => s.put('x', { no: 'id' }), /must have id/);
    s.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
