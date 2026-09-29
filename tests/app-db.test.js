import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Db } from '#app/db';
import { openStore } from '#store/store';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const tmp = () => mkdtempSync(join(tmpdir(), 'meridian-db-'));
const openDb = (dir) => new Db(openStore(dir));

test('insert stamps id, created_at and tenant_id', () => {
  const dir = tmp();
  try {
    const db = openDb(dir);
    const doc = db.insert('findings', { tenant_id: 't1', title: 'x' });
    assert.ok(doc.id);
    assert.ok(doc.created_at);
    assert.equal(doc.tenant_id, 't1');
    db.store.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('byId enforces tenant isolation (cross-tenant reads return null)', () => {
  const dir = tmp();
  try {
    const db = openDb(dir);
    const doc = db.insert('findings', { tenant_id: 't1', title: 'x' });
    assert.equal(db.byId('findings', 't1', doc.id).title, 'x');
    assert.equal(db.byId('findings', 't2', doc.id), null);
    db.store.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('list filters by tenant and paginates', () => {
  const dir = tmp();
  try {
    const db = openDb(dir);
    for (let i = 0; i < 7; i++) db.insert('findings', { tenant_id: 't1', n: i, title: `f${i}`, created_at: new Date(Date.now() + i).toISOString() });
    for (let i = 0; i < 3; i++) db.insert('findings', { tenant_id: 't2', n: i, title: `other${i}`, created_at: new Date().toISOString() });
    const page1 = db.list('findings', 't1', { limit: 4 });
    assert.equal(page1.rows.length, 4);
    assert.equal(page1.total, 7);
    const all = db.list('findings', 't1', { limit: 100 });
    assert.ok(all.rows.every((r) => r.tenant_id === 't1'));
    db.store.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('update refuses cross-tenant writes', () => {
  const dir = tmp();
  try {
    const db = openDb(dir);
    const doc = db.insert('findings', { tenant_id: 't1', title: 'x' });
    assert.throws(() => db.update('findings', 't2', doc.id, { title: 'hijack' }), Error);
    db.store.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('remove only deletes within the tenant', () => {
  const dir = tmp();
  try {
    const db = openDb(dir);
    const doc = db.insert('findings', { tenant_id: 't1' });
    assert.throws(() => db.remove('findings', 't2', doc.id), Error);
    db.remove('findings', 't1', doc.id);
    assert.equal(db.byId('findings', 't1', doc.id), null);
    db.store.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('byIdGlobal is the explicit cross-tenant escape hatch (staff surfaces only)', () => {
  const dir = tmp();
  try {
    const db = openDb(dir);
    const doc = db.insert('findings', { tenant_id: 't1' });
    assert.equal(db.byIdGlobal('findings', doc.id).id, doc.id);
    db.store.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('remove of a missing id throws not-found', () => {
  const dir = tmp();
  try {
    const db = openDb(dir);
    assert.throws(() => db.remove('findings', 't1', 'nope'), Error);
    db.store.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
