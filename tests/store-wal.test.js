import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Wal } from '#store/wal';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const tmp = () => mkdtempSync(join(tmpdir(), 'meridian-wal-'));

test('Wal append + readAll roundtrip preserves order', () => {
  const dir = tmp();
  try {
    const wal = new Wal(join(dir, 'wal.log'));
    wal.append({ op: 'put', c: 'users', d: { id: 'u1' } });
    wal.append({ op: 'del', c: 'users', id: 'u2' });
    wal.append({ op: 'tx', tx: [{ op: 'put' }] });
    wal.close();
    const all = Wal.readAll(join(dir, 'wal.log'));
    assert.equal(all.length, 3);
    assert.deepEqual(all[0], { op: 'put', c: 'users', d: { id: 'u1' } });
    assert.equal(all[2].op, 'tx');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('torn write at end of file is discarded during replay', () => {
  const dir = tmp();
  try {
    const p = join(dir, 'wal.log');
    const wal = new Wal(p);
    wal.append({ op: 'put', n: 1 });
    wal.close();
    // simulate a torn write: append a partial line without newline
    writeFileSync(p, '{"op":"put","n":2,"d":{"big":"tor', { flag: 'a' });
    const all = Wal.readAll(p);
    assert.equal(all.length, 1); // only the intact line survives
    assert.equal(all[0].n, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('corrupted line mid-file stops replay there (fail-closed)', () => {
  const dir = tmp();
  try {
    const p = join(dir, 'wal.log');
    const wal = new Wal(p);
    wal.append({ op: 'put', n: 1 });
    wal.close();
    writeFileSync(p, 'NOT JSON AT ALL\n', { flag: 'a' });
    const wal2 = new Wal(p);
    wal2.append({ op: 'put', n: 3 }); // written after the corruption
    wal2.close();
    const all = Wal.readAll(p);
    assert.equal(all.length, 1, `expected replay to stop at corruption, got ${all.length}`);
    assert.equal(all[0].n, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('reset truncates the log after a successful snapshot', () => {
  const dir = tmp();
  try {
    const p = join(dir, 'wal.log');
    const wal = new Wal(p);
    wal.append({ op: 'put', n: 1 });
    wal.append({ op: 'put', n: 2 });
    wal.reset();
    assert.equal(wal.count, 0);
    assert.equal(readFileSync(p, 'utf8'), '');
    wal.append({ op: 'put', n: 3 });
    wal.close();
    const all = Wal.readAll(p);
    assert.equal(all.length, 1);
    assert.equal(all[0].n, 3);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('readAll on a missing file returns empty (clean start)', () => {
  const dir = tmp();
  try {
    assert.equal(existsSync(join(dir, 'nope.log')), false);
    assert.deepEqual(Wal.readAll(join(dir, 'nope.log')), []);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
