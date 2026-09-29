import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JobQueue } from '#queue/queue';
import { Db } from '#app/db';
import { openStore } from '#store/store';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const tmp = () => mkdtempSync(join(tmpdir(), 'meridian-queue-'));
const openQ = (dir) => ({ q: new JobQueue(new Db(openStore(dir))), db: null });

test('enqueue rejects invalid states', () => {
  const dir = tmp();
  try {
    const { q } = openQ(dir);
    assert.throws(() => q.enqueue({ id: 'j1', state: 'BOGUS' }), /invalid job state/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('claim returns QUEUED jobs FIFO and marks RUNNING with lease', () => {
  const dir = tmp();
  try {
    const { q } = openQ(dir);
    q.enqueue({ id: 'j1', state: 'QUEUED', created_at: '2026-01-01T00:00:01Z' });
    q.enqueue({ id: 'j2', state: 'QUEUED', created_at: '2026-01-01T00:00:02Z' });
    const first = q.claim('w1');
    assert.equal(first.id, 'j1');
    assert.equal(first.state, 'RUNNING');
    assert.equal(first.attempts, 1);
    assert.ok(first.lease_expires_at);
    const second = q.claim('w1');
    assert.equal(second.id, 'j2');
    assert.equal(q.claim('w1'), null); // drained
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('priority preempts FIFO order', () => {
  const dir = tmp();
  try {
    const { q } = openQ(dir);
    q.enqueue({ id: 'low', state: 'QUEUED', priority: 1, created_at: '2026-01-01T00:00:01Z' });
    q.enqueue({ id: 'high', state: 'QUEUED', priority: 9, created_at: '2026-01-01T00:00:02Z' });
    assert.equal(q.claim('w1').id, 'high');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('heartbeat extends the lease only for the owning worker', () => {
  const dir = tmp();
  try {
    const { q } = openQ(dir);
    q.enqueue({ id: 'j1', state: 'QUEUED' });
    q.claim('w1');
    assert.equal(q.heartbeat('j1', 'w2'), false);
    assert.equal(q.heartbeat('j1', 'w1'), true);
    assert.equal(q.heartbeat('nope', 'w1'), false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('reclaimStale requeues expired leases and fails after max attempts', () => {
  const dir = tmp();
  try {
    const { q } = openQ(dir);
    q.enqueue({ id: 'j1', state: 'QUEUED', max_attempts: 2 });
    q.claim('w1', { leaseMs: -1000 }); // lease already expired
    const requeued = q.reclaimStale();
    assert.deepEqual(requeued, ['j1']);
    const job = q.db.store.byId('jobs', 'j1');
    assert.equal(job.state, 'QUEUED'); // attempts=1 < max 2
    // second crash exceeds max attempts → FAILED
    q.claim('w2', { leaseMs: -1000 });
    q.reclaimStale();
    const failed = q.db.store.byId('jobs', 'j1');
    assert.equal(failed.state, 'FAILED');
    assert.match(failed.error, /lease expired/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('update patches job fields', () => {
  const dir = tmp();
  try {
    const { q } = openQ(dir);
    q.enqueue({ id: 'j1', state: 'QUEUED' });
    q.update('j1', { state: 'COMPLETED', progress: 100 });
    const job = q.db.store.byId('jobs', 'j1');
    assert.equal(job.state, 'COMPLETED');
    assert.equal(job.progress, 100);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
