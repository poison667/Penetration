import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Db } from '#app/db';
import { openStore } from '#store/store';
import { FileStore } from '#app/files';
import { createServer } from '#api/server';
import { bus, TOPICS } from '#core/events';
import { hashPassword } from '#sec/crypto';
import { setSecretKey } from '#sec/crypto';
import crypto from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

setSecretKey(crypto.randomBytes(32));

async function startApi() {
  const dir = mkdtempSync(join(tmpdir(), 'meridian-sse-'));
  const store = openStore(dir);
  const db = new Db(store);
  const files = new FileStore(join(dir, 'files'), store);
  const tenant = db.insert('tenants', { name: 'SSE Tenant (test data)', status: 'active', created_at: new Date().toISOString() });
  db.insert('users', { tenant_id: tenant.id, email: 'o@x.co', name: 'O', role: 'owner', status: 'active', password_hash: hashPassword('Owner!Pass1A'), mfa_enabled: false });
  const server = createServer({ db, files, config: { uiRoot: null } });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { server, db, store, dir, tenant };
}

function openStream(port, path) {
  const events = [];
  const ctrl = new AbortController();
  const done = fetch(`http://127.0.0.1:${port}${path}`, { signal: ctrl.signal }).then(async (res) => {
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        events.push(dec.decode(value, { stream: true }));
      }
    } catch { /* aborted */ }
    return res.status;
  }).catch(() => null);
  return { events, ctrl, done };
}

test('SSE /events: 401 without credentials, streams tenant events with token', async () => {
  const h = await startApi();
  try {
    const port = h.server.address().port;

    // unauthenticated → 401 immediately
    const unauth = await fetch(`http://127.0.0.1:${port}/events`);
    assert.equal(unauth.status, 401);
    unauth.body?.cancel?.();

    // login and open a stream with the query-param token (EventSource pattern)
    const login = await fetch(`http://127.0.0.1:${port}/api/v1/auth/login`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'o@x.co', password: 'Owner!Pass1A' }),
    }).then((r) => r.json());
    const tok = login.access_token;

    const stream = openStream(port, `/events?access_token=${tok}`);
    await new Promise((r) => setTimeout(r, 250)); // let the stream open

    // publish a real event for this tenant → must arrive on the wire
    bus.publish(TOPICS.jobUpdated, { tenant_id: h.tenant.id, id: 'job_x', state: 'RUNNING' });
    // and an event for ANOTHER tenant → must be filtered out
    bus.publish(TOPICS.jobCompleted, { tenant_id: 't_other', id: 'job_y' });
    await new Promise((r) => setTimeout(r, 250));

    stream.ctrl.abort();
    const status = await stream.done;
    assert.equal(status, 200, 'authenticated stream must open');
    const wire = stream.events.join('');
    assert.match(wire, /event: job\.updated/, 'job.updated event must be forwarded');
    assert.match(wire, /"state":"RUNNING"/);
    assert.ok(!wire.includes('job_y'), 'other-tenant events must not leak onto the stream');
    assert.match(wire, /retry: 5000/, 'reconnect hint present');

    h.server.close();
    h.store.close();
  } finally {
    rmSync(h.dir, { recursive: true, force: true });
  }
});
