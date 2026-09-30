import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import crypto from 'node:crypto';
import { Db } from '#app/db';
import { openStore } from '#store/store';
import { notify } from '#app/notify';
import {
  signWebhookPayload, validateWebhookUrl, isPrivateHost,
  flushDeliveries, sendSmtpMail, WEBHOOK_MAX_ATTEMPTS,
} from '#app/webhooks';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const tmp = () => mkdtempSync(join(tmpdir(), 'meridian-notify-'));
const openDb = (dir) => new Db(openStore(dir));

/** Ephemeral webhook receiver with per-path behavior. */
function startReceiver() {
  const received = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      const hit = { path: req.url, headers: req.headers, body, at: Date.now() };
      received.push(hit);
      if (req.url.startsWith('/fail')) { res.writeHead(500); res.end('nope'); return; }
      if (req.url.startsWith('/flaky')) {
        // succeed only from the 3rd request on (exercises retry + backoff)
        const fails = received.filter((h) => h.path.startsWith('/flaky')).length;
        if (fails < 3) { res.writeHead(500); res.end('flaky'); return; }
      }
      res.writeHead(200); res.end('ok');
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({ server, received, port: server.address().port }));
  });
}

/** Minimal real SMTP test server capturing one full transaction. */
function startSmtpServer() {
  const mail = [];
  const server = net.createServer((sock) => {
    let buffer = '';
    let inData = false;
    let current = { from: null, to: [], data: '' };
    sock.write('220 test-smtp.local ESMTP\r\n');
    sock.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      if (inData) {
        if (buffer.includes('\r\n.\r\n')) {
          current.data = buffer.slice(0, buffer.indexOf('\r\n.\r\n'));
          mail.push(current);
          current = { from: null, to: [], data: '' };
          buffer = '';
          inData = false;
          sock.write('250 OK: queued as TEST123\r\n');
        }
        return;
      }
      const lines = buffer.split('\r\n');
      buffer = '';
      for (const line of lines) {
        if (!line) continue;
        if (/^EHLO/i.test(line)) { sock.write('250-test-smtp.local\r\n250 SIZE 10485760\r\n'); continue; }
        if (/^HELO/i.test(line)) { sock.write('250 test-smtp.local\r\n'); continue; }
        if (/^MAIL FROM:/i.test(line)) { current.from = line.replace(/^MAIL FROM:\s*<*/i, '').replace(/>.*$/, ''); sock.write('250 OK\r\n'); continue; }
        if (/^RCPT TO:/i.test(line)) { current.to.push(line.replace(/^RCPT TO:\s*<*/i, '').replace(/>.*$/, '')); sock.write('250 OK\r\n'); continue; }
        if (/^DATA/i.test(line)) { inData = true; sock.write('354 End data with <CR><LF>.<CR><LF>\r\n'); continue; }
        if (/^QUIT/i.test(line)) { sock.write('221 Bye\r\n'); sock.end(); continue; }
        sock.write('250 OK\r\n');
      }
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({ server, mail, port: server.address().port }));
  });
}

test('isPrivateHost + validateWebhookUrl guard SSRF surfaces', () => {
  assert.ok(isPrivateHost('localhost'));
  assert.ok(isPrivateHost('127.0.0.1'));
  assert.ok(isPrivateHost('10.1.2.3'));
  assert.ok(isPrivateHost('192.168.1.1'));
  assert.ok(!isPrivateHost('example.com'));
  assert.throws(() => validateWebhookUrl('http://127.0.0.1:9000/hook'), /private\/loopback/);
  assert.throws(() => validateWebhookUrl('ftp://example.com/x'), /http\(s\)/);
  assert.throws(() => validateWebhookUrl('not a url'), /invalid URL/);
  assert.equal(validateWebhookUrl('http://127.0.0.1:9000/hook', { allowPrivate: true }), 'http://127.0.0.1:9000/hook');
  assert.equal(validateWebhookUrl('https://example.com/hook'), 'https://example.com/hook');
});

test('webhook signature is deterministic HMAC-SHA256 over timestamp.body', () => {
  const sig = signWebhookPayload('s3cret', '{"a":1}', 1700000000000);
  assert.match(sig, /^[0-9a-f]{64}$/);
  const expected = crypto.createHmac('sha256', 's3cret').update('1700000000000.{"a":1}').digest('hex');
  assert.equal(sig, expected);
  assert.notEqual(sig, signWebhookPayload('other', '{"a":1}', 1700000000000));
});

test('notification fans out to a webhook and is delivered with a valid signature', async () => {
  const dir = tmp();
  const rc = await startReceiver();
  try {
    const db = openDb(dir);
    db.insert('webhooks', { id: 'wh_1', tenant_id: 't1', url: `http://127.0.0.1:${rc.port}/hook`, secret: 'whsec_test', events: ['*'], allow_private: true, enabled: true });
    const n = notify(db, { tenantId: 't1', type: 'job.completed', title: 'Job done', body: 'The scan finished', data: { x: 1 } });
    const pending = db.store.find('notify_deliveries', () => true);
    assert.equal(pending.length, 1, 'one outbox delivery enqueued');
    assert.equal(pending[0].status, 'pending');
    const flushed = await flushDeliveries(db);
    assert.equal(flushed, 1);
    assert.equal(rc.received.length, 1, 'receiver got the POST');
    const hit = rc.received[0];
    assert.equal(hit.headers['content-type'], 'application/json');
    assert.equal(hit.headers['x-meridian-event'], 'job.completed', 'event header carries the notification type (not a constant)');
    assert.match(hit.headers['x-meridian-signature'], /^sha256=[0-9a-f]{64}$/);
    const body = hit.body;
    const ts = Number(hit.headers['x-meridian-timestamp']);
    assert.equal(hit.headers['x-meridian-signature'], 'sha256=' + signWebhookPayload('whsec_test', body, ts));
    const parsed = JSON.parse(body);
    assert.equal(parsed.type, 'job.completed');
    assert.equal(parsed.title, 'Job done');
    assert.equal(parsed.data.x, 1);
    const d = db.store.find('notify_deliveries', () => true)[0];
    assert.equal(d.status, 'delivered');
    assert.equal(d.response_status, 200);
    assert.equal(d.attempts, 1);
    const w = db.store.findOne('webhooks', (x) => x.id === 'wh_1');
    assert.equal(w.last_status, 'delivered');
    db.store.close();
  } finally { rc.server.close(); rmSync(dir, { recursive: true, force: true }); }
});

test('event filters scope webhook fan-out', async () => {
  const dir = tmp();
  const rc = await startReceiver();
  try {
    const db = openDb(dir);
    db.insert('webhooks', { id: 'wh_1', tenant_id: 't1', url: `http://127.0.0.1:${rc.port}/hook`, secret: 's', events: ['job.'], allow_private: true, enabled: true });
    notify(db, { tenantId: 't1', type: 'monitor.up', title: 'Monitor up', body: '' });
    assert.equal(db.store.find('notify_deliveries', () => true).length, 0, 'non-matching type is not enqueued');
    notify(db, { tenantId: 't1', type: 'job.completed', title: 'Job done', body: '' });
    assert.equal(db.store.find('notify_deliveries', () => true).length, 1, 'matching prefix is enqueued');
    await flushDeliveries(db);
    assert.equal(rc.received.length, 1);
    db.store.close();
  } finally { rc.server.close(); rmSync(dir, { recursive: true, force: true }); }
});

test('webhook retries with backoff and then succeeds (flaky receiver)', async () => {
  const dir = tmp();
  const rc = await startReceiver();
  try {
    const db = openDb(dir);
    db.insert('webhooks', { id: 'wh_1', tenant_id: 't1', url: `http://127.0.0.1:${rc.port}/flaky`, secret: 's', events: ['*'], allow_private: true, enabled: true });
    notify(db, { tenantId: 't1', type: 'x.y', title: 't', body: '' });
    const t0 = Date.now();
    await flushDeliveries(db, { now: t0 }); // attempt 1 → 500
    let d = db.store.find('notify_deliveries', () => true)[0];
    assert.equal(d.status, 'pending');
    assert.equal(d.attempts, 1);
    assert.ok(new Date(d.next_attempt_at).getTime() > t0, 'next attempt scheduled in the future');
    // not due yet at t0+10s (backoff is 15s)
    assert.equal(await flushDeliveries(db, { now: t0 + 10_000 }), 0);
    // due at t0+16s → attempt 2 → 500 again
    await flushDeliveries(db, { now: t0 + 16_000 });
    d = db.store.find('notify_deliveries', () => true)[0];
    assert.equal(d.attempts, 2);
    assert.equal(d.status, 'pending');
    // due at t0+16s+61s → attempt 3 → 200 → delivered
    await flushDeliveries(db, { now: t0 + 16_000 + 61_000 });
    d = db.store.find('notify_deliveries', () => true)[0];
    assert.equal(d.status, 'delivered');
    assert.equal(d.attempts, 3);
    assert.equal(rc.received.length, 3, 'receiver saw all three attempts');
    db.store.close();
  } finally { rc.server.close(); rmSync(dir, { recursive: true, force: true }); }
});

test('webhook gives up after max attempts and records the failure', async () => {
  const dir = tmp();
  const rc = await startReceiver();
  try {
    const db = openDb(dir);
    db.insert('webhooks', { id: 'wh_1', tenant_id: 't1', url: `http://127.0.0.1:${rc.port}/fail`, secret: 's', events: ['*'], allow_private: true, enabled: true });
    notify(db, { tenantId: 't1', type: 'x.y', title: 't', body: '' });
    let t = Date.now();
    for (let i = 0; i < WEBHOOK_MAX_ATTEMPTS; i++) {
      await flushDeliveries(db, { now: t });
      t += 400_000; // advance past every backoff window
    }
    const d = db.store.find('notify_deliveries', () => true)[0];
    assert.equal(d.status, 'failed');
    assert.equal(d.attempts, WEBHOOK_MAX_ATTEMPTS);
    assert.match(d.last_error, /HTTP 500/);
    const w = db.store.findOne('webhooks', (x) => x.id === 'wh_1');
    assert.equal(w.last_status, 'failed');
    db.store.close();
  } finally { rc.server.close(); rmSync(dir, { recursive: true, force: true }); }
});

test('email channel delivers a real SMTP transaction to a loopback test server', async () => {
  const dir = tmp();
  const smtp = await startSmtpServer();
  try {
    const db = openDb(dir);
    db.insert('email_channels', { id: 'emch_1', tenant_id: 't1', smtp_host: '127.0.0.1', smtp_port: smtp.port, from: 'meridian@example.com', to: 'ops@example.com, security@example.com', events: ['*'], enabled: true });
    notify(db, { tenantId: 't1', type: 'job.completed', title: 'Scan finished', body: 'The scan finished with 5 findings.' });
    const flushed = await flushDeliveries(db);
    assert.equal(flushed, 1);
    const d = db.store.find('notify_deliveries', () => true)[0];
    assert.equal(d.kind, 'email');
    assert.equal(d.status, 'delivered', `delivery failed: ${d.last_error}`);
    assert.equal(smtp.mail.length, 1, 'SMTP server received one message');
    const m = smtp.mail[0];
    assert.equal(m.from, 'meridian@example.com');
    assert.deepEqual(m.to.sort(), ['ops@example.com', 'security@example.com'].sort());
    assert.ok(m.data.includes('Subject: [Meridian] Scan finished'));
    assert.ok(m.data.includes('The scan finished with 5 findings.'));
    db.store.close();
  } finally { smtp.server.close(); rmSync(dir, { recursive: true, force: true }); }
});

test('sendSmtpMail rejects invalid input without touching the network', async () => {
  await assert.rejects(() => sendSmtpMail({}), /requires host/);
  await assert.rejects(() => sendSmtpMail({ host: '127.0.0.1', from: 'a@b.c' }), /at least one recipient/);
});
