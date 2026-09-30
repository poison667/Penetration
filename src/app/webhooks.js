import { createHmac } from 'node:crypto';
import net from 'node:net';
import { URL } from 'node:url';

/**
 * External notification delivery channels.
 *
 * - Webhooks: tenant-registered HTTPS/HTTP endpoints receiving signed JSON POSTs
 *   (X-Meridian-Signature: sha256=<hmac>) with an outbox + bounded retries.
 * - Email: a real minimal SMTP client (EHLO/MAIL FROM/RCPT TO/DATA/QUIT) — delivery
 *   is verifiable against any SMTP server, including a loopback test receiver.
 *
 * SMS intentionally remains a documented limitation: it requires an external carrier
 * API with credentials, so no messages are ever claimed sent (see docs/LIMITATIONS.md).
 */

const DELIVERY_KIND = 'notify_deliveries';
export const WEBHOOK_MAX_ATTEMPTS = 3;
/** Backoff between delivery attempts (seconds), indexed by attempt number. */
export const WEBHOOK_BACKOFF_S = [15, 60, 300];

/** Syntactic private/loopback host check (no DNS — conservative). */
export function isPrivateHost(hostname) {
  const h = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
  return h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal')
    || /^127\./.test(h) || /^10\./.test(h) || /^192\.168\./.test(h) || /^172\.(1[6-9]|2\d|3[01])\./.test(h)
    || h === '::1' || h === '0.0.0.0' || /^169\.254\./.test(h);
}

/** Validate a webhook target URL. Throws a descriptive error when rejected. */
export function validateWebhookUrl(raw, { allowPrivate = false } = {}) {
  let u;
  try { u = new URL(raw); } catch { throw new Error('invalid URL'); }
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('webhook URL must be http(s)');
  if (!u.hostname) throw new Error('webhook URL has no hostname');
  if (isPrivateHost(u.hostname) && !allowPrivate) {
    throw new Error('webhook URL points at a private/loopback host — set allow_private explicitly (this target must be authorized like any other)');
  }
  return u.toString();
}

/** HMAC-SHA256 signature over body + timestamp (replay-protected). */
export function signWebhookPayload(secret, body, timestampMs) {
  return createHmac('sha256', String(secret)).update(`${timestampMs}.${body}`).digest('hex');
}

function nowIso() { return new Date().toISOString(); }

/**
 * Enqueue external deliveries for a freshly created notification.
 * Called from notify() — never throws (delivery problems must not break notification creation).
 */
export function enqueueExternalDeliveries(db, notification) {
  try {
    const webhooks = db.store.find('webhooks', (w) => w.tenant_id === notification.tenant_id && w.enabled !== false);
    for (const w of webhooks) {
      const events = Array.isArray(w.events) && w.events.length ? w.events : ['*'];
      const match = events.includes('*') || events.some((e) => { if (e === '*') return true; if (e === notification.type) return true; const pfx = e.endsWith('.') ? e : e + '.'; return String(notification.type).startsWith(pfx); });
      if (!match) continue;
      db.insert(DELIVERY_KIND, {
        tenant_id: notification.tenant_id, webhook_id: w.id, notification_id: notification.id,
        kind: 'webhook', target: w.url, event: notification.type,
        payload: JSON.stringify({ id: notification.id, type: notification.type, title: notification.title, body: notification.body, data: notification.data, created_at: notification.created_at }),
        attempts: 0, max_attempts: WEBHOOK_MAX_ATTEMPTS, status: 'pending',
        next_attempt_at: nowIso(), last_error: null, response_status: null,
        created_at: nowIso(), delivered_at: null,
      });
    }
    const email = db.store.findOne('email_channels', (e) => e.tenant_id === notification.tenant_id && e.enabled !== false);
    if (email) {
      const events = Array.isArray(email.events) && email.events.length ? email.events : ['*'];
      const match = events.includes('*') || events.some((e) => { if (e === '*') return true; if (e === notification.type) return true; const pfx = e.endsWith('.') ? e : e + '.'; return String(notification.type).startsWith(pfx); });
      if (match) {
        db.insert(DELIVERY_KIND, {
          tenant_id: notification.tenant_id, email_channel_id: email.id, notification_id: notification.id,
          kind: 'email', target: `${email.smtp_host}:${email.smtp_port}`, event: notification.type,
          payload: JSON.stringify({ from: email.from, to: email.to, subject: `[Meridian] ${notification.title}`, text: notification.body || '' }),
          attempts: 0, max_attempts: WEBHOOK_MAX_ATTEMPTS, status: 'pending',
          next_attempt_at: nowIso(), last_error: null, response_status: null,
          created_at: nowIso(), delivered_at: null,
        });
      }
    }
  } catch (e) {
    // enqueueing must never break notification creation
    console.error('[notify-delivery] enqueue failed:', e?.message || e);
  }
}

/** Deliver one pending delivery. Returns true when the row state changed. */
async function attemptDelivery(db, d, { nowMs }) {
  const payload = d.payload;
  if (d.kind === 'webhook') {
    const ts = nowMs;
    const sig = signWebhookPayload(db.store.findOne('webhooks', (w) => w.id === d.webhook_id)?.secret || '', payload, ts);
    let status = null, err = null;
    try {
      const res = await fetch(d.target, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'user-agent': 'Meridian-Webhook/1.0', 'x-meridian-signature': `sha256=${sig}`, 'x-meridian-timestamp': String(ts), 'x-meridian-event': d.event || 'notification' },
        body: payload, signal: AbortSignal.timeout(10_000),
      });
      status = res.status;
      if (!res.ok) err = `HTTP ${res.status}`;
    } catch (e) { err = String(e?.message || e); }
    return finishAttempt(db, d, { ok: !err, status, err, nowMs });
  }
  if (d.kind === 'email') {
    const channel = db.store.findOne('email_channels', (e) => e.id === d.email_channel_id);
    const p = JSON.parse(payload);
    let err = null;
    try {
      if (!channel) throw new Error('email channel was removed before delivery');
      await sendSmtpMail({ host: channel.smtp_host, port: channel.smtp_port, from: p.from, to: p.to, subject: p.subject, text: p.text });
    } catch (e) { err = String(e?.message || e); }
    return finishAttempt(db, d, { ok: !err, status: err ? null : 250, err, nowMs });
  }
  db.store.put(DELIVERY_KIND, { ...d, status: 'failed', last_error: `unknown delivery kind: ${d.kind}` });
  return true;
}

function finishAttempt(db, d, { ok, status, err, nowMs }) {
  const attempts = d.attempts + 1;
  if (ok) {
    db.store.put(DELIVERY_KIND, { ...d, attempts, status: 'delivered', response_status: status, last_error: null, delivered_at: nowIso() });
    if (d.webhook_id) {
      const w = db.store.findOne('webhooks', (x) => x.id === d.webhook_id);
      if (w) db.store.put('webhooks', { ...w, last_status: 'delivered', last_delivery_at: nowIso() });
    }
    return true;
  }
  if (attempts >= d.max_attempts) {
    db.store.put(DELIVERY_KIND, { ...d, attempts, status: 'failed', response_status: status, last_error: err || 'delivery failed', delivered_at: null });
    if (d.webhook_id) {
      const w = db.store.findOne('webhooks', (x) => x.id === d.webhook_id);
      if (w) db.store.put('webhooks', { ...w, last_status: 'failed', last_delivery_at: nowIso() });
    }
    return true;
  }
  const backoffS = WEBHOOK_BACKOFF_S[Math.min(attempts - 1, WEBHOOK_BACKOFF_S.length - 1)];
  db.store.put(DELIVERY_KIND, { ...d, attempts, status: 'pending', response_status: status, last_error: err || 'delivery failed', next_attempt_at: new Date(nowMs + backoffS * 1000).toISOString() });
  return true;
}

/**
 * Flush due deliveries (outbox pattern). Called by the scheduler on every tick.
 * @param {object} db platform db
 * @param {{ now?: number, limit?: number }} opts clock injection for tests
 */
export async function flushDeliveries(db, { now = Date.now(), limit = 20 } = {}) {
  const due = db.store.find(DELIVERY_KIND, (d) => d.status === 'pending' && d.next_attempt_at <= new Date(now).toISOString()).slice(0, limit);
  for (const d of due) await attemptDelivery(db, d, { nowMs: now });
  return due.length;
}

/**
 * Minimal but real SMTP client: EHLO → MAIL FROM → RCPT TO → DATA → QUIT.
 * Works against any RFC-5321 server (verified against a loopback test receiver).
 */
export function sendSmtpMail({ host, port = 25, from, to, subject = '', text = '', timeoutMs = 10_000 }) {
  return new Promise((resolve, reject) => {
    const recipients = Array.isArray(to) ? to : String(to || '').split(/[,;]\s*/).filter(Boolean);
    if (!host || !from || !recipients.length) return reject(new Error('sendSmtpMail requires host, from and at least one recipient'));
    const sock = net.createConnection({ host, port: Number(port) || 25 });
    let stage = 'connect', buffer = '', lastCode = 0, rcptOk = 0, settled = false;
    const fail = (e) => { if (!settled) { settled = true; try { sock.destroy(); } catch {} reject(e); } };
    const done = () => { if (!settled) { settled = true; sock.end(); resolve({ code: lastCode }); } };
    const timer = setTimeout(() => fail(new Error('SMTP timeout')), timeoutMs);
    sock.on('error', fail);
    sock.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      const lines = buffer.split('\r\n');
      buffer = lines.pop() || '';
      const line = lines[lines.length - 1];
      if (!line || !/^\d{3}/.test(line)) return;
      lastCode = Number(line.slice(0, 3));
      if (lastCode >= 500) return fail(new Error(`SMTP error ${lastCode}: ${line.slice(0, 200)}`));
      switch (stage) {
        case 'connect': sock.write('EHLO meridian.local\r\n'); stage = 'ehlo'; return;
        case 'ehlo': sock.write(`MAIL FROM:<${from}>\r\n`); stage = 'mail'; return;
        case 'mail':
          if (lastCode !== 250) return fail(new Error(`MAIL FROM rejected: ${lastCode}`));
          sock.write(`RCPT TO:<${recipients[0]}>\r\n`); rcptOk = 0; stage = 'rcpt'; return;
        case 'rcpt':
          if (lastCode !== 250 && lastCode !== 251) return fail(new Error(`RCPT TO rejected: ${lastCode}`));
          rcptOk += 1;
          if (rcptOk < recipients.length) { sock.write(`RCPT TO:<${recipients[rcptOk]}>\r\n`); return; }
          sock.write('DATA\r\n'); stage = 'data'; return;
        case 'data':
          if (lastCode !== 354) return fail(new Error(`DATA rejected: ${lastCode}`));
          sock.write(`From: ${from}\r\nTo: ${recipients.join(', ')}\r\nSubject: ${subject}\r\nDate: ${new Date().toUTCString()}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n${text}\r\n.\r\n`);
          stage = 'body'; return;
        case 'body':
          if (lastCode !== 250) return fail(new Error(`message body rejected: ${lastCode}`));
          sock.write('QUIT\r\n'); stage = 'quit'; return;
        case 'quit': clearTimeout(timer); return done();
        default: return;
      }
    });
    sock.on('close', () => { clearTimeout(timer); if (!settled) fail(new Error('SMTP connection closed unexpectedly')); });
  });
}
