import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Db } from '#app/db';
import { openStore } from '#store/store';
import { FileStore } from '#app/files';
import { createServer } from '#api/server';
import { hashPassword } from '#sec/crypto';
import { totpNow, base32Decode, setSecretKey } from '#sec/crypto';
import crypto from 'node:crypto';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

setSecretKey(crypto.randomBytes(32)); // in-memory platform key (seals MFA secrets)

const B = 'http://127.0.0.1';

async function api(port, path, { method = 'GET', token, body } = {}) {
  const res = await fetch(`${B}:${port}${path}`, {
    method,
    headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  let json = null;
  try { json = await res.json(); } catch {}
  return { status: res.status, json, headers: res.headers };
}

async function startApi() {
  const dir = mkdtempSync(join(tmpdir(), 'meridian-api-'));
  const store = openStore(dir);
  const db = new Db(store);
  const files = new FileStore(join(dir, 'files'), store);
  const tenant = db.insert('tenants', { name: 'API Tenant (test data)', status: 'active', created_at: new Date().toISOString() });
  const other = db.insert('tenants', { name: 'Other Tenant (test data)', status: 'active', created_at: new Date().toISOString() });
  db.insert('users', { tenant_id: tenant.id, email: 'owner@x.co', name: 'O', role: 'owner', status: 'active', password_hash: hashPassword('Owner!Pass1A'), mfa_enabled: false });
  db.insert('users', { tenant_id: tenant.id, email: 'viewer@x.co', name: 'V', role: 'viewer', status: 'active', password_hash: hashPassword('Viewer!Pass1A'), mfa_enabled: false });
  db.insert('users', { tenant_id: other.id, email: 'other@x.co', name: 'X', role: 'owner', status: 'active', password_hash: hashPassword('Other!Pass1A'), mfa_enabled: false });
  const server = createServer({ db, files, config: { uiRoot: null } });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { server, db, store, files, dir, tenant, other };
}

test('API server: login, auth enforcement, RBAC, tenant isolation, secure headers', async () => {
  const h = await startApi();
  try {
    const port = h.server.address().port;

    // unauthenticated → 401
    assert.equal((await api(port, '/api/v1/jobs')).status, 401);

    // bad login → 401
    assert.equal((await api(port, '/api/v1/auth/login', { method: 'POST', body: { email: 'owner@x.co', password: 'nope' } })).status, 401);

    // real login → tokens
    const login = await api(port, '/api/v1/auth/login', { method: 'POST', body: { email: 'owner@x.co', password: 'Owner!Pass1A' } });
    assert.equal(login.status, 200);
    assert.ok(login.json.access_token || login.json.accessToken);
    const ownerTok = login.json.access_token || login.json.accessToken;
    assert.ok(login.json.refresh_token || login.json.refreshToken);

    // authenticated surface works
    const me = await api(port, '/api/v1/auth/me', { token: ownerTok });
    assert.equal(me.status, 200);
    assert.equal(me.json.user?.email || me.json.email, 'owner@x.co');

    // catalog is real
    const cat = await api(port, '/api/v1/catalog', { token: ownerTok });
    assert.equal(cat.status, 200);
    const services = cat.json.services || cat.json;
    assert.ok(services.length >= 20, `expected a full catalog, got ${services.length}`);

    // evidence list endpoint (summaries only, never content payloads)
    const ev = await api(port, '/api/v1/evidence?limit=50', { token: ownerTok });
    assert.equal(ev.status, 200);
    assert.ok(Array.isArray(ev.json.evidence));
    for (const e of ev.json.evidence) {
      assert.ok(e.id && e.kind && e.sha256, 'evidence summaries carry id/kind/sha256');
      assert.ok(!('content' in e), 'list endpoint must not ship evidence content');
    }

    // secure headers on every response
    const any = await fetch(`${B}:${port}/api/v1/catalog`, { headers: { authorization: `Bearer ${ownerTok}` } });
    assert.equal(any.headers.get('x-content-type-options'), 'nosniff');
    assert.ok(any.headers.get('content-security-policy'));

    // RBAC: viewer cannot create service requests
    const vlogin = await api(port, '/api/v1/auth/login', { method: 'POST', body: { email: 'viewer@x.co', password: 'Viewer!Pass1A' } });
    const viewerTok = vlogin.json.access_token || vlogin.json.accessToken;
    assert.equal(vlogin.status, 200);
    const assetBody = { identifier: 'https://example.com', kind: 'web_host', title: 'X', port: 443, authorization: { status: 'declared', scope_domains: ['example.com'], authorized_by: 'Test Owner' } };
    const asset = await api(port, '/api/v1/assets', { method: 'POST', token: viewerTok, body: assetBody });
    assert.equal(asset.status, 403, 'viewer must not create assets');

    // tenant isolation over the wire: other tenant's data is invisible
    const ologin = await api(port, '/api/v1/auth/login', { method: 'POST', body: { email: 'other@x.co', password: 'Other!Pass1A' } });
    const otherTok = ologin.json.access_token || ologin.json.accessToken;
    const created = await api(port, '/api/v1/assets', { method: 'POST', token: ownerTok, body: { identifier: 'https://owner-asset.example', kind: 'web_host', title: 'Owner asset', port: 443, authorization: { status: 'declared', scope_domains: ['owner-asset.example'], authorized_by: 'Test Owner' } } });
    assert.equal(created.status, 201, `owner must create asset: ${JSON.stringify(created.json)}`);
    const ownerId = created.json.asset?.id || created.json.id;
    // cross-tenant fetch by id → 404 (no existence leak)
    assert.equal((await api(port, `/api/v1/assets/${ownerId}`, { token: otherTok })).status, 404, 'cross-tenant asset read must 404');
    const otherAssets = await api(port, '/api/v1/assets', { token: otherTok });
    const list = otherAssets.json.assets || otherAssets.json.rows || otherAssets.json;
    assert.ok(Array.isArray(list) && list.every((a) => a.identifier !== 'https://owner-asset.example'), 'cross-tenant asset must not appear in listings');

    // register + login flow for a fresh tenant
    const reg = await api(port, '/api/v1/auth/register', { method: 'POST', body: { email: 'new@y.co', password: 'NewUser!Pass1A', name: 'N', tenant_name: 'NewCo' } });
    assert.ok([200, 201].includes(reg.status), `register failed: ${JSON.stringify(reg.json)}`);
    const nlogin = await api(port, '/api/v1/auth/login', { method: 'POST', body: { email: 'new@y.co', password: 'NewUser!Pass1A' } });
    assert.equal(nlogin.status, 200);

    // 404 for unknown routes, 405-ish behavior stays consistent
    assert.equal((await api(port, '/api/v1/nonexistent', { token: ownerTok })).status, 404);

    // unknown route without auth still 404 (routing precedes auth for unknown paths)
    assert.equal((await api(port, '/api/v1/nonexistent')).status, 404);

    h.server.close();
    h.store.close();
  } finally {
    rmSync(h.dir, { recursive: true, force: true });
  }
});

test('API server: API key creation, listing and scoped use', async () => {
  const h = await startApi();
  try {
    const port = h.server.address().port;
    const login = await api(port, '/api/v1/auth/login', { method: 'POST', body: { email: 'owner@x.co', password: 'Owner!Pass1A' } });
    const ownerTok = login.json.access_token || login.json.accessToken;

    // create a key (regression: this route crashed with `require is not defined`)
    const created = await api(port, '/api/v1/api-keys', { method: 'POST', token: ownerTok, body: { name: 'test key', scopes: ['read'] } });
    assert.equal(created.status, 201, JSON.stringify(created.json));
    assert.match(created.json.key, /^mk_/);
    assert.ok(created.json.note, 'one-time-display note present');

    // the key appears in listings (prefix only — never the raw key)
    const listed = await api(port, '/api/v1/api-keys', { token: ownerTok });
    assert.equal(listed.status, 200);
    const key = listed.json.keys.find((k) => k.name === 'test key');
    assert.ok(key, 'created key listed');
    assert.equal(key.prefix, created.json.key.slice(0, 10));
    assert.ok(!JSON.stringify(listed.json).includes(created.json.key), 'raw key must never appear in listings');

    // the key authenticates API calls
    const viaKey = await fetch(`http://127.0.0.1:${port}/api/v1/auth/me`, { headers: { authorization: `Bearer ${created.json.key}` } });
    assert.equal(viaKey.status, 200);

    h.server.close();
    h.store.close();
  } finally {
    rmSync(h.dir, { recursive: true, force: true });
  }
});

test('API server: MFA challenge + TOTP verification on login', async () => {
  const h = await startApi();
  try {
    const port = h.server.address().port;
    const login = await api(port, '/api/v1/auth/login', { method: 'POST', body: { email: 'owner@x.co', password: 'Owner!Pass1A' } });
    const ownerTok = login.json.access_token || login.json.accessToken;

    // enroll MFA: setup returns a base32 secret (pending until confirmed)
    const setup = await api(port, '/api/v1/auth/mfa/setup', { method: 'POST', token: ownerTok, body: {} });
    assert.equal(setup.status, 200);
    const secretB32 = setup.json.secret;
    assert.match(secretB32 || '', /^[A-Z2-7]+$/);
    assert.match(setup.json.otpauth_url, /^otpauth:\/\/totp\//);
    const secret = base32Decode(secretB32);

    // confirm enrollment with the current code (this consumes the code)
    const enable = await api(port, '/api/v1/auth/mfa/enable', { method: 'POST', token: ownerTok, body: { code: totpNow(secret) } });
    assert.equal(enable.status, 200, JSON.stringify(enable.json));
    assert.equal(enable.json.mfa_enabled, true);

    // login now requires TOTP — password alone yields no token
    const chal = await api(port, '/api/v1/auth/login', { method: 'POST', body: { email: 'owner@x.co', password: 'Owner!Pass1A' } });
    assert.equal(chal.status, 200);
    assert.equal(chal.json.mfa_required, true);
    assert.ok(!chal.json.access_token, 'no token may be issued before TOTP');

    // valid TOTP completes login — use the NEXT step window: the enable code was consumed (replay protection)
    const nextCode = totpNow(secret, { atMs: Date.now() + 31_000 });
    const done = await api(port, '/api/v1/auth/login', { method: 'POST', body: { email: 'owner@x.co', password: 'Owner!Pass1A', totp: nextCode } });
    assert.equal(done.status, 200);
    assert.ok(done.json.access_token || done.json.accessToken, 'TOTP login must yield tokens');

    // wrong TOTP fails (pick 6 digits guaranteed different from the real next-window code)
    const wrong = nextCode === '000000' ? '000001' : '000000';
    const bad = await api(port, '/api/v1/auth/login', { method: 'POST', body: { email: 'owner@x.co', password: 'Owner!Pass1A', totp: wrong } });
    assert.equal(bad.status, 401);

    h.server.close();
    h.store.close();
  } finally {
    rmSync(h.dir, { recursive: true, force: true });
  }
});

test('API server: webhook + email channel registry (RBAC, SSRF guard, secret hygiene)', async () => {
  const h = await startApi();
  try {
    const port = h.server.address().port;
    const login = await api(port, '/api/v1/auth/login', { method: 'POST', body: { email: 'owner@x.co', password: 'Owner!Pass1A' } });
    const ownerTok = login.json.access_token || login.json.accessToken;
    const vlogin = await api(port, '/api/v1/auth/login', { method: 'POST', body: { email: 'viewer@x.co', password: 'Viewer!Pass1A' } });
    const viewerTok = vlogin.json.access_token || vlogin.json.accessToken;

    // anonymous → 401 on both verbs
    assert.equal((await api(port, '/api/v1/webhooks')).status, 401, 'anon GET /webhooks must 401');
    assert.equal((await api(port, '/api/v1/webhooks', { method: 'POST', body: { url: 'https://example.com/hook' } })).status, 401, 'anon POST /webhooks must 401');

    // SSRF guard: private target without allow_private → 400
    const priv = await api(port, '/api/v1/webhooks', { method: 'POST', token: ownerTok, body: { url: 'http://127.0.0.1:9/hook' } });
    assert.equal(priv.status, 400, `private URL must be rejected: ${JSON.stringify(priv.json)}`);

    // create → 201, secret returned exactly once
    const created = await api(port, '/api/v1/webhooks', { method: 'POST', token: ownerTok, body: { url: 'https://example.com/hook', events: ['job.'] } });
    assert.equal(created.status, 201, JSON.stringify(created.json));
    const wh = created.json.webhook;
    assert.ok(wh.id && wh.secret, 'creation response carries id + one-time secret');
    assert.deepEqual(wh.events, ['job.']);

    // listing strips the secret everywhere
    const listed = await api(port, '/api/v1/webhooks', { token: ownerTok });
    assert.equal(listed.status, 200);
    assert.ok(!JSON.stringify(listed.json).includes(wh.secret), 'secret must never appear in listings');
    const got = listed.json.webhooks.find((w) => w.id === wh.id);
    assert.ok(got && got.secret === undefined, 'stored webhook row has secret removed');

    // RBAC: viewer lacks settings:write → 403 on create; read allowed
    assert.equal((await api(port, '/api/v1/webhooks', { method: 'POST', token: viewerTok, body: { url: 'https://example.com/hook' } })).status, 403, 'viewer must not create webhooks');
    assert.equal((await api(port, '/api/v1/webhooks', { token: viewerTok })).status, 200, 'viewer may list webhooks');

    // deliveries endpoint responds (empty) and strips payloads
    const deliv = await api(port, `/api/v1/webhooks/${wh.id}/deliveries`, { token: ownerTok });
    assert.equal(deliv.status, 200);
    assert.ok(Array.isArray(deliv.json.deliveries));

    // email channel settings: anon 401, viewer 403 on write, owner 200 round-trip
    assert.equal((await api(port, '/api/v1/settings/email', { method: 'PUT', token: viewerTok, body: { smtp_host: '127.0.0.1', smtp_port: 2525, from: 'a@x.co', to: 'b@x.co' } })).status, 403, 'viewer must not write email settings');
    const emailPut = await api(port, '/api/v1/settings/email', { method: 'PUT', token: ownerTok, body: { smtp_host: '127.0.0.1', smtp_port: 2525, from: 'alerts@x.co', to: 'owner@x.co', events: ['monitor.'] } });
    assert.equal(emailPut.status, 200, JSON.stringify(emailPut.json));
    const emailGet = await api(port, '/api/v1/settings/email', { token: ownerTok });
    assert.equal(emailGet.status, 200);
    assert.equal(emailGet.json.email_channel.smtp_host, '127.0.0.1');
    assert.deepEqual(emailGet.json.email_channel.events, ['monitor.']);

    // re-pathed automation webhook registry still works (inbound triggers)
    const auto = await api(port, '/api/v1/automation/webhooks', { method: 'POST', token: ownerTok, body: { event: 'job_completed', url: 'https://example.com/cb' } });
    assert.equal(auto.status, 201, JSON.stringify(auto.json));
    assert.match(auto.json.token, /^mwh_/);

    // delete → gone
    assert.equal((await api(port, `/api/v1/webhooks/${wh.id}`, { method: 'DELETE', token: ownerTok })).status, 200);
    assert.equal((await api(port, '/api/v1/webhooks', { token: ownerTok })).json.webhooks.length, 0, 'webhook removed');

    // audit trail captured create + delete
    const audit = await api(port, '/api/v1/audit?limit=50', { token: ownerTok });
    const rows = audit.json.entries || audit.json.logs || [];
    const actions = rows.map((a) => a.action);
    assert.ok(actions.includes('webhook.created') && actions.includes('webhook.deleted'), `audit must record webhook lifecycle: ${actions.join(',')}`);
  } finally {
    h.server.close();
    h.store.close();
    rmSync(h.dir, { recursive: true, force: true });
  }
});

test('API server: document OCR — upload image, extract text, request without asset', async () => {
  const h = await startApi();
  try {
    const port = h.server.address().port;
    const login = await api(port, '/api/v1/auth/login', { method: 'POST', body: { email: 'owner@x.co', password: 'Owner!Pass1A' } });
    const ownerTok = login.json.access_token || login.json.accessToken;
    const { ocrProviderInfo } = await import('#docint/ocr');
    const provider = await ocrProviderInfo();
    const png = readFileSync('tests/fixtures/ocr-sample.png');

    // multipart upload (field "file")
    const fd = new FormData();
    fd.append('file', new Blob([png], { type: 'image/png' }), 'ocr-sample.png');
    fd.append('tags', 'ocr-test');
    const up = await fetch(`http://127.0.0.1:${port}/api/v1/documents`, { method: 'POST', headers: { authorization: `Bearer ${ownerTok}` }, body: fd });
    const upJson = await up.json().catch(() => ({}));
    assert.equal(up.status, 201, JSON.stringify(upJson));
    const doc = upJson.document;
    assert.ok(doc.id, 'document stored');
    assert.equal(doc.requires_ocr, true, 'upload marks images requires_ocr (extraction runs separately)');

    // inline extraction: real OCR when the engine is installed, honest absence otherwise
    const ext = await api(port, `/api/v1/documents/${doc.id}/extract`, { method: 'POST', token: ownerTok, body: {} });
    assert.equal(ext.status, 200, JSON.stringify(ext.json));
    if (provider.available) {
      assert.ok(ext.json.ocr && ext.json.ocr.engine, 'ocr metadata present');
      assert.match(ext.json.document.extraction_method, /^ocr:/);
      assert.ok(/MERIDIAN OCR 4217|4217/.test(String(ext.json.text_preview || '')), `OCR text preview: ${JSON.stringify(ext.json.text_preview)}`);
    } else {
      assert.equal(ext.json.document.requires_ocr, true, 'absence reported, not faked');
      assert.equal((ext.json.text_preview || '').length, 0);
    }

    // document services are asset-less: request without asset_id now works
    const req = await api(port, '/api/v1/requests', { method: 'POST', token: ownerTok, body: { service: 'doc_extract', params: { document_id: doc.id } } });
    assert.equal(req.status, 202, JSON.stringify(req.json));
    assert.ok(req.json.job_id, 'job queued without an asset');

    // viewer may read documents but not write extraction
    const vlogin = await api(port, '/api/v1/auth/login', { method: 'POST', body: { email: 'viewer@x.co', password: 'Viewer!Pass1A' } });
    const viewerTok = vlogin.json.access_token || vlogin.json.accessToken;
    assert.equal((await api(port, '/api/v1/documents', { token: viewerTok })).status, 200, 'viewer may list documents');
    assert.equal((await api(port, `/api/v1/documents/${doc.id}/extract`, { method: 'POST', token: viewerTok, body: {} })).status, 403, 'viewer must not run extraction');

    h.server.close();
    h.store.close();
  } finally {
    rmSync(h.dir, { recursive: true, force: true });
  }
});
