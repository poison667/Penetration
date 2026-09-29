import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Db } from '#app/db';
import { openStore } from '#store/store';
import { FileStore } from '#app/files';
import { createServer } from '#api/server';
import { hashPassword } from '#sec/crypto';
import { totpNow, base32Decode, setSecretKey } from '#sec/crypto';
import crypto from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
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
