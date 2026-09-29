import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Db } from '#app/db';
import { openStore } from '#store/store';
import { createSession, rotateSession, authenticate, requireAuth, verifyLoginCredentials } from '#api/authn';
import { hashPassword } from '#sec/crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const tmp = () => mkdtempSync(join(tmpdir(), 'meridian-authn-'));

function seedUser(db, { role = 'owner', email = 'u@t.co', password = 'Passw0rd!Abc' } = {}) {
  return db.insert('users', { tenant_id: 't1', email, name: 'U', role, status: 'active', password_hash: hashPassword(password), mfa_enabled: false });
}

test('verifyLoginCredentials accepts valid credentials and rejects wrong ones', () => {
  const dir = tmp();
  try {
    const store = openStore(dir);
    const db = new Db(store);
    seedUser(db);
    assert.equal(verifyLoginCredentials(db, 'u@t.co', 'Passw0rd!Abc')?.email, 'u@t.co');
    assert.equal(verifyLoginCredentials(db, 'u@t.co', 'wrong'), null);
    assert.equal(verifyLoginCredentials(db, 'nobody@t.co', 'Passw0rd!Abc'), null);
    store.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('createSession issues opaque tokens; only hashes are stored', () => {
  const dir = tmp();
  try {
    const store = openStore(dir);
    const db = new Db(store);
    const user = seedUser(db);
    const { accessToken, refreshToken } = createSession(db, user, { ip: '127.0.0.1' });
    assert.match(accessToken, /^mat_/);
    assert.match(refreshToken, /^mrt_/);
    const session = db.store.find('sessions', (s) => s.user_id === user.id)[0];
    assert.ok(!JSON.stringify(session).includes(accessToken), 'raw access token must never be stored');
    assert.ok(!JSON.stringify(session).includes(refreshToken), 'raw refresh token must never be stored');
    assert.equal(session.token_hash.length, 64);
    store.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('authenticate resolves a Bearer token to user + session', () => {
  const dir = tmp();
  try {
    const store = openStore(dir);
    const db = new Db(store);
    const user = seedUser(db);
    const { accessToken } = createSession(db, user);
    const auth = authenticate(db, { headers: { authorization: `Bearer ${accessToken}` } });
    assert.equal(auth.user.email, 'u@t.co');
    assert.ok(auth.session);
    assert.equal(authenticate(db, { headers: { authorization: 'Bearer mat_bogus' } }), null);
    assert.equal(authenticate(db, { headers: {} }), null);
    store.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('expired sessions are rejected', () => {
  const dir = tmp();
  try {
    const store = openStore(dir);
    const db = new Db(store);
    const user = seedUser(db);
    const { accessToken, session } = createSession(db, user);
    db.store.put('sessions', { ...session, expires_at: new Date(Date.now() - 1000).toISOString() });
    assert.equal(authenticate(db, { headers: { authorization: `Bearer ${accessToken}` } }), null);
    store.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('rotateSession rotates tokens and detects refresh-token reuse', () => {
  const dir = tmp();
  try {
    const store = openStore(dir);
    const db = new Db(store);
    const user = seedUser(db);
    const { refreshToken: rt1 } = createSession(db, user);
    const second = rotateSession(db, rt1);
    assert.match(second.accessToken, /^mat_/);
    // replaying the OLD refresh token must fail and revoke the chain
    assert.throws(() => rotateSession(db, rt1), Error);
    assert.throws(() => rotateSession(db, second.refreshToken), /revoked|invalid/i);
    store.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('requireAuth enforces role permissions', () => {
  const dir = tmp();
  try {
    const store = openStore(dir);
    const db = new Db(store);
    const owner = seedUser(db, { role: 'owner' });
    const viewer = seedUser(db, { role: 'viewer', email: 'v@t.co' });
    const { accessToken: ownerTok } = createSession(db, owner);
    const { accessToken: viewerTok } = createSession(db, viewer);

    const guard = requireAuth(['findings:write']);
    const mkCtx = (tok) => ({ auth: authenticate(db, { headers: { authorization: `Bearer ${tok}` } }), throw: (s, m) => { const e = new Error(m || s); e.status = s; throw e; } });

    guard(mkCtx(ownerTok)); // owner passes
    assert.throws(() => guard(mkCtx(viewerTok)), Error); // viewer lacks write
    assert.throws(() => guard({ auth: null, throw: (s, m) => { const e = new Error(m || s); e.status = s; throw e; } }), Error);
    store.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
