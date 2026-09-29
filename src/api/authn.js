import crypto from 'node:crypto';
import { unauthorized, forbidden } from '#core/errors';
import { verifyPassword } from '#sec/crypto';
import { roleHas } from '#core/taxonomy';
import { nowIso, sha256 } from '#core/util';

const ACCESS_TTL_MS = 2 * 60 * 60 * 1000;        // 2 hours
const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

export function createSession(db, user, { userAgent = null, ip = null } = {}) {
  const accessToken = `mat_${crypto.randomBytes(32).toString('base64url')}`;
  const refreshToken = `mrt_${crypto.randomBytes(32).toString('base64url')}`;
  const session = db.insert('sessions', {
    tenant_id: user.tenant_id, user_id: user.id,
    token_hash: sha256(accessToken), refresh_hash: sha256(refreshToken),
    created_at: nowIso(), expires_at: new Date(Date.now() + ACCESS_TTL_MS).toISOString(),
    refresh_expires_at: new Date(Date.now() + REFRESH_TTL_MS).toISOString(),
    revoked_at: null, rotated_to: null, user_agent: userAgent, ip,
  });
  return { session, accessToken, refreshToken, expiresIn: ACCESS_TTL_MS / 1000 };
}

/** Rotate a refresh token; detect reuse of rotated tokens (session family revocation). */
export function rotateSession(db, refreshToken) {
  const hash = sha256(refreshToken);
  const session = db.store.byIndex('sessions', 'token_hash', hash)[0] || db.store.findOne('sessions', (s) => s.refresh_hash === hash);
  if (!session) throw unauthorized('invalid refresh token');
  if (session.revoked_at) {
    // reuse detected: revoke the whole rotation family — ancestors AND descendants
    const seen = new Set();
    let cur = session;
    while (cur && cur.rotated_from && !seen.has(cur.id)) {
      seen.add(cur.id);
      const parent = db.store.findOne('sessions', (s) => s.id === cur.rotated_from);
      if (parent) { db.store.put('sessions', { ...parent, revoked_at: parent.revoked_at || nowIso() }); cur = parent; } else break;
    }
    // forward: revoke every descendant issued from this session
    let frontier = [session];
    const fwdSeen = new Set();
    while (frontier.length) {
      const next = [];
      for (const s of frontier) {
        if (fwdSeen.has(s.id)) continue;
        fwdSeen.add(s.id);
        db.store.put('sessions', { ...s, revoked_at: s.revoked_at || nowIso() });
        if (s.rotated_to) next.push(...db.store.find('sessions', (x) => x.id === s.rotated_to));
      }
      frontier = next;
    }
    db.store.put('sessions', { ...session, revoked_at: nowIso() });
    throw unauthorized('refresh token reuse detected — session family revoked');
  }
  if (new Date(session.refresh_expires_at) < new Date()) throw unauthorized('refresh token expired');
  const user = db.byIdGlobal('users', session.user_id);
  if (!user || user.status !== 'active') throw unauthorized('account is not active');
  const tokens = createSession(db, user, { userAgent: session.user_agent, ip: session.ip });
  db.store.put('sessions', { ...session, revoked_at: nowIso(), rotated_to: tokens.session.id });
  db.store.put('sessions', { ...tokens.session, rotated_from: session.id });
  return { user, ...tokens };
}

export function authenticate(db, req, { allowCookie = false } = {}) {
  const auth = req.headers['authorization'];
  let token = null;
  if (auth && auth.startsWith('Bearer ')) token = auth.slice(7);
  else if (allowCookie) {
    const cookie = req.headers['cookie'] || '';
    const m = /(?:^|;\s*)meridian_session=([^;]+)/.exec(cookie);
    if (m) token = m[1];
  }
  if (!token) return null;
  const hash = sha256(token);
  let session = db.store.byIndex('sessions', 'token_hash', hash)[0];
  if (!session) return null;
  if (session.revoked_at || new Date(session.expires_at) < new Date()) return null;
  const user = db.byIdGlobal('users', session.user_id);
  if (!user || user.status !== 'active') return null;
  return { user, session };
}

export function authenticateApiKey(db, req) {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) return null;
  const key = auth.slice(7);
  if (!key.startsWith('mk_')) return null;
  const rec = db.store.byIndex('api_keys', 'key_hash', sha256(key))[0];
  if (!rec || rec.revoked_at) return null;
  const user = db.byIdGlobal('users', rec.user_id);
  if (!user) return null;
  db.store.put('api_keys', { ...rec, last_used_at: nowIso() });
  return { user, apiKey: rec };
}

/** Route guard factory: requires authentication + permissions. */
export function requireAuth(perms = []) {
  return (ctx) => {
    const { auth } = ctx;
    if (!auth) throw unauthorized();
    const role = auth.user.role;
    const scopes = auth.apiKey?.scopes;
    if (scopes) {
      for (const p of perms) if (!scopes.includes(p) && !scopes.includes('*')) throw forbidden(`api key lacks scope: ${p}`);
    } else {
      for (const p of perms) if (!roleHas(role, p)) throw forbidden(`role "${role}" lacks permission: ${p}`);
    }
    return true;
  };
}

export function verifyLoginCredentials(db, email, password) {
  const user = db.store.findOne('users', (u) => u.email === email && u.status === 'active');
  if (!user) return null;
  if (!verifyPassword(password, user.password_hash)) return null;
  return user;
}
