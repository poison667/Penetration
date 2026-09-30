import crypto from 'node:crypto';

/** Password hashing (scrypt, per-password salt, constant-time verify). */
export function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const N = 16384, r = 8, p = 1;
  const hash = crypto.scryptSync(password, salt, 64, { N, r, p });
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64')}$${hash.toString('base64')}`;
}
export function verifyPassword(password, stored) {
  try {
    const [scheme, N, r, p, saltB64, hashB64] = String(stored).split('$');
    if (scheme !== 'scrypt') return false;
    const salt = Buffer.from(saltB64, 'base64');
    const expected = Buffer.from(hashB64, 'base64');
    const actual = crypto.scryptSync(password, salt, expected.length, { N: Number(N), r: Number(r), p: Number(p) });
    return crypto.timingSafeEqual(actual, expected);
  } catch { return false; }
}

export function timingSafeEqualStr(a, b) {
  const ba = Buffer.from(String(a ?? ''));
  const bb = Buffer.from(String(b ?? ''));
  if (ba.length !== bb.length) { crypto.timingSafeEqual(ba, ba); return false; }
  return crypto.timingSafeEqual(ba, bb);
}

/** AES-256-GCM authenticated encryption for secrets at rest (e.g. TOTP seeds). */
let keyCache = null;
export function setSecretKey(keyBytes) { keyCache = Buffer.from(keyBytes); }
function secretKey() {
  if (!keyCache) throw new Error('secret key not initialized');
  return keyCache;
}
export function sealSecret(plaintext) {
  // Binary-safe: UTF-8 coercion of arbitrary bytes (TOTP seeds) is LOSSY,
  // so Buffers are tagged and base64-wrapped before encryption.
  const payload = Buffer.isBuffer(plaintext) ? `b64:${Buffer.from(plaintext).toString('base64')}` : String(plaintext);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', secretKey(), iv);
  const ct = Buffer.concat([cipher.update(payload, 'utf8'), cipher.final()]);
  return `${iv.toString('base64')}.${cipher.getAuthTag().toString('base64')}.${ct.toString('base64')}`;
}
export function openSecret(sealed) {
  try {
    const [ivB64, tagB64, ctB64] = String(sealed).split('.');
    const decipher = crypto.createDecipheriv('aes-256-gcm', secretKey(), Buffer.from(ivB64, 'base64'));
    decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
    const plain = Buffer.concat([decipher.update(Buffer.from(ctB64, 'base64')), decipher.final()]).toString('utf8');
    return plain.startsWith('b64:') ? Buffer.from(plain.slice(4), 'base64') : plain;
  } catch { return null; }
}

/** Generate or load the installation secret key (data/secret.key). */
export function loadOrCreateSecretKey(dataDir, fs) {
  const path = `${dataDir}/secret.key`;
  if (fs.existsSync(path)) {
    const raw = fs.readFileSync(path);
    if (raw.length === 32) { setSecretKey(raw); return raw; }
  }
  const key = crypto.randomBytes(32);
  fs.mkdirSync(dataDir, { recursive: true });
  fs.writeFileSync(path, key, { mode: 0o600 });
  setSecretKey(key);
  return key;
}


/** RFC 4648 base32 (A-Z2-7, no padding) — used for TOTP secrets. */
const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function base32Encode(buf) {
  let bits = 0, value = 0, out = '';
  for (const byte of Buffer.from(buf)) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += B32_ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}
export function base32Decode(str) {
  let bits = 0, value = 0; const out = [];
  for (const ch of String(str).toUpperCase().replace(/=+$/, '').replace(/\s/g, '')) {
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}

/** RFC 6238 TOTP (SHA-1, 30s step, 6 digits) for MFA. */
export function generateTotpSecret() {
  return crypto.randomBytes(20); // 160-bit secret
}
export function hotp(secretBuf, counter, digits = 6) {
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 2 ** 32), 0);
  buf.writeUInt32BE(counter >>> 0, 4);
  const h = crypto.createHmac('sha1', secretBuf).update(buf).digest();
  const off = h[h.length - 1] & 0x0f;
  const code = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(code % 10 ** digits).padStart(digits, '0');
}
export function totpNow(secretBuf, { step = 30, digits = 6, atMs = Date.now() } = {}) {
  return hotp(secretBuf, Math.floor(atMs / 1000 / step), digits);
}
/** Verify TOTP with ±1 step window. Returns the matched counter (persist it as
 * the user's last-used counter) or null. Replay protection: counters at or
 * below `lastCounter` are rejected — a code that already succeeded can never
 * succeed again. */
export function verifyTotp(secretBuf, code, { step = 30, digits = 6, atMs = Date.now(), lastCounter = -Infinity } = {}) {
  if (!/^\d{6}$/.test(String(code))) return null;
  const counter = Math.floor(atMs / 1000 / step);
  for (const drift of [0, -1, 1]) {
    const c = counter + drift;
    if (c <= lastCounter) continue;
    if (hotp(secretBuf, c, digits) === String(code)) return c;
  }
  return null;
}
export function otpauthUrl(email, secretB32) {
  const label = encodeURIComponent(`Meridian:${email}`);
  return `otpauth://totp/${label}?secret=${secretB32}&issuer=Meridian&algorithm=SHA1&digits=6&period=30`;
}
