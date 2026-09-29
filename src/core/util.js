import crypto from 'node:crypto';

/** sha256 hex of string or buffer */
export function sha256(input) {
  return crypto.createHash('sha256').update(typeof input === 'string' ? input : Buffer.from(input)).digest('hex');
}
export function hmacSha256(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest('hex');
}
export function bytesToHex(buf) { return Buffer.from(buf).toString('hex'); }

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function base32Encode(buf) {
  const b = Buffer.from(buf); let bits = 0, value = 0, out = '';
  for (const byte of b) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}
export function base32Decode(s) {
  let bits = 0, value = 0; const out = [];
  for (const ch of s.toUpperCase().replace(/=+$/, '').replace(/\s/g, '')) {
    const idx = B32.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}

const ID_ALPHABET = 'abcdefghjkmnpqrstvwxyz23456789';
/** collision-resistant prefixed id, e.g. job_m3xk9... */
export function newId(prefix) {
  const bytes = crypto.randomBytes(16);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += ID_ALPHABET[bytes[i] % ID_ALPHABET.length];
  return `${prefix}_${s}`;
}
export function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

export function nowIso() { return new Date().toISOString(); }
export function epochMs() { return Date.now(); }
export function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
export function clamp(n, min, max) { return Math.min(max, Math.max(min, n)); }

/** stable stringify (sorted keys) for hashing/serialization */
export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(value[k] ?? null)).join(',') + '}';
}

export function truncateStr(s, n = 2000) {
  const str = String(s ?? '');
  return str.length <= n ? str : str.slice(0, n) + `…[truncated ${str.length - n} chars]`;
}
export function pick(obj, keys) {
  const out = {};
  for (const k of keys) if (obj && Object.prototype.hasOwnProperty.call(obj, k)) out[k] = obj[k];
  return out;
}
export function omit(obj, keys) {
  const out = { ...obj };
  for (const k of keys) delete out[k];
  return out;
}
export function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}
/** deep get by dot/bracket path: a.b[0].c */
export function deepGet(obj, path) {
  let cur = obj;
  for (const part of String(path).split('.')) {
    if (cur == null) return undefined;
    const m = part.match(/^(.+)\[(\d+)\]$/);
    if (m) cur = cur[m[1]]?.[Number(m[2])];
    else cur = cur[part];
  }
  return cur;
}
export function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
export function formatBytes(n) {
  if (n == null) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}
export function formatDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return `${d.toISOString().slice(0, 10)} ${d.toISOString().slice(11, 19)}Z`;
}
export function chunk(arr, n) {
  const out = [];
  for (let i = 0; i < arr.length; i += n) out.push(arr.slice(i, i + n));
  return out;
}
/** median of numbers */
export function mean(nums) { return nums.length ? nums.reduce((a, b) => a + b, 0) / nums.length : 0; }
export function median(nums) {
  if (!nums.length) return null;
  const s = [...nums].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}
export function percentile(nums, p) {
  if (!nums.length) return null;
  const s = [...nums].sort((a, b) => a - b);
  const idx = clamp(Math.ceil((p / 100) * s.length) - 1, 0, s.length - 1);
  return s[idx];
}
export function stddev(nums) {
  if (nums.length < 2) return 0;
  const mean = nums.reduce((a, b) => a + b, 0) / nums.length;
  return Math.sqrt(nums.reduce((a, b) => a + (b - mean) ** 2, 0) / (nums.length - 1));
}
