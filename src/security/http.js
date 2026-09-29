import crypto from 'node:crypto';

/** Token-bucket rate limiter (process-local). */
export class TokenBucket {
  constructor(capacity, refillPerSec) {
    this.capacity = capacity; this.refillPerSec = refillPerSec;
    this.tokens = capacity; this.last = Date.now();
  }
  tryTake(n = 1) {
    const now = Date.now();
    this.tokens = Math.min(this.capacity, this.tokens + ((now - this.last) / 1000) * this.refillPerSec);
    this.last = now;
    if (this.tokens >= n) { this.tokens -= n; return true; }
    return false;
  }
}

export class RateLimiter {
  constructor() { this.buckets = new Map(); }
  bucket(key, capacity, refillPerSec) {
    const id = `${key}:${capacity}:${refillPerSec}`;
    let b = this.buckets.get(id);
    if (!b) { b = new TokenBucket(capacity, refillPerSec); this.buckets.set(id, b); }
    return b;
  }
  allow(key, capacity, refillPerSec, n = 1) { return this.bucket(key, capacity, refillPerSec).tryTake(n); }
  sweep(maxAgeMs = 3600_000) {
    const cutoff = Date.now() - maxAgeMs;
    for (const [id, b] of this.buckets) if (b.last < cutoff) this.buckets.delete(id);
  }
}

/**
 * Parse a multipart/form-data body into fields and files.
 * @returns {{fields: Record<string,string>, files: Array<{name:string, filename:string, contentType:string, data:Buffer}>}}
 */
export function parseMultipart(buffer, contentType) {
  const m = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType || '');
  if (!m) throw new Error('missing multipart boundary');
  const boundary = `--${m[1] || m[2]}`;
  const bBoundary = Buffer.from(boundary);
  const fields = {};
  const files = [];
  let pos = buffer.indexOf(bBoundary);
  while (pos !== -1) {
    let start = pos + bBoundary.length;
    if (buffer.slice(start, start + 2).toString() === '\r\n') start += 2;
    else if (buffer.slice(start, start + 2).toString() === '--') break; // final boundary
    const headerEnd = buffer.indexOf('\r\n\r\n', start);
    if (headerEnd === -1) break;
    const headerBlock = buffer.slice(start, headerEnd).toString('utf8');
    const next = buffer.indexOf(bBoundary, headerEnd + 4);
    if (next === -1) break;
    let dataEnd = next - 2; // strip trailing \r\n before boundary
    if (dataEnd < headerEnd + 4) dataEnd = headerEnd + 4;
    const data = buffer.slice(headerEnd + 4, dataEnd);
    const cd = /content-disposition:\s*form-data;([^\r\n]*)/i.exec(headerBlock);
    const ct = /content-type:\s*([^\r\n;]+)/i.exec(headerBlock);
    if (cd) {
      const nameM = /name="([^"]*)"/i.exec(cd[1]);
      const fileM = /filename="([^"]*)"/i.exec(cd[1]);
      const name = nameM ? nameM[1] : 'field';
      if (fileM) {
        files.push({ name, filename: fileM[1], contentType: ct ? ct[1].trim().toLowerCase() : 'application/octet-stream', data });
      } else {
        fields[name] = data.toString('utf8');
      }
    }
    pos = next;
  }
  return { fields, files };
}

/** Sanitize a user-provided filename for storage (no traversal, no control chars). */
export function sanitizeFilename(name) {
  const base = String(name || 'file').split(/[\\/]/).pop();
  const clean = base.replace(/[\x00-\x1f\u007f]/g, '').replace(/[^A-Za-z0-9._ -]/g, '_').replace(/^\.+/, '').trim();
  return clean.slice(0, 120) || 'file';
}

/** Magic-byte sniffing for upload safety (defense-in-depth alongside allowlists). */
export function sniffMagic(buf) {
  const hex = Buffer.from(buf).subarray(0, 16).toString('hex').toUpperCase();
  const ascii = Buffer.from(buf).subarray(0, 8).toString('latin1');
  if (ascii.startsWith('%PDF-')) return { mime: 'application/pdf', ext: 'pdf' };
  if (hex.startsWith('89504E470D0A1A0A')) return { mime: 'image/png', ext: 'png' };
  if (hex.startsWith('FFD8FF')) return { mime: 'image/jpeg', ext: 'jpg' };
  if (hex.startsWith('504B0304') || hex.startsWith('504B0506')) return { mime: 'application/zip', ext: 'zip' };
  if (hex.startsWith('D0CF11E0A1B11AE1')) return { mime: 'application/x-ole-storage', ext: 'doc' };
  if (hex.startsWith('1F8B')) return { mime: 'application/gzip', ext: 'gz' };
  return null;
}

/** Redact a secret for safe display: keep a short prefix + fingerprint. */
export function redactSecret(secret) {
  const s = String(secret);
  const prefix = s.slice(0, 6);
  return `${prefix}…(${crypto.createHash('sha256').update(s).digest('hex').slice(0, 12)})`;
}

export const SECRET_PATTERNS = [
  { id: 'aws_access_key', pattern: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { id: 'aws_secret', pattern: /\baws[a-z_ ]{0,20}['"][0-9a-zA-Z\/+]{40}['"]/i },
  { id: 'github_token', pattern: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/ },
  { id: 'slack_token', pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { id: 'stripe_secret', pattern: /\b(sk|rk)_(live|test)_[A-Za-z0-9]{16,}\b/ },
  { id: 'google_api_key', pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/ },
  { id: 'private_key', pattern: /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { id: 'jwt', pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  { id: 'generic_api_key', pattern: /\b(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|passwd|password)\b['"\s:=]{1,4}['"][A-Za-z0-9+\/=_\-.,:;@#$%^&*()!~]{16,}['"]/i },
];

/** Scan text (e.g. fetched JS) for embedded secrets. Returns matches with redacted values. */
export function scanForSecrets(text) {
  const found = [];
  for (const { id, pattern } of SECRET_PATTERNS) {
    const flags = pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g';
    const re = new RegExp(pattern.source, flags);
    let m;
    while ((m = re.exec(text)) !== null) {
      const value = m[0].length > 400 ? m[0].slice(0, 400) : m[0];
      found.push({ kind: id, match: value.slice(0, 80), redacted: redactSecret(value), sha256: crypto.createHash('sha256').update(value).digest('hex'), index: m.index });
      if (found.length > 50) return found;
    }
  }
  return found;
}
