import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import { URL } from 'node:url';
import crypto from 'node:crypto';
import { TokenBucket } from '#sec/http';
import { assertFetchAllowed } from '#sec/net';

/**
 * Engine HTTP client. Every request:
 *  - is SSRF-validated per hop (scheme, DNS, private/reserved ranges)
 *  - is rate-limited per host (token bucket)
 *  - has timeouts and a response size cap
 *  - produces an evidence-shaped capture (request line, headers, excerpt, sha256)
 * Redirects are followed manually and re-validated.
 */
export class Fetcher {
  constructor(opts = {}) {
    this.allowPrivate = !!opts.allowPrivate;
    this.perHostRps = opts.perHostRps ?? 5;
    this.timeoutMs = opts.timeoutMs ?? 10_000;
    this.maxBytes = opts.maxBytes ?? 2_000_000;
    this.maxRedirects = opts.maxRedirects ?? 5;
    this.userAgent = opts.userAgent ?? 'Meridian-AuditBot/1.0 (+authorized-assessment; contact: platform-admin)';
    this.buckets = new Map();
    this.requestCount = 0;
  }
  #bucket(host) {
    let b = this.buckets.get(host);
    if (!b) { b = new TokenBucket(Math.max(2, this.perHostRps), this.perHostRps); this.buckets.set(host, b); }
    return b;
  }

  async fetch(url, opts = {}) {
    const start = Date.now();
    const hops = [];
    let current = url;
    for (let hop = 0; hop <= this.maxRedirects; hop++) {
      let target;
      try { target = await assertFetchAllowed(current, { allowPrivate: opts.allowPrivate ?? this.allowPrivate }); }
      catch (e) { return this.#err(url, start, hops, e, 'ssrf_blocked'); }
      const host = target.url.hostname;
      if (!this.#bucket(host).tryTake()) {
        // wait for bucket refill (bounded) — keeps scans polite
        await new Promise((r) => setTimeout(r, Math.min(2000, 1000 / this.perHostRps)));
        this.#bucket(host).tryTake();
      }
      const res = await this.#requestOnce(target.url, opts, host);
      this.requestCount++;
      const isRedirect = [301, 302, 303, 307, 308].includes(res.status);
      if (isRedirect && !opts.noRedirect) {
        const loc = res.headers['location']?.[0];
        hops.push({ url: current, status: res.status, location: loc || null });
        if (!loc) return this.#ok(current, res, hops, start, url, false);
        try { current = new URL(loc, current).toString(); } catch { return this.#ok(current, res, hops, start, url, false); }
        continue;
      }
      return this.#ok(current, res, hops, start, url, false);
    }
    return this.#err(url, start, hops, new Error('too many redirects'), 'too_many_redirects');
  }

  #ok(finalUrl, res, hops, start, requestedUrl) {
    const headers = {};
    for (const [k, v] of Object.entries(res.headers)) headers[k] = Array.isArray(v) ? v : v;
    const bodyBuf = res.body || Buffer.alloc(0);
    return {
      ok: res.status >= 200 && res.status < 400,
      requestedUrl, finalUrl,
      status: res.status, statusText: res.statusText || '',
      headers,
      setCookies: res.headers['set-cookie'] || [],
      contentType: String(res.headers['content-type']?.[0] || ''),
      bodyText: bodyBuf.toString('utf8'),
      bodyBytes: res.bodyBytes,
      bodySha256: res.bodySha256,
      truncated: res.truncated,
      ttfbMs: res.ttfbMs, totalMs: Date.now() - start,
      redirects: hops, hops: hops.length,
      error: null,
    };
  }
  #err(url, start, hops, e, code) {
    return {
      ok: false, requestedUrl: url, finalUrl: url, status: 0, statusText: '',
      headers: {}, setCookies: [], contentType: '', bodyText: '', bodyBytes: 0,
      bodySha256: null, truncated: false, ttfbMs: null, totalMs: Date.now() - start,
      redirects: hops, hops: hops.length, error: String(e.message || e), errorCode: code || 'network_error',
    };
  }

  #requestOnce(u, opts, host) {
    return new Promise((resolve) => {
      const isHttps = u.protocol === 'https:';
      const mod = isHttps ? https : http;
      const started = Date.now();
      const reqOpts = {
        method: opts.method || 'GET',
        hostname: u.hostname.replace(/^\[|\]$/g, ''),
        port: u.port || (isHttps ? 443 : 80),
        path: u.pathname + u.search,
        headers: {
          'user-agent': opts.userAgent || this.userAgent,
          accept: opts.accept || 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'accept-language': 'en;q=0.8',
          ...normalizeHeaders(opts.headers || {}),
        },
        timeout: this.timeoutMs,
      };
      if (isHttps) { reqOpts.rejectUnauthorized = false; reqOpts.servername = u.hostname; }
      let body = null;
      if (opts.body != null) {
        body = Buffer.isBuffer(opts.body) ? opts.body : Buffer.from(String(opts.body));
        if (!reqOpts.headers['content-type']) reqOpts.headers['content-type'] = 'application/x-www-form-urlencoded';
        reqOpts.headers['content-length'] = body.length;
      }
      const req = mod.request(reqOpts, (res) => {
        const ttfbMs = Date.now() - started;
        const chunks = [];
        let size = 0; let truncated = false;
        res.on('data', (c) => {
          if (size + c.length <= this.maxBytes) { chunks.push(c); size += c.length; }
          else { truncated = true; res.destroy(); }
        });
        res.on('end', () => finish(false));
        res.on('close', () => finish(false));
        res.on('error', () => finish(true));
        let done = false;
        function finish(errored) {
          if (done) return; done = true;
          const bodyBuf = Buffer.concat(chunks);
          resolve({
            status: res.statusCode, statusText: res.statusMessage || '',
            headers: groupHeaders(res.headers),
            body: bodyBuf, bodyBytes: size, bodySha256: crypto.createHash('sha256').update(bodyBuf).digest('hex'),
            truncated, ttfbMs, errored,
          });
        }
      });
      req.on('timeout', () => { req.destroy(new Error('timeout')); });
      req.on('error', (e) => resolve({ status: 0, statusText: '', headers: {}, body: Buffer.alloc(0), bodyBytes: 0, bodySha256: null, truncated: false, ttfbMs: null, errored: true, error: e.message }));
      if (body) req.write(body);
      req.end();
    });
  }

  /** TLS handshake probe with version/cipher constraints (audit mode: inspect even invalid certs). */
  tlsProbe(host, port, { minVersion, maxVersion, ciphers, servername, timeoutMs = 8000 } = {}) {
    return new Promise((resolve) => {
      const started = Date.now();
      const socket = tls.connect({
        host, port: Number(port) || 443,
        servername: servername || host,
        rejectUnauthorized: false,
        ...(minVersion ? { minVersion } : {}),
        ...(maxVersion ? { maxVersion } : {}),
        ...(ciphers ? { ciphers } : {}),
        ALPNProtocols: ['h2', 'http/1.1'],
      }, () => {
        try {
          const cert = socket.getPeerCertificate(true);
          const chain = [];
          let c = cert;
          for (let i = 0; i < 5 && c && Object.keys(c).length; i++) {
            chain.push(summarizeCert(c));
            c = c.issuerCertificate && c.issuerCertificate !== c ? c.issuerCertificate : null;
          }
          const out = {
            ok: true, host, port,
            protocol: socket.getProtocol(),
            alpn: socket.alpnProtocol || null,
            cipher: socket.getCipher() || null,
            authorized: socket.authorized,
            authorizationError: socket.authorized ? null : String(socket.authorizationError?.message || socket.authorizationError || ''),
            cert: chain[0] || null, chain,
            latencyMs: Date.now() - started,
          };
          socket.end();
          resolve(out);
        } catch (e) { socket.destroy(); resolve({ ok: false, host, port, error: String(e.message || e) }); }
      });
      socket.setTimeout(timeoutMs, () => { socket.destroy(); resolve({ ok: false, host, port, error: 'timeout' }); });
      socket.on('error', (e) => resolve({ ok: false, host, port, error: String(e.message || e), code: e.code }));
    });
  }
}

function normalizeHeaders(h) {
  const out = {};
  for (const [k, v] of Object.entries(h)) out[k.toLowerCase()] = v;
  return out;
}
function groupHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers)) out[k.toLowerCase()] = Array.isArray(v) ? v : [String(v)];
  return out;
}
function summarizeCert(cert) {
  if (!cert || !Object.keys(cert).length) return null;
  return {
    subject: cert.subject || null,
    issuer: cert.issuer || null,
    subjectaltname: cert.subjectaltname || null,
    valid_from: cert.valid_from || null,
    valid_to: cert.valid_to || null,
    valid_to_ts: cert.valid_to ? Date.parse(cert.valid_to) : null,
    sigAlgorithm: cert.sig_alg || null,
    fingerprint256: cert.fingerprint256 || null,
    serialNumber: cert.serialNumber || null,
    bits: cert.bits || null,
    issuerCN: cert.issuer?.CN || null,
    subjectCN: cert.subject?.CN || null,
  };
}

/** Evidence capture helper — turns a fetch result into an evidence record body. */
export function fetchEvidence(res, { excerptBytes = 2048 } = {}) {
  return {
    kind: 'http_exchange',
    request: { method: res.requestedMethod || 'GET', url: res.requestedUrl, final_url: res.finalUrl },
    response: {
      status: res.status,
      headers: res.headers,
      set_cookie: res.setCookies,
      content_type: res.contentType,
      body_bytes: res.bodyBytes,
      body_sha256: res.bodySha256,
      body_excerpt: res.bodyText.slice(0, excerptBytes),
      timing: { ttfb_ms: res.ttfbMs, total_ms: res.totalMs },
      redirects: res.redirects,
    },
    error: res.error,
  };
}
