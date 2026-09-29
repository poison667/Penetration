import { scanForSecrets } from '#sec/http';

/** Engine: Cryptography Assessment (client-side static analysis + transport). */
export const cryptoEngine = {
  key: 'sec_crypto',
  title: 'Cryptography Assessment',
  async run(ctx) {
    const start = ctx.asset.base_url || ctx.asset.identifier;
    const page = await ctx.getOrFetch(start);

    // CRP-007/CRP-002 hardcoded secrets & weak algorithms in all fetched JS+HTML
    const sources = [{ url: start, body: page.res.bodyText, type: page.res.contentType }];
    // fetch inline + external scripts discovered by crawl
    const scriptUrls = new Set();
    for (const s of ctx.state.crawl?.scripts || []) if (s.src) scriptUrls.add(s.src);
    for (const [url] of ctx.pages) {
      const p = ctx.pages.get(url);
      for (const m of (p?.res.bodyText || '').matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) {
        try { scriptUrls.add(new URL(m[1], url).toString()); } catch { /* skip */ }
      }
    }
    for (const su of [...scriptUrls].slice(0, 25)) {
      const r = await ctx.fetch(su);
      if (r.ok && /javascript|ecmascript/i.test(r.contentType)) sources.push({ url: su, body: r.bodyText, type: r.contentType });
    }

    for (const src of sources) {
      // secrets
      const found = scanForSecrets(src.body);
      if (found.length) {
        ctx.report('CRP-007', {
          severity: 'critical', confidence: found.some((f) => f.kind !== 'generic_api_key') ? 'high' : 'medium',
          endpoint: src.url, target: ctx.asset.identifier,
          facts: found.slice(0, 5).map((f) => `${f.kind} pattern present: ${f.redacted}`),
          inference: ['Secret-like values in client-delivered code are fully readable by every visitor — treat as compromised and rotate.'],
          evidence: [ctx.evidenceRaw('secret_scan', { source: src.url, found: found.map((f) => ({ kind: f.kind, redacted: f.redacted, sha256: f.sha256 })) }, `Secret scan of ${src.url}`)],
          affected: src.url,
        });
      }
      // weak algorithms
      const weak = [];
      if (/\bmd5\s*\(/i.test(src.body)) weak.push('MD5');
      if (/\bsha1\s*\(|sha-1/i.test(src.body)) weak.push('SHA-1');
      if (/CryptoJS\.(DES|RC4|MD5)/i.test(src.body)) weak.push('CryptoJS legacy cipher');
      if (weak.length) {
        ctx.report('CRP-002', {
          severity: 'medium', confidence: 'medium', endpoint: src.url, target: ctx.asset.identifier,
          facts: weak.map((w) => `Usage of weak algorithm ${w} detected in client code.`),
          inference: ['Weak primitives in client code (hashing, legacy ciphers) — verify purpose; replace with modern algorithms.'],
          evidence: [ctx.evidenceRaw('static_analysis', { source: src.url, weak: weak.map((f) => f.redacted || f) }, `Weak algorithm usage in ${src.url}`)],
        });
      }
      // CRP-005 weak randomness for tokens
      if (/Math\.random\s*\(\s*\)[^;]{0,80}(token|session|secret|password|key|nonce|otp)/i.test(src.body) || /(token|session|secret|password|nonce|otp)[^;]{0,80}Math\.random\s*\(\s*\)/i.test(src.body)) {
        ctx.report('CRP-005', {
          severity: 'high', confidence: 'medium', endpoint: src.url, target: ctx.asset.identifier,
          facts: ['Math.random() is used in proximity to token/session/secret generation.'],
          inference: ['Math.random is not cryptographically secure — predictable tokens.'],
          evidence: [ctx.evidenceRaw('static_analysis', { source: src.url, pattern: 'Math.random near token generation' }, `Weak randomness in ${src.url}`)],
        });
      }
      // CRP-006 tokens in web storage
      if (/localStorage\.setItem\s*\(\s*["'][^"']*(token|jwt|auth|secret|password)/i.test(src.body) || /sessionStorage\.setItem\s*\(\s*["'][^"']*(token|jwt|auth|secret)/i.test(src.body)) {
        ctx.report('CRP-006', {
          severity: 'high', confidence: 'medium', endpoint: src.url, target: ctx.asset.identifier,
          facts: ['Tokens are persisted to localStorage/sessionStorage in client code.'],
          inference: ['Web-stored tokens are readable by any XSS — prefer HttpOnly cookies.'],
          evidence: [ctx.evidenceRaw('static_analysis', { source: src.url, sink: 'web-storage' }, `Token storage in ${src.url}`)],
        });
      }
      // CRP-004 salting signals (static)
      if (/\bmd5\s*\(\s*\w+\s*\+\s*["'][^"']{0,4}["']\s*\)/i.test(src.body)) {
        ctx.report('CRP-004', { severity: 'medium', confidence: 'low', endpoint: src.url, target: ctx.asset.identifier, facts: ['Hash usage with short/constant salt-like string detected in client code.'], inference: ['Static short salts defeat rainbow-table resistance; use per-item random salts.'], evidence: [ctx.evidenceRaw('static_analysis', { source: src.url }, `Salt usage in ${src.url}`)] });
      }
      // CRP-003 incorrect usage: ECB / static IV
      if (/\bECB\b|mode:\s*["']?ecb/i.test(src.body) || /iv:\s*["'][0-9a-fA-F]{16,32}["']/i.test(src.body)) {
        ctx.report('CRP-003', { severity: 'medium', confidence: 'medium', endpoint: src.url, target: ctx.asset.identifier, facts: ['ECB mode or constant IV detected in client code.'], inference: ['Deterministic encryption leaks equality patterns; use random IVs with AEAD.'], evidence: [ctx.evidenceRaw('static_analysis', { source: src.url }, `Incorrect algorithm usage in ${src.url}`)] });
      }
    }

    // CRP-001 plaintext transport — if the target is HTTP and has password fields
    if (new URL(start).protocol === 'http:') {
      const login = await ctx.getOrFetch(new URL('/login', new URL(start).origin).toString());
      if (login.res.ok && /type=["']?password/i.test(login.res.bodyText)) {
        ctx.report('TLS-009', {
          severity: 'high', confidence: 'confirmed', endpoint: '/login', target: ctx.asset.identifier,
          facts: ['Login page with password field is served over plain HTTP.'],
          inference: ['Credentials are transmitted in cleartext — network observers can capture them.'],
          evidence: [ctx.evidenceFrom(login.res, 'Password form over HTTP')],
        });
        ctx.report('CRP-001', { severity: 'high', confidence: 'confirmed', endpoint: '/login', target: ctx.asset.identifier, facts: ['Sensitive data (credentials) transmitted unencrypted.'], inference: ['Enforce HTTPS for all authentication flows.'], evidence: [ctx.evidenceFrom(login.res, 'Credential transport over HTTP')] });
      }
    }
  },
};
