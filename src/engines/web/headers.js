import { parseCsp } from '#lib/csp';

/** Engine: HTTP security header & cookie audit (configuration checks). */
export const headersEngine = {
  key: 'headers',
  title: 'HTTP Security Header Audit',
  async run(ctx) {
    const start = ctx.asset.base_url || ctx.asset.identifier;
    const page = await ctx.getOrFetch(start);
    if (!page.res.ok) throw new Error(`cannot fetch start URL: ${page.res.error || page.res.status}`);
    const h = page.res.headers;
    const ev = () => ctx.evidenceFrom(page.res, `Response headers for ${page.res.finalUrl}`);
    const base = () => ({ endpoint: new URL(page.res.finalUrl).pathname, target: ctx.asset.identifier });

    // CSP (CFG-006)
    const cspRaw = h['content-security-policy']?.join('; ');
    if (!cspRaw) {
      ctx.report('CFG-006', { ...base(), severity: 'medium', confidence: 'confirmed', facts: ['No Content-Security-Policy header is present.'], inference: ['Without CSP the page has no defense-in-depth against XSS and content injection.'], evidence: [ev()] });
    } else {
      const issues = parseCsp(cspRaw);
      if (issues.length) {
        ctx.report('CFG-006', { ...base(), severity: 'medium', confidence: 'confirmed', facts: [`CSP present: "${cspRaw.slice(0, 300)}"`, ...issues.map((i) => i.fact)], inference: issues.map((i) => i.inference), evidence: [ev()] });
      }
    }

    // X-Frame-Options / frame-ancestors (CFG-007)
    const xfo = h['x-frame-options']?.[0];
    const hasFrameAncestors = /frame-ancestors/i.test(cspRaw || '');
    if (!xfo && !hasFrameAncestors) {
      ctx.report('CFG-007', { ...base(), severity: 'medium', confidence: 'confirmed', facts: ['Neither X-Frame-Options nor CSP frame-ancestors is set.'], inference: ['The page can be embedded in third-party frames (clickjacking exposure).'], evidence: [ev()] });
    }

    // HSTS (CFG-008) — only meaningful over HTTPS
    if (new URL(page.res.finalUrl).protocol === 'https:') {
      const hsts = h['strict-transport-security']?.[0];
      const maxAge = hsts ? parseInt(/max-age=(\d+)/i.exec(hsts)?.[1] || '0', 10) : 0;
      if (!hsts) {
        ctx.report('CFG-008', { ...base(), severity: 'medium', confidence: 'confirmed', facts: ['Strict-Transport-Security header is missing.'], inference: ['Users can be downgraded to HTTP (SSL-strip risk).'], evidence: [ev()] });
      } else if (maxAge < 15768000) {
        ctx.report('CFG-008', { ...base(), severity: 'low', confidence: 'confirmed', facts: [`HSTS max-age is ${maxAge} seconds (< 6 months).`], inference: ['A short max-age weakens downgrade protection.'], evidence: [ev()] });
      }
    }

    // X-Content-Type-Options (CFG-009)
    if (!h['x-content-type-options']) {
      ctx.report('CFG-009', { ...base(), severity: 'low', confidence: 'confirmed', facts: ['X-Content-Type-Options header is missing.'], inference: ['Browsers may MIME-sniff responses, enabling content-type confusion.'], evidence: [ev()] });
    }
    // Referrer-Policy (CFG-010)
    if (!h['referrer-policy']) {
      ctx.report('CFG-010', { ...base(), severity: 'low', confidence: 'confirmed', facts: ['Referrer-Policy header is missing.'], inference: ['Full URLs (incl. query strings) may leak to third parties via Referer.'], evidence: [ev()] });
    }
    // Permissions-Policy (CFG-011)
    if (!h['permissions-policy']) {
      ctx.report('CFG-011', { ...base(), severity: 'info', confidence: 'confirmed', facts: ['Permissions-Policy header is missing.'], inference: ['Powerful browser features are not explicitly restricted.'], evidence: [ev()] });
    }
    // COOP/COEP (CFG-012)
    if (!h['cross-origin-opener-policy']) {
      ctx.report('CFG-012', { ...base(), severity: 'info', confidence: 'confirmed', facts: ['Cross-Origin-Opener-Policy header is missing.'], inference: ['Cross-window attacks (e.g. XS-Leaks) are not mitigated.'], evidence: [ev()] });
    }

    // Cookie flags (SES-002/003/004) for session-looking cookies
    const isHttps = new URL(page.res.finalUrl).protocol === 'https:';
    for (const cookie of page.res.setCookies) {
      const name = cookie.split('=')[0];
      const isSessionCookie = /session|sid|auth|token|login|jsession|phpsess|csrf/i.test(name) && !/csrf/i.test(name) ? /session|sid|auth|token|login/i.test(name) : /sess|sid|token/i.test(name);
      if (!isSessionCookie) continue;
      const lower = cookie.toLowerCase();
      const facts = [`Cookie "${name}" set with attributes: ${cookie.slice(0, 200)}`];
      const missing = [];
      if (!lower.includes('httponly')) missing.push('HttpOnly');
      if (isHttps && !lower.includes('secure')) missing.push('Secure');
      if (!lower.includes('samesite')) missing.push('SameSite');
      if (missing.length) {
        ctx.report(missing.includes('Secure') && isHttps ? 'SES-002' : missing.includes('HttpOnly') ? 'SES-003' : 'SES-004', {
          ...base(), severity: missing.length > 1 ? 'high' : 'medium', confidence: 'confirmed', parameter: name,
          facts: [...facts, `Missing attributes: ${missing.join(', ')}.`],
          inference: ['Missing cookie hardening attributes expose the session token to theft (XSS for HttpOnly, network for Secure, CSRF for SameSite).'],
          evidence: [ev()], affected: `cookie:${name}`,
        });
      }
      // scope (SES-005) + expiration (SES-006)
      const domainMatch = /domain=([^;]+)/i.exec(cookie);
      if (domainMatch && domainMatch[1].trim().startsWith('.')) {
        ctx.report('SES-005', { ...base(), severity: 'low', confidence: 'confirmed', parameter: name, facts: [`Cookie "${name}" is scoped to parent domain "${domainMatch[1].trim()}" (all subdomains).`], inference: ['Broad domain scope shares the cookie with every subdomain — a compromise of any subdomain exposes it.'], evidence: [ev()] });
      }
      const maxAge = parseInt(/max-age=(\d+)/i.exec(cookie)?.[1] || '0', 10);
      const expires = /expires=/i.test(cookie);
      if (isSessionCookie && maxAge === 0 && !expires) {
        ctx.report('SES-006', { ...base(), severity: 'medium', confidence: 'medium', parameter: name, facts: [`Session cookie "${name}" has no Max-Age/Expires (browser-session cookie).`], inference: ['No server-enforced expiry may keep sessions alive long after inactivity (verify server-side timeout).'], evidence: [ev()] });
      }
    }

    // Cache-control on sensitive-ish responses (ATH-013 handled in auth engine too)
    ctx.metrics.header_audit = { url: page.res.finalUrl, checked: 12 };
  },
};
