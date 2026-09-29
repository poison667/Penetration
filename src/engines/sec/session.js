import { URL } from 'node:url';
import { sha256 } from '#core/util';
import { forms } from '#lib/html';
import { ensureCrawled } from '#lib/crawl';

/** Engine: Session Management Assessment. */
export const sessionEngine = {
  key: 'sec_session',
  title: 'Session Management Assessment',
  async run(ctx) {
    await ensureCrawled(ctx, { maxPages: ctx.params?.max_pages || 6 });
    const start = ctx.asset.base_url || ctx.asset.identifier;
    const origin = new URL(start).origin;

    // Find login to obtain real session tokens
    let loginUrl = null, userField = 'username', passField = 'password', method = 'POST';
    const loginPage = await ctx.getOrFetch(new URL('/login', origin).toString());
    if (loginPage.res.ok && loginPage.dom) {
      const f = forms(loginPage.dom, loginPage.res.finalUrl).find((x) => x.fields.some((v) => v.type === 'password'));
      if (f) {
        loginUrl = f.action || loginPage.res.finalUrl;
        userField = f.fields.find((v) => /user|email|login|name/i.test(v.name || ''))?.name || userField;
        passField = f.fields.find((v) => v.type === 'password')?.name || passField;
        method = f.method === 'GET' ? 'GET' : 'POST';
      }
    }
    const creds = ctx.params?.test_username && ctx.params?.test_password
      ? { u: ctx.params.test_username, p: ctx.params.test_password }
      : null;

    // Collect session token samples (anonymous + authenticated)
    const samples = [];
    for (let i = 0; i < 8; i++) {
      const r = await ctx.fetch(start);
      const cookie = (r.setCookies || [])[0];
      if (cookie) samples.push(cookie);
    }
    let authedCookie = null;
    if (loginUrl && creds) {
      const login = await ctx.fetch(loginUrl, { method, headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ [userField]: creds.u, [passField]: creds.p }).toString() });
      const anon = samples[0]?.split('=')[1]?.split(';')[0];
      authedCookie = (login.setCookies || [])[0];
      const authed = authedCookie?.split('=')[1]?.split(';')[0];
      if (anon && authed) {
        // SES-011 rotation on login
        if (anon === authed) {
          ctx.report('SES-011', {
            severity: 'high', confidence: 'medium', target: ctx.asset.identifier, endpoint: loginUrl,
            facts: ['Session token value is identical before and after authentication.'],
            inference: ['Session id is not rotated at privilege change — session fixation is possible.'],
            evidence: [ctx.evidenceRaw('session', { anonymous_token_hash: sha256(anon).slice(0, 24), authenticated_token_hash: sha256(authed).slice(0, 24), equal: true }, 'Session token comparison across login')],
          });
        }
      }
    } else {
      ctx.log('info', 'authenticated session tests skipped (requires test credentials)');
    }

    // SES-010 entropy assessment (anonymous samples)
    const tokenValues = samples.map((c) => c.split('=')[1]?.split(';')[0]).filter(Boolean);
    ctx.metrics.session_tokens = { collected: tokenValues.length, lengths: tokenValues.map((t) => t.length) };
    if (tokenValues.length >= 4) {
      const uniq = new Set(tokenValues).size;
      const avgLen = tokenValues.reduce((a, t) => a + t.length, 0) / tokenValues.length;
      const charSets = tokenValues.map((t) => new Set(t).size);
      const avgCharset = charSets.reduce((a, b) => a + b, 0) / charSets.length;
      const entropyBits = avgLen * Math.log2(Math.max(2, avgCharset));
      const sequential = tokenValues.some((t, i) => i > 0 && t.length === tokenValues[i - 1].length && /^\d+$/.test(t) && Number(t) - Number(tokenValues[i - 1]) >= 0 && Number(t) - Number(tokenValues[i - 1]) < 100);
      const facts = [
        `Collected ${tokenValues.length} session tokens: ${uniq} unique.`,
        `Average token length: ${avgLen.toFixed(1)} chars; estimated entropy ≈ ${entropyBits.toFixed(0)} bits.`,
        sequential ? 'Consecutive numeric increments detected between tokens.' : 'No sequential pattern detected in the sample.',
      ];
      if (avgLen < 20 || entropyBits < 64 || sequential) {
        ctx.report('SES-010', {
          severity: avgLen < 16 || sequential ? 'high' : 'medium', confidence: 'medium', target: ctx.asset.identifier,
          facts,
          inference: ['Token randomness/length appears insufficient — tokens may be predictable (sample-based estimate, bounded confidence).'],
          evidence: [ctx.evidenceRaw('session', { token_hashes: tokenValues.map((t) => sha256(t).slice(0, 16)), lengths: tokenValues.map((t) => t.length) }, 'Session token entropy sample')],
        });
      }
    }

    // SES-001 tokens in URLs — crawl link graph
    const withToken = (ctx.state.crawl?.links || []).filter((l) => /[?&](sid|sessionid|session_id|token|auth|jsessionid|phpsessid)=/i.test(l.url));
    const pageUrlToken = ctx.pages.size && [...ctx.pages.keys()].some((u) => /[?&](sid|sessionid|jsessionid|phpsessid)=/i.test(u));
    if (withToken.length || pageUrlToken) {
      ctx.report('SES-001', {
        severity: 'high', confidence: 'medium', target: ctx.asset.identifier,
        facts: [`Session-token-like parameters appear in URLs: ${withToken.slice(0, 5).map((l) => l.url.slice(0, 120)).join(' ') || '(crawled page URLs)'}.`],
        inference: ['Session ids in URLs leak via history, referers and logs.'],
        evidence: [ctx.evidenceRaw('derived', { urls: withToken.slice(0, 20).map((l) => l.url) }, 'URLs carrying session-token parameters')],
      });
    }

    // SES-013 CSRF protections on forms
    const stateChangeForms = (ctx.state.crawl?.forms || []).filter((f) => (f.method || 'GET') === 'POST');
    const formSample = stateChangeForms.length ? stateChangeForms : [];
    const noCsrf = [];
    for (const f of formSample.slice(0, 10)) {
      const page = await ctx.getOrFetch(f.page || start);
      const tokenInForm = f.fields.some((x) => /csrf|_token|token|anticsrf/i.test(x.name || '')) || (page.res.bodyText.match(/name=["'][^"']*csrf[^"']*["']/i) || []).length > 0;
      if (!tokenInForm) noCsrf.push(f.action || f.page);
    }
    const sameSiteSession = samples.some((c) => /samesite/i.test(c));
    if (noCsrf.length && !sameSiteSession) {
      ctx.report('SES-013', {
        severity: 'medium', confidence: 'medium', target: ctx.asset.identifier,
        facts: [`${noCsrf.length} POST forms without a CSRF token field (e.g. ${noCsrf[0]}).`, 'Session cookie does not set SameSite.'],
        inference: ['State-changing forms lack CSRF defenses.'],
        evidence: [ctx.evidenceRaw('derived', { forms: noCsrf.slice(0, 10) }, 'POST forms without CSRF tokens')],
      });
    }

    // SES-014 clickjacking exposure (framing defenses)
    {
      const home = ctx.pages.get(start)?.res || (await ctx.fetch(start));
      const xfo = home.headers['x-frame-options']?.[0] || null;
      const csp = home.headers['content-security-policy']?.[0] || null;
      const frameAncestors = csp ? /frame-ancestors\s+[^;]+/i.exec(csp)?.[0] : null;
      if (!xfo && !frameAncestors) {
        ctx.report('SES-014', {
          severity: 'medium', confidence: 'confirmed', target: ctx.asset.identifier,
          facts: [`No X-Frame-Options header and no CSP frame-ancestors directive on ${home.finalUrl || start}.`],
          inference: ['The page can be framed by any site — clickjacking (UI redressing) attacks are viable.'],
          evidence: [ctx.evidenceFrom(home, 'Response without framing defenses')],
        });
      }
    }

    // Authenticated session lifecycle probes (require test credentials)
    if (loginUrl && creds && authedCookie) {
      const cookiePair = authedCookie.split(';')[0];
      const protectedUrl = new URL('/profile', origin).toString();

      // SES-008 session survives logout
      {
        const logout = await ctx.fetch(new URL('/logout', origin).toString(), { headers: { cookie: cookiePair }, method: 'GET', redirect: 'manual' });
        const after = await ctx.fetch(protectedUrl, { headers: { cookie: cookiePair } });
        const stillAuthed = after.status === 200 && !/login|sign in|password/i.test(after.bodyText.slice(0, 800));
        ctx.metrics.session_after_logout = { status: after.status, still_authed: stillAuthed };
        if (stillAuthed) {
          ctx.report('SES-008', {
            severity: 'high', confidence: 'confirmed', target: ctx.asset.identifier, endpoint: '/logout',
            facts: [`After logging out (request to /logout with the session cookie), the SAME session cookie still authorizes ${protectedUrl} (HTTP ${after.status}).`],
            inference: ['Logout does not invalidate the server-side session — stolen tokens remain valid after logout.'],
            evidence: [ctx.evidenceFrom(logout, 'Logout request'), ctx.evidenceFrom(after, 'Protected page accessible post-logout')],
          });
        }
      }

      // SES-009 unbounded simultaneous sessions
      {
        const login2 = await ctx.fetch(loginUrl, { method, headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ [userField]: creds.u, [passField]: creds.p }).toString() });
        const cookie2 = (login2.setCookies || [])[0]?.split(';')[0];
        if (cookie2 && cookie2 !== cookiePair) {
          const r1 = await ctx.fetch(protectedUrl, { headers: { cookie: cookiePair } });
          const r2 = await ctx.fetch(protectedUrl, { headers: { cookie: cookie2 } });
          const bothValid = r1.status === 200 && r2.status === 200;
          ctx.metrics.simultaneous_sessions = { both_valid: bothValid };
          if (bothValid) {
            ctx.report('SES-009', {
              severity: 'medium', confidence: 'confirmed', target: ctx.asset.identifier,
              facts: [`Two concurrent logins for the same account produced two distinct session tokens; both remain valid simultaneously (HTTP 200 on ${protectedUrl} for each).`],
              inference: ['Unbounded simultaneous sessions — account sharing and hijack persistence are harder to detect and terminate.'],
              evidence: [ctx.evidenceFrom(r1, 'First concurrent session'), ctx.evidenceFrom(r2, 'Second concurrent session')],
            });
          }
        }
      }

      // SES-012 session puzzling (pre-auth token reused post-auth)
      {
        const anonToken = samples[0]?.split(';')[0];
        if (anonToken && anonToken !== cookiePair) {
          const preAuth = await ctx.fetch(protectedUrl, { headers: { cookie: anonToken } });
          if (preAuth.status === 200 && !/login|sign in|password/i.test(preAuth.bodyText.slice(0, 800))) {
            ctx.report('SES-012', {
              severity: 'low', confidence: 'low', target: ctx.asset.identifier,
              facts: [`A token issued in the anonymous stage is accepted in the authenticated stage for ${protectedUrl}.`],
              inference: ['Multi-stage state reuse (session puzzling) can let pre-authentication state influence post-auth decisions.'],
              evidence: [ctx.evidenceFrom(preAuth, 'Pre-auth token accepted post-auth')],
            });
          }
        } else {
          ctx.log('info', 'session puzzling probe inconclusive: no distinct pre-authentication token was issued');
        }
      }
    }

    // SES-007 idle timeout (observable cookie lifetime)
    {
      const cookie = authedCookie || samples[0];
      const maxAge = /max-age\s*=\s*(\d+)/i.exec(cookie || '')?.[1] || null;
      const expires = /expires\s*=\s*([^;]+)/i.exec(cookie || '')?.[1] || null;
      ctx.metrics.session_cookie_lifetime = { max_age: maxAge, expires };
      if (cookie && !maxAge && !expires) {
        ctx.report('SES-007', {
          severity: 'low', confidence: 'low', target: ctx.asset.identifier,
          facts: ['The session cookie carries no Max-Age/Expires lifetime (browser-session cookie).'],
          inference: ['No idle/absolute timeout is enforced via cookie lifetime — server-side inactivity timeouts may still apply but are not observable from the outside.'],
          evidence: [ctx.evidenceRaw('session', { cookie_attributes: cookie.split(';').slice(1).map(s => s.trim()).filter(Boolean) }, 'Session cookie attributes')],
        });
      }
    }

    ctx.metrics.session_forms_checked = formSample.length;
  },
};
