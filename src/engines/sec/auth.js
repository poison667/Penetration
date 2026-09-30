import { URL } from 'node:url';
import { forms } from '#lib/html';
import { sha256 } from '#core/util';

/** Engine: Authentication Security Assessment. */
export const authEngine = {
  key: 'sec_auth',
  title: 'Authentication Security Assessment',
  async run(ctx) {
    const start = ctx.asset.base_url || ctx.asset.identifier;
    const origin = new URL(start).origin;
    const basePage = await ctx.getOrFetch(start);
    if (!basePage.res.ok) throw new Error(`cannot fetch start URL: ${basePage.res.error || basePage.res.status}`);

    // Discover login + reset forms from crawl or common paths
    const candidates = [];
    if (ctx.state.crawl) {
      for (const f of ctx.state.crawl.forms) if (/password/i.test(JSON.stringify(f.fields))) candidates.push(f);
    }
    if (!candidates.length) {
      for (const path of ['/login', '/signin', '/user/login', '/accounts/login/']) {
        const p = await ctx.getOrFetch(new URL(path, new URL(start).origin).toString());
        if (p.res.ok && p.dom) {
          for (const f of forms(p.dom, p.url)) if (f.fields.some((x) => (x.type || '').toLowerCase() === 'password')) candidates.push(f);
        }
      }
    }
    if (!candidates.length) {
      ctx.log('info', 'no login form discovered; authentication checks limited to signals');
      ctx.inventory.auth = { login_form_found: false };
    }
    const loginForm = candidates.find((f) => f.fields.some((x) => (x.type || '') === 'password'));
    ctx.inventory.auth = { login_form_found: !!loginForm, form: loginForm ? { action: loginForm.action, method: loginForm.method, fields: loginForm.fields.map((f) => ({ name: f.name, type: f.type })) } : null };

    if (loginForm) {
      const loginUrl = loginForm.action || start;
      const userField = loginForm.fields.find((f) => /user|email|login|account|name/i.test(f.name || ''))?.name || 'username';
      const passField = loginForm.fields.find((f) => (f.type || '') === 'password')?.name || 'password';
      const postLogin = (user, pass) => ctx.fetch(loginUrl, {
        method: loginForm.method === 'POST' ? 'POST' : 'GET',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ [userField]: user, [passField]: pass }).toString(),
      });

      // ATH-001 user enumeration via differential responses (3 random users vs known pattern)
      const knownUser = ctx.params?.test_username || 'admin';
      const randUser = `meridian_probe_${Math.random().toString(36).slice(2, 10)}`;
      const rKnown = await postLogin(knownUser, `WrongPass!${Date.now()}`);
      const rRand = await postLogin(randUser, `WrongPass!${Date.now()}`);
      ctx.metrics.auth_differential = {
        known_status: rKnown.status, rand_status: rRand.status,
        known_len: rKnown.bodyBytes, rand_len: rRand.bodyBytes,
        known_hash: sha256(rKnown.bodyText).slice(0, 16), rand_hash: sha256(rRand.bodyText).slice(0, 16),
      };
      const norm = (s) => String(s || '').replace(/\d+/g, 'N').replace(/\s+/g, ' ').trim();
      const differentBody = norm(rKnown.bodyText) !== norm(rRand.bodyText);
      if (rKnown.status !== rRand.status || differentBody) {
        ctx.report('ATH-001', {
          severity: 'medium', confidence: 'medium', endpoint: loginUrl, target: ctx.asset.identifier, parameter: userField,
          facts: [
            `Login with "${knownUser}" (wrong password): HTTP ${rKnown.status}, ${rKnown.bodyBytes} bytes.`,
            `Login with "${randUser}" (wrong password): HTTP ${rRand.status}, ${rRand.bodyBytes} bytes.`,
            'Responses differ for existing vs non-existing usernames.',
          ],
          inference: ['The endpoint reveals whether a username exists (account enumeration).'],
          evidence: [ctx.evidenceFrom(rKnown, `Login attempt with likely-existing user "${knownUser}"`), ctx.evidenceFrom(rRand, `Login attempt with random user "${randUser}"`)],
          affected: loginUrl,
        });
      }

      // ATH-003 bypass signals: blank password / auth-parameter tampering (non-destructive)
      const blank = await postLogin(knownUser, '');
      if (blank.ok && /dashboard|welcome|logout|my account/i.test(blank.bodyText)) {
        ctx.report('ATH-003', {
          severity: 'high', confidence: 'medium', endpoint: loginUrl, target: ctx.asset.identifier,
          facts: [`Login with empty password for "${knownUser}" returned HTTP ${blank.status} with authenticated-looking content.`],
          inference: ['Possible authentication bypass (verify manually).'],
          evidence: [ctx.evidenceFrom(blank, 'Empty-password authentication probe')],
        });
      }

      // ATH-004 brute-force / lockout: 6 rapid failures then observe
      if (ctx.profile !== 'passive') {
        let lastStatus = null; const statuses = [];
        for (let i = 0; i < 6; i++) {
          const r = await postLogin(randUser, `BruteForce!${i}`);
          statuses.push(r.status);
          lastStatus = r;
        }
        const throttled = statuses.some((s) => s === 429 || s === 403);
        const captchaNow = /captcha|recaptcha|hcaptcha/i.test(lastStatus.bodyText || '');
        if (!throttled && !captchaNow) {
          ctx.report('ATH-004', {
            severity: 'medium', confidence: 'medium', endpoint: loginUrl, target: ctx.asset.identifier,
            facts: [`Six consecutive failed logins produced statuses: ${statuses.join(', ')} — no 429/403 lockout observed.`, captchaNow ? 'A CAPTCHA appeared during the burst.' : 'No CAPTCHA was presented during the burst.'],
            inference: ['No brute-force protection was triggered after 6 failures (assessment is bounded and non-destructive).'],
            evidence: [ctx.evidenceFrom(lastStatus, 'Sixth failed login response')],
          });
        }
      }

      // ATH-005 password quality signals (client-side only; server enforcement unknown)
      const pwInput = loginForm.fields.find((f) => (f.type || '') === 'password');
      const facts = [];
      if (pwInput?.maxlength && Number(pwInput.maxlength) < 12) facts.push(`Password input limits length to ${pwInput.maxlength}.`);
      if (/pattern=/i.test(JSON.stringify(loginForm))) facts.push('Password input uses a restrictive pattern.');
      if (facts.length) {
        ctx.report('ATH-005', {
          severity: 'low', confidence: 'low', endpoint: loginUrl, target: ctx.asset.identifier,
          facts: [...facts, 'Server-side policy was not tested (would require account flows).'],
          inference: ['Client-side hints suggest possible password policy constraints; verify server enforcement.'],
          evidence: [ctx.evidenceFrom(basePage.res, 'Login form markup')],
        });
      }

      // ATH-007 autocomplete on password fields
      if (pwInput && (pwInput.autocomplete || '') === 'on') {
        ctx.report('ATH-007', { severity: 'low', confidence: 'confirmed', endpoint: loginUrl, target: ctx.asset.identifier, facts: [`Password field declares autocomplete="on".`], inference: ['Browsers will offer to persist credentials; use autocomplete="new-password" where inappropriate.'], evidence: [ctx.evidenceFrom(basePage.res, 'Login form markup')] });
      }
      // ATH-006 remember-me
      const remember = loginForm.fields.find((f) => /remember|keep me|stay/i.test(`${f.name} ${f.label || ''} ${f.id || ''}`));
      if (remember) {
        ctx.report('ATH-006', { severity: 'info', confidence: 'low', endpoint: loginUrl, target: ctx.asset.identifier, facts: [`Remember-me control "${remember.name}" present on login form.`], inference: ['Verify the implementation uses random rotating tokens with expiry (not raw credentials).'], evidence: [ctx.evidenceFrom(basePage.res, 'Login form markup')] });
      }
      // ATH-010 CAPTCHA presence
      if (!/recaptcha|hcaptcha|turnstile|captcha/i.test(basePage.res.bodyText)) {
        ctx.report('ATH-010', { severity: 'info', confidence: 'confirmed', endpoint: loginUrl, target: ctx.asset.identifier, facts: ['No CAPTCHA/anti-automation widget detected on the login page.'], inference: ['Credential stuffing is limited only by rate limiting (if present).'], evidence: [ctx.evidenceFrom(basePage.res, 'Login page markup')] });
      }
      // ATH-011 MFA presence
      if (!/otp|totp|two.factor|2fa|authenticator|passkey|webauthn/i.test(basePage.res.bodyText)) {
        ctx.report('ATH-011', { severity: 'info', confidence: 'confirmed', endpoint: loginUrl, target: ctx.asset.identifier, facts: ['No MFA mechanism detected on the login page.'], inference: ['Single-factor authentication only.'], evidence: [ctx.evidenceFrom(basePage.res, 'Login page markup')] });
      }

      // ATH-002 reset-flow enumeration (probe reset endpoint existence).
      // Use addresses actually discovered on the site (mailto links / page text) as the
      // "plausible account" side — a generic address cannot reveal an enumeration difference.
      const discoveredEmails = new Set();
      for (const source of [basePage, ...(ctx.state.crawl?.pages || []).map((p) => ({ res: { bodyText: (ctx.pages.get(p.url)?.res?.bodyText) || '' } }))]) {
        const text = source?.res?.bodyText || '';
        for (const m of text.matchAll(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi)) discoveredEmails.add(m[0].toLowerCase());
        if (discoveredEmails.size >= 5) break;
      }
      const knownCandidates = [...discoveredEmails, 'known-user@example.org'];
      const resetPaths = ['/forgot-password', '/password-reset', '/reset-password', '/account/forgot'];
      for (const rp of resetPaths) {
        const resetUrl = new URL(rp, new URL(start).origin).toString();
        const page = await ctx.getOrFetch(resetUrl);
        if (!page.res.ok || !page.dom) continue;
        const rf = forms(page.dom, resetUrl).find((f) => f.fields.some((x) => /email|user/i.test(x.name || '')));
        if (rf) {
          let ev1 = null, ev2 = null, differs = false, knownAddr = knownCandidates[0];
          for (const cand of knownCandidates.slice(0, 4)) {
            ev1 = await ctx.fetch(resetUrl, { method: rf.method === 'POST' ? 'POST' : 'GET', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ [rf.fields[0].name]: cand }).toString() });
            ev2 = await ctx.fetch(resetUrl, { method: rf.method === 'POST' ? 'POST' : 'GET', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ [rf.fields[0].name]: `nouser-${Date.now()}@example.org` }).toString() });
            if (ev1.status !== ev2.status || sha256(ev1.bodyText) !== sha256(ev2.bodyText)) { differs = true; knownAddr = cand; break; }
          }
          if (differs) {
            ctx.report('ATH-002', { severity: 'medium', confidence: 'medium', endpoint: resetUrl, target: ctx.asset.identifier, facts: [`Reset request for a discovered address (${knownAddr}): HTTP ${ev1.status}, ${ev1.bodyBytes}B.`, `Reset request for a random address: HTTP ${ev2.status}, ${ev2.bodyBytes}B.`, 'Responses differ — account existence is disclosed.'], inference: ['Password reset can be used to enumerate accounts.'], evidence: [ctx.evidenceFrom(ev1, 'Reset request: discovered account address'), ctx.evidenceFrom(ev2, 'Reset request: random address')] });
          }
          // ATH-008 reset token in URL (response analysis)
          if (/token=[A-Za-z0-9]{10,}/i.test(ev1.bodyText) && /<a\s+href=["'][^"']*token=/i.test(ev1.bodyText)) {
            ctx.report('ATH-008', { severity: 'high', confidence: 'medium', endpoint: resetUrl, target: ctx.asset.identifier, facts: ['Reset response contains a tokenized link (token visible in page/HTML).'], inference: ['If this page is user-visible, reset tokens leak via URL/history/referrer.'], evidence: [ctx.evidenceFrom(ev1, 'Reset response containing token link')] });
          }
        }
        break; // first matching reset form is enough
      }

      // ATH-014 default credentials (intrusive profile only, authorized)
      if (ctx.profile === 'intrusive') {
        for (const [u, p] of [['admin', 'admin'], ['admin', 'password'], ['root', 'root']]) {
          const r = await postLogin(u, p);
          if (r.ok && /dashboard|welcome|logout|profile/i.test(r.bodyText) && !/invalid|wrong|error|failed/i.test(r.bodyText.slice(0, 2000))) {
            ctx.report('ATH-014', { severity: 'high', confidence: 'low', endpoint: loginUrl, target: ctx.asset.identifier, facts: [`Login with default credentials ${u}/${p} returned HTTP ${r.status} with authenticated-looking content.`], inference: ['Default credentials appear functional — verify manually before remediation (confidence: low to avoid false positives).'], evidence: [ctx.evidenceFrom(r, `Default credential attempt ${u}`)] });
            break;
          }
        }
      } else {
        ctx.log('info', 'default-credential probes skipped (requires intrusive profile)');
      }

      // ATH-012 logout invalidation — needs test credentials
      if (ctx.params?.test_username && ctx.params?.test_password) {
        const login = await postLogin(ctx.params.test_username, ctx.params.test_password);
        const cookies = (login.setCookies || []).map((c) => c.split(';')[0]).join('; ');
        if (cookies) {
          const protectedPage = await ctx.fetch(start, { headers: { cookie: cookies } });
          const startUrl = new URL(start).origin;
          const logout = await ctx.fetch(new URL('/logout', startUrl).toString(), { headers: { cookie: cookies } });
          const replay = await ctx.fetch(start, { headers: { cookie: cookies } });
          const authed = (res) => /logout|profile|dashboard|welcome/i.test(res.bodyText || '');
          if (authed(protectedPage) && authed(replay)) {
            ctx.report('ATH-012', { severity: 'high', confidence: 'medium', target: ctx.asset.identifier, endpoint: '/logout', facts: ['Session cookie remained valid after requesting /logout (protected page still shows authenticated content).'], inference: ['Logout does not invalidate the server-side session.'], evidence: [ctx.evidenceFrom(login, 'Login establishing session'), ctx.evidenceFrom(logout, 'Logout request'), ctx.evidenceFrom(replay, 'Post-logout replay of protected page')] });
          }
        }
      } else {
        ctx.log('info', 'logout-invalidation test skipped (requires test credentials)');
      }
    }

    // ATH-013 cache control on auth pages
    if (loginForm || /login/i.test(basePage.res.finalUrl)) {
      const cc = basePage.res.headers['cache-control']?.[0];
      if (!cc || !/no-store|no-cache/i.test(cc)) {
        ctx.report('ATH-013', { severity: 'low', confidence: 'confirmed', endpoint: new URL(basePage.res.finalUrl).pathname, target: ctx.asset.identifier, facts: [`Authentication-relevant page served with Cache-Control: ${cc || '(none)'}.`], inference: ['Shared caches/proxies may retain authenticated content.'], evidence: [ctx.evidenceFrom(basePage.res, 'Cache-control on auth page')] });
      }
    }
    // ATH-016 SSO inventory (assisted)
    // ATH-009: password change re-authentication (assisted — needs a change-password surface + creds)
    if (ctx.params?.test_username && ctx.params?.test_password && loginForm) {
      const cpPaths = ['/change-password', '/password/change', '/account/password', '/settings/password'];
      for (const cp of cpPaths) {
        const cpUrl = new URL(cp, origin).toString();
        const page = await ctx.getOrFetch(cpUrl);
        const hasForm = page.res.ok && page.dom && /<form/i.test(page.res.bodyText);
        if (!hasForm) continue;
        const userField = loginForm.fields.find((f) => /user|email|login|account|name/i.test(f.name || ''))?.name || 'username';
        const passField = loginForm.fields.find((f) => (f.type || '') === 'password')?.name || 'password';
        const login = await ctx.fetch(loginForm.action || start, {
          method: loginForm.method === 'POST' ? 'POST' : 'GET',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ [userField]: ctx.params.test_username, [passField]: ctx.params.test_password }).toString(),
        });
        const cookie = (login.setCookies || [])[0]?.split(';')[0];
        if (!cookie) break;
        // attempt WITHOUT the current password — only the new one
        const attempt = await ctx.fetch(cpUrl, {
          method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
          body: new URLSearchParams({ new_password: 'Mrpd!NewPass1', password_confirm: 'Mrpd!NewPass1', password1: 'Mrpd!NewPass1', password2: 'Mrpd!NewPass1' }).toString(),
        });
        const accepted = attempt.status >= 200 && attempt.status < 300 && !/current password|old password|incorrect|error|invalid/i.test(attempt.bodyText.slice(0, 1500));
        ctx.metrics.password_change_without_current = { path: cp, status: attempt.status, accepted };
        if (accepted) {
          ctx.report('ATH-009', {
            severity: 'medium', confidence: 'medium', endpoint: cp, target: ctx.asset.identifier,
            facts: [`A POST to ${cp} with only a NEW password (no current-password field) was accepted (HTTP ${attempt.status}).`],
            inference: ['Password change does not require re-authentication — a hijacked session or XSS can silently take over the account.'],
            evidence: [ctx.evidenceFrom(attempt, 'Password change accepted without current password')],
          });
        }
        break;
      }
    }

    // ATH-015: authentication history / new-login notifications (assisted)
    {
      const histPaths = ['/login-history', '/security', '/account/security', '/notifications', '/activity'];
      let found = false;
      for (const hp of histPaths) {
        const r = await ctx.fetch(new URL(hp, origin).toString());
        if (r.status === 200 && /login history|recent activity|security events|sign-in history|new sign-in/i.test(r.bodyText)) { found = true; break; }
      }
      ctx.metrics.auth_history_surface = found;
      if (!found) {
        ctx.report('ATH-015', {
          severity: 'info', confidence: 'low', target: ctx.asset.identifier,
          facts: [`No authentication history / login-activity surface was found at common paths (${histPaths.join(', ')}).`],
          inference: ['Users cannot self-detect account compromise; new-login notifications were not observed.'],
          evidence: [ctx.evidenceRaw('derived', { paths_probed: histPaths, found: false }, 'Authentication history surface probe')],
        });
      }
    }

    const ssoHints = [];
    for (const [label, re] of [['SAML', /saml|samlrequest/i], ['OAuth/OIDC', /oauth|openid|\.well-known\/openid/i], ['Social login', /accounts\.google\.com|facebook\.com\/login|login\.microsoftonline/i]]) {
      if (re.test(basePage.res.bodyText)) ssoHints.push(label);
    }
    ctx.inventory.auth.sso = ssoHints;
    if (ssoHints.length) {
      ctx.report('ATH-016', { severity: 'info', confidence: 'low', target: ctx.asset.identifier, facts: [`SSO mechanisms detected: ${ssoHints.join(', ')}.`], inference: ['Verify session lifetimes and single-logout propagation across SSO-integrated apps.'], evidence: [ctx.evidenceFrom(basePage.res, 'SSO references on entry page')] });
    }
  },
};
