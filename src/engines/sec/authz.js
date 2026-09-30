import { URL } from 'node:url';
import { forms } from '#lib/html';
import { ensureCrawled } from '#lib/crawl';

/** Engine: Authorization Testing. */
export const authzEngine = {
  key: 'sec_authz',
  title: 'Authorization Testing',
  async run(ctx) {
    await ensureCrawled(ctx, { maxPages: ctx.params?.max_pages || 6 });
    const start = ctx.asset.base_url || ctx.asset.identifier;
    const origin = new URL(start).origin;
    const creds = ctx.params?.test_username && ctx.params?.test_password ? { u: ctx.params.test_username, p: ctx.params.test_password } : null;

    // AUT-001 path traversal on parameters (read-only signatures)
    // Rank candidates: exact keyword names first, then keyword-prefixed (file_x), then
    // loose substrings last — otherwise fields like "username" (ends with "name") or
    // "xml_document" (contains "doc") starve the probe budget before real file params.
    const KEYWORDS = /^(file|path|page|include|name|doc|template|filename|filepath|docpath|page_id|file_id)$/i;
    const score = (n) => (KEYWORDS.test(n) ? 0 : /^(file|path|page|doc|template|include)[_-]/i.test(n) || /[-_](file|path|page|doc|template)$/i.test(n) ? 1 : 2);
    const traversalParams = [];
    for (const f of ctx.state.crawl?.forms || []) {
      for (const field of f.fields) if (/file|path|page|include|name|doc|template/i.test(field.name || '')) traversalParams.push({ f, field, rank: score(field.name || '') });
    }
    traversalParams.sort((a, b) => a.rank - b.rank);
    for (const t of traversalParams.slice(0, 6)) {
      const payload = '../../../../etc/passwd';
      const r = t.f.method === 'POST'
        ? await ctx.fetch(t.f.action, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ [t.field.name]: payload }).toString() })
        : await ctx.fetch(`${t.f.action}?${encodeURIComponent(t.field.name)}=${encodeURIComponent(payload)}`);
      if (r.ok && /root:x:0:0|daemon:\/usr\/sbin/.test(r.bodyText)) {
        ctx.report('AUT-001', { severity: 'high', confidence: 'confirmed', endpoint: t.f.action, parameter: t.field.name, target: ctx.asset.identifier, facts: [`Traversal payload in "${t.field.name}" returned passwd-file content.`], inference: ['Filesystem access is not confined — path traversal confirmed.'], evidence: [ctx.evidenceFrom(r, 'passwd content via traversal')] });
      }
    }

    // AUT-002 unauthenticated access to protected resources
    const protectedPaths = ['/admin', '/dashboard', '/profile', '/account', '/user', '/settings', '/api/user', '/api/me'];
    for (const path of protectedPaths) {
      const res = await ctx.fetch(new URL(path, origin).toString());
      const body = res.bodyText;
      const looksAuthed = res.status === 200 && (/<form[^>]*password/i.test(body) ? false : /logout|my account|profile|dashboard|welcome back|settings/i.test(body) && !/login|sign in|password/i.test(body.slice(0, 1500)));
      if (looksAuthed) {
        ctx.report('AUT-002', {
          severity: 'high', confidence: 'medium', endpoint: path, target: ctx.asset.identifier,
          facts: [`GET ${path} without credentials returned HTTP 200 with authenticated-content markers and no login form.`],
          inference: ['The endpoint may be accessible without authorization (manual verification recommended).'],
          evidence: [ctx.evidenceFrom(res, `Unauthenticated access probe on ${path}`)],
        });
      }
    }

    if (!creds) {
      ctx.log('info', 'credential-based authorization tests (IDOR/vertical) skipped — provide test_username/test_password');
      ctx.inventory.authz = { credential_tests: 'skipped_no_credentials' };
      return;
    }

    // Login and obtain a session
    const loginPage = await ctx.getOrFetch(new URL('/login', origin).toString());
    let cookie = null;
    if (loginPage.res.ok && loginPage.dom) {
      const f = forms(loginPage.dom, loginPage.res.finalUrl).find((x) => x.fields.some((v) => v.type === 'password'));
      if (f) {
        const userField = f.fields.find((v) => /user|email|login|name/i.test(v.name || ''))?.name || 'username';
        const passField = f.fields.find((v) => v.type === 'password')?.name || 'password';
        const login = await ctx.fetch(f.action || loginPage.res.finalUrl, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ [userField]: creds.u, [passField]: creds.p }).toString() });
        cookie = (login.setCookies || []).map((c) => c.split(';')[0]).join('; ') || null;
        if (!cookie) {
          // maybe the session cookie was set on a prior request
          ctx.log('warn', 'login did not yield a session cookie; credential-based authz tests limited');
        }
      }
    }
    if (!cookie) { ctx.inventory.authz = { credential_tests: 'login_failed' }; return; }
    const authHeaders = { cookie };

    // AUT-004/006 IDOR: numeric object ids on profile-ish endpoints
    const idEndpoints = ['/profile', '/account', '/user', '/api/user'];
    for (const path of idEndpoints) {
      const marker = (s) => (s.match(/user[_ -]?(id|name)\s*[:=]\s*["']?(\w+)/i) || [])[2];
      outer: for (const id of [1, 2]) {
        const u = new URL(`${path}?id=${id}`, origin).toString();
        const own = await ctx.fetch(u, { headers: authHeaders });
        if (!own.ok) continue;
        for (const otherId of [id + 1, id + 2, id + 10]) {
          const other = await ctx.fetch(new URL(`${path}?id=${otherId}`, origin).toString(), { headers: authHeaders });
          if (other.ok && marker(other.bodyText) && marker(other.bodyText) !== marker(own.bodyText)) {
            ctx.report('AUT-004', {
              severity: 'high', confidence: 'confirmed', endpoint: `${path}?id=${otherId}`, parameter: 'id', target: ctx.asset.identifier,
              facts: [`Authenticated as test account; ${path}?id=${id} shows data for "${marker(own.bodyText)}".`, `${path}?id=${otherId} returns data for a different account "${marker(other.bodyText)}" (HTTP ${other.status}).`],
              inference: ['Object-level authorization is missing — horizontal privilege escalation (IDOR) confirmed.'],
              reproduction: { steps: [`Authenticate with the test account`, `Request ${path}?id=${otherId} and observe another user\'s data`] },
              evidence: [ctx.evidenceFrom(own, `Own record (${path}?id=${id})`), ctx.evidenceFrom(other, `Other user record (${path}?id=${otherId})`)],
            });
            ctx.report('AUT-005', { severity: 'high', confidence: 'confirmed', endpoint: `${path}?id=${otherId}`, parameter: 'id', target: ctx.asset.identifier, facts: [`Endpoint returns object data without verifying the requesting user owns it.`], inference: ['Missing object-level authorization.'], evidence: [ctx.evidenceFrom(other, 'Object access without ownership check')] });
            break outer;
          }
        }
      }
    }

    // AUT-006: direct object references in use (passive inventory)
    if (ctx.state.crawl) {
      const dorLinks = ctx.state.crawl.links
        .map((l) => l.url)
        .filter((u) => /[?&](id|uid|user|account|order|doc|file)=\d+|\/\d{2,}(?=[/?#]|$)/.test(u))
        .slice(0, 20);
      if (dorLinks.length) {
        ctx.report('AUT-006', {
          severity: 'info', confidence: 'confirmed', target: ctx.asset.identifier,
          facts: [`${dorLinks.length} URLs reference objects by direct (sequential) identifiers, e.g. ${dorLinks.slice(0, 3).join(', ')}.`],
          inference: ['Direct object references are not inherently a flaw, but each requires an object-level authorization check (see AUT-004/AUT-005 tests).'],
          evidence: [ctx.evidenceRaw('derived', { urls: dorLinks }, 'Direct object reference inventory')],
        });
      }
    }

    // AUT-003 vertical privilege escalation: admin paths with regular session
    for (const path of ['/admin', '/admin/users', '/administrator']) {
      const res = await ctx.fetch(new URL(path, origin).toString(), { headers: authHeaders });
      if (res.status === 200 && /admin (panel|dashboard)|users list|manage/i.test(res.bodyText) && !/login|password/i.test(res.bodyText.slice(0, 1000))) {
        ctx.report('AUT-003', { severity: 'critical', confidence: 'medium', endpoint: path, target: ctx.asset.identifier, facts: [`Regular (non-admin) test account can access ${path} (HTTP 200, admin content).`], inference: ['Vertical privilege escalation — role checks missing on the admin surface.'], evidence: [ctx.evidenceFrom(res, 'Admin surface accessed with regular account')] });
      }
    }
  },
};
