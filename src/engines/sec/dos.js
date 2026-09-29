import { URL } from 'node:url';
import { forms } from '#lib/html';
import { ensureCrawled } from '#lib/crawl';

/** Engine: DoS / Resilience (safe, strictly bounded probes). */
export const dosEngine = {
  key: 'sec_dos',
  title: 'DoS Resilience Assessment (safe)',
  async run(ctx) {
    await ensureCrawled(ctx, { maxPages: ctx.params?.max_pages || 6 });
    const start = ctx.asset.base_url || ctx.asset.identifier;
    const origin = new URL(start).origin;

    // DOS-001 anti-automation: burst 15 rapid requests, observe 429/503/captcha
    const statuses = []; let last = null;
    for (let i = 0; i < 15; i++) {
      const r = await ctx.fetch(start);
      statuses.push(r.status); last = r;
      if (r.status === 429) break;
    }
    const throttled = statuses.includes(429) || statuses.includes(503);
    ctx.metrics.anti_automation = { burst: statuses.length, statuses: [...new Set(statuses)] };
    if (!throttled) {
      ctx.report('DOS-001', {
        severity: 'low', confidence: 'medium', endpoint: new URL(start).pathname, target: ctx.asset.identifier,
        facts: [`A burst of ${statuses.length} sequential requests produced no rate-limit response (statuses observed: ${[...new Set(statuses)].join(', ')}).`],
        inference: ['No anti-automation/rate-limiting was triggered by this bounded burst; scraper/DoS exposure cannot be ruled out.'],
        evidence: [ctx.evidenceFrom(last, 'Final burst response')],
      });
    } else {
      ctx.report('DOS-001', { severity: 'info', confidence: 'confirmed', endpoint: new URL(start).pathname, target: ctx.asset.identifier, facts: [`Rate limiting engaged after ${statuses.indexOf(429) + 1} requests (HTTP 429).`], inference: ['Anti-automation controls present.'], evidence: [ctx.evidenceFrom(last, 'Rate-limited response')] });
    }

    // DOS-002 lockout resilience (only if a login form exists; conservative 5 attempts)
    const loginPage = await ctx.getOrFetch(new URL('/login', origin).toString());
    if (loginPage.res.ok && loginPage.dom) {
      const f = forms(loginPage.dom, loginPage.res.finalUrl).find((x) => x.fields.some((v) => v.type === 'password'));
      if (f) {
        const userField = f.fields.find((v) => /user|email|login/i.test(v.name || ''))?.name || 'username';
        const passField = f.fields.find((v) => v.type === 'password')?.name || 'password';
        const statuses2 = [];
        let last2 = null;
        for (let i = 0; i < 5; i++) {
          const r = await ctx.fetch(f.action, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ [userField]: 'lockout_probe_user', [passField]: `Xy${i}!lockout` }).toString() });
          statuses2.push(r.status); last2 = r;
        }
        const locked = statuses2.some((s) => s === 423 || s === 429 || /locked/i.test(last2.bodyText || ''));
        if (!locked) {
          ctx.report('DOS-002', { severity: 'medium', confidence: 'medium', endpoint: f.action, target: ctx.asset.identifier, facts: [`Five failed logins for a probe account yielded statuses: ${statuses2.join(', ')} with no lockout indication.`], inference: ['Account lockout may be absent or threshold > 5 — brute-force resilience depends on other controls.'], evidence: [ctx.evidenceFrom(last2, 'Fifth failed login response')] });
        }
      }
    }

    // DOS-003 SQL wildcard timing: leading-wildcard search probe vs plain term
    const searchForm = (ctx.state.crawl?.forms || []).find((x) => /search|query|q/i.test(JSON.stringify(x.fields.map((v) => v.name))));
    if (searchForm) {
      const field = searchForm.fields.find((v) => /q|search|query/i.test(v.name || ''))?.name || 'q';
      const action = searchForm.action;
      const plain = await ctx.fetch(action + (searchForm.method === 'POST' ? '' : `?${field}=test`), searchForm.method === 'POST' ? { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ [field]: 'test' }).toString() } : {});
      const wild = await ctx.fetch(action + (searchForm.method === 'POST' ? '' : `?${field}=%25%25`), searchForm.method === 'POST' ? { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ [field]: '%%' }).toString() } : {});
      const delta = (wild.totalMs || 0) - (plain.totalMs || 0);
      ctx.metrics.wildcard_timing = { plain_ms: plain.totalMs, wildcard_ms: wild.totalMs, delta_ms: delta };
      if (delta > 1500) {
        ctx.report('DOS-003', { severity: 'low', confidence: 'medium', endpoint: action, parameter: field, target: ctx.asset.identifier, facts: [`Plain query: ${plain.totalMs}ms; leading-wildcard query "%%": ${wild.totalMs}ms (Δ${delta}ms).`], inference: ['Wildcard searches cause disproportionate server load — resource exhaustion vector (single-sample measurement).'], evidence: [ctx.evidenceFrom(plain, 'Baseline search timing'), ctx.evidenceFrom(wild, 'Wildcard search timing')] });
      }
    }

    // DOS-004 large payload (intrusive only)
    if (ctx.profile === 'intrusive') {
      const r = await ctx.fetch(start, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'x=' + 'A'.repeat(2_000_000) });
      if (r.status === 200 && !r.error) {
        ctx.report('DOS-004', { severity: 'low', confidence: 'medium', endpoint: new URL(start).pathname, target: ctx.asset.identifier, facts: ['A 2MB form body was accepted (HTTP 200) without rejection.'], inference: ['No request-size limit observed on this endpoint.'], evidence: [ctx.evidenceFrom(r, 'Large payload acceptance')] });
      }
    } else {
      ctx.log('info', 'large-payload probe skipped (requires intrusive profile)');
    }
  },
};
