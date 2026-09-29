import { URL } from 'node:url';
import { byTag, attr, innerText } from '#lib/html';
import { ensureCrawled } from '#lib/crawl';

/** Engine: Business Logic Assessment (assisted inventory + evidence). */
export const bizlogicEngine = {
  key: 'sec_bizlogic',
  title: 'Business Logic Assessment (assisted)',
  async run(ctx) {
    await ensureCrawled(ctx, { maxPages: ctx.params?.max_pages || 6 });
    const start = ctx.asset.base_url || ctx.asset.identifier;
    const page = await ctx.getOrFetch(start);
    const crawl = ctx.state.crawl;

    // BIZ-001 feature misuse inventory: quantity/price/coupon params
    const riskParams = [];
    for (const f of crawl?.forms || []) {
      for (const v of f.fields) {
        if (/qty|quantity|price|amount|total|coupon|discount|promo|voucher|shipping/i.test(`${v.name} ${v.placeholder || ''} ${v.id || ''}`)) {
          riskParams.push({ form: f.action, field: v.name, page: f.page });
        }
      }
    }
    ctx.inventory.business_logic = { risky_parameters: riskParams };
    if (riskParams.length) {
      ctx.report('BIZ-001', {
        severity: 'info', confidence: 'confirmed', target: ctx.asset.identifier,
        facts: riskParams.slice(0, 10).map((r) => `Business-critical parameter "${r.field}" on ${r.form}`),
        inference: ['Price/quantity/discount parameters are client-controlled inputs — verify server-side recomputation and bounds (e.g. negative quantities, zero prices). Assisted check: no values were modified.'],
        evidence: [ctx.evidenceRaw('derived', { risk_params: riskParams }, 'Business-critical parameter inventory')],
      });
    }

    // BIZ-003 trust relationships: third-party script origins
    if (page.dom) {
      const thirdParty = byTag(page.dom, 'script').filter((s) => {
        const src = attr(s, 'src') || '';
        try { return src && new URL(src, start).host !== new URL(start).host; } catch { return false; }
      });
      const withSri = thirdParty.filter((s) => attr(s, 'integrity'));
      if (thirdParty.length > withSri.length) {
        ctx.report('BIZ-003', {
          severity: 'info', confidence: 'confirmed', endpoint: new URL(start).pathname, target: ctx.asset.identifier,
          facts: [`${thirdParty.length} third-party scripts loaded; ${thirdParty.length - withSri.length} lack integrity (SRI) attributes.`],
          inference: ['Trust is extended to third-party origins without integrity verification — script compromise becomes page compromise.'],
          evidence: [ctx.evidenceFrom(page.res, 'Third-party script inventory')],
        });
        if (thirdParty.length > withSri.length) {
          ctx.report('BIZ-004', { severity: 'low', confidence: 'confirmed', endpoint: new URL(start).pathname, target: ctx.asset.identifier, facts: [`${thirdParty.length - withSri.length} external scripts without SRI.`], inference: ['Data integrity of loaded code is not verifiable.'], evidence: [ctx.evidenceFrom(page.res, 'Scripts lacking SRI')] });
        }
      }
    }

    // BIZ-002 non-repudiation signals: audit/version endpoints (assisted)
    ctx.report('BIZ-002', {
      severity: 'info', confidence: 'low', target: ctx.asset.identifier,
      facts: ['Non-repudiation (tamper-evident audit trails, signatures on critical actions) cannot be verified from external responses.'],
      inference: ['Review the application\'s audit logging and signing of critical transactions manually.'],
      evidence: [ctx.evidenceRaw('derived', { check: 'non-repudiation', method: 'manual-review-required' }, 'Non-repudiation assessment scope')],
    });

    // BIZ-005 segregation of duties (assisted)
    const adminSurfaces = (crawl?.pages || []).filter((p) => /admin|manage|approve/i.test(p.url)).length;
    ctx.report('BIZ-005', {
      severity: 'info', confidence: 'low', target: ctx.asset.identifier,
      facts: [adminSurfaces ? `${adminSurfaces} admin/manage surfaces discovered in crawl.` : 'No admin surfaces discovered in crawl scope.'],
      inference: ['Verify that initiation, approval and execution of sensitive operations are separated across roles.'],
      evidence: [ctx.evidenceRaw('derived', { admin_surfaces: adminSurfaces }, 'Segregation of duties inventory')],
    });
  },
};
