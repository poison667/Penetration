import { URL } from 'node:url';
import { byTag, attr, forms } from '#lib/html';

/** Engine: Payment / High-Risk Functionality Assessment (passive, authorized scope). */
export const paymentEngine = {
  key: 'sec_payment',
  title: 'Payment / High-Risk Functionality Assessment',
  async run(ctx) {
    const start = ctx.asset.base_url || ctx.asset.identifier;
    const origin = new URL(start).origin;
    const KNOWN_PROVIDERS = /(js\.stripe\.com|checkout\.stripe\.com|js\.braintreegateway\.com|paypal\.com|checkout\.com|adyen\.com|squareup\.com|worldpay)/i;

    const paymentPaths = ['/', '/cart', '/checkout', '/shop', '/store', '/pricing', '/billing'];
    const paymentPages = [];
    for (const path of paymentPaths) {
      const p = await ctx.getOrFetch(new URL(path, origin).toString());
      if (p.res.ok && p.dom) {
        const isPayment = /card|payment|checkout|cart|price|purchase|billing|stripe|paypal/i.test(p.res.bodyText.slice(0, 4000));
        if (isPayment) paymentPages.push(p);
      }
    }
    ctx.inventory.payment = { pages: paymentPages.map((p) => p.url) };
    if (!paymentPages.length) {
      ctx.log('info', 'no payment surfaces detected in scope — payment checks informational');
    }

    for (const p of paymentPages) {
      const dom = p.dom;
      const base = { endpoint: new URL(p.url).pathname, target: ctx.asset.identifier };
      const ev = () => ctx.evidenceFrom(p.res, `Payment surface ${p.url}`);

      // PAY-001 inventory
      ctx.report('PAY-001', {
        severity: 'info', confidence: 'confirmed', ...base,
        facts: [`Payment-related page detected at ${p.url}.`],
        inference: ['Page added to PCI-scoped surface inventory.'],
        evidence: [ev()],
      });

      // PAY-002 first-party card fields
      const cardFields = [];
      for (const input of byTag(dom, 'input')) {
        const name = `${attr(input, 'name') || ''} ${attr(input, 'autocomplete') || ''} ${attr(input, 'id') || ''}`;
        if (/card|cc-|cvc|cvv|pan|expir/i.test(name)) cardFields.push(attr(input, 'name') || attr(input, 'id'));
      }
      if (cardFields.length) {
        ctx.report('PAY-002', {
          severity: 'high', confidence: 'confirmed', ...base,
          facts: [`First-party card input fields present: ${cardFields.join(', ')}.`],
          inference: ['Card data would enter the page\'s JS context (PCI SAQ A-EP or D scope) — use provider-hosted fields/iframes instead.'],
          evidence: [ev()],
          affected: p.url,
        });
      }

      // PAY-004 payment iframes
      const payIframes = byTag(dom, 'iframe').map((f) => attr(f, 'src')).filter(Boolean);
      const unknown = payIframes.filter((src) => !KNOWN_PROVIDERS.test(src) && src.startsWith('http'));
      if (unknown.length) {
        ctx.report('PAY-004', {
          severity: 'medium', confidence: 'medium', ...base,
          facts: [`Payment page embeds iframes from origins not on the known-provider list: ${unknown.slice(0, 3).join(', ')}.`],
          inference: ['Verify each embedded origin is a legitimate payment provider; allowlist via CSP frame-src.'],
          evidence: [ev()],
        });
      }

      // PAY-003 payment page transport + script integrity
      if (new URL(p.url).protocol !== 'https:') {
        ctx.report('PAY-003', { severity: 'high', confidence: 'confirmed', ...base, facts: ['Payment-related page is served over HTTP.'], inference: ['Payment flows must be HTTPS-only.'], evidence: [ev()] });
      }
      const csp = p.res.headers['content-security-policy']?.join('; ') || null;
      const scriptsNoSri = byTag(dom, 'script').filter((s) => attr(s, 'src') && !attr(s, 'integrity')).length;
      if (!csp || scriptsNoSri > 2) {
        ctx.report('PAY-003', {
          severity: 'medium', confidence: 'medium', ...base,
          facts: [csp ? 'CSP present.' : 'No CSP on payment page.', `${scriptsNoSri} external scripts without SRI.`],
          inference: ['Script-skimming (Magecart-class) risk is elevated without strict CSP + SRI on payment pages.'],
          evidence: [ev()],
        });
      }

      // PAY-005 test/debug payment modes
      if (/test mode|sandbox|debug.*(payment|card)|mockpay|fake.?card|4242 4242 4242 4242/i.test(p.res.bodyText) && new URL(p.url).pathname === '/checkout') {
        ctx.report('PAY-005', { severity: 'high', confidence: 'medium', ...base, facts: ['Page text suggests a test/sandbox payment mode reachable in this environment.'], inference: ['Test payment modes can allow order completion without real payment.'], evidence: [ev()] });
      }
    }
  },
};
