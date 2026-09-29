import { URL } from 'node:url';

/** Engine: HTML5 / Modern Web Security. */
export const html5Engine = {
  key: 'sec_html5',
  title: 'HTML5 / Modern Web Security',
  async run(ctx) {
    const start = ctx.asset.base_url || ctx.asset.identifier;
    const origin = new URL(start).origin;
    const page = await ctx.getOrFetch(start);

    // Collect all fetched scripts for static analysis
    const scriptUrls = new Set();
    for (const [url, p] of ctx.pages) {
      for (const m of (p.res.bodyText || '').matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) {
        try { scriptUrls.add(new URL(m[1], url).toString()); } catch { /* skip */ }
      }
    }
    const bodies = [{ url: start, body: page.res.bodyText }];
    for (const su of [...scriptUrls].slice(0, 20)) {
      const r = await ctx.fetch(su);
      if (r.ok) bodies.push({ url: su, body: r.bodyText });
    }

    // H5-001 postMessage without origin checks
    for (const { url, body } of bodies) {
      const handlers = [...body.matchAll(/addEventListener\s*\(\s*['"]message['"]\s*,/gi)];
      for (const h of handlers) {
        const window = body.slice(h.index, h.index + 600);
        const checksOrigin = /event\.origin|e\.origin|\.origin\s*(===|!==|==|!=|\?)/i.test(window);
        if (!checksOrigin) {
          ctx.report('H5-001', {
            severity: 'medium', confidence: 'medium', endpoint: url, target: ctx.asset.identifier,
            facts: [`A message event listener without a visible origin validation was found in ${url}.`],
            inference: ['Any origin can postMessage this handler — data theft or DOM manipulation via Web Messaging.'],
            evidence: [ctx.evidenceRaw('static_analysis', { source: url, snippet: window.slice(0, 300) }, 'postMessage handler without origin check')],
          });
        }
      }
    }

    // H5-002/H5-006 web storage + indexeddb sensitive usage
    for (const { url, body } of bodies) {
      const storage = /localStorage\.setItem\s*\(\s*["'][^"']*(token|jwt|auth|secret|password|credit|ssn|card)/i.test(body);
      const idb = /indexedDB\.open\s*\(\s*["'][^"']*(user|auth|token|payment)/i.test(body);
      if (storage) {
        ctx.report('H5-002', { severity: 'medium', confidence: 'medium', endpoint: url, target: ctx.asset.identifier, facts: ['Sensitive-looking keys are written to Web Storage in client code.'], inference: ['XSS-readable persistence of sensitive data.'], evidence: [ctx.evidenceRaw('static_analysis', { source: url }, 'Web storage sensitive usage')] });
      }
      if (idb) {
        ctx.report('H5-006', { severity: 'low', confidence: 'low', endpoint: url, target: ctx.asset.identifier, facts: ['IndexedDB database with sensitive name opened by client code.'], inference: ['Client-side persistence of sensitive data should be avoided.'], evidence: [ctx.evidenceRaw('static_analysis', { source: url }, 'IndexedDB usage')] });
      }
      // H5-005 websockets
      if (/new WebSocket\s*\(\s*['"]ws:\/\//i.test(body)) {
        ctx.report('H5-005', { severity: 'medium', confidence: 'confirmed', endpoint: url, target: ctx.asset.identifier, facts: ['Client code opens unencrypted ws:// WebSocket connections.'], inference: ['WebSocket traffic is interceptable; use wss:// and authenticate the handshake.'], evidence: [ctx.evidenceRaw('static_analysis', { source: url }, 'ws:// usage')] });
      }
      // H5-004 service workers
      if (/serviceWorker\.register\s*\(\s*['"]([^"']+)['"]/i.test(body)) {
        const swPath = /serviceWorker\.register\s*\(\s*['"]([^"']+)['"]/i.exec(body)[1];
        const swUrl = new URL(swPath, url).toString();
        const sw = await ctx.fetch(swUrl);
        if (sw.ok) {
          const swBody = sw.bodyText;
          const wideScope = /fetch\s*\(\s*request/i.test(swBody) && !/self\.origin|url\.startsWith/i.test(swBody);
          ctx.report('H5-004', {
            severity: 'low', confidence: 'medium', endpoint: swUrl, target: ctx.asset.identifier,
            facts: [`Service worker registered at ${swUrl} (${sw.bodyBytes} bytes).`, wideScope ? 'Fetch handler appears to proxy all requests without origin filtering.' : 'Fetch handler includes origin checks.'],
            inference: ['A compromised service worker persists and can rewrite all page traffic — protect its hosting path.'],
            evidence: [ctx.evidenceFrom(sw, 'Service worker source')],
          });
        }
      }
    }

    // H5-003 CORS probe (safe: Origin spoof variations)
    const probes = ['https://probe.meridian.invalid', 'null'];
    for (const originProbe of probes) {
      const r = await ctx.fetch(start, { headers: { origin: originProbe } });
      const acao = r.headers['access-control-allow-origin']?.[0];
      const acac = r.headers['access-control-allow-credentials']?.[0];
      if (acao && (acao === '*' || acao === originProbe)) {
        ctx.report('H5-003', {
          severity: acac === 'true' ? 'high' : 'medium', confidence: 'confirmed', endpoint: new URL(start).pathname, target: ctx.asset.identifier,
          facts: [`Request with Origin: ${originProbe} received Access-Control-Allow-Origin: ${acao}${acac ? `, Allow-Credentials: ${acac}` : ''}.`],
          inference: acac === 'true' ? 'Arbitrary origins are allowed with credentials — any site can read authenticated responses cross-origin.' : 'The origin is reflected, permitting cross-origin reads from arbitrary sites.',
          evidence: [ctx.evidenceFrom(r, `CORS probe with spoofed Origin ${originProbe}`)],
        });
      }
    }
  },
};
