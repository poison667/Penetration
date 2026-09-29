import { URL } from 'node:url';
import { images, scripts as getScripts, byTag, attr } from '#lib/html';

/** Engine: Performance — real measured network timings and resource inventory. */
export const perfEngine = {
  key: 'perf',
  title: 'Performance Analysis',
  async run(ctx) {
    const start = ctx.asset.base_url || ctx.asset.identifier;
    const page = await ctx.getOrFetch(start, { headers: { 'cache-control': 'no-cache' } });
    if (!page.res.ok) throw new Error(`cannot fetch start URL: ${page.res.error || page.res.status}`);
    const h = page.res.headers;
    const u = new URL(page.res.finalUrl);
    const base = { endpoint: '/', target: ctx.asset.identifier };
    const ev = () => ctx.evidenceFrom(page.res, `Performance measurement for ${page.res.finalUrl}`);

    // TTFB (PRF-001) — median of 3 requests
    const tt = [page.res.ttfbMs];
    for (let i = 0; i < 2; i++) {
      const r = await ctx.fetch(start);
      if (r.ok && r.ttfbMs != null) tt.push(r.ttfbMs);
    }
    tt.sort((a, b) => a - b);
    const ttfbMedian = tt[Math.floor(tt.length / 2)];
    ctx.metrics.ttfb_ms_median = ttfbMedian;
    ctx.metrics.ttfb_samples = tt;
    if (ttfbMedian > 800) {
      ctx.report('PRF-001', { ...base, severity: ttfbMedian > 2000 ? 'high' : 'medium', confidence: 'confirmed', facts: [`Median TTFB is ${ttfbMedian}ms over ${tt.length} requests (samples: ${tt.join(', ')}ms).`], inference: ['Server response time is slower than the 800ms target.'], evidence: [ev()] });
    }

    // Transfer size (PRF-002)
    if (page.res.bodyBytes > 500_000) {
      ctx.report('PRF-002', { ...base, severity: 'low', confidence: 'confirmed', facts: [`HTML document is ${(page.res.bodyBytes / 1024).toFixed(0)} KB.`], inference: ['Large documents delay first render.'], evidence: [ev()] });
    }
    ctx.metrics.html_bytes = page.res.bodyBytes;

    // Compression (PRF-003)
    const encoding = h['content-encoding']?.[0];
    ctx.metrics.compression = encoding || null;
    if (!encoding && page.res.bodyBytes > 10_000 && /text\/html|text\/(css|javascript)|application\/json/i.test(page.res.contentType)) {
      ctx.report('PRF-003', { ...base, severity: 'medium', confidence: 'confirmed', facts: ['Response has no Content-Encoding (uncompressed).'], inference: ['Compression typically reduces text payloads 60–80%.'], evidence: [ev()] });
    }

    // Redirects (PRF-004)
    ctx.metrics.redirects = page.res.hops;
    if (page.res.hops > 1) {
      ctx.report('PRF-004', { ...base, severity: 'low', confidence: 'confirmed', facts: [`Start URL resolves through ${page.res.hops} redirects: ${page.res.redirects.map((r) => `${r.status}→${r.location}`).join(' ')}.`], inference: ['Each redirect adds a full round trip.'], evidence: [ev()] });
    }

    // Resource inventory (PRF-005)
    if (page.dom) {
      const imgs = images(page.dom);
      const scrs = getScripts(page.dom, start);
      const css = byTag(page.dom, 'link').filter((l) => (attr(l, 'rel') || '').toLowerCase() === 'stylesheet').map((l) => attr(l, 'href'));
      ctx.metrics.resources = { images: imgs.length, scripts: scrs.length, stylesheets: css.length };
      const blocking = scrs.filter((s) => !s.async && s.src && !(s.type || '').includes('module'));
      if (blocking.length > 3) {
        ctx.report('PRF-007', { ...base, severity: 'low', confidence: 'medium', facts: [`${blocking.length} synchronous (non-async) script tags block HTML parsing.`], inference: ['Synchronous scripts in the document delay first paint.'], evidence: [ev()] });
      }
      if (imgs.length > 30) {
        ctx.report('PRF-005', { ...base, severity: 'low', confidence: 'medium', facts: [`${imgs.length} <img> elements on the page.`], inference: ['Heavy image inventories need lazy-loading and modern formats.'], evidence: [ev()] });
      }
    }

    // Caching (PRF-006) — check a static-ish asset
    const cacheCtl = h['cache-control']?.[0];
    ctx.metrics.cache_control = cacheCtl || null;
    if (page.dom) {
      const firstScript = getScripts(page.dom, start).find((s) => /\.(js|css)(\?|$)/.test(s.src || ''))?.src;
      if (firstScript) {
        const assetRes = await ctx.fetch(firstScript);
        const ac = assetRes.headers['cache-control']?.[0];
        ctx.metrics.asset_cache_control = ac || null;
        if (assetRes.ok && (!ac || !/(max-age=\d{5,}|immutable)/i.test(ac))) {
          ctx.report('PRF-006', { ...base, endpoint: new URL(firstScript).pathname, severity: 'medium', confidence: 'confirmed', facts: [`Static asset ${firstScript} served with Cache-Control: ${ac || '(none)'}.`], inference: ['Long-lived caching with hashed filenames improves repeat visits.'], evidence: [ctx.evidenceFrom(assetRes, `Cache headers for ${firstScript}`)] });
        }
      }
    }

    // Protocol (PRF-008)
    const proto = h['connection'] ? null : null;
    ctx.metrics.http_version_note = 'HTTP version negotiated by client stack: HTTP/1.1 (client limitation); server ALPN advertised separately in TLS engine.';
    ctx.report('PRF-008', { ...base, severity: 'info', confidence: 'confirmed', facts: [`Total time for HTML fetch: ${page.res.totalMs}ms; body ${page.res.bodyBytes} bytes; keep-alive ${h['connection']?.[0] || 'default'}.`], inference: ['Enable HTTP/2+ for multiplexing (verify server ALPN).'], evidence: [ev()] });

    // CWV adapter status (PRF-009) — honest disclosure
    ctx.report('PRF-009', { ...base, severity: 'info', confidence: 'confirmed', facts: ['Network-layer metrics measured: TTFB, transfer size/time, compression, redirects, resource inventory.', 'Rendering metrics (LCP/CLS/INP) require a real browser engine — the browser-provider adapter is defined in docs/LIMITATIONS.md and not active in this deployment.'], inference: ['Treat rendering vitals as not yet measured; do not infer them from network timings.'], evidence: [ctx.evidenceRaw('derived', { measured: ['ttfb', 'transfer', 'compression', 'redirects', 'resources'], browser_metrics: 'not_measured_no_active_provider' }, 'Measurement scope statement')] });

    ctx.metrics.total_ms = page.res.totalMs;
  },
};
