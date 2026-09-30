import { URL } from 'node:url';
import { title as getTitle, metaGet, headings, images, canonical, lang, links, innerText, byTag, attr } from '#lib/html';

/** Engine: SEO Analysis — per-page checks from crawled pages. */
export const seoEngine = {
  key: 'seo',
  title: 'SEO Analysis',
  async run(ctx) {
    const start = ctx.asset.base_url || ctx.asset.identifier;
    let pages = ctx.state.crawl?.pages?.length ? [...ctx.state.crawl.pages.keys?.() ?? []] : [];
    // prefer crawled page list if available (crawl stores in ctx.pages too)
    const targets = ctx.pages.size ? [...ctx.pages.keys()] : [start];
    let analyzed = 0;
    for (const url of targets.slice(0, ctx.params?.max_pages || 15)) {
      const page = await ctx.getOrFetch(url);
      if (!page.res.ok || !page.dom) continue;
      analyzed++;
      const dom = page.dom;
      const t = getTitle(dom);
      const desc = metaGet(dom, 'description');
      const hs = headings(dom);
      const path = new URL(url).pathname;
      const base = { endpoint: path, target: ctx.asset.identifier };
      const ev = () => ctx.evidenceFrom(page.res, `SEO signals for ${url}`);

      if (!t || t.length < 10 || t.length > 65) {
        ctx.report('SEO-001', { ...base, severity: t ? 'low' : 'medium', confidence: 'confirmed', facts: [t ? `Title length is ${t.length} chars: "${t.slice(0, 80)}".` : 'No <title> element.'], inference: ['Title quality affects ranking and click-through.'], evidence: [ev()] });
      }
      if (!desc || desc.length < 50 || desc.length > 170) {
        ctx.report('SEO-002', { ...base, severity: 'low', confidence: 'confirmed', facts: [desc ? `Meta description length is ${desc.length} chars.` : 'No meta description.'], inference: ['Missing meta descriptions let search engines synthesize snippets.'], evidence: [ev()] });
      }
      const h1s = hs.filter((h) => h.level === 1);
      if (h1s.length !== 1) {
        ctx.report('SEO-003', { ...base, severity: 'low', confidence: 'confirmed', facts: [`${h1s.length} h1 elements on page.`], inference: ['Exactly one h1 is the expected document outline.'], evidence: [ev()] });
      }
      let prev = 0; let skip = false;
      for (const h of hs) { if (prev && h.level > prev + 1) { skip = true; break; } prev = h.level; }
      if (skip) ctx.report('SEO-003', { ...base, severity: 'low', confidence: 'confirmed', facts: ['Heading levels skip (e.g. h2 → h4).'], inference: ['Broken heading hierarchy weakens content structure signals.'], evidence: [ev()] });

      const noAlt = images(dom).filter((i) => i.alt == null || i.alt.trim() === '');
      if (noAlt.length) {
        ctx.report('SEO-004', { ...base, severity: 'medium', confidence: 'confirmed', facts: [`${noAlt.length} images without alt text (e.g. ${noAlt[0].src || 'inline'}).`], inference: ['Alt text is required for accessibility and image SEO.'], evidence: [ev()] });
      }
      if (!canonical(dom)) ctx.report('SEO-005', { ...base, severity: 'low', confidence: 'confirmed', facts: ['No canonical link element.'], inference: ['Duplicate content may dilute ranking signals.'], evidence: [ev()] });
      const robotsMeta = metaGet(dom, 'robots');
      if (robotsMeta && /noindex/i.test(robotsMeta)) {
        ctx.report('SEO-006', { ...base, severity: 'info', confidence: 'confirmed', facts: [`Page declares noindex: "${robotsMeta}".`], inference: ['Verify noindex is intentional.'], evidence: [ev()] });
      }
      const viewport = metaGet(dom, 'viewport');
      if (!viewport) ctx.report('SEO-009', { ...base, severity: 'medium', confidence: 'confirmed', facts: ['No viewport meta tag.'], inference: ['Mobile-friendliness is a ranking factor.'], evidence: [ev()] });
      if (!lang(dom)) ctx.report('SEO-010', { ...base, severity: 'low', confidence: 'confirmed', facts: ['<html> has no lang attribute.'], inference: ['Language declaration helps indexing and accessibility.'], evidence: [ev()] });
      const og = metaGet(dom, 'og:title');
      if (!og) ctx.report('SEO-012', { ...base, severity: 'info', confidence: 'confirmed', facts: ['No Open Graph metadata (og:title missing).'], inference: ['Social sharing will lack previews.'], evidence: [ev()] });
      // structured data
      const jsonLd = byTag(dom, 'script').filter((s) => (attr(s, 'type') || '').includes('ld+json'));
      if (!jsonLd.length) {
        ctx.report('SEO-008', { ...base, severity: 'low', confidence: 'confirmed', facts: ['No JSON-LD structured data found.'], inference: ['Structured data enables rich results.'], evidence: [ev()] });
      } else {
        for (const s of jsonLd) { try { JSON.parse(innerText(s) || '{}'); } catch { ctx.report('SEO-008', { ...base, severity: 'low', confidence: 'confirmed', facts: ['A JSON-LD block is malformed (parse error).'], inference: ['Invalid structured data is ignored by search engines.'], evidence: [ev()] }); } }
      }
      // content depth
      const text = innerText(dom) || '';
      const words = text.split(/\s+/).filter(Boolean).length;
      if (words < 150 && !['/', ''].includes(path)) {
        ctx.report('SEO-014', { ...base, severity: 'info', confidence: 'medium', facts: [`Page body text is ~${words} words.`], inference: ['Thin content may underperform in rankings.'], evidence: [ev()] });
      }
      // URL quality
      if (new URL(url).search.length > 100 || /[A-Z]/.test(new URL(url).pathname)) {
        ctx.report('SEO-013', { ...base, severity: 'info', confidence: 'medium', facts: [`URL: ${url}`], inference: ['Short lowercase URLs with few parameters are preferable.'], evidence: [ev()] });
      }
      // HTTPS (SEO-015)
      if (new URL(url).protocol !== 'https:') {
        ctx.report('SEO-015', { ...base, severity: 'medium', confidence: 'confirmed', facts: ['Page served over plain HTTP.'], inference: ['HTTPS is a ranking signal and prerequisite for modern web APIs.'], evidence: [ev()] });
      }
    }
    // sitemap check (SEO-007)
    const robotsRes = await ctx.fetch(new URL('/robots.txt', start).toString());
    const sitemapRes = await ctx.fetch(new URL('/sitemap.xml', start).toString());
    if (!sitemapRes.ok && !/sitemap:/i.test(robotsRes.bodyText || '')) {
      const ev = ctx.evidenceRaw('http_exchange', { robots_txt_status: robotsRes.status, sitemap_status: sitemapRes.status }, 'robots.txt and sitemap.xml availability');
      ctx.report('SEO-007', { severity: 'low', confidence: 'confirmed', endpoint: '/sitemap.xml', target: ctx.asset.identifier, facts: [`sitemap.xml returned HTTP ${sitemapRes.status}; robots.txt ${robotsRes.status}.`], inference: ['No sitemap discovered.'], evidence: [ev] });
    } else if (/sitemap:\s*(\S+)/i.test(robotsRes.bodyText || '')) {
      // a sitemap is declared in robots.txt — verify it is actually reachable
      const declared = /sitemap:\s*(\S+)/i.exec(robotsRes.bodyText)[1];
      const declaredRes = await ctx.fetch(declared);
      if (!declaredRes.ok) {
        const ev = ctx.evidenceRaw('http_exchange', { declared_sitemap: declared, status: declaredRes.status, error: declaredRes.error || null }, 'Declared sitemap reachability');
        ctx.report('SEO-007', { severity: 'low', confidence: 'confirmed', endpoint: declared, target: ctx.asset.identifier, facts: [`robots.txt declares Sitemap: ${declared}, but fetching it failed (HTTP ${declaredRes.status || 'error'}${declaredRes.error ? ': ' + declaredRes.error.slice(0, 80) : ''}).`], inference: ['The declared sitemap is stale or points at the wrong host — crawlers cannot use it.'], evidence: [ev] });
      }
    }
    // broken internal links (SEO-011) — sample up to 20 internal links
    const internal = (ctx.state.crawl?.links || []).filter((l) => !l.external).slice(0, 20);
    const broken = [];
    for (const l of internal) {
      if (!l.url.startsWith('http')) continue;
      const r = await ctx.fetch(l.url, { method: 'HEAD' });
      if (r.status >= 400 || r.errorCode === 'network_error') broken.push({ url: l.url, status: r.status || 'error' });
    }
    if (broken.length) {
      const ev = ctx.evidenceRaw('derived', { broken }, 'Broken internal link check');
      ctx.report('SEO-011', { severity: 'low', confidence: 'confirmed', target: ctx.asset.identifier, facts: broken.map((b) => `${b.url} → ${b.status}`), inference: ['Broken links degrade crawlability and user signals.'], evidence: [ev] });
    }
    ctx.metrics.seo_pages_analyzed = analyzed;
  },
};
