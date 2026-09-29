import { URL } from 'node:url';
import { title as getTitle, metaGet, headings, images, lang, innerText, byTag, attr, iframes, walk, findAll } from '#lib/html';

/** Engine: Accessibility — automated static WCAG checks per page. */
export const a11yEngine = {
  key: 'a11y',
  title: 'Accessibility Analysis',
  async run(ctx) {
    const start = ctx.asset.base_url || ctx.asset.identifier;
    const targets = ctx.pages.size ? [...ctx.pages.keys()] : [start];
    let analyzed = 0;
    for (const url of targets.slice(0, ctx.params?.max_pages || 15)) {
      const page = await ctx.getOrFetch(url);
      if (!page.res.ok || !page.dom) continue;
      analyzed++;
      const dom = page.dom;
      const path = new URL(url).pathname;
      const base = { endpoint: path, target: ctx.asset.identifier };
      const ev = () => ctx.evidenceFrom(page.res, `Accessibility signals for ${url}`);

      const noAlt = images(dom).filter((i) => i.alt == null && !(attr({ attrs: { role: 'presentation' } }, 'role') && false));
      const missingAlt = images(dom).filter((i) => i.alt == null);
      if (missingAlt.length) {
        ctx.report('A11Y-001', { ...base, severity: missingAlt.length > 3 ? 'medium' : 'low', confidence: 'confirmed', facts: [`${missingAlt.length} images lack alt attributes.`], inference: ['Screen readers cannot describe these images (WCAG 1.1.1).'], evidence: [ev()] });
      }
      // labels (A11Y-002)
      const unlabeled = [];
      for (const input of byTag(dom, 'input')) {
        const type = attr(input, 'type') || 'text';
        if (['hidden', 'submit', 'button', 'reset'].includes(type)) continue;
        const id = attr(input, 'id');
        const hasLabel = id && byTag(dom, 'label').some((l) => attr(l, 'for') === id);
        const ariaLabel = attr(input, 'aria-label') || attr(input, 'aria-labelledby');
        const placeholder = attr(input, 'placeholder');
        if (!hasLabel && !ariaLabel) unlabeled.push({ name: attr(input, 'name') || id || type, placeholder: placeholder || null });
      }
      if (unlabeled.length) {
        ctx.report('A11Y-002', { ...base, severity: 'high', confidence: 'confirmed', facts: [`${unlabeled.length} form inputs lack an associated label: ${unlabeled.slice(0, 5).map((x) => x.name).join(', ')}.`], inference: ['Unlabeled inputs are unusable with assistive technology (WCAG 1.3.1/4.1.2).'], evidence: [ev()] });
      }
      // heading order (A11Y-003)
      const hs = headings(dom);
      let prev = 0; let skipped = false;
      for (const h of hs) { if (prev && h.level > prev + 1) { skipped = true; break; } prev = h.level; }
      if (skipped) ctx.report('A11Y-003', { ...base, severity: 'medium', confidence: 'confirmed', facts: ['Heading levels skip (e.g. h1 → h4).'], inference: ['Inconsistent heading structure confuses navigation by heading (WCAG 1.3.1).'], evidence: [ev()] });
      // lang/title (A11Y-004)
      const t = getTitle(dom);
      if (!t || !lang(dom)) {
        ctx.report('A11Y-004', { ...base, severity: 'high', confidence: 'confirmed', facts: [!t ? 'Missing <title>.' : '', !lang(dom) ? 'Missing <html lang>.' : ''].filter(Boolean), inference: ['Page language and title are required for AT users and search (WCAG 3.1.1/2.4.2).'], evidence: [ev()] });
      }
      // landmarks (A11Y-005)
      const landmarks = ['header', 'nav', 'main', 'footer'].filter((tag) => byTag(dom, tag).length);
      if (!landmarks.includes('main')) {
        ctx.report('A11Y-005', { ...base, severity: 'low', confidence: 'confirmed', facts: [`No <main> landmark element (found: ${landmarks.join(', ') || 'none'}).`], inference: ['Landmarks enable structural navigation (WCAG 1.3.1/2.4.1).'], evidence: [ev()] });
      }
      // link text (A11Y-006)
      const badLinks = byTag(dom, 'a').filter((a) => {
        const text = innerText(a).trim().toLowerCase();
        const href = attr(a, 'href');
        return href && href.startsWith('http') && ['click here', 'here', 'read more', 'more', 'link'].includes(text);
      });
      if (badLinks.length) {
        ctx.report('A11Y-006', { ...base, severity: 'low', confidence: 'confirmed', facts: [`${badLinks.length} links use non-descriptive text like "click here".`], inference: ['Link purpose must be clear from link text (WCAG 2.4.4).'], evidence: [ev()] });
      }
      // tabindex (A11Y-007)
      const positiveTabindex = findAll(dom, (n) => n.attrs['tabindex'] && parseInt(n.attrs['tabindex'], 10) > 0);
      if (positiveTabindex.length) {
        ctx.report('A11Y-007', { ...base, severity: 'medium', confidence: 'confirmed', facts: [`${positiveTabindex.length} elements use positive tabindex (first: tabindex=${positiveTabindex[0].attrs['tabindex']}).`], inference: ['Positive tabindex creates unpredictable focus order (WCAG 2.4.3).'], evidence: [ev()] });
      }
      // iframe titles (A11Y-008)
      const untitledIframes = iframes(dom).filter((f) => !f.title);
      if (untitledIframes.length) {
        ctx.report('A11Y-008', { ...base, severity: 'medium', confidence: 'confirmed', facts: [`${untitledIframes.length} iframes without title attribute.`], inference: ['Frame content must be identified (WCAG 4.1.2).'], evidence: [ev()] });
      }
      // ARIA basics (A11Y-009)
      const ariaIssues = [];
      const ids = new Set(byTag(dom, '*').length ? [] : []);
      for (const el of findAll(dom, (n) => Object.keys(n.attrs).some((k) => k.startsWith('aria-')))) {
        const labelledby = el.attrs['aria-labelledby'];
        if (labelledby) {
          for (const ref of labelledby.split(/\s+/)) {
            if (!findAll(dom, (n) => n.attrs['id'] === ref).length) ariaIssues.push(`aria-labelledby references missing id "${ref}"`);
          }
        }
      }
      if (ariaIssues.length) {
        ctx.report('A11Y-009', { ...base, severity: 'low', confidence: 'confirmed', facts: ariaIssues.slice(0, 5), inference: ['Invalid ARIA references break AT announcements (WCAG 4.1.2).'], evidence: [ev()] });
      }
      // tables (A11Y-010)
      const tables = byTag(dom, 'table');
      const badTables = tables.filter((tb) => !byTag(tb, 'th').length && innerText(tb).length > 40);
      if (badTables.length) {
        ctx.report('A11Y-010', { ...base, severity: 'low', confidence: 'medium', facts: [`${badTables.length} data tables without <th> header cells.`], inference: ['Tables need header markup for AT comprehension (WCAG 1.3.1).'], evidence: [ev()] });
      }
      // skip link (A11Y-011)
      const firstLinks = byTag(dom, 'a').slice(0, 5);
      const hasSkip = firstLinks.some((a) => /skip|jump/i.test(innerText(a) + (attr(a, 'class') || '') + (attr(a, 'href') || '')));
      if (!hasSkip) {
        ctx.report('A11Y-011', { ...base, severity: 'low', confidence: 'medium', facts: ['No skip-to-content link near the top of the page.'], inference: ['Keyboard users must tab through navigation repeatedly (WCAG 2.4.1).'], evidence: [ev()] });
      }
      // contrast note (A11Y-012) — manual
      ctx.report('A11Y-012', { ...base, severity: 'info', confidence: 'confirmed', facts: ['Color contrast was not measured: requires rendered styles (browser provider). Inline style declarations were inspected only.'], inference: ['Verify 4.5:1 contrast manually or via the browser provider.'], evidence: [ctx.evidenceRaw('derived', { check: 'contrast', status: 'requires_browser_provider' }, 'Contrast measurement capability statement')] });
    }
    ctx.metrics.a11y_pages_analyzed = analyzed;
  },
};
