import { URL } from 'node:url';
import { links, forms, scripts, metas, metaGet, title as pageTitle, iframes } from '#lib/html';
import { crawl } from '#lib/crawl';

/** Engine: Information Gathering (recon). */
export const reconEngine = {
  key: 'recon',
  title: 'Information Gathering',
  async run(ctx) {
    const base = new URL(ctx.asset.base_url || ctx.asset.identifier);
    const start = base.toString();

    // 1. robots.txt (REC-001)
    const robotsRes = await ctx.fetch(new URL('/robots.txt', base).toString());
    if (robotsRes.ok) {
      const ev = ctx.evidenceFrom(robotsRes, `robots.txt of ${base.host}`);
      ctx.inventory.robots = { found: true, url: robotsRes.finalUrl, size: robotsRes.bodyBytes, excerpt: robotsRes.bodyText.slice(0, 2000) };
      ctx.state.robotsTxt = robotsRes.bodyText;
      const disallowed = [...robotsRes.bodyText.matchAll(/^\s*disallow:\s*(\S+)$/gim)].map((m) => m[1]).slice(0, 50);
      ctx.report('REC-001', {
        severity: 'info', confidence: 'confirmed', endpoint: '/robots.txt',
        facts: [`robots.txt is served (HTTP ${robotsRes.status}, ${robotsRes.bodyBytes} bytes).`, disallowed.length ? `Disallowed paths declared: ${disallowed.slice(0, 10).join(', ')}` : 'No disallow directives found.'],
        inference: disallowed.some((p) => /admin|private|backup|config|secret|\.git|db/i.test(p))
          ? ['Disallowed paths reveal potentially sensitive areas of the application (information disclosure for attackers).']
          : ['robots.txt does not disclose obviously sensitive paths.'],
        evidence: [ev], recommendation: 'Review robots.txt entries; never use robots.txt as an access control.',
      });
    } else {
      ctx.inventory.robots = { found: false };
    }

    // 2. sitemap discovery (REC-002)
    let sitemapUrls = [];
    const robotsTxt = ctx.state.robotsTxt || '';
    for (const m of robotsTxt.matchAll(/^\s*sitemap:\s*(\S+)$/gim)) sitemapUrls.push(m[1]);
    const sitemapRes = await ctx.fetch(new URL('/sitemap.xml', base).toString());
    if (sitemapRes.ok) sitemapUrls.push(sitemapRes.finalUrl);
    ctx.inventory.sitemaps = [...new Set(sitemapUrls)];
    if (ctx.inventory.sitemaps.length) {
      const ev = ctx.evidenceFrom(sitemapRes.ok ? sitemapRes : robotsRes, `Sitemap references for ${base.host}`);
      const { parseSitemap } = await import('#lib/robots');
      const parsed = parseSitemap(sitemapRes.ok ? sitemapRes.bodyText : '');
      ctx.inventory.sitemapUrls = parsed.urls.slice(0, 500);
      ctx.report('REC-002', {
        severity: 'info', confidence: 'confirmed', endpoint: '/sitemap.xml',
        facts: [`Sitemap(s) discovered: ${ctx.inventory.sitemaps.join(', ')}`, sitemapRes.ok ? `Primary sitemap lists ${parsed.urls.length} URLs${parsed.isIndex ? ' (index document)' : ''}.` : 'Primary sitemap referenced from robots.txt.'],
        inference: ['Sitemap URLs expand the known attack surface for further authorized testing.'],
        evidence: [ev],
      });
    }

    // 3. Crawl for entry points, third-party content, client code (REC-005/006/007)
    const c = await crawl(ctx, { startUrl: start, maxPages: ctx.params?.max_pages || 10, respectRobots: ctx.params?.respect_robots !== false });
    ctx.state.crawl = c;
    const thirdParties = new Map();
    for (const l of c.links) {
      if (l.external) {
        let host = '';
        try { host = new URL(l.url).host; } catch { continue; }
        thirdParties.set(host, (thirdParties.get(host) || 0) + 1);
      }
    }
    for (const s of c.scripts) {
      if (s.src) { try { const host = new URL(s.src).host; if (host !== base.host) thirdParties.set(host, (thirdParties.get(host) || 0) + 1); } catch { /* relative */ } }
    }
    ctx.inventory.entry_points = c.forms;
    ctx.inventory.pages = c.pages;
    ctx.inventory.third_parties = [...thirdParties.entries()].map(([host, count]) => ({ host, count }));
    if (thirdParties.size) {
      const pageEv = c.pages.length ? ctx.evidenceRaw('derived', { third_parties: ctx.inventory.third_parties, source_pages: c.pages.map((p) => p.url) }, `Third-party content inventory for ${base.host}`) : null;
      ctx.report('REC-005', {
        severity: 'info', confidence: 'confirmed',
        facts: [`Third-party content referenced from ${thirdParties.size} external hosts: ${[...thirdParties.keys()].slice(0, 15).join(', ')}.`],
        inference: ['Each third-party dependency is part of the trust boundary of the page (supply-chain and privacy exposure).'],
        evidence: [pageEv],
      });
    }
    const jsCount = c.scripts.filter((s) => s.src).length + c.scripts.filter((s) => !s.src && s.inline > 0).length;
    const evEp = ctx.evidenceRaw('derived', {
      pages: c.pages.length, forms: c.forms.map((f) => ({ page: f.page, action: f.action, method: f.method, fields: f.fields.map((x) => x.name).filter(Boolean) })),
      scripts: c.scripts.length, blocked_by_robots: c.blocked.length, fetch_errors: c.errors,
    }, `Crawl inventory for ${base.host}`);
    ctx.report('REC-006', {
      severity: 'info', confidence: 'confirmed',
      facts: [`Crawled ${c.pages.length} pages within authorized scope.`, `${c.forms.length} form entry points and ${jsCount} scripts inventoried.`, c.blocked.length ? `${c.blocked.length} URLs skipped per robots.txt.` : ''],
      inference: ['Entry points and parameters inventoried here define the surface for deeper validation testing.'],
      evidence: [evEp],
    });

    // 4. User-Agent differential (REC-011)
    const normal = ctx.pages.get(start) || await ctx.getOrFetch(start);
    const uaRes = await ctx.fetch(start, { headers: { 'user-agent': 'curl/8.0' } });
    if (normal.res.ok && uaRes.ok) {
      const same = normal.res.bodySha256 === uaRes.bodySha256;
      if (!same) {
        ctx.report('REC-011', {
          severity: 'info', confidence: 'medium',
          facts: [`Response body differs between browser UA and curl UA (sha256 ${normal.res.bodySha256?.slice(0, 12)}… vs ${uaRes.bodySha256?.slice(0, 12)}…).`],
          inference: ['Content or functionality varies by User-Agent; verify no security decisions (auth bypass, hidden admin) depend on the UA.'],
          evidence: [ctx.evidenceFrom(normal.res, 'Response with browser User-Agent'), ctx.evidenceFrom(uaRes, 'Response with curl User-Agent')],
        });
      }
    }

    // 5. Search-engine exposure hints (REC-010)
    const dom = normal.dom;
    if (dom) {
      const robotsMeta = metaGet(dom, 'robots');
      const xRobots = normal.res.headers['x-robots-tag']?.[0] || null;
      const facts = [];
      if (robotsMeta) facts.push(`Meta robots: "${robotsMeta}".`);
      if (xRobots) facts.push(`X-Robots-Tag: "${xRobots}".`);
      if (facts.length) {
        ctx.report('REC-010', {
          severity: 'info', confidence: 'confirmed', endpoint: '/',
          facts, inference: ['Indexing directives influence what search engines and caches retain; verify intent.'],
          evidence: [ctx.evidenceFrom(normal.res, 'Indexing directives in response')],
        });
      }
    }

    // 6. DNS/hostnames (REC-009) — passive via dns module when asset is domain-like
    try {
      const dns = await import('node:dns/promises');
      const addrs = await dns.resolve4(base.hostname).catch(() => []);
      const cnames = await dns.resolveCname(base.hostname).catch(() => []);
      ctx.inventory.dns = { a: addrs, cname: cnames };
      if (cnames.length) {
        ctx.report('REC-009', {
          severity: 'info', confidence: 'confirmed', target: base.hostname,
          facts: [`${base.hostname} is a CNAME for ${cnames.join(', ')}.`],
          inference: ['DNS aliases reveal hosting relationships and related infrastructure.'],
          evidence: [ctx.evidenceRaw('dns', { hostname: base.hostname, a: addrs, cname: cnames }, `DNS resolution for ${base.hostname}`)],
        });
      }
    } catch { /* dns optional */ }

    ctx.metrics.crawled_pages = c.pages.length;

    // REC-007: client-side code inventory (script resources across crawled pages)
    const scriptUrls = new Set();
    for (const [url, page] of ctx.pages) {
      const doc = page.dom;
      if (!doc) continue;
      for (const s of scripts(doc, url)) { const u = s.src || s; if (u) scriptUrls.add(new URL(u, url).toString()); }
    }
    if (scriptUrls.size) {
      ctx.report('REC-007', {
        severity: 'info', confidence: 'confirmed', target: base.hostname,
        facts: [`${scriptUrls.size} client-side script resources are referenced across ${c.pages.length} crawled pages.`],
        inference: ['Client-side code is in scope for review: secrets, API endpoints and logic shipped to browsers are visible to anyone.'],
        evidence: [ctx.evidenceRaw('derived', { scripts: [...scriptUrls].slice(0, 50) }, 'Client-side script inventory')],
      });
      ctx.inventory.scripts = [...scriptUrls].slice(0, 100);
    }

    // REC-008: network port exposure (authorized targets only — declared/common web ports)
    {
      const net = await import('node:net');
      const authorizedPorts = [...new Set([80, 443, ...(ctx.asset.authorization?.ports || [])])].filter((p) => Number.isInteger(p) && p > 0 && p < 65536);
      const probePort = (port) => new Promise((resolve) => {
        const s = net.connect({ host: base.hostname, port }, () => { s.destroy(); resolve(true); });
        s.setTimeout(2500, () => { s.destroy(); resolve(false); });
        s.on('error', () => resolve(false));
      });
      const open = [];
      for (const p of authorizedPorts) if (await probePort(p)) open.push(p);
      ctx.inventory.open_ports = open;
      ctx.report('REC-008', {
        severity: 'info', confidence: 'confirmed', target: base.hostname,
        facts: [`TCP connect probes (authorized scope only): ${authorizedPorts.join(', ')} — open: ${open.length ? open.join(', ') : '(none beyond probed set)'}.`],
        inference: ['Only ports explicitly authorized for assessment were probed; open services expand the attack surface inventory.'],
        evidence: [ctx.evidenceRaw('network', { host: base.hostname, probed: authorizedPorts, open }, 'Authorized port reachability')],
      });
    }

    // REC-012: application fingerprint summary
    {
      const gen = [];
      for (const [url, page] of ctx.pages) {
        if (!page.dom) continue;
        const g = metaGet(page.dom, 'generator');
        if (g) gen.push({ url, generator: g });
      }
      const server = ctx.pages.get(start)?.res?.headers?.['server']?.[0] || null;
      const powered = ctx.pages.get(start)?.res?.headers?.['x-powered-by']?.[0] || null;
      if (gen.length || server || powered) {
        ctx.report('REC-012', {
          severity: 'info', confidence: 'confirmed', target: base.hostname,
          facts: [`Fingerprint signals: Server=${server || 'n/a'}, X-Powered-By=${powered || 'n/a'}${gen.length ? `, meta generator=${gen[0].generator}` : ''}.`],
          inference: ['Version-disclosing fingerprints aid targeted exploitation; remove or generalize them.'],
          evidence: [ctx.evidenceRaw('derived', { server, powered_by: powered, generators: gen.slice(0, 10) }, 'Application fingerprint')],
        });
        ctx.inventory.fingerprint = { server, powered_by: powered, generators: gen.slice(0, 10) };
      }
    }

    // REC-013: related applications and hostnames
    {
      const external = new Map();
      const addHost = (u) => { try { const h = new URL(u).host; if (h && h !== base.host) external.set(h, (external.get(h) || 0) + 1); } catch { /* skip */ } };
      for (const [url, page] of ctx.pages) {
        if (!page.dom) continue;
        for (const l of links(page.dom, url)) addHost(l);
        for (const s of scripts(page.dom, url)) addHost(s.src || s); // scripts and other resources count as third-party dependencies
      }
      if (external.size) {
        ctx.report('REC-013', {
          severity: 'info', confidence: 'confirmed', target: base.hostname,
          facts: [`${external.size} distinct external hostnames are referenced from crawled pages: ${[...external.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([h, n]) => `${h} (${n} refs)`).join(', ')}.`],
          inference: ['Third-party dependencies (CDNs, analytics, fonts) inherit trust and are part of the client-side supply chain.'],
          evidence: [ctx.evidenceRaw('derived', { external_hosts: [...external.entries()].slice(0, 50) }, 'Related hostnames inventory')],
        });
        ctx.inventory.external_hosts = [...external.keys()].slice(0, 100);
      }
    }
  },
};
