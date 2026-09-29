import { crawl } from '#lib/crawl';

/** Engine: Crawl & Spider — page/entry-point inventory. */
export const crawlEngine = {
  key: 'crawl',
  title: 'Website Crawl & Spider',
  async run(ctx) {
    const start = ctx.asset.base_url || ctx.asset.identifier;
    const c = await crawl(ctx, { startUrl: start, maxPages: ctx.params?.max_pages || 10, respectRobots: ctx.params?.respect_robots !== false });
    ctx.state.crawl = c;
    ctx.inventory.pages = c.pages;
    ctx.inventory.forms = c.forms;
    ctx.inventory.scripts = c.scripts;
    const ev = ctx.evidenceRaw('crawl', {
      pages: c.pages, forms: c.forms, scripts: c.scripts.filter((s) => s.src).map((s) => s.src),
      link_count: c.links.length, blocked: c.blocked, errors: c.errors,
    }, `Crawl of ${start} (${c.pages.length} pages)`);
    ctx.report('REC-006', {
      severity: 'info', confidence: 'confirmed', target: ctx.asset.identifier,
      facts: [
        `Crawled ${c.pages.length} pages, discovered ${c.links.length} links, ${c.forms.length} forms.`,
        c.errors.length ? `${c.errors.length} URLs failed to fetch.` : 'All fetched URLs responded.',
      ],
      inference: ['The crawl graph and parameter inventory scope deeper audit engines.'],
      evidence: [ev],
    });
    ctx.metrics.crawled_pages = c.pages.length;
  },
};
