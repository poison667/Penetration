import { test } from 'node:test';
import assert from 'node:assert/strict';
import { crawl } from '#lib/crawl';
import { buildContext } from '#engines';
import { createServer } from 'node:http';

/** Real in-process website the crawler must actually discover and map. */
function miniSite() {
  const pages = {
    '/': { body: '<html><head><title>Home</title></head><body><a href="/about">About</a> <a href="/private/secret">Secret</a> <a href="https://elsewhere.example/x">Ext</a></body></html>', type: 'text/html' },
    '/about': { body: '<html><head><title>About</title></head><body><a href="/contact">Contact</a></body></html>', type: 'text/html' },
    '/contact': { body: '<html><head><title>Contact</title></head><body>contact page</body></html>', type: 'text/html' },
    '/private/secret': { body: '<html><body>disallowed by robots</body></html>', type: 'text/html' },
    '/robots.txt': { body: 'User-agent: *\nDisallow: /private/\n', type: 'text/plain' },
  };
  const server = createServer((req, res) => {
    const p = new URL(req.url, 'http://x').pathname;
    const page = pages[p];
    if (!page) { res.writeHead(404, { 'content-type': 'text/plain' }); return res.end('nope'); }
    res.writeHead(200, { 'content-type': page.type });
    res.end(page.body);
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

test('crawl discovers same-host pages, skips external and non-html, respects robots.txt', async () => {
  const server = await miniSite();
  try {
    const port = server.address().port;
    const ctx = buildContext({ db: null, job: { tenant_id: 't1', id: 'job_crawl' }, asset: { identifier: `http://127.0.0.1:${port}`, authorization: { allow_private: true, scope_domains: ['127.0.0.1'] } }, service: { key: 'web_audit', profiles: ['safe'] }, params: {} });
    const out = await crawl(ctx, { startUrl: `http://127.0.0.1:${port}/`, maxPages: 10 });
    const urls = out.pages.map((p) => new URL(p.url).pathname).sort();
    assert.deepEqual(urls, ['/', '/about', '/contact']); // /private blocked by robots, external ignored
    assert.ok(out.blocked.some((u) => u.includes('/private/secret')), 'robots-disallowed URL must be recorded as blocked');
    assert.equal(out.errors.length, 0);
    assert.ok(out.links.some((l) => l.url === 'https://elsewhere.example/x'), 'external link recorded in graph');
    assert.ok(ctx.pages.size >= 3, 'page cache populated');
    assert.ok(ctx.state.robots, 'robots state cached for composite engines');
    // titles came from real DOM parsing
    const home = out.pages.find((p) => p.url.endsWith('/'));
    assert.equal(home.title, 'Home');
    // robots off → secret page reachable (authorized testing mode)
    const ctx2 = buildContext({ db: null, job: { tenant_id: 't1', id: 'job_crawl2' }, asset: { identifier: `http://127.0.0.1:${port}`, authorization: { allow_private: true, scope_domains: ['127.0.0.1'] } }, service: { key: 'web_audit', profiles: ['safe'] }, params: {} });
    const out2 = await crawl(ctx2, { startUrl: `http://127.0.0.1:${port}/`, maxPages: 10, respectRobots: false });
    assert.ok(out2.pages.some((p) => p.url.includes('/private/secret')), 'respectRobots=false must allow the disallowed path');
    // ensureCrawled reuses existing state instead of re-fetching
    const before = ctx2.requests;
    const { ensureCrawled } = await import('#lib/crawl');
    await ensureCrawled(ctx2, { maxPages: 10, respectRobots: false });
    assert.equal(ctx2.requests, before, 'ensureCrawled must reuse ctx.state.crawl');
  } finally {
    server.close();
  }
});

test('crawl honors maxPages budget', async () => {
  const server = await miniSite();
  try {
    const port = server.address().port;
    const ctx = buildContext({ db: null, job: { tenant_id: 't1', id: 'job_crawl3' }, asset: { identifier: `http://127.0.0.1:${port}`, authorization: { allow_private: true, scope_domains: ['127.0.0.1'] } }, service: { key: 'web_audit', profiles: ['safe'] }, params: {} });
    const out = await crawl(ctx, { startUrl: `http://127.0.0.1:${port}/`, maxPages: 2 });
    assert.equal(out.pages.length, 2);
  } finally {
    server.close();
  }
});
