import { URL } from 'node:url';
import { parseRobots, isAllowed } from './robots.js';
import { links, forms, scripts, title as pageTitle } from './html.js';

/**
 * Polite breadth-first crawler: stays on the asset's authorized host scope,
 * respects robots.txt (unless explicitly disabled for authorized testing),
 * records page inventory, forms, scripts and link graph.
 */
export async function crawl(ctx, { startUrl, maxPages = 10, respectRobots = true } = {}) {
  const base = new URL(startUrl);
  const queue = [base.toString()];
  const seen = new Set(queue.map((u) => normalize(u)));
  const out = { pages: [], links: [], forms: [], scripts: [], blocked: [], errors: [] };

  let robots = ctx.state.robots || null;
  if (respectRobots && !robots) {
    const res = await ctx.fetch(new URL('/robots.txt', base).toString());
    if (res.ok) { robots = parseRobots(res.bodyText); ctx.state.robots = robots; }
  }

  while (queue.length && out.pages.length < maxPages) {
    const url = queue.shift();
    if (robots && !isAllowed(robots, ctx.fetcher.userAgent, new URL(url).pathname).allowed) {
      out.blocked.push(url);
      continue;
    }
    const page = await ctx.getOrFetch(url);
    if (!page.res.ok || !page.dom) {
      out.errors.push({ url, status: page.res.status, error: page.res.error });
      continue;
    }
    const u = new URL(url);
    if (u.host !== base.host) continue;
    out.pages.push({ url, status: page.res.status, title: pageTitle(page.dom), bytes: page.res.bodyBytes });
    const ls = links(page.dom, url);
    out.links.push(...ls.map((l) => ({ from: url, ...l })));
    out.forms.push(...forms(page.dom, url).map((f) => ({ page: url, ...f })));
    for (const s of scripts(page.dom, url)) out.scripts.push({ page: url, ...s });
    for (const l of ls) {
      if (!l.url.startsWith('http')) continue;
      const lu = new URL(l.url);
      if (lu.host !== base.host) continue;
      const n = normalize(l.url);
      if (!seen.has(n) && !/\.(jpg|jpeg|png|gif|svg|ico|css|woff2?|ttf|eot|pdf|zip|mp4|webm)$/i.test(lu.pathname)) {
        seen.add(n);
        queue.push(lu.toString());
      }
    }
  }
  ctx.state.crawl = out;
  return out;
}

/** Engines that need crawl state call this — crawls lazily if not already done (composite runs share the result). */
export async function ensureCrawled(ctx, { maxPages = 8 } = {}) {
  if (!ctx.state.crawl) {
    const start = ctx.asset.base_url || ctx.asset.identifier;
    await crawl(ctx, { startUrl: start, maxPages, respectRobots: ctx.params?.respect_robots !== false });
  }
  return ctx.state.crawl;
}

function normalize(u) {
  try {
    const x = new URL(u);
    return `${x.origin}${x.pathname}${x.search}`;
  } catch { return u; }
}
