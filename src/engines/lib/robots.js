/**
 * robots.txt parsing (Robots Exclusion Protocol, pragmatic subset) and
 * sitemap.xml discovery/parsing.
 */
export function parseRobots(text) {
  const groups = [];
  const sitemaps = [];
  let current = null;
  let lastAgents = [];
  for (const rawLine of String(text ?? '').split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, '').trim();
    if (!line) continue;
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    const field = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    if (field === 'user-agent') {
      if (!current || current.rules.length || current.delay != null) {
        if (current) groups.push(current);
        current = { agents: [], rules: [], delay: null };
      }
      current.agents.push(value.toLowerCase());
    } else if (field === 'sitemap') {
      if (/^https?:\/\//i.test(value)) sitemaps.push(value);
    } else if (field === 'disallow' || field === 'allow') {
      if (!current) current = { agents: [], rules: [], delay: null };
      current.rules.push({ type: field, path: value });
    } else if (field === 'crawl-delay') {
      const d = parseFloat(value);
      if (!Number.isNaN(d) && current) current.delay = d;
    }
  }
  if (current) groups.push(current);
  return { groups, sitemaps };
}

function pathMatches(pattern, path) {
  if (pattern === '') return { match: false, len: 0 };
  let p = pattern;
  let end = false;
  if (p.endsWith('$')) { end = true; p = p.slice(0, -1); }
  const reSrc = p.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  const re = new RegExp(`^${reSrc}${end ? '$' : ''}`);
  const m = re.test(path);
  return { match: m, len: p.length };
}

/** Returns {allowed: boolean, rule: string|null} for a UA and path. */
export function isAllowed(robots, userAgent, path) {
  const ua = (userAgent || '*').toLowerCase();
  let group = robots.groups.find((g) => g.agents.includes(ua));
  if (!group) group = robots.groups.find((g) => g.agents.includes('*'));
  if (!group) return { allowed: true, rule: null };
  let best = null;
  for (const r of group.rules) {
    const m = pathMatches(r.path, path);
    if (!m.match) continue;
    if (!best || m.len > best.len) best = { type: r.type, len: m.len };
  }
  if (!best) return { allowed: true, rule: null };
  return { allowed: best.type === 'allow', rule: best.type };
}

/** Parse a sitemap or sitemap-index XML document. */
export function parseSitemap(xml) {
  const urls = [];
  const sitemaps = [];
  const locRe = /<loc>\s*([^<]+?)\s*<\/loc>/gi;
  let m;
  const isIndex = /<sitemapindex/i.test(xml);
  while ((m = locRe.exec(xml)) !== null) {
    const loc = m[1].trim();
    if (isIndex) sitemaps.push(loc);
    else urls.push(loc);
  }
  return { isIndex, urls, sitemaps };
}
