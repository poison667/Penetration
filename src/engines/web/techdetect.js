import { metaGet, scripts as getScripts } from '#lib/html';
import { TECH_SIGNATURES } from '#lib/signatures';

/** Engine: Technology Detection — fingerprint from real responses. */
export const techDetectEngine = {
  key: 'techdetect',
  title: 'Technology Detection',
  async run(ctx) {
    const start = ctx.asset.base_url || ctx.asset.identifier;
    const page = await ctx.getOrFetch(start);
    if (!page.res.ok) throw new Error(`cannot fetch start URL: ${page.res.error || page.res.status}`);
    const headers = page.res.headers;
    const body = page.res.bodyText;
    const meta = page.dom ? { generator: metaGet(page.dom, 'generator') } : {};
    const scripts = page.dom ? getScripts(page.dom, start) : [];
    const cookies = page.res.setCookies;

    const detected = [];
    for (const sig of TECH_SIGNATURES) {
      try {
        if (sig.match(headers, body, meta, scripts, cookies)) {
          detected.push({ tech: sig.tech, kind: sig.kind });
        }
      } catch { /* signature errors never abort the engine */ }
    }
    ctx.inventory.technologies = detected;

    // Version detail extraction where disclosed
    const serverHeader = headers['server']?.[0];
    const xpb = headers['x-powered-by']?.[0];
    const versionFacts = [];
    if (serverHeader) versionFacts.push(`Server header: "${serverHeader}".`);
    if (xpb) versionFacts.push(`X-Powered-By header: "${xpb}".`);
    if (meta.generator) versionFacts.push(`Meta generator: "${meta.generator}".`);

    if (detected.length || versionFacts.length) {
      const ev = ctx.evidenceRaw('fingerprint', {
        detected, server: serverHeader || null, x_powered_by: xpb || null, generator: meta.generator || null,
        set_cookies: cookies.map((c) => c.split('=')[0]), script_hints: scripts.filter((s) => s.src).map((s) => s.src).slice(0, 30),
      }, `Technology fingerprint for ${ctx.asset.identifier}`);
      ctx.report('REC-004', {
        severity: 'info', confidence: 'confirmed', endpoint: new URL(start).pathname,
        facts: [
          detected.length ? `Detected technologies: ${detected.map((d) => d.tech).join(', ')}.` : 'No technologies fingerprinted beyond disclosed headers.',
          ...versionFacts,
        ],
        inference: ['Fingerprinted components should be tracked for vulnerabilities and kept patched (supply-chain risk).'],
        evidence: [ev],
      });
      if (serverHeader && /[0-9]+\.[0-9]+/.test(serverHeader)) {
        ctx.report('CFG-015', {
          severity: 'info', confidence: 'confirmed', endpoint: '/',
          facts: [`Server header discloses version information: "${serverHeader}".`],
          inference: ['Exact versions let attackers map known CVEs efficiently.'],
          evidence: [ev],
        });
      }
    }
    ctx.metrics.technologies_detected = detected.length;
  },
};
