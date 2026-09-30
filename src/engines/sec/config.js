import { URL } from 'node:url';
import { COMMON_FILE_PROBES, ADMIN_PATH_PROBES } from '#lib/signatures';
import { innerText } from '#lib/html';
import { ensureCrawled } from '#lib/crawl';

/** Engine: Configuration Management Testing. */
export const configEngine = {
  key: 'sec_config',
  title: 'Configuration Management Testing',
  async run(ctx) {
    const start = new URL(ctx.asset.base_url || ctx.asset.identifier);
    const origin = start.origin;
    // crawl in-scope pages so page-content checks (stack traces, sensitive HTML data)
    // see real site pages, not just the entry page and probed paths
    await ensureCrawled(ctx, { maxPages: ctx.params?.max_pages || 6 });

    // CFG-002/REC-003 exposed common files (safe GETs)
    for (const probe of COMMON_FILE_PROBES) {
      const url = new URL(probe.path, origin).toString();
      const res = await ctx.fetch(url);
      if (!res.ok || res.status !== 200) continue;
      const body = res.bodyText;
      const confirmed = probe.expect ? probe.expect.test(body.slice(0, 4096)) : body.length > 0 && res.status === 200;
      if (confirmed) {
        const sevMap = { 'environment-config': 'critical', 'version-control': 'high', 'backup-archive': 'high', 'dependency-manifest': 'medium', 'server-config': 'medium', diagnostic: 'high', admin: 'medium', 'os-metadata': 'low', 'old-file': 'medium', 'backup-file': 'medium' };
        ctx.report(probe.path === '/.env' ? 'REC-003' : 'CFG-002', {
          severity: sevMap[probe.kind] || 'medium', confidence: 'confirmed', endpoint: probe.path, target: ctx.asset.identifier,
          facts: [`GET ${probe.path} returned HTTP 200 (${res.bodyBytes} bytes, type "${res.contentType}").`, probe.kind === 'environment-config' && /SECRET|PASSWORD|KEY|TOKEN/i.test(body) ? 'Response content matches environment variable patterns including secret-like names.' : `Content classified as ${probe.kind}.`],
          inference: [probe.kind === 'environment-config' ? 'Server configuration/secrets are downloadable by unauthenticated users.' : 'A file that should not be web-accessible is exposed (information disclosure / attack surface).'],
          evidence: [ctx.evidenceFrom(res, `Exposed ${probe.kind} at ${probe.path}`)],
          affected: probe.path,
        });
        if (probe.path === '/.env') {
          const { scanForSecrets } = await import('#sec/http');
          const found = scanForSecrets(body);
          if (found.length) {
            ctx.report('CRP-007', {
              severity: 'critical', confidence: 'confirmed', endpoint: probe.path, target: ctx.asset.identifier,
              facts: found.map((f) => `Secret-like value (${f.kind}) present: ${f.redacted}`),
              inference: ['Live credentials may be extractable from this file; rotate immediately.'],
              evidence: [ctx.evidenceRaw('secret_scan', { found: found.map((f) => ({ kind: f.kind, redacted: f.redacted, sha256: f.sha256 })) }, 'Secret scan of exposed file')],
            });
          }
        }
      }
    }

    // CFG-001 admin interfaces
    for (const path of ADMIN_PATH_PROBES) {
      const res = await ctx.fetch(new URL(path, origin).toString());
      if (res.status === 200 && /<html|login|password|dashboard|admin/i.test(res.bodyText.slice(0, 3000))) {
        const hasLoginForm = /type=["']?password/i.test(res.bodyText);
        ctx.report('CFG-001', {
          severity: hasLoginForm ? 'medium' : 'high', confidence: hasLoginForm ? 'medium' : 'high',
          endpoint: path, target: ctx.asset.identifier,
          facts: [`GET ${path} returned HTTP 200.`, hasLoginForm ? 'A login form is present (interface reachable). The engine did NOT attempt credential bypass without authorization flags.' : 'Administrative content is served without an authentication prompt.'],
          inference: hasLoginForm ? ['Admin interface is internet-reachable; verify it is intended, add rate limiting and MFA.'] : ['Administrative functionality appears accessible without authentication.'],
          evidence: [ctx.evidenceFrom(res, `Admin path probe ${path}`)],
        });
      }
    }

    // CFG-003 HTTP methods + CFG-004 XST
    const opt = await ctx.fetch(start.toString(), { method: 'OPTIONS' });
    const allow = opt.headers['allow']?.[0] || opt.headers['access-control-allow-methods']?.[0] || null;
    ctx.metrics.http_methods = allow;
    const risky = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT'];
    if (allow) {
      const present = risky.filter((m) => allow.toUpperCase().split(/[\s,]+/).includes(m));
      if (present.length) {
        ctx.report('CFG-003', { severity: 'medium', confidence: 'confirmed', endpoint: '/', target: ctx.asset.identifier, facts: [`Server advertises methods: ${allow}.`, `Risky methods present: ${present.join(', ')}.`], inference: ['Unnecessary methods expand the attack surface (file upload via PUT, deletion via DELETE).'], evidence: [ctx.evidenceFrom(opt, 'OPTIONS response enumerating methods')] });
      }
    }
    const trace = await ctx.fetch(start.toString(), { method: 'TRACE', headers: { 'X-Meridian-Probe': 'xst-check' } });
    if (trace.status === 200 && /X-Meridian-Probe/i.test(trace.bodyText)) {
      ctx.report('CFG-004', { severity: 'medium', confidence: 'confirmed', endpoint: '/', target: ctx.asset.identifier, facts: ['TRACE method is enabled and echoes request headers (Cross-Site Tracing).'], inference: ['XST can be used to read HttpOnly cookies in legacy browsers.'], evidence: [ctx.evidenceFrom(trace, 'TRACE response echoing headers')] });
    }

    // CFG-005 extension handling
    const bak = await ctx.fetch(new URL('/index.html.bak', origin).toString());
    if (bak.status === 200 && /text\/plain|application\/octet-stream/i.test(bak.contentType)) {
      ctx.report('CFG-005', { severity: 'low', confidence: 'medium', endpoint: '/index.html.bak', target: ctx.asset.identifier, facts: ['Backup extension served as raw content type.'], inference: ['Backup file handling suggests stale files may exist (see CFG-002 probes).'], evidence: [ctx.evidenceFrom(bak, 'Backup extension handling')] });
    }

    // CFG-013 non-production data / stack traces: inspect crawled pages for error signatures
    const pages = ctx.pages.size ? [...ctx.pages.values()] : [];
    const errSigs = [/stack trace:?/i, /traceback \(most recent call last\)/i, /Fatal error:.+on line \d+/i, /Warning: .+\.php on line/i, /ORA-\d{5}/i, /MySQLSyntaxErrorException/i, /SQLSTATE\[/i, /Notice: Undefined/i, /java\.lang\.\w+Exception/i, /at [\w$.]+\([\w$.]+\.java:\d+\)/];
    for (const p of pages.slice(0, 10)) {
      for (const sig of errSigs) {
        if (sig.test(p.res.bodyText)) {
          ctx.report('CFG-013', {
            severity: 'high', confidence: 'confirmed', endpoint: new URL(p.url).pathname, target: ctx.asset.identifier,
            facts: [`Response contains error/debug output matching ${sig}: "${sig.exec(p.res.bodyText)?.[0]?.slice(0, 120)}".`],
            inference: ['Verbose errors disclose internals (paths, SQL, stack) — enable in production by misconfiguration.'],
            evidence: [ctx.evidenceFrom(p.res, 'Response containing stack trace / debug output')],
          });
          break;
        }
      }
    }

    // CFG-014 sensitive client-side data in HTML
    for (const p of pages.slice(0, 10)) {
      const hits = [];
      const patterns = [
        ['API key pattern', /(?:api[_-]?key|apikey)['"\s:=]{1,4}['"][A-Za-z0-9\-_]{16,}['"]/i],
        ['bearer token in HTML', /['"]Bearer [A-Za-z0-9._\-]{16,}['"]/],
        ['email list exposure', /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}(?:[^"<>]*@[a-z0-9.-]+\.[a-z]{2,}){4,}/i],
        ['internal IP addresses', /\b(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b/],
      ];
      for (const [label, re] of patterns) if (re.test(p.res.bodyText)) hits.push(label);
      if (hits.length) {
        ctx.report('CFG-014', {
          severity: 'high', confidence: 'medium', endpoint: new URL(p.url).pathname, target: ctx.asset.identifier,
          facts: [`HTML contains potentially sensitive data: ${hits.join(', ')}.`],
          inference: ['Data embedded client-side is fully readable by anyone with page access.'],
          evidence: [ctx.evidenceFrom(p.res, 'Page containing sensitive client-side data')],
        });
      }
    }

    // CFG-016 debug endpoints, CFG-017 directory listing
    for (const path of ['/debug/vars', '/actuator/env', '/_debug', '/trace']) {
      const res = await ctx.fetch(new URL(path, origin).toString());
      if (res.status === 200 && /(debug|actuator|vars|trace)/i.test(res.bodyText.slice(0, 500)) && res.bodyBytes > 50) {
        ctx.report('CFG-016', { severity: 'medium', confidence: 'medium', endpoint: path, target: ctx.asset.identifier, facts: [`GET ${path} returned HTTP 200 with ${res.bodyBytes} bytes.`], inference: ['Diagnostic endpoint exposed in production.'], evidence: [ctx.evidenceFrom(res, `Debug endpoint ${path}`)] });
      }
      if (res.status === 200 && /<title>Index of \//i.test(res.bodyText)) {
        ctx.report('CFG-017', { severity: 'medium', confidence: 'confirmed', endpoint: path, target: ctx.asset.identifier, facts: ['Directory listing is enabled.'], inference: ['Full file inventory disclosure.'], evidence: [ctx.evidenceFrom(res, `Directory listing at ${path}`)] });
      }
    }
  },
};
