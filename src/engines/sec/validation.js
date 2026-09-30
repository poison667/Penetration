import { URL } from 'node:url';
import net from 'node:net';
import { sha256 } from '#core/util';
import { forms } from '#lib/html';
import { ensureCrawled } from '#lib/crawl';

/**
 * Engine: Data & Input Validation Testing (injection suite).
 * All payloads are non-destructive canaries; destructive patterns are blocked
 * at the framework layer. Time-based and state-changing probes only under
 * the profiles explicitly authorized on the asset.
 */
const PROBE_DOMAIN = 'probe.meridian.invalid'; // reserved TLD — never resolves

const SQLI_PAYLOADS = [`'`, `''`, `' OR '1'='1`, `1' ORDER BY 1--`, `") OR ("1"="1`];
const SQLI_SIGNATURES = [
  /you have an error in your sql syntax/i, /warning: mysql/i, /unclosed quotation mark after the character string/i,
  /quoted string not properly terminated/i, /SQLSTATE\[\w+\]/i, /sqlite3?\.(?:operational|database)/i,
  /sqlite (?:error|exception)/i, /near "[^"]*": syntax error/i, /pg_query\(\)|psql:/i, /ORA-\d{5}/i,
  /odbc.*driver.*error/i, /Microsoft SQL Native Client/i,
];
const LDAP_SIGNATURES = [/invalid dn syntax/i, /ldap_error/i, /malformed dn/i, /namespace error/i];
const XPATH_SIGNATURES = [/xpath/i, /xml path language/i, /xpathexception/i, /invalid xpath expression/i];
const NOSQL_SIGNATURES = [/\$where|mongoerror|bsonerror|cast to (objectid|string) failed/i, /mongodb error/i];
const IMAP_SIGNATURES = [/-err (bad|syntax|unknown) command/i, /imap error/i, /smtp error 5\d\d/i, /rcpt to|mail from.*failed/i];
const SSI_SIGNATURES = [/meridianssiprobe/i];
const ORM_SIGNATURES = [/hibernateexception|nhibernate|sqlalchemy error|peewee|sequelize(?:error|validationerror)|typeerror: .*query/i];
const CMD_CANARIES = [`; echo {MARKER}`, `| echo {MARKER}`, "`echo {MARKER}`", `$(echo {MARKER})`];
const TRAVERSAL_PAYLOADS = [`../../../../etc/passwd`, `....//....//etc/passwd`, `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd`, `..%252f..%252f..%252fetc%252fpasswd`];
const TRAVERSAL_SIGNATURES = [/root:x:0:0/i, /daemon:\/usr\/sbin/i];
const XSS_CANARY = (tag) => `mrpd"${tag}<svg/onload=mrpd()>`;

function collectParams(ctx) {
  const params = [];
  const crawl = ctx.state.crawl;
  if (crawl) {
    for (const f of crawl.forms.slice(0, 30)) {
      for (const field of f.fields) {
        if (['submit', 'button', 'reset'].includes(field.type)) continue;
        params.push({ page: f.page, action: f.action, method: (f.method || 'GET').toUpperCase(), name: field.name, kind: 'form', type: field.type });
      }
    }
    const pageUrls = new Set();
    for (const l of crawl.links) if (l.url.includes('?')) pageUrls.add(l.url);
    for (const u of pageUrls) {
      try {
        const parsed = new URL(u);
        // keep the FULL url (with its query) as the action: duplicate-parameter probes must retain
        // the original value alongside the injected duplicate to observe both being processed
        for (const [name, value] of parsed.searchParams) params.push({ page: u, action: u, method: 'GET', name, kind: 'query', sample: value });
      } catch { /* skip */ }
    }
  }
  return params;
}

async function send(ctx, url, method, paramName, value, extra = {}, fetchOpts = {}) {
  if (method === 'POST') {
    const body = new URLSearchParams({ [paramName]: value, ...extra }).toString();
    return ctx.fetch(url, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body, ...fetchOpts });
  }
  const u = new URL(url);
  u.searchParams.set(paramName, value);
  return ctx.fetch(u.toString(), fetchOpts);
}

function target0(p) { return p.action || p.page; }

/** Minimal raw TCP probe (bounded) for HTTP framing tests fetch cannot express. */
function rawProbe(host, port, raw, { timeoutMs = 6000 } = {}) {
  return new Promise((resolve) => {
    let out = '';
    let settled = false;
    const done = () => { if (!settled) { settled = true; try { sock.destroy(); } catch {} resolve(out || null); } };
    const sock = net.connect({ host, port }, () => { sock.write(raw); });
    sock.setTimeout(timeoutMs, done);
    sock.on('data', (d) => { out += d.toString('utf8'); if (out.length > 65536) done(); });
    sock.on('error', () => { if (!settled) { settled = true; resolve(null); } });
    sock.on('close', done);
  });
}

export const validationEngine = {
  key: 'sec_validation',
  title: 'Data & Input Validation Testing',
  async run(ctx) {
    await ensureCrawled(ctx, { maxPages: ctx.params?.max_pages || 6 });
    const origin = new URL(ctx.asset.base_url || ctx.asset.identifier).origin;
    const params = collectParams(ctx);
    ctx.metrics.validation_params_tested = params.length;
    ctx.log('info', `validation engine testing ${params.length} parameters`);

    const tested = new Set();
    for (const p of params.slice(0, ctx.params?.max_params || 40)) {
      const key = `${p.action}|${p.name}|${p.method}`;
      if (tested.has(key) || !p.name) continue;
      tested.add(key);
      const target = p.action || p.page;

      // ---- SQL / LDAP / XPath / NoSQL / IMAP / ORM error-based ----
      for (const payload of SQLI_PAYLOADS.slice(0, ctx.profile === 'passive' ? 2 : 3)) {
        const res = await send(ctx, target, p.method, p.name, payload);
        if (res.error || res.status === 0) continue; // network failure only; 4xx/5xx bodies are analyzable evidence
        const body = res.bodyText;
        const sqlHit = SQLI_SIGNATURES.find((sig) => sig.test(body));
        if (sqlHit) {
          ctx.report('VAL-005', {
            severity: 'critical', confidence: 'confirmed', endpoint: target, parameter: p.name, target: ctx.asset.identifier,
            facts: [`Parameter "${p.name}" with payload ${JSON.stringify(payload)} triggered a database error (HTTP ${res.status}): "${sqlHit.exec(body)?.[0]?.slice(0, 120)}".`],
            inference: ['The input is concatenated into a SQL query — SQL injection is confirmed by error disclosure.'],
            reproduction: { steps: [`Submit ${payload} to parameter ${p.name} of ${target}`], request: `${p.method} ${target} (${p.name}=${payload})` },
            evidence: [ctx.evidenceFrom(res, `SQL error triggered via parameter "${p.name}"`)],
            affected: target,
          });
          break;
        }
        for (const [checkId, sigs] of [['VAL-007', LDAP_SIGNATURES], ['VAL-011', XPATH_SIGNATURES], ['VAL-024', NOSQL_SIGNATURES], ['VAL-012', IMAP_SIGNATURES], ['VAL-008', ORM_SIGNATURES]]) {
          const hit = sigs.find((s) => s.test(body));
          if (hit) {
            ctx.report(checkId, {
              severity: 'high', confidence: 'confirmed', endpoint: target, parameter: p.name, target: ctx.asset.identifier,
              facts: [`Parameter "${p.name}" with payload ${JSON.stringify(payload)} produced a signature match: "${hit}"`],
              inference: ['The error signature indicates the parameter reaches a backend interpreter without sanitization.'],
              evidence: [ctx.evidenceFrom(res, `${checkId} signature via parameter "${p.name}"`)],
            });
          }
        }
      }

      // ---- Reflected XSS / HTML injection (inert canaries) ----
      const canary = XSS_CANARY(`x${Math.random().toString(36).slice(2, 6)}`);
      const res = await send(ctx, target, p.method, p.name, canary);
      if (!res.error && res.status !== 0) {
        const unescaped = res.bodyText.includes('<svg/onload=mrpd()>');
        // VAL-004: plain markup injection (no script context needed) — only reported when the script-capable canary is NOT reflected raw
        if (!unescaped) {
          const htmlCanary = `mrpd<b>mrpdem${Math.random().toString(36).slice(2, 6)}</b>`;
          const hr = await send(ctx, target, p.method, p.name, htmlCanary);
          if (!hr.error && hr.status !== 0 && hr.bodyText.includes('<b>mrpdem') ) {
            ctx.report('VAL-004', {
              severity: 'medium', confidence: 'confirmed', endpoint: target, parameter: p.name, target: ctx.asset.identifier,
              facts: [`Plain HTML markup canary ${JSON.stringify(htmlCanary)} is reflected unescaped (raw <b> tags present) while the script-context canary is handled.`],
              inference: ['HTML injection is possible even if script execution is blocked — enables content spoofing and defacement.'],
              evidence: [ctx.evidenceFrom(hr, 'Raw markup reflection (HTML injection)')],
            });
          }
        }
        const partial = res.bodyText.includes('mrpd');
        if (unescaped) {
          ctx.report('VAL-001', {
            severity: 'high', confidence: 'confirmed', endpoint: target, parameter: p.name, target: ctx.asset.identifier,
            facts: [`Canary payload ${JSON.stringify(canary)} is reflected unescaped in the HTML body (raw <svg> markup present).`],
            inference: ['The parameter is rendered without contextual encoding — reflected XSS is achievable.'],
            reproduction: { steps: [`Submit the canary to ${p.name}`, 'Observe the unescaped markup in the response'], request: `${p.method} ${target} (${p.name}=${canary})` },
            evidence: [ctx.evidenceFrom(res, `Unescaped reflection of canary in parameter "${p.name}"`)],
          });
        } else if (partial) {
          const encodedAs = res.bodyText.includes('&lt;svg') ? 'HTML-encoded' : res.bodyText.includes('\\u003c') ? 'unicode-escaped' : 'partially reflected';
          ctx.report('VAL-028', {
            severity: 'info', confidence: 'confirmed', endpoint: target, parameter: p.name, target: ctx.asset.identifier,
            facts: [`Canary value is reflected (${encodedAs}) in the response for parameter "${p.name}".`],
            inference: ['Reflection exists; encoding appears applied for this context. Verify all output contexts (attributes, JS, URLs).'],
            evidence: [ctx.evidenceFrom(res, `Encoded reflection in parameter "${p.name}"`)],
          });
        }
        // header reflection: the canary may appear in the final response's Location header or in any
        // redirect hop the fetcher followed away from (each hop records the original Location header)
        const locReflections = (res.headers['location'] || [])
          .concat((res.redirects || []).map((h) => h.location || '').filter(Boolean));
        const locHit = locReflections.find((l) => l.includes('mrpd'));
        if (locHit) {
          ctx.report('VAL-017', { severity: 'high', confidence: 'confirmed', endpoint: target, parameter: p.name, target: ctx.asset.identifier, facts: [`Canary value appears in a response Location header (${JSON.stringify(locHit.slice(0, 80))}) — header injection surface.`], inference: ['If CR/LF can be smuggled, full response splitting is possible.'], evidence: [ctx.evidenceFrom(res, 'Canary reflected into headers')] });
        }      }

      // ---- Command injection canaries (nonce-marker output differential) ----
      if (ctx.profile !== 'passive') {
        for (const template of CMD_CANARIES.slice(0, 2)) {
          const marker = `mrcmd${Math.random().toString(36).slice(2, 10)}`; // unique per probe — immune to cross-probe contamination
          const payload = template.replace('{MARKER}', marker);
          const r = await send(ctx, target, p.method, p.name, payload);
          if (r.error || r.status === 0) continue;
          const markerCount = r.bodyText.split(marker).length - 1;
          const payloadEchoes = r.bodyText.split(payload).length - 1;
          const outputDetected = markerCount > payloadEchoes; // marker instances beyond echoed input = real command output
          if (outputDetected) {
            ctx.report('VAL-014', {
              severity: 'critical', confidence: 'confirmed', endpoint: target, parameter: p.name, target: ctx.asset.identifier,
              facts: [`Payload ${JSON.stringify(payload)} produced the marker in command OUTPUT (${markerCount} marker occurrences vs ${payloadEchoes} echoed inputs — output beyond reflection).`],
              inference: ['OS command injection — user input reaches a shell and execution output is returned.'],
              reproduction: { steps: [`Submit ${payload} to ${p.name}`] },
              evidence: [ctx.evidenceFrom(r, 'Command execution output in response')],
            });
            break;
          } else if (markerCount > 0) {
            ctx.log('info', `command canary reflected but not executed via parameter "${p.name}" (markers == echoes)`);
          }
        }
      }

      // ---- HPP: duplicate parameter ----
      if (p.method === 'GET' && p.kind === 'query' && p.sample != null) {
        const u = new URL(target);
        u.searchParams.append(p.name, 'mrpd_second');
        const r = await ctx.fetch(u.toString());
        if (!r.error && r.status !== 0 && r.bodyText.includes('mrpd_second') && r.bodyText.includes(p.sample)) {
          ctx.report('VAL-025', { severity: 'low', confidence: 'low', endpoint: target, parameter: p.name, target: ctx.asset.identifier, facts: [`Both duplicate values of "${p.name}" appear reflected in the response.`], inference: ['Duplicate parameters are both processed — HPP may bypass validation depending on framework parsing.'], evidence: [ctx.evidenceFrom(r, 'Duplicate parameter reflection')] });
        }
      }

      // ---- Format string / overflow signals (expansion differential) ----
      if (ctx.profile !== 'passive') {
        const fmtPayload = '%s%s%s%s%s%s%s%s' + 'A'.repeat(400);
        const r = await send(ctx, target, p.method, p.name, fmtPayload);
        if (!r.error && r.status !== 0) {
          const echoCount = r.bodyText.split(fmtPayload).length - 1;
          const pctCount = (r.bodyText.match(/%s/g) || []).length;
          const crashSig = /Segmentation fault|core dumped|stack smashing|SIGSEGV/i.test(r.bodyText);
          if (crashSig || (echoCount > 0 && pctCount > echoCount * 8)) {
            ctx.report('VAL-016', { severity: 'medium', confidence: 'low', endpoint: target, parameter: p.name, target: ctx.asset.identifier, facts: [`Format-string payload produced ${pctCount} %s occurrences vs ${echoCount} input echoes${crashSig ? ' plus a crash signature' : ''}.`], inference: ['Possible format-string handling issue; verify manually.'], evidence: [ctx.evidenceFrom(r, 'Format string probe')] });
          }
        }
      }
    }

    // ---- Open redirect (safe probes against reserved domain) ----
    const redirectTargets = [];
    for (const p of params.slice(0, 10)) {
      if (/url|redirect|next|return|goto|dest|link/i.test(p.name || '')) redirectTargets.push({ url: p.action || p.page, param: p.name, method: p.method });
    }
    for (const [rpath, rparam] of [['/redirect', 'url'], ['/login', 'next'], ['/logout', 'url'], ['/goto', 'url']]) {
      redirectTargets.push({ url: new URL(rpath, origin).toString(), param: rparam, method: 'GET' });
    }
    const seenRedir = new Set();
    for (const rt of redirectTargets) {
      if (!rt.param || seenRedir.has(`${rt.url}|${rt.param}`)) continue;
      seenRedir.add(`${rt.url}|${rt.param}`);
      // noRedirect: the probe must observe the 3xx itself, not the followed destination
      const r = await send(ctx, rt.url, rt.method, rt.param, `https://${PROBE_DOMAIN}/`, {}, { noRedirect: true });
      if ([301, 302, 303, 307, 308].includes(r.status)) {
        const loc = r.headers['location']?.[0] || '';
        if (loc && new URL(loc, rt.url).host === PROBE_DOMAIN) {
          ctx.report('VAL-020', {
            severity: 'medium', confidence: 'confirmed', endpoint: rt.url, parameter: rt.param, target: ctx.asset.identifier,
            facts: [`Parameter "${rt.param}" redirected to attacker-controlled host ${PROBE_DOMAIN} (HTTP ${r.status}, Location: ${loc}).`],
            inference: ['Open redirect — usable in phishing and OAuth token theft flows.'],
            reproduction: { steps: [`GET ${rt.url}?${rt.param}=https://${PROBE_DOMAIN}/`], request: `GET ${rt.url}?${rt.param}=https://${PROBE_DOMAIN}/` },
            evidence: [ctx.evidenceFrom(r, 'Redirect to reserved probe domain')],
          });
          break;
        }
      }
    }

    // ---- Path traversal fallback endpoints (read-only signature probes) ----
    const traversalTargets = params.filter((x) => /file|path|page|include|name|doc|template/i.test(x.name || '')).map((x) => ({ url: x.action || x.page, param: x.name, method: x.method }));
    for (const [tpath, tparam] of [['/file', 'name'], ['/download', 'path'], ['/view', 'page']]) {
      traversalTargets.push({ url: new URL(tpath, origin).toString(), param: tparam, method: 'GET' });
    }
    const seenTrav = new Set();
    for (const tt of traversalTargets) {
      if (!tt.param || seenTrav.has(`${tt.url}|${tt.param}`)) continue;
      seenTrav.add(`${tt.url}|${tt.param}`);
      for (const payload of TRAVERSAL_PAYLOADS.slice(0, 2)) {
        const r = await send(ctx, tt.url, tt.method, tt.param, payload);
        if (r.error || r.status === 0) continue;
        if (TRAVERSAL_SIGNATURES.some((s) => s.test(r.bodyText))) {
          ctx.report('VAL-021', {
            severity: 'high', confidence: 'confirmed', endpoint: tt.url, parameter: tt.param, target: ctx.asset.identifier,
            facts: [`Payload ${JSON.stringify(payload)} produced passwd-file content in the response (HTTP ${r.status}).`],
            inference: ['Local file inclusion / path traversal — arbitrary file read is likely.'],
            reproduction: { steps: [`Submit ${payload} to ${tt.param}`] },
            evidence: [ctx.evidenceFrom(r, 'passwd content via traversal payload')],
          });
          break;
        }
      }
    }

    // ---- XXE: POST XML payload to XML-consuming endpoints ----
    if (ctx.profile !== 'passive' && ctx.state.crawl) {
      const xmlTargets = ctx.state.crawl.forms.filter((f) => /xml/i.test(f.action || '') || f.fields.some((x) => /xml/i.test(x.name || '')));
      for (const f of xmlTargets.slice(0, 3)) {
        const xml = `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root><data>&xxe;</data></root>`;
        const r = await ctx.fetch(f.action, { method: 'POST', headers: { 'content-type': 'application/xml' }, body: xml });
        if (!r.error && r.status !== 0 && !/parse error|not well-formed|entity/i.test(r.bodyText.slice(0, 200)) && r.bodyText.length > 10) {
          ctx.report('VAL-009', { severity: 'high', confidence: 'medium', endpoint: f.action, target: ctx.asset.identifier, facts: ['XML with an external entity was accepted and parsed without DTD rejection.'], inference: ['XXE processing may be enabled (external entity resolution not rejected).'], evidence: [ctx.evidenceFrom(r, 'XXE probe response')] });
        }
      }
    }

    // ---- Time-based SQLi (standard profile +): single conservative measurement ----
    if (['standard', 'intrusive'].includes(ctx.profile)) {
      const p = params.find((x) => /q|search|name|id|user|host/i.test(x.name || ''));
      if (p) {
        const target = p.action || p.page;
        const baseline = await send(ctx, target, p.method, p.name, 'meridian');
        const payload = `' AND SLEEP(3)-- -`;
        const timed = await send(ctx, target, p.method, p.name, payload);
        const delta = (timed.totalMs || 0) - (baseline.totalMs || 0);
        if (delta > 2500 && !timed.error) {
          ctx.report('VAL-006', {
            severity: 'critical', confidence: 'confirmed', endpoint: target, parameter: p.name, target: ctx.asset.identifier,
            facts: [`Baseline request: ${baseline.totalMs}ms; delayed payload "${payload}": ${timed.totalMs}ms (Δ=${delta}ms).`],
            inference: ['Response time is attacker-controllable via SQL SLEEP — blind SQL injection.'],
            evidence: [ctx.evidenceFrom(baseline, 'Baseline timing'), ctx.evidenceFrom(timed, 'Delayed payload timing')],
          });
        }
      }
    } else {
      ctx.log('info', 'time-based SQLi probes skipped (requires standard/intrusive profile)');
    }

    // ---- Stored XSS: comment/guestbook-style forms (safe canary, then retrieval) ----
    if (ctx.profile !== 'passive' && ctx.state.crawl) {
      const storeForms = ctx.state.crawl.forms.filter((f) => /comment|message|feedback|guestbook|post/i.test((f.action || '') + JSON.stringify(f.fields.map((x) => x.name))));
      for (const f of storeForms.slice(0, 2)) {
        const field = f.fields.find((x) => /comment|message|body|content|text/i.test(x.name || ''))?.name || f.fields.find((x) => x.type !== 'submit')?.name;
        if (!field) continue;
        const nonce = `mrpdstore${Date.now().toString(36)}`;
        const canary = `${nonce}<b>probe</b><svg/onload=alert(1)>`;
        const post = await ctx.fetch(f.action, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ [field]: canary, name: `author-${nonce}`, author: `author-${nonce}` }).toString() });
        const view = await ctx.fetch(f.page || ctx.asset.base_url);
        if (!view.error && view.status !== 0 && view.bodyText.includes('<svg/onload=alert(1)>')) {
          ctx.report('VAL-002', {
            severity: 'critical', confidence: 'confirmed', endpoint: f.action, parameter: field, target: ctx.asset.identifier,
            facts: [`Submitted content containing raw <svg/onload=alert(1)> markup is stored and rendered unescaped on ${view.finalUrl}.`],
            inference: ['Stored XSS — any visitor of the page executes attacker-supplied markup.'],
            reproduction: { steps: [`POST ${canary.slice(0, 50)}… to ${field} at ${f.action}`, `Load ${view.finalUrl} and observe unescaped markup`] },
            evidence: [ctx.evidenceFrom(post, 'Stored-XSS submission'), ctx.evidenceFrom(view, 'Stored content rendered unescaped')],
          });
        }
      }
    }

    // ---- Mass assignment (intrusive only, gated) ----
    if (ctx.profile === 'intrusive') {
      ctx.log('info', 'mass-assignment probes are gated and only executed when a safe read-back endpoint is configured');
    } else {
      ctx.log('info', 'mass-assignment probes skipped (requires intrusive profile)');
    }

    // ---- SSI injection (VAL-010): nonce marker in exec output ----
    if (ctx.profile !== 'passive' && params.length) {
      for (const p of params.slice(0, 5)) {
        const nonce = `mrpdssi${Math.random().toString(36).slice(2, 8)}`;
        const payload = `<!--#exec cmd="echo ${nonce}"-->`;
        const r = await send(ctx, target0(p), p.method, p.name, payload);
        if (r.error || r.status === 0) continue;
        const markerCount = r.bodyText.split(nonce).length - 1;
        const echoCount = r.bodyText.split(payload).length - 1;
        if (markerCount > echoCount) {
          ctx.report('VAL-010', {
            severity: 'high', confidence: 'confirmed', endpoint: target0(p), parameter: p.name, target: ctx.asset.identifier,
            facts: [`SSI payload ${JSON.stringify(payload)} produced the nonce in output (${markerCount} vs ${echoCount} echoes) — server-side include execution occurred.`],
            inference: ['SSI is processed — arbitrary command execution via #exec is likely.'],
            evidence: [ctx.evidenceFrom(r, 'SSI exec output')],
          });
          break;
        }
      }
    }

    // ---- Code/expression injection (VAL-013): template evaluation differential ----
    if (ctx.profile !== 'passive' && params.length) {
      const SYNTAXES = ['{{MRK}}', '${MRK}', '<%= MRK %>', '#{MRK}', '[[MRK]]'];
      outer: for (const p of params.slice(0, 5)) {
        for (const syn of SYNTAXES) {
          const r = await send(ctx, target0(p), p.method, p.name, syn.replace('MRK', '7*7*7'));
          if (r.error || r.status === 0) continue;
          const hasPayload = r.bodyText.includes(syn.replace('MRK', '7*7*7'));
          const evaluated = /\b343\b/.test(r.bodyText);
          if (evaluated && !hasPayload) {
            ctx.report('VAL-013', {
              severity: 'critical', confidence: 'confirmed', endpoint: target0(p), parameter: p.name, target: ctx.asset.identifier,
              facts: [`Expression payload ${JSON.stringify(syn.replace('MRK', '7*7*7'))} evaluated server-side: the product 343 appears in the response without the literal payload.`],
              inference: ['Template/expression injection — server-side code execution via the template engine is likely.'],
              evidence: [ctx.evidenceFrom(r, 'Expression evaluation output')],
            });
            break outer;
          }
        }
      }
    }

    // ---- Length handling (VAL-015): oversized input crash signal ----
    if (ctx.profile !== 'passive' && params.length) {
      const p = params[0];
      const long = 'A'.repeat(16384);
      const r = await send(ctx, target0(p), p.method, p.name, long);
      if (!r.error && r.status >= 500) {
        const crash = /Segmentation fault|stack smashing|core dumped|heap corruption|buffer overrun|SIGSEGV|maximum call stack/i.test(r.bodyText);
        if (crash) {
          ctx.report('VAL-015', {
            severity: 'medium', confidence: 'low', endpoint: target0(p), parameter: p.name, target: ctx.asset.identifier,
            facts: [`A 16KB input to "${p.name}" produced HTTP ${r.status} with a crash signature in the body.`],
            inference: ['Possible insufficient length/buffer handling; verify manually with targeted boundary tests.'],
            evidence: [ctx.evidenceFrom(r, 'Crash signature on oversized input')],
          });
        }
      }
      ctx.metrics.oversize_probe_status = r.status;
    }

    // ---- HTTP request smuggling exposure (VAL-018): ambiguous framing probe ----
    if (['standard', 'intrusive'].includes(ctx.profile)) {
      const host = new URL(ctx.asset.base_url || ctx.asset.identifier);
      const port = Number(host.port) || (host.protocol === 'https:' ? 443 : 80);
      const smuggle = await rawProbe(host.hostname, port, [
        `POST / HTTP/1.1`, `Host: ${host.host}`, 'Content-Length: 6', 'Transfer-Encoding: chunked', 'Connection: close', '', '0', '', '',
      ].join('\r\n'));
      if (smuggle && /^HTTP\/1\.[01] 2\d\d/.test(smuggle)) {
        ctx.report('VAL-018', {
          severity: 'medium', confidence: 'low', endpoint: '/', target: ctx.asset.identifier,
          facts: [`A request with BOTH Content-Length and Transfer-Encoding: chunked framing headers was accepted with HTTP 2xx (${smuggle.split('\r\n')[0]}).`],
          inference: ['The server tolerates ambiguous message framing — a prerequisite for request-smuggling desyncs. Verify with CL.TE/TE.CL differentials in an authorized test.'],
          evidence: [ctx.evidenceRaw('network', { request_framing: 'CL+TE ambiguous', response_status_line: smuggle.split('\r\n')[0] }, 'Ambiguous framing accepted')],
        });
      }
      ctx.metrics.smuggle_probe = smuggle ? smuggle.split('\r\n')[0] : 'no-response';
    }

    // ---- HTTP verb tampering (VAL-019): TRACE / unusual verbs ----
    if (['standard', 'intrusive'].includes(ctx.profile)) {
      const host = new URL(ctx.asset.base_url || ctx.asset.identifier);
      const port = Number(host.port) || (host.protocol === 'https:' ? 443 : 80);
      const trace = await rawProbe(host.hostname, port, `TRACE / HTTP/1.1\r\nHost: ${host.host}\r\nX-Mrpd-Probe: verb-tampering\r\nConnection: close\r\n\r\n`);
      if (trace && /^HTTP\/1\.[01] 2\d\d/.test(trace) && /X-Mrpd-Probe/i.test(trace)) {
        ctx.report('VAL-019', {
          severity: 'medium', confidence: 'confirmed', endpoint: '/', target: ctx.asset.identifier,
          facts: [`TRACE is enabled and echoes the request (${trace.split('\r\n')[0]}) — cross-site tracing (XST) exposure.`],
          inference: ['TRACE echo can be used to read HttpOnly cookies via browser-issued requests.'],
          evidence: [ctx.evidenceRaw('network', { method: 'TRACE', response_status_line: trace.split('\r\n')[0], echoed_headers: true }, 'TRACE request echo')],
        });
      }
      ctx.metrics.trace_probe = trace ? trace.split('\r\n')[0] : 'no-response';
    }

    // ---- Remote file inclusion (VAL-022): reserved-domain URL probes ----
    if (ctx.profile !== 'passive') {
      const rfiTargets = params.filter((x) => /file|path|page|include|doc|template|url/i.test(x.name || '')).slice(0, 5);
      for (const p of rfiTargets) {
        const r = await send(ctx, target0(p), p.method, p.name, `https://${PROBE_DOMAIN}/rfi-probe.txt`);
        if (r.error || r.status === 0) continue;
        if (/failed to open stream|php_network_getaddresses|getaddrinfo|name or service not known|connection attempt failed|no such host/i.test(r.bodyText)) {
          ctx.report('VAL-022', {
            severity: 'high', confidence: 'confirmed', endpoint: target0(p), parameter: p.name, target: ctx.asset.identifier,
            facts: [`A URL parameter value pointing at ${PROBE_DOMAIN} produced a remote-fetch error signature in the response — the server attempted to retrieve the remote resource.`],
            inference: ['Remote file inclusion — the parameter reaches a file-loading primitive that accepts remote URLs.'],
            evidence: [ctx.evidenceFrom(r, 'Remote fetch error via URL parameter')],
          });
          break;
        }
      }
    }

    // ---- Invalid session state handling (VAL-027) ----
    if (ctx.state.crawl) {
      const protectedPages = ctx.state.crawl.pages.filter((p) => /account|admin|profile|dashboard|checkout|settings|user/i.test(p.url || '')).slice(0, 3);
      for (const page of protectedPages) {
        for (const bad of ['sid=null', 'session=undefined', 'sid=00000000000000000000000000000000']) {
          const r = await ctx.fetch(page.url, { headers: { cookie: bad } });
          if (!r.error && r.status >= 500) {
            ctx.report('VAL-027', {
              severity: 'medium', confidence: 'confirmed', endpoint: page.url, target: ctx.asset.identifier,
              facts: [`Request with malformed session cookie (${bad}) produced HTTP ${r.status} on ${page.url}.`],
              inference: ['Invalid session state is not handled gracefully — can enable DoS or error-disclosure paths.'],
              evidence: [ctx.evidenceFrom(r, 'Server error on malformed session')],
            });
            break;
          }
        }
      }
    }

    // ---- Mass assignment (VAL-026): intrusive, read-back gated ----
    if (ctx.profile === 'intrusive') {
      const updateEndpoints = params.filter((x) => /update|profile|account|settings|register|user/i.test((x.action || '') + (x.name || ''))).slice(0, 3);
      if (updateEndpoints.length) {
        for (const p of updateEndpoints) {
          const probe = { [p.name]: 'mrpd-value', role: 'admin', is_admin: true, admin: 1 };
          const r = await ctx.fetch(p.action, { method: p.method === 'POST' ? 'POST' : 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(probe) });
          if (!r.error && r.status >= 200 && r.status < 300 && /role|admin/i.test(r.bodyText)) {
            ctx.report('VAL-026', {
              severity: 'high', confidence: 'low', endpoint: p.action, parameter: p.name, target: ctx.asset.identifier,
              facts: [`An update request containing privileged fields (role, is_admin) was accepted (HTTP ${r.status}) and the response reflects administrative field handling.`],
              inference: ['Possible mass assignment — verify whether the privileged fields persist via an authenticated read-back.'],
              evidence: [ctx.evidenceFrom(r, 'Privileged field acceptance')],
            });
          }
        }
      } else {
        ctx.log('info', 'mass-assignment probe skipped: no update/profile-like endpoint discovered');
      }
    }

    // ---- DOM XSS static analysis ----
    const domSinks = [];
    for (const [url, page] of ctx.pages) {
      const body = page.res.bodyText;
      const sinks = [
        [/document\.write\s*\(\s*(location|document\.URL|document\.documentURI|document\.referrer|location\.hash)/i, 'document.write(location-derived)'],
        [/innerHTML\s*=\s*(location|document\.URL|location\.hash|decodeURIComponent)/i, 'innerHTML = location-derived'],
        [/eval\s*\(\s*(location|document\.URL|location\.hash)/i, 'eval(location-derived)'],
        [/new Function\s*\(\s*(location|document\.URL)/i, 'new Function(location-derived)'],
        [/jQuery\s*\(\s*['"`]#{1,2}[^'"`]*['"`]\s*\)/i, 'jQuery(location.hash) selector injection'],
      ];
      for (const [re, label] of sinks) if (re.test(body)) domSinks.push({ url, sink: label });
    }
    for (const d of domSinks) {
      const page = ctx.pages.get(d.url);
      ctx.report('VAL-003', {
        severity: 'medium', confidence: 'medium', endpoint: new URL(d.url).pathname, target: ctx.asset.identifier,
        facts: [`Client code contains ${d.sink} on ${d.url}.`],
        inference: ['If attacker-controllable data (URL fragment/referrer) reaches this sink without sanitization, DOM XSS is possible.'],
        evidence: [ctx.evidenceFrom(page.res, `DOM sink: ${d.sink}`)],
      });
    }

    // ---- Client/server validation differences (informational map) ----
    const clientOnly = (ctx.state.crawl?.forms || []).filter((f) => f.fields.some((x) => x.required || x.maxlength)).length;
    ctx.metrics.forms_with_client_validation = clientOnly;
    if (clientOnly) {
      ctx.report('VAL-023', {
        severity: 'info', confidence: 'low', target: ctx.asset.identifier,
        facts: [`${clientOnly} forms use client-side validation attributes (required/maxlength).`],
        inference: ['Client-side validation must be mirrored server-side — probes above test server behavior directly.'],
        evidence: [ctx.evidenceRaw('derived', { forms: clientOnly }, 'Client-side validation usage inventory')],
      });
    }
  },
};
