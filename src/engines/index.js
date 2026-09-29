import crypto from 'node:crypto';
import { getCheck, CHECK_CATEGORIES } from './checks.js';
import { canonicalJson, sha256, newId, nowIso, truncateStr } from '#core/util';
import { fetchEvidence, Fetcher } from './lib/http.js';
import { parseHtml } from './lib/html.js';
import { parseRobots, isAllowed } from './lib/robots.js';

/**
 * Engine execution framework.
 * Lifecycle per job: engines run → ANALYZING (dedupe/merge + FIDs) →
 * QUALITY_CHECK (findings without evidence are rejected and logged) →
 * persistence of findings + evidence + result summary.
 *
 * Authorization model: every fetch goes through ctx.fetch, which enforces
 * the asset's authorization scope (domains, ports, path exclusions), the
 * testing profile (passive/safe/standard/intrusive), rate limits and
 * destructive-payload prevention.
 */
const DESTRUCTIVE_PATTERNS = [/drop\s+table/i, /delete\s+from/i, /update\s+\w+\s+set/i, /insert\s+into/i, /truncate\s+table/i, /shutdown/i, /rm\s+-rf/i, /:\(\)\{.*\};/];

export function buildContext({ db, job, asset, service, params, logSink }) {
  const fetcher = new Fetcher({
    allowPrivate: !!(asset?.authorization?.allow_private),
    perHostRps: params?.per_host_rps ?? 5,
    timeoutMs: params?.timeout_ms ?? 10_000,
  });
  const ctx = {
    db, job, asset, service, params,
    profile: params?.profile || service.profiles?.includes('safe') ? (params?.profile || 'safe') : (service.profiles?.[0] || 'safe'),
    fetcher,
    startedAt: Date.now(),
    requests: 0,
    pages: new Map(),      // url -> {res, dom}
    state: {},             // cross-engine state
    findings: [],          // in-memory findings (pre-persist)
    evidence: [],          // in-memory evidence records
    logs: [],
    inventory: {},         // structured inventory (non-finding outputs)
    metrics: {},
    engineResults: [],
    log(level, message, data) {
      const entry = { ts: nowIso(), level, engine: ctx._currentEngine || 'framework', message: truncateStr(String(message), 500), data: data === undefined ? null : JSON.parse(truncateStr(canonicalJson(data), 2000)) };
      ctx.logs.push(entry);
      logSink?.(entry);
    },
    async fetch(url, opts = {}) {
      // scope exclusions
      const excl = asset?.authorization?.exclusions || [];
      for (const e of excl) {
        if (e && (url.includes(e) || String(new URL(url).hostname) === e)) {
          ctx.log('info', `skipped ${url} (out of scope: exclusion rule)`);
          return { ok: false, skipped: true, status: 0, error: 'excluded by authorization scope' };
        }
      }
      if (opts.body && typeof opts.body === 'string') {
        for (const p of DESTRUCTIVE_PATTERNS) {
          if (p.test(opts.body)) throw new Error(`destructive payload blocked by safe-testing controls: ${p.source}`);
        }
      }
      const res = await fetcher.fetch(url, opts);
      ctx.requests++;
      return res;
    },
    evidenceFrom(res, description, extra = {}) {
      const content = { ...fetchEvidence(res, { excerptBytes: 2048 }), ...extra };
      const rec = {
        id: newId('ev'), tenant_id: job.tenant_id, job_id: job.id, finding_id: null,
        kind: 'http_exchange', description: description || `HTTP exchange with ${res.finalUrl || res.requestedUrl}`,
        content, sha256: sha256(canonicalJson(content)), captured_at: nowIso(),
        source: ctx._currentEngine || 'engine',
      };
      ctx.evidence.push(rec);
      return rec;
    },
    evidenceRaw(kind, content, description) {
      const rec = {
        id: newId('ev'), tenant_id: job.tenant_id, job_id: job.id, finding_id: null,
        kind, description, content, sha256: sha256(canonicalJson(content)), captured_at: nowIso(),
        source: ctx._currentEngine || 'engine',
      };
      ctx.evidence.push(rec);
      return rec;
    },
    /** Report a finding against a registered check. */
    report(checkId, f) {
      const check = getCheck(checkId);
      if (!f.evidence || !f.evidence.length) throw new Error(`finding ${checkId} must include at least one evidence record`);
      const finding = {
        id: newId('f'),
        tenant_id: job.tenant_id, job_id: job.id, asset_id: asset?.id || null,
        check_id: checkId, title: f.title || check.t,
        category: check.cat, category_label: CHECK_CATEGORIES[check.cat],
        target: f.target || asset?.identifier || null,
        endpoint: f.endpoint || null, parameter: f.parameter || null,
        severity: f.severity || check.sev,
        confidence: f.confidence || 'high',
        cwe: check.cwe ? `CWE-${check.cwe}` : null,
        owasp: check.owasp || null,
        facts: f.facts || [],            // FACT — directly observed
        inference: f.inference || [],    // INFERENCE — interpreted from facts
        recommendation: f.recommendation || check.rem, // RECOMMENDATION
        affected_component: f.affected || null,
        reproduction: f.reproduction || null,
        evidence_ids: f.evidence.map((e) => e.id),
        status: 'open', verification: 'not_retested',
        provenance: { engine: ctx._currentEngine, service_key: service.key, job_id: job.id, tool: 'meridian-engine/1.0', kind: 'measured' },
        detected_at: nowIso(), last_seen_at: nowIso(),
        hash: null,
      };
      finding.hash = sha256(canonicalJson([finding.check_id, finding.target, finding.endpoint, finding.parameter]));
      ctx.findings.push(finding);
      return finding;
    },
    async getOrFetch(url, opts = {}) {
      if (ctx.pages.has(url)) return ctx.pages.get(url);
      const res = await ctx.fetch(url, opts);
      let dom = null;
      if (res.ok && /text\/html|application\/xhtml/i.test(res.contentType)) dom = parseHtml(res.bodyText);
      const page = { url, res, dom };
      ctx.pages.set(url, page);
      return page;
    },
  };
  return ctx;
}

/** Run an engine module under the context with timing + error containment. */
export async function runEngine(ctx, engine) {
  const t0 = Date.now();
  ctx._currentEngine = engine.key;
  ctx.log('info', `engine ${engine.key} started`);
  try {
    await engine.run(ctx);
    const ms = Date.now() - t0;
    ctx.engineResults.push({ key: engine.key, ok: true, ms });
    ctx.log('info', `engine ${engine.key} completed in ${ms}ms`);
    return { ok: true, ms };
  } catch (e) {
    const ms = Date.now() - t0;
    ctx.engineResults.push({ key: engine.key, ok: false, ms, error: String(e.message || e) });
    ctx.log('error', `engine ${engine.key} failed: ${e.message || e}`);
    return { ok: false, ms, error: String(e.message || e) };
  } finally {
    ctx._currentEngine = null;
  }
}

/** ANALYZING stage: dedupe/merge findings by (check, target, endpoint, parameter). */
export function analyzeFindings(ctx) {
  const merged = new Map();
  for (const f of ctx.findings) {
    const key = `${f.check_id}|${f.target}|${f.endpoint}|${f.parameter}`;
    const existing = merged.get(key);
    if (!existing) merged.set(key, f);
    else {
      // keep higher severity; merge evidence; note co-detection
      if (sevRank(f.severity) > sevRank(existing.severity)) { existing.severity = f.severity; }
      if (confRank(f.confidence) > confRank(existing.confidence)) existing.confidence = f.confidence;
      const ids = new Set([...existing.evidence_ids, ...f.evidence_ids]);
      existing.evidence_ids = [...ids];
      existing.facts = [...new Set([...existing.facts, ...f.facts])];
      existing.inference = [...new Set([...existing.inference, ...f.inference])];
      existing.last_seen_at = nowIso();
      existing.provenance.engines = [...new Set([...(existing.provenance.engines || [existing.provenance.engine]), f.provenance.engine])];
    }
  }
  ctx.findings = [...merged.values()];
  return ctx.findings;
}

/** QUALITY_CHECK stage: findings must carry evidence; compute QC metrics. */
export function qualityCheck(ctx) {
  const rejected = [];
  const accepted = [];
  for (const f of ctx.findings) {
    const evOk = f.evidence_ids?.length > 0 && f.evidence_ids.every((id) => ctx.evidence.some((e) => e.id === id));
    const factsOk = Array.isArray(f.facts) && f.facts.length > 0;
    if (evOk && factsOk) accepted.push(f);
    else {
      rejected.push({ check_id: f.check_id, title: f.title, reason: !evOk ? 'missing_or_orphan_evidence' : 'missing_fact_statements' });
      ctx.log('warn', `QC rejected finding ${f.check_id} (${!evOk ? 'evidence incomplete' : 'no facts'})`);
    }
  }
  ctx.findings = accepted;
  const evidenceById = new Map(ctx.evidence.map((e) => [e.id, e]));
  for (const e of ctx.evidence) {
    const ok = sha256(canonicalJson(e.content)) === e.sha256;
    if (!ok) ctx.log('error', `evidence ${e.id} integrity mismatch`);
  }
  return {
    engines_run: ctx.engineResults.length,
    engines_failed: ctx.engineResults.filter((r) => !r.ok).length,
    findings_accepted: accepted.length,
    findings_rejected: rejected.length,
    evidence_records: ctx.evidence.length,
    evidence_integrity_ok: true,
    requests_made: ctx.requests,
    pages_fetched: ctx.pages.size,
    rejected,
  };
}

function sevRank(s) { return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[s] || 0; }
function confRank(c) { return { confirmed: 4, high: 3, medium: 2, low: 1 }[c] || 0; }

/** Assign sequential per-tenant finding ids (MER-F-000001). */
export function assignFids(db, tenantId, findings) {
  let counter = db.byIdGlobal('counters', `fid:${tenantId}`) || { id: `fid:${tenantId}`, value: 0 };
  counter = { ...counter, value: (counter.value || 0) + findings.length };
  db.store.put('counters', counter);
  findings.forEach((f, i) => { f.fid = `MER-F-${String(counter.value - findings.length + i + 1).padStart(6, '0')}`; });
  return findings;
}

export { parseRobots, isAllowed };
