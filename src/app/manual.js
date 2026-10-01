/**
 * Manual-work hub (specification Part 9 — delivery extension).
 *
 * Real assessments combine automated scanning with manual testing. This
 * module gives manual work first-class records:
 *
 *   - createManualFinding: a human-identified issue stored with the SAME
 *     structure as engine findings (fid, hash, evidence, categories), so it
 *     flows into the same findings views, retests and reports.
 *   - parseHar / importHar: HTTP Archive (HAR 1.2) import — the export format
 *     produced by browser DevTools, Burp Suite ("Save item as… HAR") and
 *     OWASP ZAP. Every imported exchange becomes a normal evidence record
 *     that can be attached to manual findings.
 *
 * Evidence discipline is unchanged: a manual finding must carry at least one
 * evidence record (a tester note and/or imported HAR exchanges) — the QC
 * invariant "no finding without evidence" applies to humans too.
 */
import { canonicalJson, sha256, nowIso, newId } from '#core/util';
import { badRequest } from '#core/errors';
import { getCheck, CHECK_CATEGORIES } from '../engines/checks.js';
import { assignFids } from '../engines/index.js';
import { recordAudit } from '#app/audit';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const MAX_BODY_BYTES = 32 * 1024;   // per HAR request/response body kept
const MAX_ENTRIES = 500;            // per import
const MAX_HEADER_BYTES = 8 * 1024;  // per header value kept

const trunc = (s, n) => (s == null ? null : (String(s).length > n ? String(s).slice(0, n) + `…[truncated ${String(s).length - n} chars]` : String(s)));

/** Create a manual finding (same record shape as engine findings). */
export function createManualFinding({ db, tenantId, userId = null, body }) {
  const title = String(body.title || '').trim();
  if (!title || title.length < 4) throw badRequest('title is required (at least 4 characters)');
  const description = String(body.description || '').trim();
  if (!description) throw badRequest('description is required — state what you observed (this becomes the finding FACT)');
  const severity = body.severity || 'medium';
  if (!SEVERITIES.includes(severity)) throw badRequest(`severity must be one of: ${SEVERITIES.join(', ')}`);
  const checkId = body.check_id || 'MAN-001';
  if (!/^MAN-00[1-4]$/.test(checkId)) throw badRequest('manual findings must use check ids MAN-001…MAN-004');
  const check = getCheck(checkId);
  const asset = body.asset_id ? db.byId('assets', tenantId, body.asset_id) : null;
  if (body.asset_id && !asset) throw badRequest('asset not found for this tenant');

  const evidence = [];
  // tester note is always the first evidence record
  evidence.push({
    id: newId('ev'), tenant_id: tenantId, job_id: null, finding_id: null,
    kind: 'manual_note', description: `Manual tester note by ${userId || 'unknown user'}`,
    content: { note: trunc(description, 8192), entered_at: nowIso() },
    sha256: null, captured_at: nowIso(), source: 'manual', captured_by: userId || null,
  });
  // optional pasted HTTP exchange
  if (body.http_exchange) {
    const { request, response } = body.http_exchange;
    if (!request?.url) throw badRequest('http_exchange.request.url is required');
    const content = {
      request: { method: request.method || 'GET', url: trunc(request.url, 2048), headers: trunc(request.headers, MAX_HEADER_BYTES), body: trunc(request.body, MAX_BODY_BYTES) },
      response: { status: Number(response?.status) || 0, headers: trunc(response?.headers, MAX_HEADER_BYTES), body: trunc(response?.body, MAX_BODY_BYTES) },
    };
    evidence.push({
      id: newId('ev'), tenant_id: tenantId, job_id: null, finding_id: null,
      kind: 'http_exchange', description: `Manual HTTP exchange: ${content.request.method} ${content.request.url}`,
      content, sha256: null, captured_at: nowIso(), source: 'manual', captured_by: userId || null,
    });
  }
  // link imported HAR evidence records
  const harIds = Array.isArray(body.har_evidence_ids) ? body.har_evidence_ids : [];
  for (const id of harIds) {
    const ev = db.byId('evidence', tenantId, id);
    if (!ev) throw badRequest(`har evidence ${id} not found for this tenant`);
    if (ev.kind !== 'har_exchange') throw badRequest(`evidence ${id} is not a HAR exchange`);
    evidence.push(ev);
  }

  const target = asset?.identifier || (body.target ? String(body.target) : 'manual');
  const endpoint = body.endpoint ? String(body.endpoint).slice(0, 300) : null;
  const parameter = body.parameter ? String(body.parameter).slice(0, 200) : null;

  const finding = {
    id: newId('f'), tenant_id: tenantId, job_id: null, asset_id: asset?.id || null,
    check_id: checkId, title: title.slice(0, 200),
    category: check.cat, category_label: CHECK_CATEGORIES[check.cat],
    target, endpoint, parameter,
    severity, confidence: 'confirmed', // a human verified it by definition
    cwe: body.cwe ? `CWE-${String(body.cwe).replace(/^CWE-/, '')}` : null,
    owasp: body.owasp || null,
    facts: [trunc(description, 8192)],
    inference: [],
    recommendation: body.recommendation ? trunc(body.recommendation, 4000) : check.rem,
    affected_component: null,
    reproduction: body.reproduction ? trunc(body.reproduction, 4000) : null,
    evidence_ids: [],
    status: 'open', verification: 'not_retested',
    provenance: { engine: 'manual', service_key: 'manual', job_id: null, tool: 'meridian-manual/1.0', kind: 'manual', entered_by: userId || null },
    detected_at: nowIso(), last_seen_at: nowIso(), first_detected_at: nowIso(),
    hash: null, fid: null,
  };
  finding.hash = sha256(canonicalJson([finding.check_id, finding.target, finding.endpoint, finding.parameter]));

  // persist evidence (compute sha over content), then the finding with FID
  for (const ev of evidence) {
    ev.sha256 = sha256(canonicalJson(ev.content));
    db.store.put('evidence', ev);
    finding.evidence_ids.push(ev.id);
  }
  assignFids(db, tenantId, [finding]);
  db.store.put('findings', finding);
  recordAudit(db.store, {
    tenantId, actorType: userId ? 'user' : 'system', actorId: userId,
    action: 'finding.created_manual', resource: 'finding', resourceId: finding.id,
    detail: { fid: finding.fid, check_id: checkId, severity, evidence_count: finding.evidence_ids.length },
  });
  return finding;
}

/** Parse a HAR 1.2 document into normalized exchanges (defensive, size-capped). */
export function parseHar(har, { maxEntries = MAX_ENTRIES } = {}) {
  if (!har || typeof har !== 'object' || !har.log || !Array.isArray(har.log.entries)) {
    throw badRequest('not a HAR document: missing log.entries');
  }
  const entries = [];
  for (const e of har.log.entries.slice(0, maxEntries)) {
    const req = e.request || {};
    const res = e.response || {};
    const url = String(req.url || '');
    if (!/^https?:\/\//i.test(url)) continue; // skip non-HTTP entries (data:, ws:, …)
    const content = res.content || {};
    let body = null;
    if (typeof content.text === 'string' && content.text) {
      body = content.encoding === 'base64'
        ? trunc(Buffer.from(content.text, 'base64').toString('utf8'), MAX_BODY_BYTES)
        : trunc(content.text, MAX_BODY_BYTES);
    }
    entries.push({
      started_at: e.startedDateTime || null,
      time_ms: Number(e.time) || null,
      method: String(req.method || 'GET').toUpperCase(),
      url: trunc(url, 2048),
      http_version: e.request?.httpVersion || null,
      request: {
        method: String(req.method || 'GET').toUpperCase(),
        url: trunc(url, 2048),
        headers: (req.headers || []).slice(0, 100).map((h) => `${h.name}: ${trunc(h.value, 512)}`).join('\n'),
        body: req.postData?.text ? trunc(req.postData.text, MAX_BODY_BYTES) : null,
      },
      response: {
        status: Number(res.status) || 0,
        headers: (res.headers || []).slice(0, 100).map((h) => `${h.name}: ${trunc(h.value, 512)}`).join('\n'),
        body,
        mime: content.mimeType || res.content?.mimeType || null,
      },
    });
  }
  if (!entries.length) throw badRequest('HAR contains no HTTP entries');
  return { entries, total_in_file: har.log.entries.length, truncated: har.log.entries.length > maxEntries };
}

/** Import a HAR: every exchange becomes a tenant evidence record. */
export function importHar({ db, tenantId, userId = null, assetId = null, har }) {
  const asset = assetId ? db.byId('assets', tenantId, assetId) : null;
  if (assetId && !asset) throw badRequest('asset not found for this tenant');
  const { entries, total_in_file, truncated } = parseHar(har);
  const imported = [];
  for (const x of entries) {
    const content = { ...x, captured_from: 'har_import' };
    const ev = {
      id: newId('ev'), tenant_id: tenantId, job_id: null, finding_id: null,
      kind: 'har_exchange',
      description: `${x.method} ${x.url} → ${x.response.status}`,
      content, sha256: sha256(canonicalJson(content)),
      captured_at: nowIso(), source: 'har_import', captured_by: userId || null,
      asset_id: asset?.id || null,
    };
    db.store.put('evidence', ev);
    imported.push(ev);
  }
  const rec = db.insert('har_imports', {
    tenant_id: tenantId, asset_id: asset?.id || null, imported_by: userId || null,
    entries: imported.map((e) => ({ evidence_id: e.id, method: e.content.method, url: e.content.url, status: e.content.response.status, mime: e.content.response.mime })),
    stats: { imported: imported.length, total_in_file, truncated },
    created_at: nowIso(),
  });
  recordAudit(db.store, {
    tenantId, actorType: userId ? 'user' : 'system', actorId: userId,
    action: 'har.imported', resource: 'har_import', resourceId: rec.id,
    detail: { entries: imported.length, asset_id: asset?.id || null },
  });
  return { import: rec, evidence: imported };
}
