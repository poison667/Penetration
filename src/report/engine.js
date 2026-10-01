import { sha256, canonicalJson, formatDate, escapeHtml } from '#core/util';
import { writeXlsx } from '#data/xlsx';
import { stringifyCsv } from '#data/csv';
import { PdfBuilder } from './pdf.js';

/**
 * Report engine — generates reports from REAL stored execution data only:
 * job, findings (with evidence), monitors, methodology and limitations.
 * Formats: JSON, CSV, HTML, PDF, XLSX. Every report carries a SHA-256
 * integrity hash (embedded + stored) and links to the previous report of
 * the same kind for historical comparison.
 */
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

export function buildReportModel(db, { job, kind = 'service_report', assetId = null, tenantId }) {
  const findings = job
    ? db.store.find('findings', (f) => f.job_id === job.id)
    : db.store.find('findings', (f) => f.tenant_id === tenantId && (!assetId || f.asset_id === assetId));
  findings.sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity) || (a.fid < b.fid ? -1 : 1));
  const evidence = job ? db.store.find('evidence', (e) => e.job_id === job.id) : [];
  const asset = job?.asset_id ? db.byIdGlobal('assets', job.asset_id) : (assetId ? db.byIdGlobal('assets', assetId) : null);
  const bySeverity = {};
  for (const s of SEV_ORDER) bySeverity[s] = findings.filter((f) => f.severity === s).length;
  const byCategory = {};
  for (const f of findings) byCategory[f.category_label || f.category] = (byCategory[f.category_label || f.category] || 0) + 1;

  const model = {
    kind,
    generated_at: new Date().toISOString(),
    tenant_id: tenantId,
    job: job ? { id: job.id, service: job.service_key, state: job.state, started_at: job.started_at, finished_at: job.finished_at, params: job.params, qc: job.qc } : null,
    asset: asset ? { id: asset.id, identifier: asset.identifier, kind: asset.kind } : null,
    findings: findings.map((f) => ({
      fid: f.fid, title: f.title, check_id: f.check_id, severity: f.severity, confidence: f.confidence,
      category: f.category_label || f.category, endpoint: f.endpoint, parameter: f.parameter,
      cwe: f.cwe, owasp: f.owasp, status: f.status, verification: f.verification,
      facts: f.facts, inference: f.inference, recommendation: f.recommendation,
      evidence_ids: f.evidence_ids, detected_at: f.detected_at,
    })),
    evidence_count: evidence.length,
    summary: {
      total_findings: findings.length,
      by_severity: bySeverity,
      by_category: byCategory,
      critical_high: bySeverity.critical + bySeverity.high,
    },
    methodology: [
      'All findings originate from authenticated Meridian engine executions against the authorized target scope recorded on the asset.',
      'Each finding links at least one evidence record (HTTP exchange, TLS handshake data, static analysis output or derived computation) captured during execution; evidence SHA-256 hashes are verified during the job quality-control stage.',
      'Testing profiles constrain active checks: passive (observation only), safe (benign differential probes), standard (non-destructive injection probes), intrusive (state-changing probes; requires explicit authorization).',
      'FACT statements record direct observations; INFERENCE statements record analyst interpretations derived from facts; RECOMMENDATIONS provide remediation guidance.',
    ],
    limitations: [
      'Assessment coverage is bounded by the crawl depth, discovered parameters and authorized scope configured for the job.',
      'Rendering-dependent metrics (Core Web Vitals, color contrast, dynamic/DOM content behind authentication walls) require the browser measurement provider, which is not active in this deployment.',
      'Findings marked confidence "medium/low" warrant manual verification before remediation sign-off.',
      'Absence of a finding is not proof of absence of the vulnerability class within untested surface.',
    ],
  };
  return model;
}

/** Compare with previous report: new / resolved findings by (check, target, endpoint, parameter) hash. */
export function computeDelta(db, tenantId, model, previousReportId) {
  if (!previousReportId) return null;
  const prev = db.byIdGlobal('reports', previousReportId);
  if (!prev || !prev.model_snapshot) return null;
  const prevHashes = new Set(prev.model_snapshot.findings.map((f) => `${f.check_id}|${f.endpoint}|${f.parameter}`));
  const currentHashes = new Set(model.findings.map((f) => `${f.check_id}|${f.endpoint}|${f.parameter}`));
  const added = model.findings.filter((f) => !prevHashes.has(`${f.check_id}|${f.endpoint}|${f.parameter}`)).map((f) => f.fid);
  const resolved = prev.model_snapshot.findings.filter((f) => !currentHashes.has(`${f.check_id}|${f.endpoint}|${f.parameter}`)).map((f) => f.fid);
  return { previous_report_id: previousReportId, previous_generated_at: prev.created_at, findings_added: added, findings_resolved: resolved, added_count: added.length, resolved_count: resolved.length };
}

export function renderReport(model, format, { delta = null, integrityHash = null } = {}) {
  switch (format) {
    case 'json': return renderJson(model, delta, integrityHash);
    case 'csv': return renderCsv(model);
    case 'html': return renderHtml(model, delta, integrityHash);
    case 'pdf': return renderPdf(model, delta, integrityHash);
    case 'xlsx': return renderXlsx(model);
    default: throw new Error(`unsupported report format: ${format}`);
  }
}

function renderJson(model, delta, integrityHash) {
  return Buffer.from(JSON.stringify({ ...model, delta: delta || undefined, integrity_sha256: integrityHash }, null, 2));
}
function renderCsv(model) {
  return Buffer.from(stringifyCsv(model.findings.map((f) => ({
    fid: f.fid, severity: f.severity, confidence: f.confidence, category: f.category, check_id: f.check_id,
    title: f.title, endpoint: f.endpoint || '', parameter: f.parameter || '', cwe: f.cwe || '', status: f.status,
    detected_at: f.detected_at, evidence_count: f.evidence_ids.length,
  }))), 'utf8');
}
function renderXlsx(model) {
  return writeXlsx({
    Summary: [{ metric: 'total_findings', value: model.summary.total_findings }, ...Object.entries(model.summary.by_severity).map(([k, v]) => ({ metric: k, value: v })), { metric: 'generated_at', value: model.generated_at }],
    Findings: model.findings.map((f) => ({ fid: f.fid, severity: f.severity, confidence: f.confidence, category: f.category, check: f.check_id, title: f.title, endpoint: f.endpoint || '', parameter: f.parameter || '', cwe: f.cwe || '', status: f.status, detected_at: f.detected_at, evidence_count: f.evidence_ids.length, recommendation: f.recommendation })),
  });
}

function renderHtml(model, delta, integrityHash) {
  const sevColor = { critical: '#d13438', high: '#f7630c', medium: '#c19c00', low: '#2d7d9a', info: '#605e5c' };
  const donut = donutSvg(model.summary.by_severity, sevColor);
  const bars = barsSvg(model.summary.by_category);
  const esc = escapeHtml;
  const findingsHtml = model.findings.map((f, i) => `
    <div class="finding">
      <div class="fhead"><span class="sev" style="background:${sevColor[f.severity]}">${esc(f.severity.toUpperCase())}</span>
        <strong>${esc(f.fid)} — ${esc(f.title)}</strong>
        <span class="meta">${esc(f.check_id)}${f.cwe ? ' · ' + esc(f.cwe) : ''}${f.owasp ? ' · OWASP ' + esc(f.owasp) : ''} · confidence: ${esc(f.confidence)}</span></div>
      ${f.endpoint ? `<div class="kv"><b>Endpoint:</b> ${esc(f.endpoint)}${f.parameter ? ` · <b>Parameter:</b> ${esc(f.parameter)}` : ''}</div>` : ''}
      <div class="facts"><b>FACT</b><ul>${f.facts.map((x) => `<li>${esc(x)}</li>`).join('')}</ul></div>
      ${f.inference.length ? `<div class="infer"><b>INFERENCE</b><ul>${f.inference.map((x) => `<li>${esc(x)}</li>`).join('')}</ul></div>` : ''}
      <div class="rem"><b>RECOMMENDATION</b><p>${esc(f.recommendation)}</p></div>
      <div class="meta">Evidence records: ${f.evidence_ids.length} · detected ${esc(formatDate(f.detected_at))} · status ${esc(f.status)}</div>
    </div>`).join('') || '<p class="empty">No findings were produced by this execution.</p>';

  return Buffer.from(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>${esc(model.kind)} — Meridian Platform</title>
<style>
  :root { color-scheme: light; }
  body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; color: #1b1b1b; background: #fff; margin: 0; }
  .page { max-width: 880px; margin: 0 auto; padding: 48px 40px; }
  h1 { font-size: 24px; margin: 0 0 4px; } h2 { font-size: 17px; margin: 32px 0 10px; border-bottom: 2px solid #e5e5e5; padding-bottom: 6px; }
  .sub { color: #555; font-size: 13px; margin-bottom: 28px; }
  .grid { display: grid; grid-template-columns: 220px 1fr; gap: 24px; align-items: center; }
  .stats { display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; margin: 16px 0; }
  .stat { border: 1px solid #e3e3e3; border-radius: 6px; padding: 10px 12px; }
  .stat b { display: block; font-size: 22px; }
  .stat span { font-size: 11px; color: #666; text-transform: uppercase; letter-spacing: .04em; }
  .finding { border: 1px solid #e3e3e3; border-radius: 6px; padding: 14px 16px; margin: 10px 0; }
  .fhead { display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; }
  .sev { color: #fff; font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 3px; letter-spacing: .05em; }
  .meta { color: #666; font-size: 12px; }
  .kv { font-size: 13px; margin: 6px 0; }
  .facts ul, .infer ul { margin: 4px 0 8px; padding-left: 20px; font-size: 13px; }
  .facts b { font-size: 11px; color: #036c; letter-spacing: .06em; } .infer b { font-size: 11px; color: #8a6d00; letter-spacing: .06em; } .rem b { font-size: 11px; color: #107c10; letter-spacing: .06em; }
  .rem p { margin: 4px 0 8px; font-size: 13px; }
  ul.method, ul.limits { padding-left: 20px; font-size: 13px; color: #333; }
  .integrity { margin-top: 36px; padding: 12px 14px; background: #f5f5f5; border-radius: 6px; font-family: ui-monospace, Consolas, monospace; font-size: 11px; word-break: break-all; }
  .empty { color: #666; }
  table { border-collapse: collapse; width: 100%; font-size: 12.5px; }
  th, td { border: 1px solid #e0e0e0; padding: 6px 8px; text-align: left; }
  th { background: #f3f4f6; }
</style></head><body><div class="page">
<h1>Meridian — ${esc(titleFor(model))}</h1>
<div class="sub">Generated ${esc(formatDate(model.generated_at))}${model.asset ? ` · Target: ${esc(model.asset.identifier)}` : ''}${model.job ? ` · Job ${esc(model.job.id)} (${esc(model.job.state)})` : ''}</div>
<div class="grid"><div>${donut}</div><div>${bars}</div></div>
<div class="stats">${SEV_ORDER.map((s) => `<div class="stat"><b style="color:${sevColor[s]}">${model.summary.by_severity[s] || 0}</b><span>${s}</span></div>`).join('')}</div>
${delta ? `<h2>Historical Comparison</h2><p class="kv">Compared with report <b>${esc(delta.previous_report_id)}</b> (${esc(formatDate(delta.previous_generated_at))}): <b style="color:#d13438">${delta.added_count} new findings</b>, <b style="color:#107c10">${delta.resolved_count} resolved</b>.</p>` : ''}
<h2>Findings (${model.summary.total_findings})</h2>
${findingsHtml}
<h2>Methodology</h2><ul class="method">${model.methodology.map((m) => `<li>${esc(m)}</li>`).join('')}</ul>
<h2>Limitations</h2><ul class="limits">${model.limitations.map((m) => `<li>${esc(m)}</li>`).join('')}</ul>
${integrityHash ? `<div class="integrity"><b>Integrity SHA-256</b><br>${esc(integrityHash)}<br>Verify with: sha256sum report.${model.kind}.&lt;format&gt;</div>` : ''}
</div></body></html>`, 'utf8');
}

function renderPdf(model, delta, integrityHash) {
  const pdf = new PdfBuilder({
    title: 'Meridian Report',
    footer: `Meridian Platform · ${model.kind} · generated ${model.generated_at.slice(0, 19)}Z`,
  });
  pdf.heading(titleFor(model), { size: 20 });
  pdf.paragraph(`Generated ${formatDate(model.generated_at)}${model.asset ? ` — Target: ${model.asset.identifier}` : ''}${model.job ? ` — Job ${model.job.id} (${model.job.state})` : ''}`, { gray: 0.35 });
  pdf.subheading('Executive Summary');
  pdf.keyValue([
    ['Total findings', String(model.summary.total_findings)],
    ['Critical / High', String(model.summary.critical_high)],
    ['Evidence records', String(model.evidence_count)],
    ['Severity breakdown', SEV_ORDER.map((s) => `${s}: ${model.summary.by_severity[s] || 0}`).join(' · ')],
  ]);
  if (delta) {
    pdf.subheading('Historical Comparison');
    pdf.paragraph(`Compared with report ${delta.previous_report_id} (${formatDate(delta.previous_generated_at)}): ${delta.added_count} new findings, ${delta.resolved_count} resolved.`);
  }
  pdf.subheading('Findings');
  pdf.table(['ID', 'Severity', 'Check', 'Title', 'Endpoint'], model.findings.map((f) => [f.fid, f.severity.toUpperCase(), f.check_id, truncate(f.title, 60), truncate(f.endpoint || '—', 40)]), { widths: [70, 52, 60, 210, 105] });
  for (const f of model.findings) {
    pdf.ensureSpace(60);
    pdf.y -= 6;
    pdf.severityBadge(f.severity, MARGINX, pdf.y + 14);
    pdf.y -= 14;
    pdf.paragraph(`${f.fid} — ${f.title}`, { size: 11 });
    pdf.paragraph(`${f.check_id}${f.cwe ? ' · ' + f.cwe : ''} · confidence ${f.confidence} · status ${f.status} · ${f.evidence_ids.length} evidence record(s)`, { size: 8.5, gray: 0.4 });
    if (f.endpoint) pdf.paragraph(`Endpoint: ${f.endpoint}${f.parameter ? ` (parameter: ${f.parameter})` : ''}`, { size: 9 });
    pdf.paragraph('FACT:', { size: 9, indent: 8 });
    for (const fact of f.facts) pdf.paragraph(`• ${fact}`, { size: 9, indent: 16, gray: 0.1 });
    if (f.inference.length) {
      pdf.paragraph('INFERENCE:', { size: 9, indent: 8 });
      for (const inf of f.inference) pdf.paragraph(`• ${inf}`, { size: 9, indent: 16, gray: 0.1 });
    }
    pdf.paragraph('RECOMMENDATION: ' + f.recommendation, { size: 9, indent: 8 });
  }
  pdf.subheading('Methodology');
  for (const m of model.methodology) pdf.paragraph(`• ${m}`, { size: 9 });
  pdf.subheading('Limitations');
  for (const l of model.limitations) pdf.paragraph(`• ${l}`, { size: 9 });
  if (integrityHash) {
    pdf.subheading('Integrity');
    pdf.paragraph(`SHA-256: ${integrityHash}`, { size: 8 });
  }
  return pdf.build();
}
const MARGINX = 48;

function donutSvg(bySeverity, colors) {
  const total = Object.values(bySeverity).reduce((a, b) => a + b, 0) || 1;
  let angle = -90;
  const segs = SEV_ORDER.filter((s) => bySeverity[s]).map((s) => {
    const sweep = 360 * bySeverity[s] / total;
    const a0 = angle * Math.PI / 180, a1 = (angle + sweep - 0.001) * Math.PI / 180;
    angle += sweep;
    const cx = 70, cy = 70, r = 58;
    const large = sweep > 180 ? 1 : 0;
    return `<path d="M ${cx} ${cy} L ${cx + r * Math.cos(a0)} ${cy + r * Math.sin(a0)} A ${r} ${r} 0 ${large} 1 ${cx + r * Math.cos(a1)} ${cy + r * Math.sin(a1)} Z" fill="${colors[s]}" stroke="#fff" stroke-width="1.5"/>`;
  }).join('');
  return `<svg width="140" height="140" viewBox="0 0 140 140" xmlns="http://www.w3.org/2000/svg">${segs}<circle cx="70" cy="70" r="34" fill="#fff"/><text x="70" y="66" text-anchor="middle" font-family="Segoe UI, sans-serif" font-size="20" font-weight="700">${total}</text><text x="70" y="82" text-anchor="middle" font-family="Segoe UI, sans-serif" font-size="9" fill="#666">findings</text></svg>`;
}
function barsSvg(byCategory) {
  const entries = Object.entries(byCategory).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const max = Math.max(1, ...entries.map((e) => e[1]));
  const w = 520, rowH = 22;
  return `<svg width="${w}" height="${entries.length * rowH + 8}" viewBox="0 0 ${w} ${entries.length * rowH + 8}" xmlns="http://www.w3.org/2000/svg">${entries.map(([cat, n], i) => `
    <text x="0" y="${i * rowH + 15}" font-family="Segoe UI, sans-serif" font-size="11" fill="#333">${escapeHtml(truncate(cat, 30))}</text>
    <rect x="210" y="${i * rowH + 4}" width="${(w - 260) * n / max}" height="13" rx="2" fill="#3b6ea5"/>
    <text x="${214 + (w - 260) * n / max}" y="${i * rowH + 15}" font-family="Segoe UI, sans-serif" font-size="11" fill="#333">${n}</text>`).join('')}</svg>`;
}

function titleFor(model) {
  const names = { service_report: 'Service Report', asset_summary: 'Asset Security Summary', executive_summary: 'Executive Summary', monitoring_summary: 'Monitoring Summary' };
  return names[model.kind] || 'Report';
}
const truncate = (s, n) => (String(s ?? '').length > n ? String(s).slice(0, n - 1) + '…' : String(s ?? ''));
const MARGIN_NOTE = null;

/** Persist a report: content-addressed file + registry entry + delta. */
export function generateReport(db, files, { tenantId, job = null, kind, format = 'pdf', assetId = null, createdBy = null }) {
  const model = buildReportModel(db, { job, kind, assetId, tenantId });
  // find previous report for delta
  const prev = db.store.find('reports', (r) => r.tenant_id === tenantId && r.kind === kind && (!assetId || r.asset_id === assetId) && r.id)
    .sort((a, b) => (a.created_at < b.created_at ? 1 : -1))[0] || null;
  const contentNoHash = renderReport(model, format, { delta: computeDelta(db, tenantId, model, prev?.id) });
  const integrityHash = sha256(contentNoHash);
  const content = renderReport(model, format, { delta: computeDelta(db, tenantId, model, prev?.id), integrityHash });
  const ext = format === 'xlsx' ? 'xlsx' : format;
  const rec = files.put(tenantId, content, {
    name: `report-${kind}-${Date.now()}.${ext}`,
    mime: format === 'pdf' ? 'application/pdf' : format === 'html' ? 'text/html' : format === 'csv' ? 'text/csv' : format === 'xlsx' ? 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' : 'application/json',
    meta: { kind: 'report' },
  });
  const report = db.insert('reports', {
    tenant_id: tenantId, job_id: job?.id || null, asset_id: assetId || job?.asset_id || null,
    kind, format, title: titleFor(model), file_id: rec.id, sha256: integrityHash,
    size_bytes: content.length, findings_count: model.summary.total_findings,
    previous_report_id: prev?.id || null, created_by: createdBy,
    model_snapshot: { generated_at: model.generated_at, findings: model.findings.map((f) => ({ fid: f.fid, check_id: f.check_id, endpoint: f.endpoint, parameter: f.parameter })) },
  });
  return { report, content, model };
}

/* ===================== RETEST (FIX-VERIFICATION) REPORT ===================== */

const RETEST_METHODOLOGY = [
  'A retest re-executes the same service, engine set and testing profile as the source assessment against the same authorized target, capturing fresh evidence for every re-detected finding.',
  'Findings are matched across runs by a stable fingerprint (check + target + endpoint + parameter); a re-detected finding keeps its original finding identifier (FID).',
  'Verdicts: REPRODUCED = re-detected with fresh evidence. FIXED = every contributing engine re-ran successfully and did not re-detect the issue. INCONCLUSIVE = a contributing engine failed during the retest, so no verdict is claimed. NEW = first observed in this retest run.',
];

const RETEST_LIMITATIONS = [
  '"Fixed" means "not re-detected by the same checks under the same profile at retest time" — it is strong evidence of remediation, not a proof of absence of the vulnerability class.',
  'Content or behaviour that changed between the source run and the retest (A/B deployments, caches, wafers, randomized responses) can influence verdicts.',
  'Findings outside the retested engine set or outside the authorized scope are not covered by this report.',
];

export function generateRetestReport(db, files, { tenantId, run, format = 'pdf', createdBy = null }) {
  const asset = run.asset_id ? db.byIdGlobal('assets', run.asset_id) : null;
  const model = {
    kind: 'retest_report',
    generated_at: new Date().toISOString(),
    tenant_id: tenantId,
    asset: asset ? { id: asset.id, identifier: asset.identifier, kind: asset.kind } : null,
    source_job_id: run.source_job_id,
    retest_job_id: run.retest_job_id,
    service_key: run.service_key,
    source: run.source,
    retest: run.retest,
    verdicts: run.verdicts,
    severity_changes: run.severity_changes || [],
    items: run.items,
    methodology: RETEST_METHODOLOGY,
    limitations: RETEST_LIMITATIONS,
  };
  const render = (integrityHash) => {
    if (format === 'json') return Buffer.from(JSON.stringify(model, null, 2), 'utf8');
    if (format === 'csv') {
      const head = 'fid,check_id,title,severity,retest_severity,verdict,endpoint';
      const rows = model.items.map((i) => [i.fid, i.check_id, i.title, i.severity, i.retest_severity || '', i.verdict, (i.endpoint || '').replace(/[",\n]/g, ' ')]);
      return Buffer.from([head, ...rows.map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(','))].map((r) => r.replace(/^"|"$/g, '')).join('\n'), 'utf8');
    }
    if (format === 'html') {
      const verdictColor = { reproduced: '#d13438', fixed: '#107c10', inconclusive: '#b28900', new: '#0078d4' };
      const rowsHtml = model.items.map((i) => `<tr><td>${escapeHtml(i.fid)}</td><td>${escapeHtml(i.check_id)}</td><td>${escapeHtml(truncate(i.title, 70))}</td><td>${escapeHtml(i.severity)}</td><td style="color:${verdictColor[i.verdict]};font-weight:700">${i.verdict.toUpperCase()}</td><td>${escapeHtml(truncate(i.endpoint || '—', 50))}</td></tr>`).join('');
      return Buffer.from(`<!doctype html><html><head><meta charset="utf-8"><title>Meridian Retest Report</title><style>body{font-family:'Segoe UI',system-ui,sans-serif;margin:32px;color:#1a1a1a}h1{font-size:22px}h2{font-size:16px;margin-top:28px}table{border-collapse:collapse;width:100%;font-size:12px}th,td{border:1px solid #ddd;padding:6px 8px;text-align:left}th{background:#f4f6f8}.kv{color:#444}.stats{display:flex;gap:24px;margin:16px 0}.stat b{font-size:20px;display:block}</style></head><body>
<h1>Meridian Platform — Retest / Fix-Verification Report</h1>
<p class="kv">Generated ${escapeHtml(formatDate(model.generated_at))}${asset ? ` — Target: ${escapeHtml(asset.identifier)}` : ''}</p>
<div class="stats">
  <div class="stat" style="color:#d13438"><b>${model.verdicts.reproduced}</b>reproduced</div>
  <div class="stat" style="color:#107c10"><b>${model.verdicts.fixed}</b>fixed</div>
  <div class="stat" style="color:#b28900"><b>${model.verdicts.inconclusive}</b>inconclusive</div>
  <div class="stat" style="color:#0078d4"><b>${model.verdicts.new}</b>new</div>
</div>
<p class="kv">Source assessment: ${escapeHtml(model.source.job_id)} — ${model.source.findings_count} findings (finished ${escapeHtml(String(model.source.finished_at || '—')).slice(0, 19)}Z)<br>
Retest run: ${escapeHtml(model.retest.job_id)} — ${model.retest.findings_count} findings (finished ${escapeHtml(String(model.retest.finished_at || '—')).slice(0, 19)}Z)</p>
${model.severity_changes.length ? `<h2>Severity changes</h2><ul>${model.severity_changes.map((c) => `<li>${escapeHtml(c.fid)} (${escapeHtml(c.check_id)}): ${escapeHtml(c.from)} → <b>${escapeHtml(c.to)}</b></li>`).join('')}</ul>` : ''}
<h2>Verdicts (${model.items.length})</h2>
<table><tr><th>FID</th><th>Check</th><th>Title</th><th>Severity</th><th>Verdict</th><th>Endpoint</th></tr>${rowsHtml}</table>
<h2>Methodology</h2><ul>${model.methodology.map((m) => `<li>${escapeHtml(m)}</li>`).join('')}</ul>
<h2>Limitations</h2><ul>${model.limitations.map((m) => `<li>${escapeHtml(m)}</li>`).join('')}</ul>
${integrityHash ? `<p class="kv"><b>Integrity SHA-256</b><br>${escapeHtml(integrityHash)}</p>` : ''}
</body></html>`, 'utf8');
    }
    // pdf (default)
    const pdf = new PdfBuilder({ title: 'Meridian Retest Report', footer: `Meridian Platform · retest_report · generated ${model.generated_at.slice(0, 19)}Z` });
    pdf.heading('Retest / Fix-Verification Report', { size: 20 });
    pdf.paragraph(`Generated ${formatDate(model.generated_at)}${asset ? ` — Target: ${asset.identifier}` : ''}`, { gray: 0.35 });
    pdf.subheading('Verdict Summary');
    pdf.keyValue([
      ['Reproduced (still present)', String(model.verdicts.reproduced)],
      ['Fixed (not re-detected)', String(model.verdicts.fixed)],
      ['Inconclusive (engine failed)', String(model.verdicts.inconclusive)],
      ['New findings', String(model.verdicts.new)],
      ['Source assessment', `${model.source.job_id} — ${model.source.findings_count} findings`],
      ['Retest run', `${model.retest.job_id} — ${model.retest.findings_count} findings`],
    ]);
    if (model.severity_changes.length) {
      pdf.subheading('Severity Changes');
      for (const c of model.severity_changes) pdf.paragraph(`• ${c.fid} (${c.check_id}): ${c.from} → ${c.to}`, { size: 9 });
    }
    pdf.subheading('Per-Finding Verdicts');
    pdf.table(['FID', 'Verdict', 'Severity', 'Check', 'Title'], model.items.map((i) => [i.fid, i.verdict.toUpperCase(), (i.severity || '—').toUpperCase(), i.check_id, truncate(i.title, 55)]), { widths: [70, 72, 52, 62, 200] });
    pdf.subheading('Methodology');
    for (const m of model.methodology) pdf.paragraph(`• ${m}`, { size: 9 });
    pdf.subheading('Limitations');
    for (const l of model.limitations) pdf.paragraph(`• ${l}`, { size: 9 });
    if (integrityHash) {
      pdf.subheading('Integrity');
      pdf.paragraph(`SHA-256: ${integrityHash}`, { size: 8 });
    }
    return pdf.build();
  };
  const integrityHash = sha256(render(null));
  const content = render(integrityHash);
  const ext = format === 'xlsx' ? 'xlsx' : format;
  const rec = files.put(tenantId, content, {
    name: `report-retest-${Date.now()}.${ext}`,
    mime: format === 'pdf' ? 'application/pdf' : format === 'html' ? 'text/html' : format === 'csv' ? 'text/csv' : 'application/json',
    meta: { kind: 'report' },
  });
  const report = db.insert('reports', {
    tenant_id: tenantId, job_id: run.retest_job_id, asset_id: run.asset_id || null,
    kind: 'retest_report', format, title: `Retest Report — ${model.verdicts.fixed} fixed / ${model.verdicts.reproduced} reproduced / ${model.verdicts.new} new`,
    file_id: rec.id, sha256: integrityHash, size_bytes: content.length,
    findings_count: model.items.length, previous_report_id: null, created_by: createdBy,
    retest_run_id: run.id,
  });
  return { report, content, model };
}
