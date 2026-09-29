/**
 * AI Readiness Assessment — every score is computed from real platform data
 * and backed by evidence references. Dimensions:
 * data availability, data quality, security posture, monitoring coverage,
 * automation maturity.
 */
export function assessReadiness(db, tenantId, assetId = null) {
  const dims = [];

  // Data availability
  const docs = db.store.find('documents', (d) => d.tenant_id === tenantId);
  const sources = db.store.find('data_sources', (s) => s.tenant_id === tenantId);
  const extracted = docs.filter((d) => d.extracted_text_sha256 || d.text_chars > 0);
  const dataAvail = clamp01(docs.length / 20) * 0.5 + clamp1(sources.length / 5) * 0.3 + (docs.length ? extracted.length / docs.length : 0) * 0.2;
  dims.push({
    dimension: 'data_availability', score: Math.round(dataAvail * 100),
    evidence: { documents: docs.length, documents_with_extracted_text: extracted.length, data_sources: sources.length, refs: docs.slice(0, 5).map((d) => d.id) },
    facts: [
      `${docs.length} documents in the vault (${extracted.length} with extracted text).`,
      `${sources.length} structured data sources imported.`,
    ],
  });

  // Data quality (from profiling runs)
  const runs = db.store.find('data_runs', (r) => r.tenant_id === tenantId);
  const profileRuns = runs.filter((r) => r.kind === 'profile');
  let quality = 0;
  if (profileRuns.length) {
    const nullRatios = profileRuns.flatMap((r) => Object.values(r.stats?.column_stats || {}).map((c) => c.null_ratio ?? 0));
    const avgNull = nullRatios.length ? nullRatios.reduce((a, b) => a + b, 0) / nullRatios.length : 0;
    quality = (1 - avgNull) * 0.7 + clamp1(profileRuns.length / 3) * 0.3;
  }
  dims.push({
    dimension: 'data_quality', score: Math.round(quality * 100),
    evidence: { profile_runs: profileRuns.length, avg_null_ratio: profileRuns.length ? +(profileRuns.flatMap((r) => Object.values(r.stats?.column_stats || {}).map((c) => c.null_ratio ?? 0)).reduce((a, b) => a + b, 0) / Math.max(1, profileRuns.flatMap((r) => Object.values(r.stats?.column_stats || {})).length)).toFixed(3) : null },
    facts: [`${profileRuns.length} profiling runs recorded.`, quality ? 'Quality score derived from measured null ratios and profiling coverage.' : 'No profiling runs yet — quality unmeasured.'],
  });

  // Security posture (from real findings)
  const findings = db.store.find('findings', (f) => f.tenant_id === tenantId && (!assetId || f.asset_id === assetId));
  const sevRank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  const open = findings.filter((f) => ['open', 'in_progress', 'retest_pending'].includes(f.status));
  const openWeight = open.reduce((a, f) => a + (sevRank[f.severity] || 1), 0);
  const posture = clamp1(1 - openWeight / 150);
  dims.push({
    dimension: 'security_posture', score: Math.round(posture * 100),
    evidence: { total_findings: findings.length, open_findings: open.length, open_by_severity: countBy(open, 'severity'), refs: open.slice(0, 5).map((f) => f.fid) },
    facts: [`${open.length} open findings of ${findings.length} total (weighted exposure ${openWeight}).`],
  });

  // Monitoring coverage
  const monitors = db.store.find('monitors', (m) => m.tenant_id === tenantId);
  const assets = db.store.find('assets', (a) => a.tenant_id === tenantId);
  const coveredAssets = new Set(monitors.map((m) => m.asset_id));
  const coverage = assets.length ? coveredAssets.size / assets.length : 0;
  const checks = db.store.find('monitor_checks', (c) => monitors.some((m) => m.id === c.monitor_id));
  dims.push({
    dimension: 'monitoring_coverage', score: Math.round(coverage * 100),
    evidence: { assets: assets.length, assets_with_monitors: coveredAssets.size, monitors: monitors.length, recorded_checks: checks.length },
    facts: [`${coveredAssets.size}/${assets.length} assets under monitoring (${monitors.length} monitors, ${checks.length} recorded checks).`],
  });

  // Automation maturity
  const rules = db.store.find('rules', (r) => r.tenant_id === tenantId);
  const workflows = db.store.find('workflows', (w) => w.tenant_id === tenantId);
  const ruleRuns = db.store.find('rule_runs', (r) => r.tenant_id === tenantId);
  const wfRuns = db.store.find('workflow_runs', (w) => w.tenant_id === tenantId);
  const automation = clamp1(rules.length / 3) * 0.4 + clamp1(workflows.length / 2) * 0.3 + clamp1((ruleRuns.length + wfRuns.length) / 10) * 0.3;
  dims.push({
    dimension: 'automation_maturity', score: Math.round(automation * 100),
    evidence: { rules: rules.length, workflows: workflows.length, rule_runs: ruleRuns.length, workflow_runs: wfRuns.length },
    facts: [`${rules.length} automation rules, ${workflows.length} workflows; ${ruleRuns.length + wfRuns.length} recorded executions.`],
  });

  const overall = Math.round(dims.reduce((a, d) => a + d.score, 0) / dims.length);
  return {
    assessed_at: new Date().toISOString(),
    overall_score: overall,
    classification: overall >= 75 ? 'ready' : overall >= 50 ? 'developing' : 'early-stage',
    dimensions: dims,
    methodology: 'Scores are computed from stored platform records only (documents, data sources, findings, monitors, automation executions). No score is estimated without a corresponding record count.',
    limitations: ['Readiness does not assess external systems not registered in this workspace.', 'Quality scoring relies on profiling runs actually executed.'],
  };
}

const clamp1 = (n) => Math.max(0, Math.min(1, n));
const clamp01 = clamp1;
function countBy(arr, key) {
  const out = {};
  for (const x of arr) out[x[key]] = (out[x[key]] || 0) + 1;
  return out;
}
