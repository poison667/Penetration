/**
 * Retest / fix-verification engine (specification Part 9 — job lifecycle extension).
 *
 * A retest re-runs the SAME service (same engine set, same profile) against the
 * SAME asset as a completed source job, then compares findings by their stable
 * fingerprint (hash = check_id + target + endpoint + parameter).
 *
 * Verdict semantics (grounded, conservative):
 *   reproduced  — the same engine re-detected the issue with fresh evidence;
 *                 the original finding keeps its FID and is marked reproduced.
 *   fixed       — every engine that contributed the original finding re-ran
 *                 successfully and did NOT re-detect it. "Fixed" always means
 *                 "not re-detected by the same checks", never "provably safe".
 *   inconclusive — at least one contributing engine failed in the retest run;
 *                    no fixed/reproduced claim is made for this finding.
 *   new         — first seen in this retest run (not present in the source run).
 *
 * Cross-run identity: a re-detected finding INHERITS the source finding's FID,
 * so a vulnerability keeps one stable identifier across assessments.
 */
import { newId, nowIso } from '#core/util';

export function isRetestJob(job) {
  return !!job?.meta?.retest_of;
}

/** Before persistence: re-detected findings inherit the source FID + verification state. */
export function linkRetestFindings(db, job, findings) {
  const source = db.store.find('findings', (f) => f.tenant_id === job.tenant_id && f.job_id === job.meta.retest_of);
  const byHash = new Map(source.map((f) => [f.hash, f]));
  for (const f of findings) {
    const src = byHash.get(f.hash);
    if (src) {
      f.fid = src.fid;                                   // stable cross-run identifier
      f.verification = 'reproduced';
      f.first_detected_at = src.detected_at;
      f.reproduced_from_finding_id = src.id;
    } else {
      f.verification = 'not_retested';
      f.first_detected_at = f.detected_at;
    }
  }
  return findings;
}

function countBy(arr, key) {
  const out = {};
  for (const x of arr) out[x[key]] = (out[x[key]] || 0) + 1;
  return out;
}

/**
 * After persistence: compare source vs retest findings, update the SOURCE
 * finding records with verdicts, and persist a retest_runs record.
 */
export function applyRetestVerdicts(db, job) {
  const sourceJobId = job.meta.retest_of;
  const sourceJob = db.store.byId('jobs', sourceJobId) || null;
  const sourceFindings = db.store.find('findings', (f) => f.tenant_id === job.tenant_id && f.job_id === sourceJobId);
  const retestFindings = db.store.find('findings', (f) => f.tenant_id === job.tenant_id && f.job_id === job.id);
  const byHash = new Map(retestFindings.map((f) => [f.hash, f]));

  const engineResults = job.result_summary?.engines || [];
  const failedEngines = new Set(engineResults.filter((e) => !e.ok).map((e) => e.key));

  const counts = { reproduced: 0, fixed: 0, inconclusive: 0, new: 0 };
  const severityChanges = [];
  const items = [];

  for (const src of sourceFindings) {
    const match = byHash.get(src.hash);
    const engines = [...new Set([...(src.provenance?.engines || []), src.provenance?.engine].filter(Boolean))];
    const engineFailed = engines.length > 0 && engines.some((e) => failedEngines.has(e));
    const verdict = match ? 'reproduced' : (engineFailed ? 'inconclusive' : 'fixed');
    counts[verdict]++;

    if (match && match.severity !== src.severity) {
      severityChanges.push({ fid: src.fid, check_id: src.check_id, from: src.severity, to: match.severity });
    }

    // the ORIGINAL finding record is the durable verdict carrier
    const patch = { verification: verdict, last_verified_at: nowIso(), verified_by_job_id: job.id, retest_verdict: verdict };
    if (verdict === 'fixed') { patch.status = 'fixed'; patch.fixed_at = nowIso(); }
    if (verdict === 'reproduced') {
      patch.status = 'open';
      patch.last_seen_at = nowIso();
      patch.reproduced_finding_id = match.id;
    }
    db.store.put('findings', { ...src, ...patch, id: src.id });

    items.push({
      source_finding_id: src.id, retest_finding_id: match?.id || null,
      fid: src.fid, check_id: src.check_id, title: src.title,
      category: src.category_label || src.category,
      severity: src.severity, retest_severity: match?.severity || null,
      endpoint: src.endpoint, parameter: src.parameter,
      verdict,
    });
  }

  for (const f of retestFindings) {
    if (sourceFindings.some((s) => s.hash === f.hash)) continue;
    counts.new++;
    items.push({
      source_finding_id: null, retest_finding_id: f.id,
      fid: f.fid, check_id: f.check_id, title: f.title,
      category: f.category_label || f.category,
      severity: f.severity, retest_severity: f.severity,
      endpoint: f.endpoint, parameter: f.parameter,
      verdict: 'new',
    });
  }

  const verdictOrder = { reproduced: 0, inconclusive: 1, fixed: 2, new: 3 };
  items.sort((a, b) => (verdictOrder[a.verdict] - verdictOrder[b.verdict]) || (a.fid < b.fid ? -1 : 1));

  const run = db.insert('retest_runs', {
    tenant_id: job.tenant_id, kind: 'retest_run',
    source_job_id: sourceJobId, retest_job_id: job.id, asset_id: job.asset_id || null,
    service_key: job.service_key,
    source: {
      job_id: sourceJobId, state: sourceJob?.state || null,
      finished_at: sourceJob?.finished_at || null,
      findings_count: sourceFindings.length,
      by_severity: countBy(sourceFindings, 'severity'),
    },
    retest: {
      job_id: job.id, state: job.state,
      finished_at: job.finished_at || nowIso(),
      findings_count: retestFindings.length,
      by_severity: countBy(retestFindings, 'severity'),
    },
    verdicts: counts,
    severity_changes: severityChanges,
    engines: engineResults,
    items,
  });
  return run;
}
