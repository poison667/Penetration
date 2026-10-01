import { nowIso } from '#core/util';
import { bus, TOPICS } from '#core/events';
import { badRequest, notFound } from '#core/errors';
import { serviceByKey, SERVICE_CATALOG } from '#app/catalog';
import { holdCredits, commitCredits, releaseAll, estimateCost } from '#app/billing';
import { notify } from '#app/notify';
import { recordAudit } from '#app/audit';
import { buildContext, runEngine, analyzeFindings, qualityCheck, assignFids } from '#engines';
import { ENGINES, engineKeysForService } from '../engines/registry.js';
import { isRetestJob, linkRetestFindings, applyRetestVerdicts } from '../engines/retest.js';

/**
 * Job lifecycle (specification Part 9):
 * REQUESTED → VALIDATING → QUEUED → RUNNING → ANALYZING → QUALITY_CHECK → COMPLETED
 * with FAILED / CANCELLED / RETRYING / PARTIALLY_COMPLETED.
 */
export function createServiceRequest({ db, tenantId, serviceKey, assetId, params = {}, userId = null, source = 'api', recurringSchedule = null }) {
  const service = serviceByKey(serviceKey);
  if (!service) throw badRequest(`unknown service: ${serviceKey}`);
  let asset = null;
  const needsAsset = !['data_profile', 'data_cleanse', 'data_dedup', 'data_transform', 'data_anomaly', 'doc_extract', 'doc_compare', 'kb_build', 'ai_readiness', 'ai_analyze'].includes(serviceKey);
  if (needsAsset) {
    if (!assetId) throw badRequest('this service requires an asset (target)');
    asset = db.byId('assets', tenantId, assetId);
    if (!asset) throw notFound('asset not found');
  }
  const request = db.insert('service_requests', {
    tenant_id: tenantId, user_id: userId, service_key: serviceKey,
    asset_id: assetId, params, status: 'submitted', recurring_schedule: recurringSchedule, source,
  });
  const profile = params.profile || (service.profiles?.includes('safe') ? 'safe' : service.profiles?.[0] || 'safe');
  const job = db.insert('jobs', {
    tenant_id: tenantId, request_id: request.id, service_key: serviceKey,
    asset_id: assetId, params: { ...params, profile },
    state: 'REQUESTED', progress: 0, priority: params.priority || 5,
    attempts: 0, max_attempts: 3, worker_id: null, error: null,
    result_summary: null, qc: null, usage: null, source,
    created_at: nowIso(), started_at: null, finished_at: null,
  });
  recordAudit(db.store, { tenantId, actorType: userId ? 'user' : 'system', actorId: userId, action: 'service.requested', resource: 'service_request', resourceId: request.id, detail: { service: serviceKey, asset_id: assetId, source } });
  return { request, job };
}

/**
 * Retest request: re-runs the SAME service against the SAME asset as a
 * completed source job (same profile), then the runner applies fix-verification
 * verdicts (reproduced / fixed / inconclusive / new) against the source findings.
 */
export function createRetestRequest({ db, tenantId, sourceJob, userId = null }) {
  if (!sourceJob || sourceJob.tenant_id !== tenantId) throw notFound('job not found');
  if (!['COMPLETED', 'PARTIALLY_COMPLETED'].includes(sourceJob.state)) {
    throw badRequest('retest requires a completed source job (current state: ' + sourceJob.state + ')');
  }
  if (!sourceJob.asset_id) throw badRequest('retest requires a job with an asset target');
  const service = serviceByKey(sourceJob.service_key);
  if (!['security', 'audit'].includes(service.category)) {
    throw badRequest('retest supports security and audit services (got: ' + service.category + ')');
  }
  const { request, job } = createServiceRequest({
    db, tenantId, serviceKey: sourceJob.service_key, assetId: sourceJob.asset_id,
    params: { ...sourceJob.params, source_job_id: sourceJob.id }, userId, source: 'retest',
  });
  const marked = db.update('jobs', tenantId, job.id, { meta: { retest_of: sourceJob.id } });
  recordAudit(db.store, { tenantId, actorType: userId ? 'user' : 'system', actorId: userId, action: 'job.retest_requested', resource: 'job', resourceId: sourceJob.id, detail: { retest_job_id: job.id, service: sourceJob.service_key } });
  return { request, job: marked };
}

/** VALIDATING stage: params, asset authorization, scope, credits hold. Idempotent per job. */
export function validateJob(db, job) {
  const service = serviceByKey(job.service_key);
  if (!service) throw badRequest(`unknown service: ${job.service_key}`);
  const params = job.params || {};
  for (const p of service.params || []) {
    if (p.optional && (params[p.key] == null || params[p.key] === '')) continue;
    if (params[p.key] == null && p.default != null) continue;
    if (params[p.key] == null) {
      if (!p.optional) throw badRequest(`missing parameter: ${p.key}`);
      continue;
    }
    const v = params[p.key];
    if (p.type === 'int' && (!Number.isInteger(Number(v)) || Number(v) < (p.min ?? 1) || Number(v) > (p.max ?? 1000))) throw badRequest(`parameter ${p.key} must be an integer in range`);
    if (p.type === 'enum' && !p.options.includes(v)) throw badRequest(`parameter ${p.key} must be one of ${p.options.join(', ')}`);
    if (p.type === 'json' && typeof v === 'string') { try { params[p.key] = JSON.parse(v); } catch { throw badRequest(`parameter ${p.key} must be valid JSON`); } }
  }
  const profile = params.profile || service.profiles?.[0] || 'safe';
  if (!service.profiles?.includes(profile)) throw badRequest(`profile ${profile} not permitted for service ${service.key} (allowed: ${service.profiles?.join(', ')})`);
  if (['standard', 'intrusive'].includes(profile)) {
    const asset = job.asset_id ? db.byIdGlobal('assets', job.asset_id) : null;
    if (!asset || !asset.authorization || asset.authorization.status !== 'verified') {
      throw badRequest(`profile ${profile} requires asset authorization status "verified"`);
    }
  }
  if (job.asset_id) {
    const asset = db.byIdGlobal('assets', job.asset_id);
    if (!asset) throw notFound('asset not found');
    const authz = asset.authorization || {};
    if (['security', 'audit'].includes(service.category) || service.engine === 'composite') {
      if (!['declared', 'verified'].includes(authz.status)) {
        throw badRequest('asset has no valid authorization record — security testing requires explicit authorization (scope, owner, date)');
      }
      if (!authz.scope_domains?.length) throw badRequest('asset authorization record must define scope domains');
    }
  }
  // credits hold (no double-hold)
  const alreadyHeld = db.store.find('credit_ledger', (l) => l.tenant_id === job.tenant_id && l.job_id === job.id && l.entry_type === 'hold').length > 0;
  const cost = alreadyHeld ? existingHoldTotal(db, job) : estimateCost(service, params);
  if (!alreadyHeld) {
    try {
      holdCredits(db, job.tenant_id, job.id, cost);
    } catch (e) {
      if (e.code === 'insufficient_credits') throw badRequest(e.message);
      throw e;
    }
  }
  return { cost, service, params };
}

function existingHoldTotal(db, job) {
  const holds = db.store.find('credit_ledger', (l) => l.tenant_id === job.tenant_id && l.job_id === job.id && l.entry_type === 'hold');
  const releases = db.store.find('credit_ledger', (l) => l.tenant_id === job.tenant_id && l.job_id === job.id && l.entry_type === 'release');
  return -holds.reduce((a, h) => a + h.amount, 0) - releases.reduce((a, r) => a + r.amount, 0);
}

/** Prepare stage: REQUESTED → VALIDATING → QUEUED (or FAILED). */
export function prepareJob(db, job) {
  if (job.state !== 'REQUESTED') return job;
  const patch = (p) => {
    const cur = db.store.byId('jobs', job.id);
    const next = { ...cur, ...p, id: job.id, updated_at: nowIso() };
    db.store.put('jobs', next);
    return next;
  };
  try {
    patch({ state: 'VALIDATING', progress: 5 });
    validateJob(db, patch({}));
    return patch({ state: 'QUEUED', progress: 10 });
  } catch (e) {
    releaseAll(db, job.tenant_id, job.id);
    const failed = patch({ state: 'FAILED', error: `validation: ${e.message}`, finished_at: nowIso() });
    bus.publish(TOPICS.jobFailed, failed);
    return failed;
  }
}

/** Run a job (claimed from queue or direct) through execution → analysis → QC. */
export async function executeJob(db, files, job, { workerId = 'worker-1' } = {}) {
  const patch = (p) => {
    const cur = db.store.byId('jobs', job.id);
    const next = { ...cur, ...p, id: job.id, updated_at: nowIso() };
    db.store.put('jobs', next);
    job = next;
    bus.publish(TOPICS.jobUpdated, { id: next.id, tenant_id: next.tenant_id, state: next.state, progress: next.progress });
    return next;
  };
  const log = (level, message, data) => {
    db.store.put('job_logs', { id: `jlog_${Math.random().toString(36).slice(2, 12)}`, job_id: job.id, tenant_id: job.tenant_id, ts: nowIso(), level, engine: 'runner', message: String(message).slice(0, 500), data: data ?? null });
  };

  let service, params, cost;
  if (job.state === 'REQUESTED') {
    // direct-invocation path (no queue): validate inline
    try {
      patch({ state: 'VALIDATING', progress: 5 });
      ({ cost, service, params } = validateJob(db, job));
      log('info', `validation passed (profile: ${params.profile || 'safe'}, estimated cost: ${cost} credits)`);
      patch({ state: 'QUEUED', progress: 10 });
    } catch (e) {
      log('error', `validation failed: ${e.message}`);
      releaseAll(db, job.tenant_id, job.id);
      patch({ state: 'FAILED', error: `validation: ${e.message}`, finished_at: nowIso() });
      bus.publish(TOPICS.jobFailed, job);
      return job;
    }
  } else {
    service = serviceByKey(job.service_key);
    params = job.params || {};
    cost = existingHoldTotal(db, job);
  }

  const asset = job.asset_id ? db.byIdGlobal('assets', job.asset_id) : null;
  if (asset) asset.base_url = deriveBaseUrl(asset);

  try {
    patch({ state: 'RUNNING', progress: 20, worker_id: workerId, started_at: job.started_at || nowIso() });
    const kind = serviceKind(service);
    let summary = null;
    if (kind === 'web') {
      const ctx = buildContext({ db, job, asset, service, params, logSink: (e) => db.store.put('job_logs', { id: `jlog_${Math.random().toString(36).slice(2, 12)}`, job_id: job.id, tenant_id: job.tenant_id, ...e }) });
      const engineKeys = engineKeysForService(service);
      const total = engineKeys.length || 1;
      for (let i = 0; i < engineKeys.length; i++) {
        const engine = ENGINES[engineKeys[i]];
        if (!engine) throw new Error(`engine not found: ${engineKeys[i]}`);
        await runEngine(ctx, engine);
        patch({ progress: 20 + Math.round(((i + 1) / total) * 50) });
      }
      patch({ state: 'ANALYZING', progress: 75 });
      const findings = analyzeFindings(ctx);
      log('info', `analysis: ${findings.length} deduplicated findings from ${ctx.findings.length} raw observations`);
      patch({ state: 'QUALITY_CHECK', progress: 85 });
      const qc = qualityCheck(ctx);
      assignFids(db, job.tenant_id, findings);
      if (isRetestJob(job)) {
        linkRetestFindings(db, job, findings);
        log('info', `retest of job ${job.meta.retest_of}: ${findings.filter((f) => f.verification === 'reproduced').length} re-detected, ${findings.filter((f) => f.verification === 'not_retested').length} new`);
      }
      for (const ev of ctx.evidence) db.store.put('evidence', ev);
      for (const f of findings) {
        for (const evId of f.evidence_ids) {
          const ev = db.store.byId('evidence', evId);
          if (ev) db.store.put('evidence', { ...ev, finding_id: f.id });
        }
        db.store.put('findings', f);
        bus.publish(TOPICS.findingCreated, { tenant_id: f.tenant_id, fid: f.fid, severity: f.severity, title: f.title });
      }
      summary = {
        kind: 'web',
        findings_count: findings.length,
        findings_by_severity: countBy(findings, 'severity'),
        engines: ctx.engineResults,
        requests_made: ctx.requests,
        pages_fetched: ctx.pages.size,
        metrics: ctx.metrics,
        inventory_keys: Object.keys(ctx.inventory),
      };
      patch({ result_summary: summary, qc, progress: 95 });
      const failedEngines = qc.engines_failed;
      const finalState = failedEngines === 0 ? 'COMPLETED' : (findings.length || failedEngines < qc.engines_run) ? 'PARTIALLY_COMPLETED' : 'FAILED';
      const usage = computeUsage(service, ctx);
      const { committed } = commitCredits(db, job.tenant_id, job.id, cost, usage.cost);
      patch({ state: finalState, progress: 100, finished_at: nowIso(), usage: { ...usage, credits_committed: committed, credits_estimate: cost } });
      log('info', `job ${finalState.toLowerCase()}: ${findings.length} findings, ${ctx.evidence.length} evidence records, ${committed} credits committed`);
      let retestRun = null;
      if (isRetestJob(job)) {
        retestRun = applyRetestVerdicts(db, job);
        log('info', `retest verdicts: ${retestRun.verdicts.reproduced} reproduced, ${retestRun.verdicts.fixed} fixed, ${retestRun.verdicts.inconclusive} inconclusive, ${retestRun.verdicts.new} new`);
        summary.retest = {
          source_job_id: retestRun.source_job_id,
          retest_run_id: retestRun.id,
          verdicts: retestRun.verdicts,
          severity_changes: retestRun.severity_changes,
        };
        patch({ result_summary: summary });
      }
      if (finalState !== 'FAILED') {
        bus.publish(TOPICS.jobCompleted, { id: job.id, tenant_id: job.tenant_id, service_key: job.service_key, asset_id: job.asset_id, findings_count: findings.length, state: finalState, job: { id: job.id } });
        notify(db, { tenantId: job.tenant_id, type: 'job_completed', title: `${service.name} ${finalState === 'COMPLETED' ? 'completed' : 'completed with warnings'}`, body: `${findings.length} findings · ${ctx.requests} requests · ${ctx.evidence.length} evidence records`, data: { job_id: job.id } });
      } else {
        bus.publish(TOPICS.jobFailed, job);
        notify(db, { tenantId: job.tenant_id, type: 'job_failed', title: `${service.name} failed`, body: `${qc.engines_failed}/${qc.engines_run} engines failed`, data: { job_id: job.id } });
      }
      return job;
    }
    const { runDataService, runDocService, runAiService } = await import('./adapters.js');
    if (kind === 'data') summary = await runDataService(db, files, job, service, params);
    else if (kind === 'documents') summary = await runDocService(db, files, job, service, params);
    else if (kind === 'ai') summary = await runAiService(db, files, job, service, params, asset);
    else throw new Error(`no runner for service kind: ${kind}`);
    patch({ state: 'ANALYZING', progress: 80 });
    patch({ state: 'QUALITY_CHECK', progress: 90 });
    const { committed } = commitCredits(db, job.tenant_id, job.id, cost, cost);
    patch({ state: 'COMPLETED', progress: 100, finished_at: nowIso(), result_summary: summary, usage: { credits_committed: committed, credits_estimate: cost }, qc: { engines_run: 1, engines_failed: 0, evidence_records: 0, findings_accepted: 0, findings_rejected: 0 } });
    bus.publish(TOPICS.jobCompleted, { id: job.id, tenant_id: job.tenant_id, service_key: job.service_key, asset_id: job.asset_id, findings_count: 0, state: 'COMPLETED', job: { id: job.id } });
    notify(db, { tenantId: job.tenant_id, type: 'job_completed', title: `${service.name} completed`, body: summary?.message || 'Service finished', data: { job_id: job.id } });
    return job;
  } catch (e) {
    log('error', `execution failed: ${e.message || e}`);
    releaseAll(db, job.tenant_id, job.id);
    const attempts = job.attempts || 1;
    const willRetry = attempts < (job.max_attempts || 3);
    patch({ state: willRetry ? 'RETRYING' : 'FAILED', error: String(e.message || e), finished_at: willRetry ? null : nowIso() });
    if (willRetry) {
      patch({ state: 'QUEUED' });
    } else {
      bus.publish(TOPICS.jobFailed, job);
      notify(db, { tenantId: job.tenant_id, type: 'job_failed', title: `${job.service_key} failed`, body: String(e.message || e).slice(0, 200), data: { job_id: job.id } });
    }
    return job;
  }
}

export function serviceKind(service) {
  const dataKeys = ['data_profile', 'data_cleanse', 'data_dedup', 'data_transform', 'data_anomaly'];
  const docKeys = ['doc_extract', 'doc_compare'];
  const aiKeys = ['kb_build', 'ai_readiness', 'ai_analyze'];
  if (dataKeys.includes(service.key)) return 'data';
  if (docKeys.includes(service.key)) return 'documents';
  if (aiKeys.includes(service.key)) return 'ai';
  if (service.engine === 'composite') return 'web';
  if (ENGINES[service.engine]) return 'web';
  throw new Error(`unknown engine: ${service.engine}`);
}

function computeUsage(service, ctx) {
  let units = 1;
  if (service.per_unit) {
    const unitCount = service.per_unit.unit === 'page' ? Math.max(1, ctx.pages.size || ctx.state.crawl?.pages?.length || 1) : 1;
    units = Math.min(service.per_unit.cap || 100, unitCount);
  }
  const cost = (service.base_credits || 0) + (service.per_unit ? units * service.per_unit.credits : 0);
  return { units, cost };
}

function countBy(arr, key) {
  const out = {};
  for (const x of arr) out[x[key]] = (out[x[key]] || 0) + 1;
  return out;
}

function deriveBaseUrl(asset) {
  const id = String(asset.identifier || '');
  if (/^https?:\/\//i.test(id)) return id.replace(/\/$/, '');
  if (/^\d+\.\d+\.\d+\.\d+$/.test(id) || id === 'localhost' || id.endsWith('.local')) {
    return `http://${id}${asset.port ? `:${asset.port}` : ''}`;
  }
  return `https://${id}${asset.port ? `:${asset.port}` : ''}`;
}
