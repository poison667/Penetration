import { nowIso, newId } from '#core/util';
import { notify } from '#app/notify';

/**
 * Workflow orchestration engine: versioned definitions, DAG steps with
 * retries, persistent execution state (resumable), notifications on failure.
 * Step types: service | condition | notify | report | api_call | delay.
 */
export async function runWorkflow(db, tenantId, workflowId, triggerContext, { requestService, generateReport } = {}) {
  const wf = db.byId('workflows', tenantId, workflowId);
  if (!wf) throw new Error('workflow not found');
  const definition = wf.definition || { steps: [] };
  const run = db.insert('workflow_runs', {
    tenant_id: tenantId, workflow_id: workflowId, workflow_version: wf.version || 1,
    trigger: { type: triggerContext?.event?.type || 'manual', detail: triggerContext?.event || null },
    state: 'running', current_step: definition.steps[0]?.id || null,
    step_states: [], started_at: nowIso(), finished_at: null, error: null,
  });
  await executeWorkflow(db, run, definition, triggerContext, { requestService, generateReport });
  return db.byIdGlobal('workflow_runs', run.id) || run;
}

export async function executeWorkflow(db, run, definition, triggerContext, { requestService, generateReport } = {}) {
  const steps = definition.steps || [];
  const stepById = Object.fromEntries(steps.map((s) => [s.id, s]));
  const context = { event: triggerContext?.event || null, workflow: { id: run.workflow_id, run_id: run.id }, steps: {} };

  const update = (patch) => {
    const cur = db.byIdGlobal('workflow_runs', run.id);
    db.store.put('workflow_runs', { ...cur, ...patch, id: run.id });
  };
  const recordStep = (stepId, state, detail) => {
    const cur = db.byIdGlobal('workflow_runs', run.id) || run;
    const stepStates = [...(cur.step_states || [])];
    const idx = stepStates.findIndex((s) => s.step_id === stepId);
    const entry = { step_id: stepId, state, detail: detail || null, at: nowIso() };
    if (idx >= 0) stepStates[idx] = entry; else stepStates.push(entry);
    update({ step_states: stepStates, current_step: stepId });
  };

  try {
    let stepId = steps[0]?.id || null;
    let guard = 0;
    while (stepId) {
      if (++guard > 200) throw new Error('workflow step limit exceeded (possible cycle)');
      const step = stepById[stepId];
      if (!step) throw new Error(`unknown step: ${stepId}`);
      update({ current_step: stepId });
      const retries = step.retries || 0;
      let lastErr = null;
      let done = false;
      for (let attempt = 0; attempt <= retries && !done; attempt++) {
        try {
          await executeStep(db, run, step, context, { requestService, generateReport });
          recordStep(stepId, attempt > 0 ? 'succeeded_after_retry' : 'succeeded', null);
          done = true;
        } catch (e) {
          lastErr = e;
          if (attempt < retries) recordStep(stepId, 'retrying', { attempt: attempt + 1, error: String(e.message || e) });
        }
      }
      if (!done) {
        if (step.on_error === 'continue') {
          recordStep(stepId, 'failed_continued', { error: String(lastErr.message || lastErr) });
          context.steps[stepId] = { failed: true, error: String(lastErr.message || lastErr) };
        } else {
          throw new Error(`step ${stepId} failed: ${lastErr.message || lastErr}`);
        }
      }
      stepId = step.next || null;
    }
    update({ state: 'completed', finished_at: nowIso() });
  } catch (e) {
    update({ state: 'failed', error: String(e.message || e), finished_at: nowIso() });
    notify(db, { tenantId: run.tenant_id, type: 'workflow_failed', title: 'Workflow failed', body: `Workflow run ${run.id} failed: ${e.message || e}`, data: { run_id: run.id } });
    const cur = db.byIdGlobal('workflow_runs', run.id);
    if (cur && cur.state !== 'failed') update({ state: 'failed', error: String(e.message || e), finished_at: nowIso() });
  }
}

async function executeStep(db, run, step, context, { requestService, generateReport }) {
  switch (step.type) {
    case 'service': {
      if (!requestService) throw new Error('requestService not wired');
      const job = await requestService({
        tenantId: run.tenant_id, serviceKey: step.service,
        assetId: step.asset_id || context.event?.asset?.id || null,
        params: step.params || {}, userId: null, source: `workflow:${run.id}`,
      });
      // await completion (bounded poll; the worker completes the job)
      const deadline = Date.now() + (step.timeout_ms || 10 * 60_000);
      let cur = null;
      while (Date.now() < deadline) {
        cur = db.byIdGlobal('jobs', job.id);
        if (['COMPLETED', 'PARTIALLY_COMPLETED', 'FAILED', 'CANCELLED'].includes(cur?.state)) break;
        await new Promise((r) => setTimeout(r, 500));
      }
      if (!cur || !['COMPLETED', 'PARTIALLY_COMPLETED'].includes(cur.state)) {
        throw new Error(`service step ${step.service} ended in state ${cur?.state || 'timeout'}`);
      }
      context.steps[step.id] = { job_id: job.id, state: cur.state, findings: cur.result_summary?.findings_count ?? null };
      return;
    }
    case 'condition': {
      const { evaluate } = await import('#core/expr');
      const ok = evaluate(step.expr, context);
      if (!ok) {
        if (!step.next_on_false) throw new Error('condition evaluated false with no next_on_false');
        context.__jump_to = step.next_on_false;
      }
      return;
    }
    case 'notify': {
      const { notify } = await import('#app/notify');
      notify(db, { tenantId: run.tenant_id, userId: step.user_id || null, type: 'workflow', title: step.title || 'Workflow notification', body: step.body || `Workflow run ${run.id}`, data: { run_id: run.id } });
      return;
    }
    case 'report': {
      if (!generateReport) throw new Error('generateReport not wired');
      generateReport({ tenantId: run.tenant_id, job: null, kind: step.kind || 'asset_summary', format: step.format || 'pdf', assetId: step.asset_id || context.event?.asset?.id || null, createdBy: `workflow:${run.id}` });
      return;
    }
    case 'api_call': {
      const res = await fetch(step.url, { method: step.method || 'POST', headers: { 'content-type': 'application/json' }, body: step.body ? JSON.stringify(step.body) : undefined });
      if (!res.ok && step.fail_on_error !== false) throw new Error(`api_call failed: HTTP ${res.status}`);
      return;
    }
    case 'delay': {
      await new Promise((r) => setTimeout(r, Math.min(step.ms || 1000, 30_000)));
      return;
    }
    default:
      throw new Error(`unknown workflow step type: ${step.type}`);
  }
}

/** Create/upgrade workflow with version history. */
const VALID_STEP_TYPES = ['service', 'condition', 'notify', 'report', 'api_call', 'delay'];
export function validateWorkflowDefinition(definition) {
  if (!definition || !Array.isArray(definition.steps) || !definition.steps.length) throw new Error('definition.steps must be a non-empty array');
  const ids = new Set();
  for (const s of definition.steps) {
    if (!s.id || typeof s.id !== 'string') throw new Error('every step requires a string id');
    if (ids.has(s.id)) throw new Error(`duplicate step id: ${s.id}`);
    ids.add(s.id);
    if (s.type && !VALID_STEP_TYPES.includes(s.type)) throw new Error(`unknown step type: ${s.type}`);
  }
  return true;
}
export function saveWorkflow(db, tenantId, { id, name, definition, enabled = true }) {
  validateWorkflowDefinition(definition);
  if (id) {
    const existing = db.byId('workflows', tenantId, id);
    if (!existing) throw new Error('workflow not found');
    const changed = JSON.stringify(existing.definition) !== JSON.stringify(definition) || existing.name !== name;
    const next = { ...existing, name, definition, enabled, version: changed ? (existing.version || 1) + 1 : existing.version, updated_at: nowIso() };
    db.store.put('workflows', next);
    if (changed) db.insert('workflow_versions', { tenant_id: tenantId, workflow_id: id, version: next.version, definition, name, created_at: nowIso() });
    return next;
  }
  const wf = db.insert('workflows', { tenant_id: tenantId, name, definition, enabled, version: 1 });
  db.insert('workflow_versions', { tenant_id: tenantId, workflow_id: wf.id, version: 1, definition, name });
  return wf;
}
