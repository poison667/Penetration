import { evaluate } from '#core/expr';
import { TOPICS, bus } from '#core/events';
import { notify } from '#app/notify';

/**
 * Automation engine: event-driven rules + workflow orchestration.
 * TRIGGERS: schedule, monitor_event, job_completed, webhook, import,
 * file_change, threshold (monitor metrics).
 * ACTIONS: run_service, run_workflow, generate_report, notify, webhook_call,
 * create_task, update_record.
 */
export class AutomationEngine {
  constructor({ db, files, requestService, generateReport, now = () => new Date().toISOString() }) {
    this.db = db; this.files = files;
    this.requestService = requestService;   // fn({tenantId, serviceKey, assetId, params, userId}) → job
    this.generateReport = generateReport;   // fn({tenantId, job, kind, format, assetId, createdBy}) → report
    this.now = now;
    this.started = false;
  }

  start() {
    if (this.started) return;
    this.started = true;
    bus.on('event', ({ topic, payload }) => {
      this.#handleEvent(topic, payload).catch((e) => console.error('[automation]', e.message));
    });
  }

  async #handleEvent(topic, payload) {
    const triggerMap = {
      [TOPICS.jobCompleted]: 'job_completed',
      [TOPICS.monitorEvent]: 'monitor_event',
      [TOPICS.dataImported]: 'import',
      [TOPICS.fileChanged]: 'file_change',
      [TOPICS.webhook]: 'webhook',
    };
    const triggerType = triggerMap[topic];
    if (!triggerType) return;
    const rules = this.db.store.find('rules', (r) => r.enabled && r.trigger?.type === triggerType);
    for (const rule of rules) {
      const ctx = { event: { type: triggerType, topic, ...payload }, trigger: rule.trigger, rule: { id: rule.id, name: rule.name } };
      try {
        if (rule.conditions && !evaluate(rule.conditions, ctx)) continue;
        await this.executeRule(rule, ctx);
      } catch (e) {
        this.db.store.put('rule_runs', { ...this.db.store.byId('rule_runs', '') || {}, }); // noop guard
        this.#recordRun(rule, ctx, 'failed', { error: String(e.message || e) });
      }
    }
  }

  /** Fire a rule manually (used by scheduler for schedule triggers + tests). */
  async fireRule(ruleId, ctx = { event: { type: 'manual' } }) {
    const rule = this.db.byIdGlobal('rules', ruleId);
    if (!rule) throw new Error('rule not found');
    if (rule.conditions && !evaluate(rule.conditions, ctx)) {
      this.#recordRun(rule, ctx, 'skipped', { reason: 'conditions_not_met' });
      return { skipped: true };
    }
    return this.executeRule(rule, ctx);
  }

  async executeRule(rule, ctx) {
    const run = this.#recordRun(rule, ctx, 'running', null);
    const results = [];
    try {
      for (const action of rule.actions || []) {
        results.push(await this.#executeAction(action, rule, ctx));
      }
      this.db.store.put('rule_runs', { ...run, state: 'completed', results, finished_at: this.now() });
      return { runId: run.id, results };
    } catch (e) {
      this.db.store.put('rule_runs', { ...run, state: 'failed', results, error: String(e.message || e), finished_at: this.now() });
      throw e;
    }
  }

  async #executeAction(action, rule, ctx) {
    const tid = rule.tenant_id;
    switch (action.type) {
      case 'run_service': {
        const job = await this.requestService({
          tenantId: tid,
          serviceKey: action.service,
          assetId: action.asset_id || ctx.event?.asset?.id || null,
          params: action.params || {},
          userId: null,
          source: `automation:${rule.id}`,
        });
        return { action: 'run_service', job_id: job.id };
      }
      case 'run_workflow': {
        const { runWorkflow } = await import('./workflow.js');
        const run = await runWorkflow(this.db, tid, action.workflow_id, ctx, { requestService: this.requestService });
        return { action: 'run_workflow', run_id: run.id };
      }
      case 'generate_report': {
        const job = ctx.event?.job || null;
        const rep = this.generateReport({ tenantId: tid, job, kind: action.kind || 'service_report', format: action.format || 'pdf', assetId: action.asset_id || ctx.event?.asset?.id || job?.asset_id || null, createdBy: `automation:${rule.id}` });
        return { action: 'generate_report', report_id: rep.report.id };
      }
      case 'notify': {
        const n = notify(this.db, { tenantId: tid, userId: action.user_id || null, type: 'automation', title: action.title || `Automation: ${rule.name}`, body: action.body || `Rule "${rule.name}" fired (${ctx.event?.type})`, data: { rule_id: rule.id, event: ctx.event } });
        return { action: 'notify', notification_id: n.id };
      }
      case 'webhook_call': {
        const res = await fetch(action.url, { method: action.method || 'POST', headers: { 'content-type': 'application/json', ...(action.secret ? { 'x-meridian-signature': 'hmac:' + (await import('node:crypto')).createHmac('sha256', action.secret).update(JSON.stringify(ctx)).digest('hex') } : {}) }, body: JSON.stringify({ rule: rule.name, event: ctx.event }) });
        return { action: 'webhook_call', status: res.status };
      }
      case 'create_task': {
        const task = this.db.insert('tasks', { tenant_id: tid, title: action.title || `Task from ${rule.name}`, status: 'open', source: `automation:${rule.id}`, due: action.due || null, detail: action.detail || JSON.stringify(ctx.event).slice(0, 500) });
        return { action: 'create_task', task_id: task.id };
      }
      case 'update_record': {
        const { record_type, record_id, patch } = action;
        if (record_type === 'finding' && record_id) {
          const f = this.db.byId('findings', tid, record_id);
          if (f) this.db.store.put('findings', { ...f, ...patch, id: f.id });
        } else if (record_type === 'asset' && record_id) {
          const a = this.db.byId('assets', tid, record_id);
          if (a) this.db.store.put('assets', { ...a, ...patch, id: a.id });
        } else if (record_type === 'monitor' && ctx.event?.monitor?.id) {
          const m = this.db.byId('monitors', tid, ctx.event.monitor.id);
          if (m) this.db.store.put('monitors', { ...m, ...patch, id: m.id });
        }
        return { action: 'update_record', record_type, record_id };
      }
      default:
        throw new Error(`unknown automation action: ${action.type}`);
    }
  }

  #recordRun(rule, ctx, state, extra) {
    const existing = null;
    const run = {
      id: `arun_${Math.random().toString(36).slice(2, 14)}`,
      tenant_id: rule.tenant_id, rule_id: rule.id, rule_name: rule.name,
      trigger_detail: { type: ctx.event?.type || 'unknown', topic: ctx.event?.topic || null, asset: ctx.event?.asset || null, job_id: ctx.event?.job?.id || ctx.event?.id || null, monitor: ctx.event?.monitor || null, payload_keys: Object.keys(ctx.event || {}) },
      state, results: [], started_at: this.now(), finished_at: null, error: null,
      ...(extra || {}),
    };
    this.db.store.put('rule_runs', run);
    return run;
  }
}
