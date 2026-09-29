import { JobQueue } from '#queue/queue';
import { executeJob, prepareJob } from './runner.js';
import { runMonitor } from './monitors.js';
import { parseCron, nextRun } from '#auto/cron';
import { applyMonthlyGrant } from '#app/billing';
import { nowIso } from '#core/util';

/**
 * Scheduler: drives everything time-based.
 *  - prepares REQUESTED jobs (VALIDATING → QUEUED) and executes queued jobs (lease reclaim)
 *  - runs due monitors
 *  - fires due schedules (automation rules / workflows)
 *  - monthly plan credit grants
 */
export class Scheduler {
  constructor({ db, files, automation, requestService, generateReport, intervalMs = 3000, workerId = 'worker-1' }) {
    this.db = db; this.files = files; this.automation = automation;
    this.requestService = requestService;
    this.generateReport = generateReport;
    this.intervalMs = intervalMs;
    this.workerId = workerId;
    this.queue = new JobQueue(db);
    this.timer = null;
    this.running = false;
    this.stats = { jobs_processed: 0, monitors_run: 0, schedules_fired: 0 };
  }

  start() {
    if (this.timer) return;
    this.timer = setInterval(() => this.tick().catch((e) => console.error('[scheduler]', e.message)), this.intervalMs);
    this.timer.unref?.();
  }
  stop() { if (this.timer) clearInterval(this.timer); this.timer = null; }

  async tick() {
    if (this.running) return; // avoid overlapping ticks
    this.running = true;
    try {
      // 1. reclaim stale leases
      this.queue.reclaimStale();
      // 1b. prepare REQUESTED jobs (VALIDATING → QUEUED / FAILED)
      const requested = this.db.store.find('jobs', (j) => j.state === 'REQUESTED').slice(0, 10);
      for (const r of requested) prepareJob(this.db, r);
      // 2. process one queued job per tick (sequential, predictable load)
      const job = this.queue.claim(this.workerId);
      if (job) {
        await executeJob(this.db, this.files, job, { workerId: this.workerId });
        this.stats.jobs_processed++;
      }
      // 3. due monitors
      const now = new Date().toISOString();
      const due = this.db.store.find('monitors', (m) => m.enabled !== false && (!m.next_run_at || m.next_run_at <= now));
      for (const monitor of due.slice(0, 10)) {
        try { await runMonitor(this.db, monitor); this.stats.monitors_run++; }
        catch (e) { this.db.store.put('monitors', { ...monitor, last_run_at: nowIso(), next_run_at: new Date(Date.now() + (monitor.interval_seconds || 300) * 1000).toISOString(), last_error: String(e.message || e) }); }
      }
      // 4. due schedules
      const dueSchedules = this.db.store.find('schedules', (s) => s.enabled !== false && (!s.next_run_at || s.next_run_at <= now));
      for (const sch of dueSchedules.slice(0, 10)) {
        try { await this.#fireSchedule(sch); this.stats.schedules_fired++; }
        catch (e) { console.error('[schedule]', sch.id, e.message); }
        const cron = safeCron(sch.cron);
        const next = cron ? nextRun(cron) : new Date(Date.now() + 3600_000);
        this.db.store.put('schedules', { ...sch, last_run_at: nowIso(), next_run_at: (next || new Date(Date.now() + 3600_000)).toISOString() });
      }
      // 5. monthly grants
      this.#monthlyBilling();
    } finally {
      this.running = false;
    }
  }

  async #fireSchedule(sch) {
    if (sch.rule_id) {
      await this.automation.fireRule(sch.rule_id, { event: { type: 'schedule', schedule_id: sch.id, name: sch.name } });
    } else if (sch.workflow_id) {
      const { runWorkflow } = await import('#auto/workflow');
      await runWorkflow(this.db, sch.tenant_id, sch.workflow_id, { event: { type: 'schedule', schedule_id: sch.id } }, { requestService: this.requestService, generateReport: this.generateReport });
    }
  }

  #monthlyBilling() {
    const periodKey = new Date().toISOString().slice(0, 7);
    const tenants = this.db.store.find('tenants', () => true);
    for (const t of tenants) {
      try { applyMonthlyGrant(this.db, t.id, periodKey); } catch { /* grants optional */ }
    }
  }
}

function safeCron(expr) {
  try { return parseCron(expr); } catch { return null; }
}
