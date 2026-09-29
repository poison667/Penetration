import { nowIso } from '#core/util';
import { JOB_STATES } from '#core/taxonomy';

/**
 * Durable job queue on top of the store. Workers claim jobs with a lease +
 * heartbeat; stale leases are reclaimed (at-least-once with attempts/ retries).
 */
export class JobQueue {
  constructor(db) { this.db = db; }

  enqueue(job) {
    if (!JOB_STATES.includes(job.state)) throw new Error(`invalid job state: ${job.state}`);
    this.db.store.put('jobs', { ...job, queued_at: nowIso() });
    return job;
  }

  /** Claim the next QUEUED job (FIFO by priority then created_at). */
  claim(workerId, { leaseMs = 120_000 } = {}) {
    const candidates = this.db.store.find('jobs', (j) => j.state === 'QUEUED')
      .sort((a, b) => (b.priority || 0) - (a.priority || 0) || (a.created_at < b.created_at ? -1 : 1));
    const job = candidates[0];
    if (!job) return null;
    const claimed = { ...job, state: 'RUNNING', worker_id: workerId, lease_expires_at: new Date(Date.now() + leaseMs).toISOString(), attempts: (job.attempts || 0) + 1, started_at: job.started_at || nowIso() };
    this.db.store.put('jobs', claimed);
    return claimed;
  }

  heartbeat(jobId, workerId, { leaseMs = 120_000 } = {}) {
    const job = this.db.store.byId('jobs', jobId);
    if (!job || job.worker_id !== workerId || job.state !== 'RUNNING') return false;
    this.db.store.put('jobs', { ...job, lease_expires_at: new Date(Date.now() + leaseMs).toISOString() });
    return true;
  }

  /** Requeue jobs whose lease expired while RUNNING (worker crash). */
  reclaimStale(now = Date.now()) {
    const stale = this.db.store.find('jobs', (j) => j.state === 'RUNNING' && j.lease_expires_at && Date.parse(j.lease_expires_at) < now);
    const requeued = [];
    for (const job of stale) {
      const next = { ...job, state: (job.attempts || 1) >= (job.max_attempts || 3) ? 'FAILED' : 'RETRYING', error: 'lease expired (worker crash recovery)', worker_id: null };
      this.db.store.put('jobs', next);
      if (next.state === 'RETRYING') this.db.store.put('jobs', { ...next, state: 'QUEUED', attempts: job.attempts || 1 });
      requeued.push(next.id);
    }
    return requeued;
  }

  update(jobId, patch) {
    const job = this.db.store.byId('jobs', jobId);
    if (!job) return null;
    const next = { ...job, ...patch, id: job.id };
    this.db.store.put('jobs', next);
    return next;
  }

  depth() {
    return this.db.store.count('jobs', (j) => j.state === 'QUEUED');
  }
}
