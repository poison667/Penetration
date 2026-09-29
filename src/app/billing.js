import { nowIso } from '#core/util';

/**
 * Credit ledger with hold → commit/release semantics (double-entry style).
 * Jobs reserve (hold) credits at validation; actual usage is committed at
 * completion; unused holds are released. Every entry records balance_after.
 */
export function balanceOf(db, tenantId) {
  const entries = db.store.find('credit_ledger', (l) => l.tenant_id === tenantId)
    .sort((a, b) => ((a.seq ?? 0) - (b.seq ?? 0)) || (a.created_at < b.created_at ? -1 : a.created_at > b.created_at ? 1 : 0));
  // Balance is the sum of all amounts — order-independent and robust even if
  // entries were written within the same millisecond.
  const balance = entries.reduce((sum, e) => sum + (e.amount || 0), 0);
  return { balance, entries: entries.length };
}

function ledger(db, tenantId, { type, amount, jobId = null, source, memo = null }) {
  const { balance } = balanceOf(db, tenantId);
  // explicit monotonic per-tenant sequence (store iteration order is id-sorted after reloads)
  const head = db.store.find('credit_ledger', (l) => l.tenant_id === tenantId)
    .reduce((m, e) => ((e.seq ?? 0) > (m?.seq ?? 0) ? e : m), null);
  const entry = db.insert('credit_ledger', {
    tenant_id: tenantId, seq: (head?.seq ?? 0) + 1, entry_type: type, amount, balance_after: balance + amount,
    job_id: jobId, source, memo, created_at: nowIso(),
  });
  return entry;
}

export function grantCredits(db, tenantId, amount, source, memo) {
  return ledger(db, tenantId, { type: 'grant', amount: Math.round(amount), source, memo });
}

export function holdCredits(db, tenantId, jobId, amount) {
  const { balance } = balanceOf(db, tenantId);
  if (balance < amount) {
    const err = new Error(`insufficient credits: balance ${balance}, required ${amount}`);
    err.code = 'insufficient_credits';
    throw err;
  }
  return ledger(db, tenantId, { type: 'hold', amount: -Math.round(amount), jobId, source: 'job_hold' });
}

export function commitCredits(db, tenantId, jobId, heldAmount, actualAmount) {
  // release the unused portion then commit usage
  const release = Math.max(0, heldAmount - actualAmount);
  if (release > 0) ledger(db, tenantId, { type: 'release', amount: release, jobId, source: 'job_release' });
  const commit = Math.min(heldAmount, actualAmount);
  if (commit > 0) ledger(db, tenantId, { type: 'commit', amount: 0, jobId, source: 'job_commit', memo: `committed ${commit} credits` });
  return { committed: commit, released: release };
}

export function releaseAll(db, tenantId, jobId) {
  const holds = db.store.find('credit_ledger', (l) => l.tenant_id === tenantId && l.job_id === jobId && l.entry_type === 'hold');
  const commits = db.store.find('credit_ledger', (l) => l.tenant_id === tenantId && l.job_id === jobId && l.entry_type === 'commit');
  const heldTotal = -holds.reduce((a, h) => a + h.amount, 0);
  const releasedTotal = db.store.find('credit_ledger', (l) => l.tenant_id === tenantId && l.job_id === jobId && l.entry_type === 'release').reduce((a, h) => a + h.amount, 0);
  const outstanding = heldTotal - releasedTotal;
  if (outstanding > 0) return ledger(db, tenantId, { type: 'release', amount: outstanding, jobId, source: 'job_release_all' });
  return null;
}

export function estimateCost(service, params = {}) {
  let cost = service.base_credits || 0;
  if (service.per_unit) {
    const units = Number(params?.[service.per_unit.unit === 'page' ? 'max_pages' : service.per_unit.unit] || 0);
    cost += Math.min(service.per_unit.cap || 100, units * service.per_unit.credits);
  }
  return Math.round(cost);
}

/** Monthly plan grant (idempotent per period). Returns the grant entry or null. */
export function applyMonthlyGrant(db, tenantId, periodKey) {
  const existing = db.store.find('credit_ledger', (l) => l.tenant_id === tenantId && l.source === `plan_grant:${periodKey}`);
  if (existing.length) return null;
  const sub = db.store.findOne('subscriptions', (s) => s.tenant_id === tenantId && s.status === 'active');
  if (!sub) return null;
  const { PLANS } = PLANSMOD;
  const plan = PLANS.find((p) => p.key === sub.plan_key);
  if (!plan || !plan.credits_monthly) return null;
  return grantCredits(db, tenantId, plan.credits_monthly, `plan_grant:${periodKey}`, `Monthly grant for ${plan.name} (${periodKey})`);
}
import * as PLANSMOD from './catalog.js';

export function buildInvoice(db, tenantId, { periodStart, periodEnd }) {
  const usage = db.store.find('credit_ledger', (l) => l.tenant_id === tenantId && l.created_at >= periodStart && l.created_at <= periodEnd);
  const commits = usage.filter((u) => u.source === 'job_commit');
  const sub = db.store.findOne('subscriptions', (s) => s.tenant_id === tenantId && s.status === 'active');
  const planKey = sub?.plan_key || 'free';
  const invoice = db.insert('invoices', {
    tenant_id: tenantId, number: `INV-${periodStart.slice(0, 7).replace('-', '')}-${String(db.store.count('invoices', (i) => i.tenant_id === tenantId) + 1).padStart(4, '0')}`,
    period_start: periodStart, period_end: periodEnd, status: 'issued',
    lines: [
      { description: `Plan: ${planKey}`, amount_cents: 0, note: 'plan billing adapter not configured in this deployment (see docs/LIMITATIONS.md)' },
      { description: `Service usage: ${commits.length} job commitments`, amount_cents: 0, credits_used: commits.length },
    ],
    amount_cents: 0,
  });
  return invoice;
}
