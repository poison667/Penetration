import crypto from 'node:crypto';
import { nowIso } from '#core/util';

/**
 * Tamper-evident audit log: per-tenant hash chain.
 * entry.hash = sha256(prevHash | canonical JSON of entry fields).
 * Any mutation of historical entries breaks the chain and is detectable.
 */
export function recordAudit(store, { tenantId = null, actorType = 'user', actorId = null, action, resource, resourceId = null, detail = null }) {
  const tid = tenantId;
  // Determine the true chain head by explicit per-tenant sequence number — the
  // store's iteration order is id-sorted after snapshot reloads and must not be
  // used for chaining.
  const existing = store.find('audit', (a) => a.tenant_id === tid);
  const head = existing.reduce((m, a) => ((a.seq ?? 0) > (m?.seq ?? 0) ? a : m), null);
  const prev = head;
  const entry = {
    id: `aud_${crypto.randomBytes(12).toString('hex')}`,
    seq: (head?.seq ?? 0) + 1,
    tenant_id: tid,
    actor_type: actorType,
    actor_id: actorId,
    action,
    resource,
    resource_id: resourceId,
    detail,
    created_at: nowIso(),
    prev_hash: prev ? prev.hash : null,
  };
  entry.hash = crypto.createHash('sha256')
    .update(entry.prev_hash || '')
    .update(JSON.stringify([entry.id, entry.seq, entry.tenant_id, entry.actor_type, entry.actor_id, entry.action, entry.resource, entry.resource_id, JSON.stringify(detail ?? null), entry.created_at]))
    .digest('hex');
  store.put('audit', entry);
  return entry;
}

/** Verify chain integrity for a tenant (or global when tenantId undefined). */
export function verifyAuditChain(store, tenantId = undefined) {
  const hashOf = (e) => crypto.createHash('sha256')
    .update(e.prev_hash || '')
    .update(JSON.stringify([e.id, e.seq, e.tenant_id, e.actor_type, e.actor_id, e.action, e.resource, e.resource_id, JSON.stringify(e.detail ?? null), e.created_at]))
    .digest('hex');
  // Chains are per-tenant and linked via an explicit monotonic `seq` (the store's
  // iteration order is id-sorted after snapshot reloads and cannot be used).
  const tenants = tenantId === undefined
    ? [...new Set(store.find('audit', () => true).map((a) => a.tenant_id))]
    : [tenantId];
  let total = 0;
  const chains = {};
  for (const tid of tenants) {
    const entries = store.find('audit', (a) => a.tenant_id === tid)
      .sort((a, b) => (a.seq ?? 0) - (b.seq ?? 0));
    total += entries.length;
    let prevHash = null;
    let expectedSeq = 1;
    let ok = true;
    for (const e of entries) {
      if ((e.seq ?? 0) !== expectedSeq || e.prev_hash !== prevHash || e.hash !== hashOf(e)) {
        chains[tid || 'platform'] = { ok: false, broken_at: e.id, entries: entries.length };
        ok = false;
        break;
      }
      prevHash = e.hash;
      expectedSeq += 1;
    }
    if (ok) chains[tid || 'platform'] = { ok: true, entries: entries.length };
  }
  const broken = Object.entries(chains).find(([, v]) => !v.ok);
  return broken
    ? { ok: false, broken_at: broken[1].broken_at, tenant: broken[0], chains, entries: total }
    : { ok: true, chains, entries: total };
}
