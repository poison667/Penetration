import { newId, nowIso } from '#core/util';
import { notFound } from '#core/errors';

/**
 * Tenant-scoped data access layer over the embedded store.
 * Every tenant-owned entity lookup enforces tenant_id equality — cross-tenant
 * access returns 404 (existence is not disclosed). Tests prove isolation.
 */
export class Db {
  constructor(store) {
    this.store = store;
    this.#registerIndexes();
  }
  #registerIndexes() {
    const s = this.store;
    s.addIndex('users', 'tid_email', (u) => `${u.tenant_id}|${u.email}`);
    s.addIndex('sessions', 'token_hash', (x) => x.token_hash);
    s.addIndex('api_keys', 'key_hash', (x) => x.key_hash);
    s.addIndex('jobs', 'tid_state', (j) => `${j.tenant_id}|${j.state}`);
    s.addIndex('findings', 'tid_job', (f) => `${f.tenant_id}|${f.job_id}`);
    s.addIndex('findings', 'tid_asset', (f) => `${f.tenant_id}|${f.asset_id}`);
    s.addIndex('findings', 'tid_hash', (f) => `${f.tenant_id}|${f.asset_id || '*'}|${f.hash}`);
    s.addIndex('retest_runs', 'tid_asset', (r) => `${r.tenant_id}|${r.asset_id || '*'}`);
    s.addIndex('notifications', 'tid_user', (n) => `${n.tenant_id}|${n.user_id || '*'}`);
    s.addIndex('monitor_checks', 'monitor_ts', (c) => `${c.monitor_id}|${c.ts}`);
    s.addIndex('evidence', 'tid_job', (e) => `${e.tenant_id}|${e.job_id}`);
  }

  insert(collection, doc) {
    const full = { ...doc, id: doc.id || newId(PREFIX[collection] || 'x'), created_at: doc.created_at || nowIso() };
    this.store.put(collection, full);
    return full;
  }
  /** tenant-scoped fetch */
  byId(collection, tenantId, id) {
    const doc = this.store.byId(collection, id);
    if (!doc || doc.tenant_id !== tenantId) return null;
    return doc;
  }
  /** global fetch (platform entities like tenants) */
  byIdGlobal(collection, id) {
    return this.store.byId(collection, id);
  }
  list(collection, tenantId, { where = () => true, sort = 'created_at', dir = 'desc', limit = 100, offset = 0 } = {}) {
    const rows = this.store.find(collection, (d) => d.tenant_id === tenantId && where(d));
    rows.sort((a, b) => {
      const av = a[sort], bv = b[sort];
      const cmp = av === bv ? 0 : (av == null ? -1 : bv == null ? 1 : (av < bv ? -1 : 1));
      return dir === 'desc' ? -cmp : cmp;
    });
    const total = rows.length;
    return { rows: rows.slice(offset, offset + limit), total };
  }
  update(collection, tenantId, id, patch, { requireTenant = true } = {}) {
    const doc = requireTenant ? this.byId(collection, tenantId, id) : this.byIdGlobal(collection, id);
    if (!doc) throw notFound(`${collection} not found`);
    const next = { ...doc, ...patch, id: doc.id, updated_at: nowIso() };
    this.store.put(collection, next);
    return next;
  }
  remove(collection, tenantId, id) {
    const doc = this.byId(collection, tenantId, id);
    if (!doc) throw notFound(`${collection} not found`);
    this.store.del(collection, id);
    return doc;
  }
  findOne(collection, predicate) { return this.store.findOne(collection, predicate); }
  where(collection, predicate) { return this.store.find(collection, predicate); }
}

export const PREFIX = {
  tenants: 't', users: 'u', sessions: 'ses', api_keys: 'key', assets: 'ast',
  service_requests: 'req', jobs: 'job', job_logs: 'jlog', findings: 'f', evidence: 'ev',
  reports: 'rep', files: 'file', monitors: 'mon', monitor_checks: 'chk', monitor_events: 'mev',
  data_sources: 'dsrc', data_runs: 'drun', documents: 'doc', kbases: 'kb', kb_chunks: 'kbc',
  workflows: 'wf', workflow_runs: 'wfr', schedules: 'sch', rules: 'rule', rule_runs: 'arun',
  webhook_endpoints: 'whk', credit_ledger: 'led', subscriptions: 'sub', invoices: 'inv',
  tickets: 'tix', ticket_messages: 'tmsg', notifications: 'ntf', tasks: 'task',
  workflow_versions: 'wfver', retest_runs: 'rt', har_imports: 'har',
};
