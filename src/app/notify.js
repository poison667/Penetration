import { bus, TOPICS } from '#core/events';

/** Persisted in-app notifications + real-time push via SSE. */
export function notify(db, { tenantId, userId = null, type, title, body, data = null }) {
  const n = db.insert('notifications', {
    tenant_id: tenantId, user_id: userId, type, title, body, data,
    read_at: null, created_at: new Date().toISOString(),
  });
  bus.publish(TOPICS.notification, n);
  return n;
}
export function notifyTenant(db, tenantId, payload) {
  return notify(db, { tenantId, userId: null, ...payload });
}
export function listNotifications(db, tenantId, userId, { unreadOnly = false, limit = 50 } = {}) {
  return db.store.find('notifications', (n) =>
    n.tenant_id === tenantId && (n.user_id === null || n.user_id === userId) && (!unreadOnly || !n.read_at),
  ).sort((a, b) => (a.created_at < b.created_at ? 1 : -1)).slice(0, limit);
}
export function markRead(db, tenantId, userId, id) {
  const n = db.byId('notifications', tenantId, id);
  if (n && (n.user_id === null || n.user_id === userId)) {
    db.store.put('notifications', { ...n, read_at: new Date().toISOString() });
    return true;
  }
  return false;
}
